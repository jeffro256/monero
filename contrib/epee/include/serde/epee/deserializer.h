#pragma once

#include <vector>

#include "constants.h"
#include "../internal/endianness.h"
#include "../internal/external/logging.h"
#include "../internal/external/numeric_cast.h"
#include "../model/constants.h"
#include "../model/deserializer.h"
#include "../model/visitor.h"

namespace serde::epee
{
    // forward declaration of internal function
    constexpr bool uint64_fits_size(uint64_t value);

    class Deserializer: public model::Deserializer
    {
    public:

        Deserializer(const const_byte_span& byte_view):
            model::Deserializer(),
            m_current(byte_view),
            m_stack(),
            m_finished(false)
        {
            m_stack.reserve(PS_MAX_OBJECT_DEPTH);
        }

        ~Deserializer() = default;

    ///////////////////////////////////////////////////////////////////////////
    // Stream helpers                                                        //
    ///////////////////////////////////////////////////////////////////////////
    private:

        uint8_t peek() const
        {
            return *m_current.begin();
        }

        const_byte_iterator consume(size_t nbytes)
        {
            CHECK_AND_ASSERT_THROW_MES
            (
                m_current.size() >= nbytes,
                "trying to consume too many bytes from deserializer"
            );

            const const_byte_iterator cursor_pre_consume = m_current.begin();
            const size_t old_view_size = m_current.size();
            m_current = { cursor_pre_consume + nbytes, old_view_size - nbytes };
            return cursor_pre_consume;
        }

        void consume(void* dst, size_t nbytes)
        {
            const const_byte_iterator src = this->consume(nbytes);
            memcpy(dst, src, nbytes);
        }

    ///////////////////////////////////////////////////////////////////////////
    // Parsing helpers                                                       //
    ///////////////////////////////////////////////////////////////////////////
    private:

        template <typename T>
        T read_pod_value()
        {
            const T* current_as_t = reinterpret_cast<const T*>(this->consume(sizeof(T)));
            return CONVERT_POD(*current_as_t);
        }

        size_t read_varint()
        {
            constexpr size_t VARINT_SIZE_MASK = 0b00000011;

            const uint8_t first_byte = this->peek();
            const size_t varint_size = 1 << (static_cast<size_t>(first_byte) & VARINT_SIZE_MASK);

            uint64_t value64 = 0;
            this->consume(&value64, varint_size);
            value64 = CONVERT_POD(value64);
            value64 >>= 2;

            return internal::safe_numeric_cast<size_t>(value64);
        }

        void validate_signature()
        {
            constexpr size_t SIGSIZE = sizeof(PORTABLE_STORAGE_SIG_AND_VER);
            const const_byte_iterator begin = this->consume(SIGSIZE);

            CHECK_AND_ASSERT_THROW_MES
            (
                0 == memcmp(begin, PORTABLE_STORAGE_SIG_AND_VER, SIGSIZE),
                "missing portable format signature and version"
            );
        }

        void deserialize_scalar(uint8_t type_code, model::BasicVisitor& visitor)
        {
            #define DESER_POD_SCALAR(sname, mname, tyname)                 \
                case SERIALIZE_TYPE_##sname:                               \
                    visitor.visit_##mname(this->read_pod_value<tyname>()); \
                    break;                                                 \

            this->doing_one_element_or_entry();

            switch (type_code)
            {
            DESER_POD_SCALAR( INT64,   int64,  int64_t)
            DESER_POD_SCALAR( INT32,   int32,  int32_t)
            DESER_POD_SCALAR( INT16,   int16,  int16_t)
            DESER_POD_SCALAR(  INT8,    int8,   int8_t)
            DESER_POD_SCALAR(UINT64,  uint64, uint64_t)
            DESER_POD_SCALAR(UINT32,  uint32, uint32_t)
            DESER_POD_SCALAR(UINT16,  uint16, uint16_t)
            DESER_POD_SCALAR( UINT8,   uint8,  uint8_t)
            DESER_POD_SCALAR(DOUBLE, float64,   double)
            case SERIALIZE_TYPE_STRING:
                {
                    const size_t str_len = this->read_varint();
                    visitor.visit_bytes({this->consume(str_len), str_len});
                    break;
                }
            DESER_POD_SCALAR(BOOL, boolean, bool)
            case SERIALIZE_TYPE_OBJECT:
                this->deserialize_raw_section(visitor);
                break;
            default:
                ASSERT_MES_AND_THROW("unrecognized type code: " << type_code);
            }
        }

        void deserialize_raw_section(model::BasicVisitor& visitor)
        {
            const size_t obj_len = this->read_varint();
            this->push_object(obj_len);
            visitor.visit_object(obj_len, *this);
        }

        void deserialize_raw_key(model::BasicVisitor& visitor)
        {
            const uint8_t key_len = *this->consume(1);
            const const_byte_iterator key = this->consume(key_len);
            this->did_read_key();
            visitor.visit_key({key, key_len});
        }

        void deserialize_section_entry(model::BasicVisitor& visitor)
        {
            const uint8_t type_code = *this->consume(1);
            if (type_code & SERIALIZE_FLAG_ARRAY)
            {
                const uint8_t scalar_type_code = type_code & ~SERIALIZE_FLAG_ARRAY;
                size_t array_len = this->read_varint();
                this->push_array(array_len, scalar_type_code);
                visitor.visit_array(array_len, *this);
            }
            else
            {
                this->deserialize_scalar(type_code, visitor);
            }
        }

    ///////////////////////////////////////////////////////////////////////////
    // State helpers                                                         //
    ///////////////////////////////////////////////////////////////////////////
    private:

        struct recursion_level
        {
            optional<uint8_t> scalar_type; // none if an object, 
            size_t remaining; // number of elements / entries which have yet to be deserialized
            bool expecting_key; // used is is_object()

            bool is_object() const
            {
                return !scalar_type;
            }
        };

        bool inside_array() const
        {
            return m_stack.size() != 0 && !m_stack.back().is_object();
        }

        bool inside_object() const
        {
            return !this->inside_array();
        }

        bool expecting_key() const
        {
            return m_stack.back().expecting_key;
        }

        uint8_t current_array_type() const
        {
            CHECK_AND_ASSERT_THROW_MES
            (
                this->inside_array(),
                "trying to get array type while inside object"
            );

            return *m_stack.back().scalar_type;
        }

        size_t remaining() const
        {
            return m_stack.size() ? m_stack.back().remaining : 0;
        }
 
        bool root() const
        {
            return m_stack.size() == 0 && !m_finished;
        }

        bool finished() const
        {
            return m_finished;
        }

        void push_array(size_t num_elements, uint8_t type_code)
        {
            m_stack.push_back({type_code, num_elements, false});
        }

        void push_object(size_t num_entries)
        {
            CHECK_AND_ASSERT_THROW_MES
            (
                m_stack.size() < PS_MAX_OBJECT_DEPTH,
                "Maximum object depth exceeded! Possibly parsing a DoS message"
            );

            m_stack.push_back({{}, num_entries, true});
        }

        void pop()
        {
            CHECK_AND_ASSERT_THROW_MES
            (
                m_stack.size() > 0,
                "binary::Deserializer internal logic error: called pop() too many times"
            );

            m_stack.pop_back();

            if (m_stack.size() == 0)
            {
                m_finished = true;
            }
        }

        void did_read_key()
        {
            m_stack.back().expecting_key = false;
        }

        void doing_one_element_or_entry()
        {
            m_stack.back().remaining--;
        }

    ///////////////////////////////////////////////////////////////////////////
    // Member Variables                                                      //
    ///////////////////////////////////////////////////////////////////////////
    private:

        const_byte_span m_current;
        
        // keep track deserializing state
        std::vector<recursion_level> m_stack;
        bool m_finished;

    ///////////////////////////////////////////////////////////////////////////
    // Deserializer interface                                                //
    ///////////////////////////////////////////////////////////////////////////
    public:

        // This is the main chunk of logic behind this Deserializer
        void deserialize_any(model::BasicVisitor& visitor) override final
        {
            if (this->finished())
            {
                visitor.visit_end_object();
            }
            else if (this->root())
            {
                this->validate_signature();
                this->deserialize_raw_section(visitor);
            }
            else if (this->remaining() == 0)
            {
                if (this->inside_array())
                {
                    this->pop();
                    visitor.visit_end_array();
                }
                else // finished object
                {
                    this->pop();
                    visitor.visit_end_object();
                }
            }
            else if (this->inside_object())
            {
                if (this->expecting_key())
                {
                    this->deserialize_raw_key(visitor);
                }
                else // expecting entry
                {
                    this->deserialize_section_entry(visitor);
                }
            }
            else // inside array with elements left
            {
                this->deserialize_scalar(this->current_array_type(), visitor);
            }
        }

        #ifndef DESER_TO_DESER_ANY
        #define DEFER_TO_DESER_ANY(mname)                                   \
            void deserialize_##mname(model::BasicVisitor& v) override final \
            { return this->deserialize_any(v); }
        #endif

        // The epee binary format is self-describing, so means we can ignore deserialization hints
        DEFER_TO_DESER_ANY(int64)
        DEFER_TO_DESER_ANY(int32)
        DEFER_TO_DESER_ANY(int16)
        DEFER_TO_DESER_ANY(int8)
        DEFER_TO_DESER_ANY(uint64)
        DEFER_TO_DESER_ANY(uint32)
        DEFER_TO_DESER_ANY(uint16)
        DEFER_TO_DESER_ANY(uint8)
        DEFER_TO_DESER_ANY(float64)
        DEFER_TO_DESER_ANY(bytes)
        DEFER_TO_DESER_ANY(boolean)
        DEFER_TO_DESER_ANY(key)
        DEFER_TO_DESER_ANY(end_array)
        DEFER_TO_DESER_ANY(end_object)

        void deserialize_array(optional<size_t>, model::BasicVisitor& visitor) override final
        {
            this->deserialize_any(visitor);
        }

        void deserialize_object(optional<size_t>, model::BasicVisitor& visitor) override final
        {
            this->deserialize_any(visitor);
        }

        bool is_human_readable() const noexcept override final
        {
            return false;
        }
    }; // class Deserializer

    template <typename T>
    T from_bytes(const const_byte_span& bytes)
    {
        Deserializer deserializer(bytes);
        optional<T> deser_res = model::Deserialize<T>::dflt(deserializer);
        CHECK_AND_ASSERT_THROW_MES
        (
            deser_res,
            "JSON Deserializer returned no data"
        );
        return *deser_res;
    }
} // namespace serde::epee