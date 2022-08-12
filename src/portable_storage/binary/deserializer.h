#pragma once

#include <vector>

#include "constants.h"
#include "../internal/endianness.h"
#include "../internal/external/logging.h"
#include "../model/constants.h"
#include "../model/deserializer.h"
#include "../model/visitor.h"

namespace portable_storage::binary
{
    // forward declaration of internal function
    constexpr bool uint64_fits_size(uint64_t value);

    // @TODO: not templated, byte_ref
    template <class t_const_uint8_iterator>
    class Deserializer: public model::Deserializer
    {
        template <typename Value>
        using Visitor = model::Visitor<Value, portable_storage::binary::Deserializer<t_const_uint8_iterator>>;

    public:

        Deserializer(t_const_uint8_iterator begin, t_const_uint8_iterator end):
            model::Deserializer(),
            m_current(begin),
            m_end(end),
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
            return *m_current;
        }

        t_const_uint8_iterator consume(size_t nbytes)
        {
            CHECK_AND_ASSERT_THROW_MES
            (
                m_end - m_current >= nbytes,
                "trying to consume too many bytes from deserializer"
            );

            t_const_uint8_iterator old = m_current;
            m_current += nbytes;
            return old;
        }

        void consume(void* dst, size_t nbytes)
        {
            t_const_uint8_iterator src = this->consume(nbytes);
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
            t_const_uint8_iterator begin = this->consume(SIGSIZE);

            CHECK_AND_ASSERT_THROW_MES
            (
                0 == memcmp(begin, PORTABLE_STORAGE_SIG_AND_VER, SIGSIZE),
                "missing portable format signature and version"
            );
        }

        template <typename Value>
        Value deserialize_scalar(uint8_t type_code, Visitor<Value>& visitor)
        {
            #define DESER_POD_SCALAR(sname, mname, tyname)                        \
                case SERIALIZE_TYPE_##sname:                                      \
                    return visitor.visit_##mname(this->read_pod_value<tyname>()); \

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
                    const char* str = reinterpret_cast<const char*>(this->consume(str_len));
                    return visitor.visit_bytes(str, str_len);
                }
            DESER_POD_SCALAR(BOOL, boolean, bool)
            case SERIALIZE_TYPE_OBJECT:
                return this->deserialize_raw_section(visitor);
            default:
                ASSERT_MES_AND_THROW("unrecognized type code: " << type_code);
            }
        }

        template <typename Value>
        Value deserialize_raw_section(Visitor<Value>& visitor)
        {
            const size_t obj_len = this->read_varint();
            this->push_object(obj_len);
            return visitor.visit_object(obj_len, *this);
        }

        template <typename Value>
        Value deserialize_raw_key(Visitor<Value>& visitor)
        {
            const uint8_t key_len = *this->consume(1);
            const char* key = reinterpret_cast<const char*>(this->consume(key_len));
            this->did_read_key();
            return visitor.visit_key(key, key_len);
        }

        template <typename Value>
        Value deserialize_section_entry(Visitor<Value>& visitor)
        {
            const uint8_t type_code = *this->consume(1);
            if (type_code & SERIALIZE_FLAG_ARRAY)
            {
                const uint8_t scalar_type_code = type_code & ~SERIALIZE_FLAG_ARRAY;
                size_t array_len = this->read_varint();
                this->push_array(array_len, scalar_type_code);
                return visitor.visit_array(array_len, *this);
            }
            else
            {
                return this->deserialize_scalar(type_code, visitor);
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
            return m_stack.back().remaining;
        }
 
        bool root() const
        {
            return m_stack.size() == 0;
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

        t_const_uint8_iterator m_current;
        t_const_uint8_iterator m_end;
        
        // keep track deserializing state
        std::vector<recursion_level> m_stack;
        bool m_finished;

    ///////////////////////////////////////////////////////////////////////////
    // Deserializer interface                                                //
    ///////////////////////////////////////////////////////////////////////////
    public:

        // This is the main chunk of logic behind this Deserializer
        template <typename Value>
        Value deserialize_any(Visitor<Value>& visitor)
        {
            if (this->finished())
            {
                ASSERT_MES_AND_THROW("trying to deserialize when data is done");
            }
            else if (this->root())
            {
                this->validate_signature();
                return this->deserialize_raw_section(visitor);
            }
            else if (this->inside_object())
            {
                if (this->expecting_key())
                {
                    return this->deserialize_raw_key(visitor);
                }
                else
                {
                    return this->deserialize_section_entry(visitor);
                }
            }
            else // inside array
            {
                return this->deserialize_scalar(this->current_array_type(), visitor);
            }
        }

        #define DEFER_TO_DESER_ANY(mname)                \
            template <typename Value>                    \
            Value deserialize_##mname(Visitor<Value>& v) \
            { return this->deserialize_any(v); }         \

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

        template <typename Value>
        Value deserialize_array(optional<size_t>, Visitor<Value>& visitor)
        {
            return this->deserialize_any(visitor);
        }

        template <typename Value>
        Value deserialize_object(optional<size_t>, Visitor<Value>& visitor)
        {
            return this->deserialize_any(visitor);
        }

        bool continue_collection() override final {
            if (this->finished())
            {
                return false;
            }
            else if (this->remaining() == 0)
            {
                this->pop();
                return false;
            }
            else
            {
                this->doing_one_element_or_entry();
                return true;
            }
        }

        bool is_human_readable() const noexcept override final
        {
            return false;
        }
    };
} // namespace portable_storage::binary

