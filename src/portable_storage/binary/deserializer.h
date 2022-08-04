#pragma once

#include <list>

#include "constants.h"
#include "../internal/endianness.h"
#include "../internal/external_libs.h"
#include "../model/constants.h"
#include "../model/deserializer.h"

namespace portable_storage::binary {
    // forward declaration of internal function
    constexpr bool uint64_fits_size(uint64_t value);

    template <class t_istream>
    class Deserializer: public model::Deserializer
    {
    public:
        Deserializer(t_istream stream):
            model::Deserializer(),
            m_stream(std::move(stream)),
            m_stack(),
            m_object_depth(0),
            m_finished(false)
        {}

        ~Deserializer() = default;
    
    private:
        struct recursion_level {
            optional<uint8_t> scalar_type; // none if an object, 
            size_t remaining; // number of elements / entries which have yet to be deserialized
            bool expecting_key; // used is is_object()

            bool is_object() const {
                return !scalar_type;
            }
        };

        template <typename T>
        T read_pod_value() {
            T res;
            m_stream.read(reinterpret_cast<char*>(&res), sizeof(T));
            return CONVERT_POD(res);
        }

        size_t read_varint() {
            constexpr size_t VARINT_SIZE_MASK = 0b00000011;

            const int first_byte = m_stream.peek();
            const size_t varint_size = 1 << (static_cast<size_t>(first_byte) & VARINT_SIZE_MASK);

            uint64_t value64 = 0;
            stream.read(reinterpret_cast<char*>(&value64), varint_size);
            value64 = CONVERT_POD(value64);
            value64 >>= 2;

            CHECK_AND_ASSERT_THROW_MES( // this should compile to nothing on most 64-bit systems
                uint64_fits_size(value64),
                "varint decoded from stream is too big for size_t: " << value64
            );

            return static_cast<size_t>(value64);
        }

        void validate_signature() {
            char sig[sizeof(PORTABLE_STORAGE_SIG_AND_VER)];
            m_stream.read(sig, sizeof(sig));

            CHECK_AND_ASSERT_THROW_MES(
                sig == PORTABLE_STORAGE_SIG_AND_VER,
                "missing signature from stream"
            );
        }

        bool inside_array() const {
            return m_stack.size() != 0 && !m_stack.back().is_object();
        }

        bool inside_object() const {
            return !this->inside_array();
        }

        bool expecting_key() const {
            return m_stack.back().expecting_key;
        }

        size_t remaining() const {
            return m_stack.back().remaining;
        }
 
        bool root() const {
            return m_stack.size() == 0;
        }

        void push_array(size_t num_elements, uint8_t type_code) {
            m_stack.push_back({type_code, num_elements, false});
        }

        void push_object(size_t num_entries) {
            CHECK_AND_ASSERT(
                m_object_depth < PS_MAX_OBJECT_DEPTH,
                "Maximum object depth exceeded! Possibly parsing a DoS message"
            );

            m_stack.push_back({{}, num_elements, true});
            m_object_depth++;
        }

        void pop() {
            CHECK_AND_ASSERT(
                m_stack.size() > 0,
                "binary::Deserializer internal logic error: called pop() too many times"
            );

            if (this->inside_object()) {
                m_object_depth--;
            }

            m_stack.pop_back();

            if (m_stack.size() == 0) {
                m_finished = true;
            }
        }

        t_istream m_stream;
        
        // keep track deserializing state
        std::list<recursion_level> m_stack;
        size_t m_object_depth;
        bool m_finished;

    // Deserializer interface
    public:
        void deserialize_any(model::Visitor& visitor) override final {
            if (m_finished) {
                ASSERT_MES_AND_THROW("trying to deserialize when data is done");
            } else if (this->root()) {
                this->validate_signature();
                const size_t root_object_length = this->read_varint();
                this->push_object(root_object_length);
                visitor.visit_object(root_object_length);
            } else if (this->inside_object()) {
                if ()
            } else if (this->inside_array()) {

            }
        }

        #define DEFER_TO_DESER_ANY(mname)                              \
            void deserialize_##mname(model::Visitor& v) override final \
            { this->deserialize_any(v); }                              \

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

        void deserialize_array(optional<size_t>, model::Visitor&) override final {
            this->deserialize_any(v);
        }

        void deserialize_object(optional<size_t>, model::Visitor&) override final {
            this->deserialize_any(v);
        }

        bool array_has_next() override final {
            return this->remaining() != 0;
        }

        bool object_has_next() override final {
            return this->remaining() != 0;
        }

        bool is_human_readable() const noexcept override final {
            return false;
        }
    };
} // namespace portable_storage::binary

