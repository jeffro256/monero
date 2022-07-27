#pragma once

#include <limits>
#include <string>

#include "binary_common.h"
#include "misc_log_ex.h"
#include "../model/serialize.h"
#include "varint.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "serialization"

#define PS_BIN_REMAINING_UNINIT std::numeric_limits<size_t>::max()

namespace portable_storage::binary {
    // Compound serializer forward declarations
    template<class>
    class BinarySectionSerializer;
    template<class>
    class BinaryArraySerializer;

    ///////////////////////////////////////////////////////////////////////////
    // BinarySerializer declaration                                          //
    ///////////////////////////////////////////////////////////////////////////

    template<class ostream_t>
    class BinarySerializer {
    public:
        typedef BinarySectionSerializer<ostream_t> object_serializer;
        typedef BinaryArraySerializer<ostream_t> array_serializer;

        BinarySerializer(ostream_t stream);

        void serialize_int64 (int64_t            value);
        void serialize_int32 (int32_t            value);
        void serialize_int16 (int16_t            value);
        void serialize_int8  (int8_t             value);
        void serialize_uint64(uint64_t           value);
        void serialize_uint32(uint32_t           value);
        void serialize_uint16(uint16_t           value);
        void serialize_uint8 (uint8_t            value);
        void serialize_double(double             value);
        void serialize_string(const std::string& value);
        void serialize_bool  (bool               value);

        object_serializer serialize_object();

        array_serializer serialize_array();

        bool is_human_readable() const { return false; }

        ostream_t move_inner_stream() { return std::move(m_stream); }

    private:
        friend class BinarySectionSerializer<ostream_t>;
        friend class BinaryArraySerializer<ostream_t>;

        enum class EntryState {
            Scalar,
            ArrayFirst,
            ArrayInside,
        };

        void write_type_code(uint8_t code);

        ostream_t m_stream;
        size_t m_object_depth;
        EntryState m_entry_state;
    };

    ///////////////////////////////////////////////////////////////////////////
    // BinarySectionSerializer declaration                                   //
    ///////////////////////////////////////////////////////////////////////////

    template <class ostream_t>
    class BinarySectionSerializer {
    public:
        BinarySectionSerializer(BinarySerializer<ostream_t>& base_serializer);

        void start(size_t num_entries);

        template<typename Serializable>
        void serialize_entry(const char* key, uint8_t key_size, const Serializable& value);

        void end();

    private:
        BinarySerializer<ostream_t>& m_base_serializer;
        size_t m_remaining;
    };

    ///////////////////////////////////////////////////////////////////////////
    // BinaryArraySerializer declaration                                     //
    ///////////////////////////////////////////////////////////////////////////

    template <class ostream_t>
    class BinaryArraySerializer {
    public:
        BinaryArraySerializer(BinarySerializer<ostream_t>& base_serializer);

        void start(size_t num_elements);

        template<typename Serializable>
        void serialize_element(const Serializable& value);

        void end();

    private:
        BinarySerializer<ostream_t>& m_base_serializer;
        size_t m_length;
        size_t m_remaining;
    };

    ///////////////////////////////////////////////////////////////////////////
    // BinarySerializer definitions                                          //
    ///////////////////////////////////////////////////////////////////////////

    template<class ostream_t>
    BinarySerializer<ostream_t>::BinarySerializer(ostream_t stream):
        m_stream(std::move(stream)),
        m_object_depth(0),
        m_entry_state(EntryState::Scalar)
    {}

    #define DEF_SERIALIZE_LE_INT(inttype, typecode)                                \
        template<class ostream_t>                                                  \
        void BinarySerializer<ostream_t>::serialize_##inttype(inttype##_t value) { \
            this->write_type_code(typecode);                                       \
            value = CONVERT_POD(value);                                            \
            m_stream.write(reinterpret_cast<const char*>(&value), sizeof(value));  \
        }                                                                          \

    DEF_SERIALIZE_LE_INT( int64,  SERIALIZE_TYPE_INT64);
    DEF_SERIALIZE_LE_INT( int32,  SERIALIZE_TYPE_INT32);
    DEF_SERIALIZE_LE_INT( int16,  SERIALIZE_TYPE_INT16);
    DEF_SERIALIZE_LE_INT(  int8,   SERIALIZE_TYPE_INT8);
    DEF_SERIALIZE_LE_INT(uint64, SERIALIZE_TYPE_UINT64);
    DEF_SERIALIZE_LE_INT(uint32, SERIALIZE_TYPE_UINT32);
    DEF_SERIALIZE_LE_INT(uint16, SERIALIZE_TYPE_UINT16);
    DEF_SERIALIZE_LE_INT( uint8,  SERIALIZE_TYPE_UINT8);

    template<class ostream_t>
    void BinarySerializer<ostream_t>::serialize_double(double value) {
        this->write_type_code(SERIALIZE_TYPE_DOUBLE);
        value = CONVERT_POD(value);
        m_stream.write(reinterpret_cast<const char*>(&value), sizeof(value));
    }

    template<class ostream_t>
    void BinarySerializer<ostream_t>::serialize_string(const std::string& value) {
        this->write_type_code(SERIALIZE_TYPE_STRING);
        write_varint(m_stream, value.length());
        m_stream.write(value.c_str(), value.length());
    }

    template<class ostream_t>
    void BinarySerializer<ostream_t>::serialize_bool(bool value) {
        this->write_type_code(SERIALIZE_TYPE_BOOL);
        m_stream.put(value ? 1 : 0);
    }

    template<class ostream_t>
    typename BinarySerializer<ostream_t>::object_serializer
            BinarySerializer<ostream_t>::serialize_object() {
        return BinarySectionSerializer<ostream_t>(*this);
    }

    template<class ostream_t>
    typename BinarySerializer<ostream_t>::array_serializer
            BinarySerializer<ostream_t>::serialize_array() {
        CHECK_AND_ASSERT_THROW_MES(
            m_entry_state == EntryState::Scalar,
            "nested arrays not allowed in the epee portable storage data model"
        );

        return BinaryArraySerializer<ostream_t>(*this);
    }

    template<class ostream_t>
    void BinarySerializer<ostream_t>::write_type_code(uint8_t code) {
        switch (m_entry_state) {
        case EntryState::Scalar:
            m_stream.put(code);
            break;
        case EntryState::ArrayFirst:
            m_stream.put(code | SERIALIZE_FLAG_ARRAY);
            break;
        case EntryState::ArrayInside:
            break;
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // BinarySectionSerializer definitions                                   //
    ///////////////////////////////////////////////////////////////////////////

    template <class ostream_t>
    BinarySectionSerializer<ostream_t>::BinarySectionSerializer(
            BinarySerializer<ostream_t>& base_serializer):
        m_base_serializer(base_serializer),
        m_remaining(PS_BIN_REMAINING_UNINIT) {}

    template <class ostream_t>
    void BinarySectionSerializer<ostream_t>::start(size_t num_entries) {
        m_remaining = num_entries;
        const bool is_root = m_base_serializer.m_object_depth == 0;
        m_base_serializer.m_object_depth++;

        if (is_root) {
            m_base_serializer.m_stream.write(
                PORTABLE_STORAGE_SIG_AND_VER,
                sizeof(PORTABLE_STORAGE_SIG_AND_VER)
            );
        } else {
            m_base_serializer.write_type_code(SERIALIZE_TYPE_OBJECT);
        }

        write_varint(m_base_serializer.m_stream, num_entries);
    }

    template<class ostream_t> template<typename Serializable>
    void BinarySectionSerializer<ostream_t>::serialize_entry(
            const char* key, uint8_t key_size, const Serializable& value
    ) {
        CHECK_AND_ASSERT_THROW_MES(m_remaining > 0, "trying to serialize too many elements");

        m_base_serializer.m_stream.put(key_size);
        m_base_serializer.m_stream.write(key, key_size);
        m_base_serializer.m_entry_state = BinarySerializer<ostream_t>::EntryState::Scalar;
        portable_storage::model::serialize(value, m_base_serializer);
        m_remaining--;
    }

    template <class ostream_t>
    void BinarySectionSerializer<ostream_t>::end() {
        CHECK_AND_ASSERT_THROW_MES(
            m_remaining == 0,
            "trying to end array serialization with" << m_remaining << " elements left"
        );

        m_base_serializer.m_object_depth--;
    }

    ///////////////////////////////////////////////////////////////////////////
    // BinaryArraySerializer definitions                                     //
    ///////////////////////////////////////////////////////////////////////////

    template <class ostream_t>
    BinaryArraySerializer<ostream_t>::BinaryArraySerializer(
            BinarySerializer<ostream_t>& base_serializer):
        m_base_serializer(base_serializer),
        m_length(PS_BIN_REMAINING_UNINIT),
        m_remaining(PS_BIN_REMAINING_UNINIT) {}

    template <class ostream_t>
    void BinaryArraySerializer<ostream_t>::start(size_t num_entries) {
        m_length = m_remaining = num_entries;
    }

    template<class ostream_t> template<typename Serializable>
    void BinaryArraySerializer<ostream_t>::serialize_element(const Serializable& value) {
        CHECK_AND_ASSERT_THROW_MES(m_remaining > 0, "trying to serialize too many elements");

        typedef typename BinarySerializer<ostream_t>::EntryState EntryState;
        const bool first = m_length == m_remaining;
        m_base_serializer.m_entry_state = first ? EntryState::ArrayFirst : EntryState::ArrayInside;
        portable_storage::model::serialize(value, m_base_serializer);
        m_remaining--;
    }

    template <class ostream_t>
    void BinaryArraySerializer<ostream_t>::end() {
        CHECK_AND_ASSERT_THROW_MES(
            m_remaining == 0,
            "trying to end array serialization with" << m_remaining << " elements left"
        );
    }
} // namespace portable_storage::binary

