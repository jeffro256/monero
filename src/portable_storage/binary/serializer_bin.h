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

    template<class t_ostream>
    class BinarySerializer {
    public:
        typedef BinarySectionSerializer<t_ostream> object_serializer;
        typedef BinaryArraySerializer<t_ostream> array_serializer;

        BinarySerializer(t_ostream stream);

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

        t_ostream move_inner_stream() { return std::move(m_stream); }

    private:
        friend class BinarySectionSerializer<t_ostream>;
        friend class BinaryArraySerializer<t_ostream>;

        enum class EntryState {
            Scalar,
            ArrayFirst,
            ArrayInside,
        };

        void write_type_code(uint8_t code);

        t_ostream m_stream;
        size_t m_object_depth;
        EntryState m_entry_state;
    };

    ///////////////////////////////////////////////////////////////////////////
    // BinarySectionSerializer declaration                                   //
    ///////////////////////////////////////////////////////////////////////////

    template <class t_ostream>
    class BinarySectionSerializer {
    public:
        BinarySectionSerializer(BinarySerializer<t_ostream>& base_serializer);

        void start(size_t num_entries);

        template<typename Serializable>
        void serialize_entry(const char* key, uint8_t key_size, const Serializable& value);

        void end();

    private:
        BinarySerializer<t_ostream>& m_base_serializer;
        size_t m_remaining;
    };

    ///////////////////////////////////////////////////////////////////////////
    // BinaryArraySerializer declaration                                     //
    ///////////////////////////////////////////////////////////////////////////

    template <class t_ostream>
    class BinaryArraySerializer {
    public:
        BinaryArraySerializer(BinarySerializer<t_ostream>& base_serializer);

        void start(size_t num_elements);

        template<typename Serializable>
        void serialize_element(const Serializable& value);

        void end();

    private:
        BinarySerializer<t_ostream>& m_base_serializer;
        size_t m_length;
        size_t m_remaining;
    };

    ///////////////////////////////////////////////////////////////////////////
    // BinarySerializer definitions                                          //
    ///////////////////////////////////////////////////////////////////////////

    template<class t_ostream>
    BinarySerializer<t_ostream>::BinarySerializer(t_ostream stream):
        m_stream(std::move(stream)),
        m_object_depth(0),
        m_entry_state(EntryState::Scalar)
    {}

    #define DEF_SERIALIZE_LE_INT(inttype, typecode)                                \
        template<class t_ostream>                                                  \
        void BinarySerializer<t_ostream>::serialize_##inttype(inttype##_t value) { \
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

    template<class t_ostream>
    void BinarySerializer<t_ostream>::serialize_double(double value) {
        this->write_type_code(SERIALIZE_TYPE_DOUBLE);
        value = CONVERT_POD(value);
        m_stream.write(reinterpret_cast<const char*>(&value), sizeof(value));
    }

    template<class t_ostream>
    void BinarySerializer<t_ostream>::serialize_string(const std::string& value) {
        this->write_type_code(SERIALIZE_TYPE_STRING);
        write_varint(m_stream, value.length());
        m_stream.write(value.c_str(), value.length());
    }

    template<class t_ostream>
    void BinarySerializer<t_ostream>::serialize_bool(bool value) {
        this->write_type_code(SERIALIZE_TYPE_BOOL);
        m_stream.put(value ? 1 : 0);
    }

    template<class t_ostream>
    typename BinarySerializer<t_ostream>::object_serializer
            BinarySerializer<t_ostream>::serialize_object() {
        return BinarySectionSerializer<t_ostream>(*this);
    }

    template<class t_ostream>
    typename BinarySerializer<t_ostream>::array_serializer
            BinarySerializer<t_ostream>::serialize_array() {
        CHECK_AND_ASSERT_THROW_MES(
            m_entry_state == EntryState::Scalar,
            "nested arrays not allowed in the epee portable storage data model"
        );

        return BinaryArraySerializer<t_ostream>(*this);
    }

    template<class t_ostream>
    void BinarySerializer<t_ostream>::write_type_code(uint8_t code) {
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

    template <class t_ostream>
    BinarySectionSerializer<t_ostream>::BinarySectionSerializer(
            BinarySerializer<t_ostream>& base_serializer):
        m_base_serializer(base_serializer),
        m_remaining(PS_BIN_REMAINING_UNINIT) {}

    template <class t_ostream>
    void BinarySectionSerializer<t_ostream>::start(size_t num_entries) {
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

    template<class t_ostream> template<typename Serializable>
    void BinarySectionSerializer<t_ostream>::serialize_entry(
            const char* key, uint8_t key_size, const Serializable& value
    ) {
        CHECK_AND_ASSERT_THROW_MES(m_remaining > 0, "trying to serialize too many elements");

        m_base_serializer.m_stream.put(key_size);
        m_base_serializer.m_stream.write(key, key_size);
        m_base_serializer.m_entry_state = BinarySerializer<t_ostream>::EntryState::Scalar;
        portable_storage::model::serialize(value, m_base_serializer);
        m_remaining--;
    }

    template <class t_ostream>
    void BinarySectionSerializer<t_ostream>::end() {
        CHECK_AND_ASSERT_THROW_MES(
            m_remaining == 0,
            "trying to end array serialization with" << m_remaining << " elements left"
        );

        m_base_serializer.m_object_depth--;
    }

    ///////////////////////////////////////////////////////////////////////////
    // BinaryArraySerializer definitions                                     //
    ///////////////////////////////////////////////////////////////////////////

    template <class t_ostream>
    BinaryArraySerializer<t_ostream>::BinaryArraySerializer(
            BinarySerializer<t_ostream>& base_serializer):
        m_base_serializer(base_serializer),
        m_length(PS_BIN_REMAINING_UNINIT),
        m_remaining(PS_BIN_REMAINING_UNINIT) {}

    template <class t_ostream>
    void BinaryArraySerializer<t_ostream>::start(size_t num_entries) {
        m_length = m_remaining = num_entries;
    }

    template<class t_ostream> template<typename Serializable>
    void BinaryArraySerializer<t_ostream>::serialize_element(const Serializable& value) {
        CHECK_AND_ASSERT_THROW_MES(m_remaining > 0, "trying to serialize too many elements");

        typedef typename BinarySerializer<t_ostream>::EntryState EntryState;
        const bool first = m_length == m_remaining;
        m_base_serializer.m_entry_state = first ? EntryState::ArrayFirst : EntryState::ArrayInside;
        portable_storage::model::serialize(value, m_base_serializer);
        m_remaining--;
    }

    template <class t_ostream>
    void BinaryArraySerializer<t_ostream>::end() {
        CHECK_AND_ASSERT_THROW_MES(
            m_remaining == 0,
            "trying to end array serialization with" << m_remaining << " elements left"
        );
    }
} // namespace portable_storage::binary

