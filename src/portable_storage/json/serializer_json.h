#pragma once

#include <limits>
#include <string>

#include "misc_log_ex.h"
#include "../model/serialize.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "serialization"

#define PS_BIN_REMAINING_UNINIT std::numeric_limits<size_t>::max()

namespace portable_storage::json {
    // Compound serializer forward declarations
    template<class>
    class JsonObjectSerializer;
    template<class>
    class JsonArraySerializer;

    ///////////////////////////////////////////////////////////////////////////
    // JsonSerializer declaration                                            //
    ///////////////////////////////////////////////////////////////////////////

    template<class t_ostream>
    class JsonSerializer {
    public:
        typedef JsonObjectSerializer<t_ostream> object_serializer;
        typedef JsonArraySerializer<t_ostream> array_serializer;

        JsonSerializer(t_ostream stream);

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

        bool is_human_readable() const { return true; }

        t_ostream move_inner_stream() { return std::move(m_stream); }

    private:
        friend class JsonObjectSerializer<t_ostream>;
        friend class JsonArraySerializer<t_ostream>;

        void write_string(const char* str, size_t length);

        t_ostream m_stream;
    };

    ///////////////////////////////////////////////////////////////////////////
    // JsonObjectSerializer declaration                                      //
    ///////////////////////////////////////////////////////////////////////////

    template <class t_ostream>
    class JsonObjectSerializer {
    public:
        JsonObjectSerializer(JsonSerializer<t_ostream>& base_serializer);

        void start(size_t num_entries);

        template<typename Serializable>
        void serialize_entry(const char* key, uint8_t key_size, const Serializable& value);

        void end();

    private:
        JsonSerializer<t_ostream>& m_base_serializer;
        size_t m_remaining;
    };

    ///////////////////////////////////////////////////////////////////////////
    // JsonArraySerializer declaration                                       //
    ///////////////////////////////////////////////////////////////////////////

    template <class t_ostream>
    class JsonArraySerializer {
    public:
        JsonArraySerializer(JsonSerializer<t_ostream>& base_serializer);

        void start(size_t num_elements);

        template<typename Serializable>
        void serialize_element(const Serializable& value);

        void end();

    private:
        JsonSerializer<t_ostream>& m_base_serializer;
        size_t m_length;
        size_t m_remaining;
    };

    ///////////////////////////////////////////////////////////////////////////
    // JsonSerializer definitions                                            //
    ///////////////////////////////////////////////////////////////////////////

    template<class t_ostream>
    JsonSerializer<t_ostream>::JsonSerializer(t_ostream stream):
        m_stream(std::move(stream))
    {}

    #define DEF_SERIALIZE_INT_AS_DOUBLE(inttype)                                 \
        template<class t_ostream>                                                \
        void JsonSerializer<t_ostream>::serialize_##inttype(inttype##_t value) { \
            this->serialize_double(static_cast<double>(value));                  \
        }                                                                        \

    DEF_SERIALIZE_INT_AS_DOUBLE( int64);
    DEF_SERIALIZE_INT_AS_DOUBLE( int32);
    DEF_SERIALIZE_INT_AS_DOUBLE( int16);
    DEF_SERIALIZE_INT_AS_DOUBLE(  int8);
    DEF_SERIALIZE_INT_AS_DOUBLE(uint64);
    DEF_SERIALIZE_INT_AS_DOUBLE(uint32);
    DEF_SERIALIZE_INT_AS_DOUBLE(uint16);
    DEF_SERIALIZE_INT_AS_DOUBLE( uint8);

    template<class t_ostream>
    void JsonSerializer<t_ostream>::serialize_double(double value) {
        m_stream << value;
    }

    template<class t_ostream>
    void JsonSerializer<t_ostream>::serialize_string(const std::string& value) {
        this->write_string(value.c_str(), value.length());
    }

    template<class t_ostream>
    void JsonSerializer<t_ostream>::serialize_bool(bool value) {
        if (value) {
            m_stream << "true";
        } else {
            m_stream << "false";
        }
    }

    template<class t_ostream>
    typename JsonSerializer<t_ostream>::object_serializer
            JsonSerializer<t_ostream>::serialize_object() {
        return JsonObjectSerializer<t_ostream>(*this);
    }

    template<class t_ostream>
    typename JsonSerializer<t_ostream>::array_serializer
            JsonSerializer<t_ostream>::serialize_array() {
        return JsonArraySerializer<t_ostream>(*this);
    }

    // @TODO: escape strings
    template<class t_ostream>
    void JsonSerializer<t_ostream>::write_string(const char* str, size_t length) {
        m_stream << '"';
        m_stream.write(str, length);
        m_stream << '"';
    }

    ///////////////////////////////////////////////////////////////////////////
    // JsonObjectSerializer definitions                                      //
    ///////////////////////////////////////////////////////////////////////////

    template <class t_ostream>
    JsonObjectSerializer<t_ostream>::JsonObjectSerializer(
            JsonSerializer<t_ostream>& base_serializer):
        m_base_serializer(base_serializer),
        m_remaining(PS_BIN_REMAINING_UNINIT) {}

    template <class t_ostream>
    void JsonObjectSerializer<t_ostream>::start(size_t num_entries) {
        m_remaining = num_entries;
        m_base_serializer.m_stream << '{';
    }

    template<class t_ostream> template<typename Serializable>
    void JsonObjectSerializer<t_ostream>::serialize_entry(
            const char* key, uint8_t key_size, const Serializable& value
    ) {
        CHECK_AND_ASSERT_THROW_MES(m_remaining > 0, "trying to serialize too many elements");

        m_base_serializer.write_string(key, key_size);
        m_base_serializer.m_stream << ':';
        portable_storage::model::serialize(value, m_base_serializer);
        m_remaining--;

        if (m_remaining != 0) {
            m_base_serializer.m_stream << ',';
        }
    }

    template <class t_ostream>
    void JsonObjectSerializer<t_ostream>::end() {
        CHECK_AND_ASSERT_THROW_MES(
            m_remaining == 0,
            "trying to end array serialization with" << m_remaining << " elements left"
        );

        m_base_serializer.m_stream << '}';
    }

    ///////////////////////////////////////////////////////////////////////////
    // BinaryArraySerializer definitions                                     //
    ///////////////////////////////////////////////////////////////////////////

    template <class t_ostream>
    JsonArraySerializer<t_ostream>::JsonArraySerializer(
            JsonSerializer<t_ostream>& base_serializer):
        m_base_serializer(base_serializer),
        m_length(PS_BIN_REMAINING_UNINIT),
        m_remaining(PS_BIN_REMAINING_UNINIT) {}

    template <class t_ostream>
    void JsonArraySerializer<t_ostream>::start(size_t num_entries) {
        m_length = m_remaining = num_entries;
        m_base_serializer.m_stream << '[';
    }

    template<class t_ostream> template<typename Serializable>
    void JsonArraySerializer<t_ostream>::serialize_element(const Serializable& value) {
        CHECK_AND_ASSERT_THROW_MES(m_remaining > 0, "trying to serialize too many elements");

        portable_storage::model::serialize(value, m_base_serializer);
        m_remaining--;

        if (m_remaining != 0) {
            m_base_serializer.m_stream << ',';
        }
    }

    template <class t_ostream>
    void BinaryArraySerializer<t_ostream>::end() {
        CHECK_AND_ASSERT_THROW_MES(
            m_remaining == 0,
            "trying to end array serialization with" << m_remaining << " elements left"
        );
    }
} // namespace portable_storage::binary

