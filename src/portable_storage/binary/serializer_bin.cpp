#include <string>

#include "binary_common.h"
#include "serializer_bin.h"
#include "varint.h"

namespace {
} // anonymous namespace

namespace portable_storage::binary {
    template<class ostream_t>
    BinarySerializer<ostream_t>::BinarySerializer(ostream_t stream):
        m_stream(std::move(stream)),
        m_object_depth(0),
        m_inside_array(false)
    {}

    #define DEF_SERIALIZE_LE_INT(inttype, typecode)                                \
        template<class ostream_t>                                                  \
        void BinarySerializer<ostream_t>::serialize_##inttype(inttype##_t value) { \
            value = CONVERT_POD(value);                                            \
            m_stream.put(typecode);                                                \
            m_stream.write(static_cast<const char*>(&value), sizeof(value));       \
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
        value = CONVERT_POD(value);
        m_stream.put(SERIALIZE_TYPE_DOUBLE);
        m_stream.write(static_cast<const char*>(&value), sizeof(value));
    }

    template<class ostream_t>
    void BinarySerializer<ostream_t>::serialize_string(const std::string& value) {
        m_stream.put(SERIALIZE_TYPE_STRING);
        write_varint(m_stream, value.length());
        m_stream.write(value.c_str(), value.length());
    }

    template<class ostream_t>
    void BinarySerializer<ostream_t>::serialize_bool(bool value) {
        m_stream.put(SERIALIZE_TYPE_BOOL);
        m_stream.put(static_cast<char>(value));
    }

    template<class ostream_t>
    BinarySerializer<ostream_t>::object_serializer
            BinarySerializer<ostream_t>::serialize_object() {
        return BinarySectionSerializer(*this);
    }

    #define DEF_SERIALIZE_LE_INT_ARRAY(inttype, typecode) \
        template <class ostream_t, typename InputIterator> \
        void BinarySerializer<ostream_t>::serialize_##typecode##_array (InputIterator begin, size_t num_elements); \

    template <typename InputIterator>
    void serialize_int64_array (InputIterator begin, size_t num_elements);
    template <typename InputIterator>
    void serialize_int32_array (InputIterator begin, size_t num_elements);
    template <typename InputIterator>
    void serialize_int16_array (InputIterator begin, size_t num_elements);
    template <typename InputIterator>
    void serialize_int8_array  (InputIterator begin, size_t num_elements);
    template <typename InputIterator>
    void serialize_uint64_array(InputIterator begin, size_t num_elements);
    template <typename InputIterator>
    void serialize_uint32_array(InputIterator begin, size_t num_elements);
    template <typename InputIterator>
    void serialize_uint16_array(InputIterator begin, size_t num_elements);
    template <typename InputIterator>
    void serialize_uint8_array (InputIterator begin, size_t num_elements);
    template <typename InputIterator>
    void serialize_bool_array  (InputIterator begin, size_t num_elements);
    template <typename InputIterator>
    void serialize_string_array(InputIterator begin, size_t num_elements);

    template <typename InputIterator>
    void serialize_object_array(InputIterator begin, size_t num_elements);

    ~BinarySerializer();

    template<class ostream_t>
    void BinarySerializer<ostream_t>::write_type_code(uint8_t code) {
        if (!m_inside_array) {
            m_stream.put(static_cast<char>(code));
        }
    }

        BinarySectionSerializer(BinarySerializer<ostream_t>& base_serializer);

        void start(size_t num_entries);

        template<typename Serializable>
        void serialize_entry(const char* key, uint8_t key_size, const Serializable& value);

        void end();

        ~BinarySectionSerializer();
} // namespace portable_storage::binary

