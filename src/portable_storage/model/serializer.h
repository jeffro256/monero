#include <string>

namespace epee_format::ser {
    template <class ObjectSerializer>
    struct Serializer {
        typedef ObjectSerializer object_serializer;

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
        void serialize_double_array(InputIterator begin, size_t num_elements);
        template <typename InputIterator>
        void serialize_string_array(InputIterator begin, size_t num_elements);
        template <typename InputIterator>
        void serialize_bool_array  (InputIterator begin, size_t num_elements);

        template <typename InputIterator>
        void serialize_object_array(InputIterator begin, size_t num_elements);

        bool is_human_readable() const;

        ~Serializer();
    };

    struct ObjectSerializer {
        void start(size_t num_entries);

        template<typename Serializable>
        void serialize_entry(const char* key, uint8_t key_size, const Serializable& value);

        void end();

        ~ObjectSerializer();
    };
}
