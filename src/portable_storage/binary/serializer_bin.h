#include <string>

namespace portable_storage::binary {
    template<class ostream_t>
    class BinarySerializer {
    public:
        // Compound serializer forward declarations
        template<class>
        class BinarySectionSerializer;
        template<class>
        class BinaryArraySerializer;

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
} // namespace portable_storage::binary
