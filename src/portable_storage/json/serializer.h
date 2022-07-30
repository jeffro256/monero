#pragma once

#include <string>

#include "misc_log_ex.h"
#include "../model/serializer.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "serialization"

namespace portable_storage::json {
    template<class t_ostream>
    class Serializer: public portable_storage::model::Serializer {
    public:
        Serializer(t_ostream stream);
        virtual ~Serializer() override final {};

        t_ostream move_inner_stream() { return std::move(m_stream); }

    private:
        void write_string(const char* str, size_t length, bool escape = true);
        void write_escaped_string(const uint8_t* str, size_t length);

        // Gets called before every primitive serialize, start_object(), key()
        // Controls the serialization of entry / element delimination
        inline void comma();

        t_ostream m_stream;
        
        // True after start_array() or start_object(), false after an element / entry is serialized
        bool m_first; 
    
    // Serializer interface
    public:
        void int64(int64_t) override final;
        void int32(int32_t) override final;
        void int16(int16_t) override final;
        void int8(int8_t) override final;
        void uint64(uint64_t) override final;
        void uint32(uint32_t) override final;
        void uint16(uint16_t) override final;
        void uint8(uint8_t) override final;
        void float64(double) override final;
        void bytes(const char*, size_t) override final;
        void boolean(bool) override final;

        void start_array(size_t) override final;
        void end_array() override final;

        void start_object(size_t) override final;
        void key(const char*, uint8_t) override final;
        void end_object() override final;

        bool is_human_readable() const noexcept override final { return true; }
    };

    template<class t_ostream>
    Serializer<t_ostream>::Serializer(t_ostream stream):
        m_stream(std::move(stream)),
        m_first(true)
    {}

    #define DEF_SERIALIZE_INT_AS_DOUBLE(inttype)                   \
        template<class t_ostream>                                  \
        void Serializer<t_ostream>::inttype(inttype##_t value) { \
            this->float64(static_cast<double>(value));             \
        }                                                          \

    DEF_SERIALIZE_INT_AS_DOUBLE( int64);
    DEF_SERIALIZE_INT_AS_DOUBLE( int32);
    DEF_SERIALIZE_INT_AS_DOUBLE( int16);
    DEF_SERIALIZE_INT_AS_DOUBLE(  int8);
    DEF_SERIALIZE_INT_AS_DOUBLE(uint64);
    DEF_SERIALIZE_INT_AS_DOUBLE(uint32);
    DEF_SERIALIZE_INT_AS_DOUBLE(uint16);
    DEF_SERIALIZE_INT_AS_DOUBLE( uint8);

    template<class t_ostream>
    void Serializer<t_ostream>::float64(double value) {
        this->comma();
        m_stream << value;
    }

    template<class t_ostream>
    void Serializer<t_ostream>::bytes(const char* buf, size_t length) {
        this->comma();
        this->write_string(buf, length);
    }

    template<class t_ostream>
    void Serializer<t_ostream>::boolean(bool value) {
        this->comma();
        m_stream << (value ? "true" : "false");
    }

    template <class t_ostream>
    void Serializer<t_ostream>::start_array(size_t num_entries) {
        this->comma(); // this should never run b/c nested arrays aren't allowed in model
        m_stream << '[';
        m_first = true;
    }

    template <class t_ostream>
    void Serializer<t_ostream>::end_array() {
        m_stream << ']';
    }

    template <class t_ostream>
    void Serializer<t_ostream>::start_object(size_t num_entries) {
        this->comma();
        m_stream << '{';
        m_first = true;
    }

    template <class t_ostream>
    void Serializer<t_ostream>::key(const char* key, uint8_t key_size) {
        this->comma();
        this->write_string(key, key_size, false); // do not escape key
        m_stream << ':';
        m_first = true; // needed so commas are not inserted after keys
    }

    template <class t_ostream>
    void Serializer<t_ostream>::end_object() {
        m_stream << '}';
    }

    template<class t_ostream>
    void Serializer<t_ostream>::write_string(const char* str, size_t length, bool escape) {
        m_stream << '"';
        if (escape) {
            this->write_escaped_string(reinterpret_cast<const uint8_t*>(str), length);
        } else {
            m_stream.write(str, length);
        }
        m_stream << '"';
    }

    // @TODO: compare performance against transform_to_escape_sequence
    // @TODO: remove in favor of rapidjson internal function
    template<class t_ostream>
    void Serializer<t_ostream>::write_escaped_string(const uint8_t* str, size_t length) {
        const uint8_t* head;
        const uint8_t* tail;
        const uint8_t* const end = str + length;

        // The tail pointer steps through the string and searches for characters which require
        // escaping. m_stream is only written to when it must write escape characters or when
        // tail reaches the end of the string.

        for (head = tail = str; tail < end; tail++) { // while not done searching characters
            if (*tail < 0x20 || *tail == '\\' || *tail == '"') { // ctrl chars are ASCII bytes < 32
                if (head != tail) { // if not flushed
                    // flush characters in [head, tail)
                    m_stream.write(reinterpret_cast<const char*>(head), tail - head);
                    head = tail;
                }

                #define JSON_SER_ESCAPE_REPL(srcchar, replstr) \
                    case srcchar: m_stream << replstr; break;  \

                switch (*tail) {
                    JSON_SER_ESCAPE_REPL('\\', "\\\\")
                    JSON_SER_ESCAPE_REPL('"', "\\\"")
                    JSON_SER_ESCAPE_REPL('\b', "\\b")
                    JSON_SER_ESCAPE_REPL('\f', "\\f")
                    JSON_SER_ESCAPE_REPL('\n', "\\n")
                    JSON_SER_ESCAPE_REPL('\r', "\\r")
                    JSON_SER_ESCAPE_REPL('\t', "\\t")
                default:
                    // Encode control character in the form "\u00XX" where X are hex digits
                    static constexpr const char hex[17] = "0123456789ABCDEF";
                    const char hex_msb = hex[*tail >> 4];
                    const char hex_lsb = hex[*tail & 0xF]; 
                    m_stream << "\\u00" << hex_msb << hex_lsb;
                    break;
                } // end switch

                // If we execute the next statement, we have escaped a character previously.
                // tail will be incremented when control flow hits bottom of for loop.
                head++;
            } // end if
        } // end for

        if (head != tail) { // if not flushed
            // flush characters in [head, tail)
            m_stream.write(reinterpret_cast<const char*>(head), tail - head);
            head = tail;
        }
    }

    template <class t_ostream>
    inline void Serializer<t_ostream>::comma() {
        if (m_first) {
            m_first = false;
        } else {
            m_stream << ',';
        }
    }
} // namespace portable_storage::binary
