#include <rapidjson/reader.h>

#include "serde/json/deserializer.h"
#include "serde/model/visitor.h"

namespace serde::json
{
    struct JsonVisitorHandler:
        public rapidjson::BaseReaderHandler<rapidjson::UTF8<>>
    {
        typedef rapidjson::SizeType SizeType;
        static_assert(std::is_same<int, int32_t>::value); // @TODO: provide contigencies
        static_assert(std::is_same<unsigned int, uint32_t>::value); // @TODO: provide contigencies

        bool Null() { ASSERT_MES_AND_THROW("null is not supported in the data model"); }
        bool Bool(bool b) { m_visitor.visit_boolean(b); return true; }
        bool Int(int i) { m_visitor.visit_int32(i); return true; }
        bool Uint(unsigned u) { m_visitor.visit_uint32(u); return true; }
        bool Int64(int64_t i) { m_visitor.visit_int64(i); return true; }
        bool Uint64(uint64_t u) { m_visitor.visit_uint64(u); return true; }
        bool Double(double d) { m_visitor.visit_float64(d); return true; }
        bool String(const char* str, SizeType length, bool copy) {
            const const_byte_span str_span(reinterpret_cast<const_byte_iterator>(str), length);
            m_visitor.visit_bytes(str_span);
            return true;
        }
        bool StartObject() { m_visitor.visit_object({}, m_deserializer); return true; }
        bool Key(const char* str, SizeType length, bool copy) { 
            const const_byte_span str_span(reinterpret_cast<const_byte_iterator>(str), length);
            m_visitor.visit_key(str_span);
            return true;
        }
        bool EndObject(SizeType memberCount) { m_visitor.visit_end_object(); return true; }
        bool StartArray() { m_visitor.visit_array({}, m_deserializer); return true; }
        bool EndArray(SizeType elementCount) { m_visitor.visit_end_array(); return true; }

        constexpr JsonVisitorHandler(model::BasicVisitor& vis, model::Deserializer& deser):
            m_visitor(vis), m_deserializer(deser) {}

        model::BasicVisitor& m_visitor;
        model::Deserializer& m_deserializer;
    };

    Deserializer::Deserializer(const char* src):
        m_json_reader(),
        m_istream(const_cast<char*>(src)) // Not necessarily a safe cast
    {
        m_json_reader.IterativeParseInit();
    }

    void Deserializer::deserialize_any(model::BasicVisitor& visitor)
    {
        JsonVisitorHandler handler = { visitor, *this };
        m_json_reader.IterativeParseNext<rapidjson::kParseDefaultFlags>(m_istream, handler);
        // @TODO: check parse complete
    }
}