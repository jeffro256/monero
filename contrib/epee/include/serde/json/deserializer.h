#pragma once

#include <rapidjson/reader.h>
#include <rapidjson/stream.h>
#include <vector>

#include "../internal/external/byte_span.h"
#include "../internal/external/logging.h"
#include "../model/deserialization.h"
#include "../model/deserializer.h"

namespace serde::json
{
    class Deserializer: public model::Deserializer
    {
    public:

        // Rapidjson streams need null terminators so src string should have a null terminator.
        // The internal stream type is also non-owning so the src buffer must remain valid
        // throughout the entire lifetime of this Deserializer instance.
        Deserializer(const char* src);
        ~Deserializer() = default;

    ///////////////////////////////////////////////////////////////////////////
    // Deserializer interface                                                //
    ///////////////////////////////////////////////////////////////////////////

        void deserialize_any(model::BasicVisitor& visitor) override final;

        #ifndef DEFER_TO_DESER_ANY
        #define DEFER_TO_DESER_ANY(mname)                                   \
            void deserialize_##mname(model::BasicVisitor& v) override final \
            { return this->deserialize_any(v); }
        #endif

        // The json format is self-describing, which means we can ignore deserialization hints
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
        DEFER_TO_DESER_ANY(end_array)
        DEFER_TO_DESER_ANY(end_object)

        void deserialize_array(optional<size_t>, model::BasicVisitor& visitor) override final
        {
            this->deserialize_any(visitor);
        }

        void deserialize_object(optional<size_t>, model::BasicVisitor& visitor) override final
        {
            this->deserialize_any(visitor);
        }

        bool is_human_readable() const noexcept override final;

    ///////////////////////////////////////////////////////////////////////////
    // private helper methods / fields                                       //
    ///////////////////////////////////////////////////////////////////////////
    private:

        friend class JsonVisitorHandler;

        rapidjson::Reader m_json_reader;
        // Non-owning stream so buffer must remain valid the entire lifetime of the Deserializer.
        rapidjson::InsituStringStream m_istream; 
    }; // class Deserializer

    template <typename T>
    T from_cstr(const char* src)
    {
        Deserializer deserializer(src);
        optional<T> deser_res = model::Deserialize<T>::dflt(deserializer);
        CHECK_AND_ASSERT_THROW_MES
        (
            deser_res,
            "JSON Deserializer returned no data"
        );
        return *deser_res;
    }
} // namespace serde::json

