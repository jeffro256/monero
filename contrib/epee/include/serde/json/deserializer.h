#pragma once

#include <vector>

#include "./deps.h"
#include "../internal/deps.h"
#include "../model/deserialization.h"
#include "../model/deserializer.h"

namespace serde::json
{
    class Deserializer: public model::SelfDescribingDeserializer
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

