#include <string>

#include "serde/model/serializer.h"

namespace serde::model
{
    void Serializer::serialize_string(const std::string& value)
    {
        this->serialize_bytes(internal::string_to_byte_span(value));
    }
}
