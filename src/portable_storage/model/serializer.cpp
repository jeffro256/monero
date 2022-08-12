#include <string>

#include "serializer.h"

namespace portable_storage::model {
    void Serializer::serialize_string(const std::string& value) {
        this->serialize_bytes(internal::string_to_byte_span(value));
    }
}
