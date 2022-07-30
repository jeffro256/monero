#include <string>

#include "serializer.h"

namespace portable_storage::model {
    void Serializer::string(const std::string& value) {
        this->bytes(value.c_str(), value.length());
    }
}