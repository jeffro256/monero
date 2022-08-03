#include <string>

#include "deserializer.h"
#include "visitor.h"

namespace portable_storage::model {
    void Deserializer::deserialize_string(Visitor& visitor) {
        this->deserialize_bytes(visitor);
    }
}