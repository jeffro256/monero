#include <string>

#include "serde/model/deserializer.h"

namespace serde::model {
    Deserializer::Deserializer() {}
    Deserializer::~Deserializer() {}

    #define DEFER_DESER_SIMPLE_TO_ANY(mname)                                               \
        void SelfDescribingDeserializer::deserialize_##mname(model::BasicVisitor& visitor) \
            { return this->deserialize_any(visitor); }

    DEFER_DESER_SIMPLE_TO_ANY(int64)
    DEFER_DESER_SIMPLE_TO_ANY(int32)
    DEFER_DESER_SIMPLE_TO_ANY(int16)
    DEFER_DESER_SIMPLE_TO_ANY(int8)
    DEFER_DESER_SIMPLE_TO_ANY(uint64)
    DEFER_DESER_SIMPLE_TO_ANY(uint32)
    DEFER_DESER_SIMPLE_TO_ANY(uint16)
    DEFER_DESER_SIMPLE_TO_ANY(uint8)
    DEFER_DESER_SIMPLE_TO_ANY(float64)
    DEFER_DESER_SIMPLE_TO_ANY(bytes)
    DEFER_DESER_SIMPLE_TO_ANY(boolean)
    DEFER_DESER_SIMPLE_TO_ANY(key)
    DEFER_DESER_SIMPLE_TO_ANY(end_array)
    DEFER_DESER_SIMPLE_TO_ANY(end_object)

    void SelfDescribingDeserializer::deserialize_array(optional<size_t>, BasicVisitor& visitor)
    { this->deserialize_any(visitor); }

    void SelfDescribingDeserializer::deserialize_object(optional<size_t>, BasicVisitor& visitor)
    { this->deserialize_any(visitor); }
}