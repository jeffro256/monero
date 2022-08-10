#include <string>

#include "deserialization.h"
#include "visitor.h"

namespace portable_storage::model {
    ///////////////////////////////////////////////////////////////////////////
    // deserialize_default() basic specializations                           //
    ///////////////////////////////////////////////////////////////////////////

    #define DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(tyname, mname)      \
        template<> tyname Deserialize<tyname>::dflt(Deserializer& deserializer) { \
            internal::DefaultVisitor<tyname> visitor;                             \
            return deserializer.deserialize_##mname(visitor);                     \
        }                                                                         \

    DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(int64_t, int64)
    DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(int32_t, int32)
    DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(int16_t, int16)
    DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(int8_t, int8)
    DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(uint64_t, uint64)
    DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(uint32_t, uint32)
    DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(uint16_t, uint16)
    DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(uint8_t, uint8)
    DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(double, float64)
    DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(std::string, bytes)
    DEFINE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZTION(bool, boolean)
}