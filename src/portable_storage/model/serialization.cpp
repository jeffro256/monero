#pragma once

#include "../internal/endianness.h"
#include "serialization.h"

namespace portable_storage::model {
    ///////////////////////////////////////////////////////////////////////////
    // serialize_default() basic specializations                        //
    ///////////////////////////////////////////////////////////////////////////

    #define DEF_DESC_SER_BASIC(sername, tyname)                                           \
        template <> void serialize_default(const tyname& value, Serializer& serializer) { \
            serializer.serialize_##sername(value);                                        \
        }                                                                                 \
    
    DEF_DESC_SER_BASIC(int64, int64_t)
    DEF_DESC_SER_BASIC(int32, int32_t)
    DEF_DESC_SER_BASIC(int16, int16_t)
    DEF_DESC_SER_BASIC(int8, int8_t)
    DEF_DESC_SER_BASIC(uint64, uint64_t)
    DEF_DESC_SER_BASIC(uint32, uint32_t)
    DEF_DESC_SER_BASIC(uint16, uint16_t)
    DEF_DESC_SER_BASIC(uint8, uint8_t)
    DEF_DESC_SER_BASIC(float64, double)
    DEF_DESC_SER_BASIC(string, std::string)
    DEF_DESC_SER_BASIC(boolean, bool)

    ///////////////////////////////////////////////////////////////////////////
    // serialize_default() overloads                                    //
    ///////////////////////////////////////////////////////////////////////////

    void serialize_default(const Serializable* value, Serializer& serializer) {
        value->serialize_default(serializer);
    }

    #define DEF_DESC_SER_BASIC_NO_REF(sername, tyname)                 \
        void serialize_default(tyname value, Serializer& serializer) { \
            serializer.serialize_##sername(value);                     \
        }                                                              \
    
    DEF_DESC_SER_BASIC_NO_REF(int64, int64_t)
    DEF_DESC_SER_BASIC_NO_REF(int32, int32_t)
    DEF_DESC_SER_BASIC_NO_REF(int16, int16_t)
    DEF_DESC_SER_BASIC_NO_REF(int8, int8_t)
    DEF_DESC_SER_BASIC_NO_REF(uint64, uint64_t)
    DEF_DESC_SER_BASIC_NO_REF(uint32, uint32_t)
    DEF_DESC_SER_BASIC_NO_REF(uint16, uint16_t)
    DEF_DESC_SER_BASIC_NO_REF(uint8, uint8_t)
    DEF_DESC_SER_BASIC_NO_REF(float64, double)
    DEF_DESC_SER_BASIC_NO_REF(boolean, bool)
}
