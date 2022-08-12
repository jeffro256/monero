#pragma once

#include <list>
#include <string>
#include <vector>

#include "../internal/endianness.h"
#include "deserializer.h"
#include "visitor.h"

namespace portable_storage::model
{
    ///////////////////////////////////////////////////////////////////////////
    // Main serialization interface                                          //
    ///////////////////////////////////////////////////////////////////////////

    template <typename Deserializable, class Deserializer>
    struct Deserialize
    {
        static Deserializable dflt(Deserializer& deserializer)
        {
            return Deserializable::deserialize_default(deserializer);
        }

        static Deserializable blob(Deserializer& deserializer)
        {
            internal::BlobVisitor<Deserializable, Deserializer> blob_vis;
            return deserializer.deserialize_bytes(blob_vis);
        }
    };

    ///////////////////////////////////////////////////////////////////////////
    // deserialize_default() basic specializations                           //
    ///////////////////////////////////////////////////////////////////////////
    
    #define DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(tyname, mname)       \
        template <class Deserializer>                                   \
        struct Deserialize<tyname, Deserializer>                        \
        {                                                               \
            static tyname dflt(Deserializer& deserializer)              \
            {                                                           \
                internal::DefaultVisitor<tyname, Deserializer> visitor; \
                return deserializer.deserialize_##mname(visitor);       \
            }                                                           \
        };                                                              \
    
    DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(int64_t, int64)
    DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(int32_t, int32)
    DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(int16_t, int16)
    DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(int8_t, int8)
    DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(uint64_t, uint64)
    DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(uint32_t, uint32)
    DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(uint16_t, uint16)
    DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(uint8_t, uint8)
    DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(double, float64)
    DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(std::string, bytes)
    DEF_DEFAULT_DESERIALIZE_SPECIALIZATION(bool, boolean)

    ///////////////////////////////////////////////////////////////////////////
    // deserialize_default() container specializations                       //
    ///////////////////////////////////////////////////////////////////////////

    #define DEF_DESERIALIZE_SPECIALIZATION_FOR_CONTAINER(contname)                      \
        template <typename Element, class Deserializer>                                 \
        struct Deserialize<contname<Element>, Deserializer>                             \
        {                                                                               \
            static contname<Element> dflt(Deserializer& deserializer)                   \
            {                                                                           \
                internal::DefaultVisitor<contname<Element>, Deserializer> cont_visitor; \
                return deserializer.deserialize_array({}, cont_visitor);                \
            }                                                                           \
            static contname<Element> blob(Deserializer& deserializer)                   \
            {                                                                           \
                internal::BlobVisitor<contname<Element>, Deserializer> cont_visitor;    \
                return deserializer.deserialize_bytes(cont_visitor);                    \
            }                                                                           \
        };                                                                              \

    DEF_DESERIALIZE_SPECIALIZATION_FOR_CONTAINER(std::list)
    DEF_DESERIALIZE_SPECIALIZATION_FOR_CONTAINER(std::vector)
}
