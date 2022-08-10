#pragma once

#include <list>
#include <string>
#include <vector>

#include "../internal/endianness.h"
#include "deserializer.h"
#include "visitor.h"

namespace portable_storage::model {
    ///////////////////////////////////////////////////////////////////////////
    // Main serialization interface                                          //
    ///////////////////////////////////////////////////////////////////////////

    template <typename Deserializable>
    struct Deserialize {
        static Deserializable dflt(Deserializer& deserializer)
        {
            return Deserializable::deserialize_default(deserializer);
        }

        static Deserializable blob(Deserializer& deserializer)
        {
            internal::BlobVisitor<T> blob_vis;
            deserializer.deserialize_string(blob_vis);
            return blob_vis.collect();
        }
    };

    ///////////////////////////////////////////////////////////////////////////
    // deserialize_default() basic specializations                           //
    ///////////////////////////////////////////////////////////////////////////

    #define DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(tyname) \
        template<> tyname Deserialize<tyname>::dflt(Deserializer&);     \
    
    DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(int64_t)
    DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(int32_t)
    DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(int16_t)
    DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(int8_t)
    DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(uint64_t)
    DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(uint32_t)
    DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(uint16_t)
    DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(uint8_t)
    DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(double)
    DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(std::string)
    DECLARE_EXPLICIT_DEFAULT_DESERIALIZE_SPECIALIZATION(bool)

    ///////////////////////////////////////////////////////////////////////////
    // deserialize_default() container specializations                       //
    ///////////////////////////////////////////////////////////////////////////

    #define DECLARE_DEFAULT_DESERIALIZE_SPECIALIZATION_FOR_CONTAINER(contname)             \
        template <typename Element>                                                        \
        contname<Element> Deserialize<contname<Element>>::dflt(Deserializer& deserializer) \
        {                                                                                  \
            internal::DefaultVisitor<contname<Element>> cont_visitor;                      \
            return deserializer.deserialize_array({}, cont_visitor);                       \
        }                                                                                  \

    DECLARE_DEFAULT_DESERIALIZE_SPECIALIZATION_FOR_CONTAINER(std::list)
    DECLARE_DEFAULT_DESERIALIZE_SPECIALIZATION_FOR_CONTAINER(std::vector)

    ///////////////////////////////////////////////////////////////////////////
    // serialize_as_blob() container specializations                         //
    ///////////////////////////////////////////////////////////////////////////

    #define DECLARE_BLOB_DESERIALIZE_SPECIALIZATION_FOR_CONTAINER(contname)                \
        template <typename Element>                                                        \
        contname<Element> Deserialize<contname<Element>>::blob(Deserializer& deserializer) \
        {                                                                                  \
            internal::BlobContainerVisitor<contname<Element>> cont_visitor;                \
            return deserializer.deserialize_array({}, cont_visitor);                       \
        }                                                                                  \

    DECLARE_BLOB_DESERIALIZE_SPECIALIZATION_FOR_CONTAINER(std::list)
}
