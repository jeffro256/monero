#pragma once

#include <list>
#include <string>
#include <vector>

#include "visitor_specializations.h"
#include "../internal/endianness.h"

namespace portable_storage::model
{
    ///////////////////////////////////////////////////////////////////////////
    // Main Deserialize interface                                            //
    ///////////////////////////////////////////////////////////////////////////

    template <typename Deserializable>
    struct Deserialize
    {
        static Deserializable dflt(Deserializer& deserializer)
        {
            return Deserializable::deserialize_default(deserializer);
        }

        static Deserializable blob(Deserializer& deserializer)
        {
            internal::BlobVisitor<Deserializable> blob_vis;
            deserializer.deserialize_bytes(blob_vis);
            return blob_vis.get_visited();
        }
    };

    ///////////////////////////////////////////////////////////////////////////
    // Deserialize::dflt() basic specializations                             //
    ///////////////////////////////////////////////////////////////////////////
    
    template <> int64_t Deserialize<int64_t>::dflt(Deserializer&);
    template <> int32_t Deserialize<int32_t>::dflt(Deserializer&);
    template <> int16_t Deserialize<int16_t>::dflt(Deserializer&);
    template <> int8_t Deserialize<int8_t>::dflt(Deserializer&);
    template <> uint64_t Deserialize<uint64_t>::dflt(Deserializer&);
    template <> uint32_t Deserialize<uint32_t>::dflt(Deserializer&);
    template <> uint16_t Deserialize<uint16_t>::dflt(Deserializer&);
    template <> uint8_t Deserialize<uint8_t>::dflt(Deserializer&);
    template <> double Deserialize<double>::dflt(Deserializer&);
    template <> std::string Deserialize<std::string>::dflt(Deserializer&);
    template <> bool Deserialize<bool>::dflt(Deserializer&);

    ///////////////////////////////////////////////////////////////////////////
    // Deserialize container specializations                                 //
    ///////////////////////////////////////////////////////////////////////////

    template <typename T> struct Deserialize<std::list<T>>;
    template <typename T> struct Deserialize<std::vector<T>>;
}

#include "deserialization.inl"
