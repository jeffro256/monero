#pragma once

#include <list>
#include <string>
#include <vector>

#include "visitor_specializations.h"
#include "../internal/endianness.h"

namespace serde::model
{
    ///////////////////////////////////////////////////////////////////////////
    // Main Deserialize interface                                            //
    ///////////////////////////////////////////////////////////////////////////

    template <typename Deserializable>
    struct Deserialize
    {
        static optional<Deserializable> dflt(Deserializer& deserializer)
        {
            return Deserializable::deserialize_default(deserializer);
        }

        static optional<Deserializable> blob(Deserializer& deserializer)
        {
            internal::BlobVisitor<Deserializable> blob_vis;
            deserializer.deserialize_bytes(blob_vis);
            return blob_vis.get_visited();
        }
    };

    ///////////////////////////////////////////////////////////////////////////
    // Deserialize::dflt() basic specializations                             //
    ///////////////////////////////////////////////////////////////////////////
    
    template <> optional<int64_t> Deserialize<int64_t>::dflt(Deserializer&);
    template <> optional<int32_t> Deserialize<int32_t>::dflt(Deserializer&);
    template <> optional<int16_t> Deserialize<int16_t>::dflt(Deserializer&);
    template <> optional<int8_t> Deserialize<int8_t>::dflt(Deserializer&);
    template <> optional<uint64_t> Deserialize<uint64_t>::dflt(Deserializer&);
    template <> optional<uint32_t> Deserialize<uint32_t>::dflt(Deserializer&);
    template <> optional<uint16_t> Deserialize<uint16_t>::dflt(Deserializer&);
    template <> optional<uint8_t> Deserialize<uint8_t>::dflt(Deserializer&);
    template <> optional<double> Deserialize<double>::dflt(Deserializer&);
    template <> optional<std::string> Deserialize<std::string>::dflt(Deserializer&);
    template <> optional<bool> Deserialize<bool>::dflt(Deserializer&);

    ///////////////////////////////////////////////////////////////////////////
    // Deserialize::blob() basic specializations                             //
    ///////////////////////////////////////////////////////////////////////////

    // deserializes string contents
    template <> optional<std::string> Deserialize<std::string>::blob(Deserializer&);

    ///////////////////////////////////////////////////////////////////////////
    // Deserialize container specializations                                 //
    ///////////////////////////////////////////////////////////////////////////

    template <typename T> struct Deserialize<std::list<T>>;
    template <typename T> struct Deserialize<std::vector<T>>;
}

#include "deserialization.inl"
