// Copyright (c) 2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <list>
#include <string>
#include <vector>

#include "../internal/visitor_specializations.h"
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

#include "../internal/deserialization.inl"
