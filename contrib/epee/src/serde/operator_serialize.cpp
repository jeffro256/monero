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

#include "serde/internal/endianness.h"
#include "serde/model/serialize_default.h"

namespace serde::model
{
    ///////////////////////////////////////////////////////////////////////////
    // serialize_default() basic                                             //
    ///////////////////////////////////////////////////////////////////////////

    #define DEF_SERIALIZE_DEFAULT_COPIED(sername, tyname)            \
        void serialize_default(tyname value, Serializer& serializer) \
        {                                                            \
            serializer.serialize_##sername(value);                   \
        }                                                            \
    
    DEF_SERIALIZE_DEFAULT_COPIED(int64, int64_t)
    DEF_SERIALIZE_DEFAULT_COPIED(int32, int32_t)
    DEF_SERIALIZE_DEFAULT_COPIED(int16, int16_t)
    DEF_SERIALIZE_DEFAULT_COPIED(int8, int8_t)
    DEF_SERIALIZE_DEFAULT_COPIED(uint64, uint64_t)
    DEF_SERIALIZE_DEFAULT_COPIED(uint32, uint32_t)
    DEF_SERIALIZE_DEFAULT_COPIED(uint16, uint16_t)
    DEF_SERIALIZE_DEFAULT_COPIED(uint8, uint8_t)
    DEF_SERIALIZE_DEFAULT_COPIED(float64, double)
    DEF_SERIALIZE_DEFAULT_COPIED(boolean, bool)

    void serialize_default(const std::string& value, Serializer& serializer)
    {
        serializer.serialize_bytes(internal::string_to_byte_span(value));
    }

    ///////////////////////////////////////////////////////////////////////////
    // serialize_as_blob() basic                                             //
    ///////////////////////////////////////////////////////////////////////////

    void serialize_as_blob(const std::string& value, Serializer& serializer)
    {
        serializer.serialize_bytes(internal::string_to_byte_span(value));
    }
}
