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
#include "serde/model/serialization.h"

namespace serde::model
{
    ///////////////////////////////////////////////////////////////////////////
    // serialize_default() basic specializations                             //
    ///////////////////////////////////////////////////////////////////////////

    #define DEF_DESC_SER_BASIC(sername, tyname)                                         \
        template <> void serialize_default(const tyname& value, Serializer& serializer) \
        {                                                                               \
            serializer.serialize_##sername(value);                                      \
        }                                                                               \
    
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

    void serialize_default(const Serializable* value, Serializer& serializer)
    {
        value->serialize_default(serializer);
    }

    #define DEF_DESC_SER_BASIC_NO_REF(sername, tyname)               \
        void serialize_default(tyname value, Serializer& serializer) \
        {                                                            \
            serializer.serialize_##sername(value);                   \
        }                                                            \
    
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

    ///////////////////////////////////////////////////////////////////////////
    // serialize_as_blob() basic specializations                             //
    ///////////////////////////////////////////////////////////////////////////

    template <> void serialize_as_blob(const std::string& value, Serializer& serializer)
    {
        serializer.serialize_bytes(internal::string_to_byte_span(value));
    }
}
