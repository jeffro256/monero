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

#include "serde/blob/deserialize_as_blob.h"
#include "serde/internal/visitor_specializations.h"
#include "serde/model/deserialize_default.h"

namespace serde::model
{
    #define DEF_DEFAULT_DESERIALIZE_NUM(tyname, mname)                      \
        bool deserialize_default(Deserializer& deserializer, tyname& value) \
        {                                                                   \
            internal::NumericVisitor<tyname> visitor(value);                \
            deserializer.deserialize_##mname(visitor);                      \
            return visitor.was_visited();                                   \
        }                                                                   \
    
    DEF_DEFAULT_DESERIALIZE_NUM(int64_t, int64)
    DEF_DEFAULT_DESERIALIZE_NUM(int32_t, int32)
    DEF_DEFAULT_DESERIALIZE_NUM(int16_t, int16)
    DEF_DEFAULT_DESERIALIZE_NUM(int8_t, int8)
    DEF_DEFAULT_DESERIALIZE_NUM(uint64_t, uint64)
    DEF_DEFAULT_DESERIALIZE_NUM(uint32_t, uint32)
    DEF_DEFAULT_DESERIALIZE_NUM(uint16_t, uint16)
    DEF_DEFAULT_DESERIALIZE_NUM(uint8_t, uint8)
    DEF_DEFAULT_DESERIALIZE_NUM(double, float64)
    DEF_DEFAULT_DESERIALIZE_NUM(bool, boolean)

    bool deserialize_default(Deserializer& deserializer, std::string& value)
    {
        internal::StringVisitor visitor(value);
        deserializer.deserialize_bytes(visitor);
        return visitor.was_visited();
    }

    bool deserialize_as_blob(Deserializer& deserializer, std::string& blob_value)
    {
        internal::BlobStringVisitor blob_string_visitor(blob_value);
        deserializer.deserialize_bytes(blob_string_visitor);
        return blob_string_visitor.was_visited();
    }
}
