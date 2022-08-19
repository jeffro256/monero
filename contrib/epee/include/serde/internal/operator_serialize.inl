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

#include "../internal/endianness.h"

namespace serde::model
{
    template <typename T> ENABLE_IF_POD(T)
    serialize_as_blob(const T& value, Serializer& serializer)
    {
        const T conv_val = CONVERT_POD(value);
        serializer.serialize_bytes({reinterpret_cast<const_byte_iterator>(&conv_val), sizeof(T)});
    }

    #define DEF_SERIALIZE_DEFAULT_FOR_CONTAINER(contname)                       \
        template <typename T>                                                   \
        void serialize_default(const contname<T>& cont, Serializer& serializer) \
        {                                                                       \
            serializer.serialize_start_array(cont.size());                      \
            for (const auto& elem: cont)                                        \
            {                                                                   \
                serialize_default(elem, serializer);                            \
            }                                                                   \
            serializer.serialize_end_array();                                   \
        }                                                                       \

    DEF_SERIALIZE_DEFAULT_FOR_CONTAINER(std::list)
    DEF_SERIALIZE_DEFAULT_FOR_CONTAINER(std::vector)

    #define DEF_SERIALIZE_AS_BLOB_FOR_CONTAINER(contname)                               \
        template <typename Element>                                                     \
        void serialize_as_blob(const contname<Element>& cont, Serializer& serializer) { \
            static_assert(std::is_pod<Element>::value);                                 \
            const size_t blob_size = cont.size() * sizeof(Element);                     \
            std::string blob(blob_size, '\0');                                          \
            Element* blob_ptr = reinterpret_cast<Element*>(blob.data());                \
            for (const auto& elem: cont) {                                              \
                *(blob_ptr++) = CONVERT_POD(elem);                                      \
            }                                                                           \
            serializer.serialize_string(blob);                                          \
        }                                                                               \
    
    DEF_SERIALIZE_AS_BLOB_FOR_CONTAINER(std::list)
    DEF_SERIALIZE_AS_BLOB_FOR_CONTAINER(std::vector)

    // @TODO: specialization for contiguous containers (remember vector<bool> evilness)
} // namespace serde::model
