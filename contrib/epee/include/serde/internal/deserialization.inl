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

namespace serde::model {
    #define DEF_DESERIALIZE_SPLZATION_FOR_CONTAINER(contname, blobvisitorname)               \
        template <typename Element>                                                          \
        struct Deserialize<contname<Element>>                                                \
        {                                                                                    \
            using Container = contname<Element>;                                             \
            using value_type = typename Container::value_type;                               \
            static optional<Container> dflt(Deserializer& deserializer)                      \
            {                                                                                \
                internal::CollectionBoundVisitor::expect_array({}, deserializer);            \
                Container cont;                                                              \
                while (true) {                                                               \
                    optional<value_type> elem = Deserialize<value_type>::dflt(deserializer); \
                    if (elem) { cont.push_back(*elem); }                                     \
                    else { break; }                                                          \
                }                                                                            \
                return std::move(cont);                                                      \
            }                                                                                \
            static optional<Container> blob(Deserializer& deserializer)                      \
            {                                                                                \
                blobvisitorname<Container> blob_visitor;                                     \
                deserializer.deserialize_bytes(blob_visitor);                                \
                return blob_visitor.get_visited();                                           \
            }                                                                                \
        };                                                                                   \

    DEF_DESERIALIZE_SPLZATION_FOR_CONTAINER(std::list, internal::BlobContainerVisitor)
    DEF_DESERIALIZE_SPLZATION_FOR_CONTAINER(std::vector, internal::BlobContiguousContainerVisitor)
}
