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

#include <cstring>
#include <tuple>

#include "operator_deserialize.h"
#include "operator_serialize.h"
#include "../internal/container.h"
#include "../internal/deps.h"

#define BEGIN_KV_SERIALIZE_MAP()                                \
    using serde_struct_enabled = void;                          \
    template <bool SerializeSelector> struct serde_struct_map { \
        template <class This, class Serdelizer>                 \
        bool operator()(Serdelizer& serdelizer, This& self) {   \
            auto fields = std::make_tuple(                      \

#define KV_SERIALIZE_BASE(fieldname, asblob, required, key, optval)           \
                serde::internal::FieldSelector                                \
                <SerializeSelector,                                           \
                decltype(self . fieldname),                                   \
                asblob, required>                                             \
                (serde::internal::cstr_to_byte_span( key ), self . fieldname, \
                optval) ,                                                     \

#define KV_SERIALIZE_VAL_POD_AS_BLOB_OPT(fieldname, optval)                   \
                KV_SERIALIZE_BASE(fieldname, true, false, #fieldname, optval) \

#define KV_SERIALIZE_N(fieldname, key)                                    \
                KV_SERIALIZE_BASE(fieldname, false, true, #fieldname, {}) \

#define KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(fieldname)                    \
                KV_SERIALIZE_BASE(fieldname, true, true, #fieldname, {}) \

#define KV_SERIALIZE_VAL_POD_AS_BLOB(fieldname)                          \
                KV_SERIALIZE_BASE(fieldname, true, true, #fieldname, {}) \

#define KV_SERIALIZE_CONTAINER_POD_AS_BLOB(fieldname)   \
                KV_SERIALIZE_VAL_POD_AS_BLOB(fieldname) \

#define KV_SERIALIZE(fieldname)                       \
                KV_SERIALIZE_N(fieldname, #fieldname) \

#define END_KV_SERIALIZE_MAP()                                                           \
                serde::internal::DummyStructField()                                      \
            );                                                                           \
            serde::internal::struct_serde<SerializeSelector>::call(fields, serdelizer);  \
            return true; }};                                                             \

#define SERDE_STRUCT_OPERATOR_FRIENDS(thisname)                                                   \
    friend void serialize_default(const thisname& address, serde::model::Serializer& serializer); \
	friend bool deserialize_default(serde::model::Deserializer& deserializer, thisname& address); \

namespace serde::model
{
    // Overload the serialize_default operator if type has the serde_struct_enabled typedef
    template <class Struct, typename = typename Struct::serde_struct_enabled>
    void serialize_default(const Struct& struct_ref, Serializer& serializer);

    // Overload the deserialize_default operator if type has the serde_struct_enabled typedef
    template <class Struct, typename = typename Struct::serde_struct_enabled>
    bool deserialize_default(Deserializer& deserializer, Struct& struct_ref);
}

#include "../internal/struct.inl"
