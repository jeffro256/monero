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

#define BEGIN_KV_SERIALIZE_MAP()                                                      \
    using serde_struct_enabled = void;                                                \
    void serialize_default(serde::model::Serializer& deserializer) const {            \
        serde_struct_map<true>()(deserializer, *this);                                \
    }                                                                                 \
    template <bool SerializeSelector> struct serde_struct_map {                       \
        template <class This, class Serdelizer>                                       \
        bool operator()(Serdelizer& serdelizer, This& self) {                         \
            auto fields = std::make_tuple(                                            \

#define END_KV_SERIALIZE_MAP()                                                           \
            );                                                                           \
            serde::internal::struct_serde<SerializeSelector>::call(fields, serdelizer);  \
            return true; }};                                                             \

#define KV_SERIALIZE(fieldname)                                          \
    typename serde::internal::StructFieldSelector                        \
    <SerializeSelector,                                                  \
    typename std::remove_reference<decltype(self . fieldname)>::type,    \
    false,                                                               \
    true>::type                                                          \
    (serde::internal::cstr_to_byte_span( #fieldname ), self . fieldname) \

namespace serde::internal
{
    template <typename ValRef, bool AsBlob>
    struct StructField
    {
        static constexpr bool do_as_blob = AsBlob;

        constexpr StructField(const const_byte_span& key, ValRef value): key(key), value(value) {}

        const_byte_span key;
        ValRef value;

        bool matches_key(const const_byte_span& other_key) const
        {
            if (other_key.size() != this->key.size()) return false;
            return 0 == memcmp(key.begin(), other_key.begin(), key.size());
        }
    };
    
    template <typename V, bool AsBlob, bool Required>
    struct StructDeserializeField: public StructField<V&, AsBlob>
    {
        static constexpr bool required = Required;

        constexpr StructDeserializeField(const const_byte_span& key, V& value):
            StructField<V&, AsBlob>(key, value), did_deser(false)
        {}

        bool did_deser;
    }; // struct StructField

    // StructFieldSelector<true, ...>::type is a StructField for serializing
    // Selects the StructField types for the tuple in serde_map in PORTABLE_STORAGE_START_STRUCT
    template <bool SerializeSelector, typename V, bool AsBlob, bool Required>
    struct StructFieldSelector
    { using type = StructField<const V&, AsBlob>; };

    // StructFieldSelector<false, ...>::type is a StructField for DEserializing
    // Selects the StructField types for the tuple in serde_map in PORTABLE_STORAGE_START_STRUCT
    template <typename V, bool AsBlob, bool Required>
    struct StructFieldSelector<false, V, AsBlob, Required>
    { using type = StructDeserializeField<V, AsBlob, Required>; };

    template <typename... SF>
    struct StructKeysVisitor: public model::BasicVisitor
    {
        static constexpr size_t NO_MATCH = std::numeric_limits<size_t>::max();

        class key_search
        {
        public:
            key_search(const const_byte_span& target_key):
                m_target_key(target_key), m_match_index(NO_MATCH), m_i(0)
            {}

            template <typename Field>
            bool operator()(Field& field)
            {
                if (field.matches_key(m_target_key))
                {
                    m_match_index = m_i;
                    return false;
                }
                else
                {
                    m_i++;
                    return true;
                } 
            }

            bool matched() const { return m_match_index != NO_MATCH; }
            size_t match_index() const { return m_match_index; }

        private:
            const const_byte_span& m_target_key;
            size_t m_match_index;
            size_t m_i;
        }; // class key_seach

        constexpr StructKeysVisitor(std::tuple<SF...>& fields):
            fields(fields), object_ended(false), match_index(NO_MATCH)
        {}

        std::string expecting() const override final
        {
            return "keys";
        }

        void visit_key(const const_byte_span& key_bytes) override final
        {
            key_search key_search(key_bytes);
            internal::tuple_for_each(fields, key_search);

            CHECK_AND_ASSERT_THROW_MES
            (
                key_search.matched(),
                "Key '" << byte_span_to_string(key_bytes) << "' was not found in struct"
            );

            match_index = key_search.match_index();
        }

        void visit_end_object() override final
        {
            object_ended = true;
        }

        std::tuple<SF...>& fields;
        bool object_ended;
        size_t match_index;
    }; // struct StructKeysVisitor

    // If true, serialize. If false, deserialize
    template <bool SerializeSelector>
    struct struct_serde
    {
        struct serialize_field
        {
            constexpr serialize_field(model::Serializer& serializer): serializer(serializer) {}

            template <class Field>
            bool operator()(Field& field)
            {
                serializer.serialize_key(field.key);

                if (Field::do_as_blob)
                {
                    model::serialize_as_blob(field.value, serializer);
                }
                else
                {
                    model::serialize_default(field.value, serializer);
                }
                
                return true;
            }

            model::Serializer& serializer;
        };

        template <typename... SF>
        static void call(const std::tuple<SF...>& fields, model::Serializer& serializer)
        {
            serialize_field serialize_field(serializer);

            serializer.serialize_start_object(sizeof...(SF));
            tuple_for_each(fields, serialize_field);
            serializer.serialize_end_object();
        }
    };

    // If true, serialize. If false, deserialize
    template <>
    struct struct_serde<false>
    {
        class deserialize_nth_field
        {
        public:

            constexpr deserialize_nth_field(size_t n, model::Deserializer& deserializer):
                m_n(n), m_i(0), m_deser(deserializer)
            {} 

            template <typename Field>
            bool operator()(Field& field)
            {
                if (m_i == m_n)
                {
                    CHECK_AND_ASSERT_THROW_MES
                    (
                        !field.did_deser, // fields should be deserialized at most once
                        "key seen twice for same object"
                    );

                    using t_field = typename std::remove_reference<decltype(field)>::type;

                    field.did_deser = t_field::do_as_blob
                        ? deserialize_as_blob(m_deser, field.value)
                        : deserialize_default(m_deser, field.value);

                    CHECK_AND_ASSERT_THROW_MES(field.did_deser, "object ended after key");
                    return false;
                }
                else
                {
                    m_i++;
                    return true;
                }
            }

        private:

            size_t m_n;
            size_t m_i;
            model::Deserializer& m_deser;
        }; // class deserialize_nth_field

        template <typename... SF>
        static void call(std::tuple<SF...>& fields, model::Deserializer& deserializer)
        {
            // @TODO: support object in arrays by return false instead of throwing
            internal::CollectionBoundVisitor::expect_object({}, deserializer);
            while (true) {
                StructKeysVisitor<SF...> keys_visitor(fields);
                deserializer.deserialize_key(keys_visitor);

                if (keys_visitor.object_ended) break;

                deserialize_nth_field dnf(keys_visitor.match_index, deserializer);
                tuple_for_each(fields, dnf);
            }

            // @TODO: required check up etc 
        }
    }; // struct struct_serde
} // namespace serde::internal

namespace serde::model
{
    // @TODO: operator serialize
    /*
    template <class Struct, typename = typename Struct::serde_struct_enabled>
    void serialize_default(const Struct& struct, Deserializer& deserializer)
    {
        return Struct::serde_struct_map<true>(deserializer, struct);
    }
    */

    // Overload the deserialize_default operator if type has the serde_struct_enabled typedef
    template <class Struct, typename = typename Struct::serde_struct_enabled>
    bool deserialize_default(Deserializer& deserializer, Struct& struct_ref)
    {
        using serde_struct_map = typename Struct::serde_struct_map<false>;
        return serde_struct_map()(deserializer, struct_ref);
    }
}
