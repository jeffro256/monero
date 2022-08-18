#pragma once

#include <cstring>
#include <tuple>

#include "deserialization.h"
#include "serialization.h"
#include "../internal/container.h"
#include "../internal/external/byte_span.h"

#define PORTABLE_STORAGE_START_STRUCT(structname)                                     \
    void serialize_default(serde::model::Serializer& deserializer) const {            \
        serde_map<true>(*this, deserializer);                                         \
    }                                                                                 \
    static structname deserialize_default(serde::model::Deserializer& deserializer) { \
        structname self;                                                              \
        serde_map<false>(self, deserializer);                                         \
        return self;                                                                  \
    }                                                                                 \
    template <bool SerializeSelector, class This, class Serdelizer>                   \
    static void serde_map(This& self, Serdelizer& serdelizer) {                       \
        auto fields = std::make_tuple(                                                \

#define PORTABLE_STORAGE_END_STRUCT                                                  \
        );                                                                           \
        serde::internal::struct_serde<SerializeSelector>::call(fields, serdelizer);  \
    }                                                                                \

#define PORTABLE_STORAGE_FIELD(fieldname)                                \
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
                using t_value = typename std::remove_reference<decltype(t_field::value)>::type;
                using D = model::Deserialize<t_value>;

                optional<t_value> dres = t_field::do_as_blob ? D::blob(m_deser) : D::dflt(m_deser);
                
                CHECK_AND_ASSERT_THROW_MES(dres, "deserialize error: object ended after key");

                field.value = std::move(*dres);
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
    };

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
        template <typename... SF>
        static void call(std::tuple<SF...>& fields, model::Deserializer& deserializer)
        {
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
    };
}
