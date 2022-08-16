#pragma once

#include <cstring>
#include <tuple>

#include "deserialization.h"
#include "serialization.h"
#include "../internal/container.h"
#include "../internal/external/byte_span.h"

#define PORTABLE_STORAGE_START_STRUCT(structname)                                  \
    void serialize_default(portable_storage::model::Serializer& deserializer) const {            \
        serde_map<true>(*this, deserializer);                                      \
    }                                                                              \
    static structname deserialize_default(portable_storage::model::Deserializer& deserializer) { \
        structname self;                                                           \
        serde_map<false>(self, deserializer);                                      \
        return self;                                                               \
    }                                                                              \
    template <bool SerializeSelector, class This, class Serdelizer>                \
    static void serde_map(This& self, Serdelizer& serdelizer) {                    \
        auto fields = std::make_tuple(                                             \

#define PORTABLE_STORAGE_END_STRUCT                                                            \
        );                                                                                     \
        portable_storage::internal::struct_serde<SerializeSelector>::call(fields, serdelizer); \
    }                                                                                          \

#define PORTABLE_STORAGE_FIELD(fieldname)                                           \
    typename portable_storage::internal::StructFieldSelector                        \
    <SerializeSelector,                                                             \
    typename std::remove_reference<decltype(self . fieldname)>::type,               \
    false,                                                                          \
    true>::type                                                                     \
    (portable_storage::internal::cstr_to_byte_span( #fieldname ), self . fieldname) \

namespace portable_storage::internal
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
    
    template <typename V, bool AsBlob>
    struct StructSerializeField: public StructField<const V&, AsBlob> {
        constexpr StructSerializeField(const const_byte_span& key, const V& value):
            StructField<const V&, AsBlob>(key, value)
        {}
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

    template <bool SerializeSelector, typename V, bool AsBlob, bool Required>
    struct StructFieldSelector;

    template <typename V, bool AsBlob, bool Required>
    struct StructFieldSelector<true, V, AsBlob, Required>
    { using type = StructSerializeField<V, AsBlob>; };

    template <typename V, bool AsBlob, bool Required>
    struct StructFieldSelector<false, V, AsBlob, Required>
    { using type = StructDeserializeField<V, AsBlob, Required>; };

    /* 
    * This struct implements a recursive templated linear search (yeah I know.. boo).
    * If the key of field at tuple[I] matches target_key, then field.value is deserialized.
    * Otherwise, a struct of type deserialize_search<I + 1> is instantiated and the () 
    * operator is called on it with the same arguments. Once I == sizeof...(SF), then that
    * means we searched every field and no key matched, so we throw an error. 
    */
    class deserialize_search
    {
    public:
        deserialize_search(const const_byte_span& target_key, model::Deserializer& deser):
            m_target_key(target_key), m_deser(deser), m_matched_key(false)
        {}

        template <typename Field>
        bool operator()(Field& field)
        {
            if (!field.matches_key(m_target_key)) return true; // continue to next field

            CHECK_AND_ASSERT_THROW_MES
            (
                !field.did_deser, // fields should be deserialized at most once
                "key was already seen: " << byte_span_to_string(m_target_key)
            );

            using t_field = typename std::remove_reference<decltype(field)>::type;
            using t_field_value = typename std::remove_reference<decltype(t_field::value)>::type;
            using D = model::Deserialize<t_field_value>;

            field.value = (t_field::do_as_blob ? D::blob(m_deser) : D::dflt(m_deser));

            m_matched_key = true;
            return false; // no need to try to deserialize more fields
        }

        bool matched() const { return m_matched_key; }

    private:
        const const_byte_span& m_target_key;
        model::Deserializer& m_deser;
        bool m_matched_key;
    }; // class deserialize_seach

    template <class FieldsTuple>
    class NormalStructVisitor: public model::BasicVisitor
    {
    public:
        NormalStructVisitor(const FieldsTuple& fields): m_fields(fields), m_deserializer(nullptr)
        {}

        std::string expecting() const override final
        {
            return "struct";
        }

        void visit_key(const const_byte_span& key_bytes) override final
        {
            CHECK_AND_ASSERT_THROW_MES
            (
                m_deserializer != nullptr,
                "Not currently deserializing an object so visit_key is not allowed"
            );

            deserialize_search ds(key_bytes, *m_deserializer);
            internal::tuple_for_each(m_fields, ds);

            CHECK_AND_ASSERT_THROW_MES
            (
                ds.matched(),
                "Key '" << byte_span_to_string(key_bytes) << "' was not found in struct"
            );
        }

        void visit_object(optional<size_t>, model::Deserializer& deserializer) override final
        {
            m_deserializer = &deserializer;

            while (deserializer.continue_collection())
            {
                deserializer.deserialize_key(*this); // values also get handled in visit_key
            }

            // @TODO: check all required fields got deserialized

            m_deserializer = nullptr; // signal that we are now outside of an object
        }
    
    private:

        FieldsTuple m_fields;
        model::Deserializer* m_deserializer;
    }; // class NormalStructVisitor

    // If true, serialize. If false, deserialize
    template <bool SerializeSelector>
    struct struct_serde {};

    template <>
    struct struct_serde<true>
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

    template <>
    struct struct_serde<false>
    {
        template <typename... SF>
        static void call(const std::tuple<SF...>& fields, model::Deserializer& deserializer)
        {
            NormalStructVisitor<decltype(fields)> struct_visitor(fields);
            deserializer.deserialize_object(sizeof...(SF), struct_visitor);
            // @TODO: required check up etc 
        }
    };
}
