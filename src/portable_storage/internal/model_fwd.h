#pragma once

namespace portable_storage::model
{
    template <typename> struct Deserialize;
    struct Deserializer;
    struct Serializer;
    struct Serializable;
    template <typename T> void serialize_default(const T&, Serializer&);
    template <typename T> void serialize_as_blob(const T&, Serializer&);
    struct BasicVisitor;
    template <typename> class GetSetVisitor;
}
