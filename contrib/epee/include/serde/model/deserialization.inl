#pragma once

namespace serde::model {
    #define DEF_DESERIALIZE_SPLZATION_FOR_CONTAINER(contname, blobvisitorname)     \
        template <typename Element>                                                \
        struct Deserialize<contname<Element>>                                      \
        {                                                                          \
            static contname<Element> dflt(Deserializer& deserializer)              \
            {                                                                      \
                internal::DefaultContainerVisitor<contname<Element>> cont_visitor; \
                deserializer.deserialize_array({}, cont_visitor);                  \
                return cont_visitor.get_visited();                                 \
            }                                                                      \
            static contname<Element> blob(Deserializer& deserializer)              \
            {                                                                      \
                blobvisitorname<contname<Element>, Deserializer> blob_visitor;     \
                deserializer.deserialize_bytes(blob_visitor);                      \
                return blob_visitor.get_visited();                                 \
            }                                                                      \
        };                                                                         \

    DEF_DESERIALIZE_SPLZATION_FOR_CONTAINER(std::list, internal::BlobContainerVisitor)
    DEF_DESERIALIZE_SPLZATION_FOR_CONTAINER(std::vector, internal::BlobContiguousContainerVisitor)
}