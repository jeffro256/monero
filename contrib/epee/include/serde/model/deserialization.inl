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
