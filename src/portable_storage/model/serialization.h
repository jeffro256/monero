#pragma once

#include <list>
#include <string>
#include <vector>

#include "../internal/endianness.h"
#include "serializer.h"

namespace portable_storage::model {
    ///////////////////////////////////////////////////////////////////////////
    // Main serialization interface                                          //
    ///////////////////////////////////////////////////////////////////////////

    struct Serializable {
        Serializable() = default;
        virtual ~Serializable() = default;

        virtual void serialize_default(Serializer& serializer) const = 0;
    };

    template <typename T>
    void serialize_default(const T& value, Serializer& serializer) {
        value.serialize_default(serializer);
    }

    template <typename T>
    void serialize_as_blob(const T& value_, Serializer& serializer) {
        static_assert(std::is_pod<T>::value);
        T value = CONVERT_POD(value_);
        serializer.serialize_bytes(reinterpret_cast<const char*>(&value), sizeof(T));
    }

    ///////////////////////////////////////////////////////////////////////////
    // serialize_default() basic specializations                        //
    ///////////////////////////////////////////////////////////////////////////

    template <> void serialize_default(const int64_t&, Serializer&);
    template <> void serialize_default(const int32_t&, Serializer&);
    template <> void serialize_default(const int16_t&, Serializer&);
    template <> void serialize_default(const int8_t&, Serializer&);
    template <> void serialize_default(const uint64_t&, Serializer&);
    template <> void serialize_default(const uint32_t&, Serializer&);
    template <> void serialize_default(const uint16_t&, Serializer&);
    template <> void serialize_default(const uint8_t&, Serializer&);
    template <> void serialize_default(const double&, Serializer&);
    template <> void serialize_default(const std::string&, Serializer&);
    template <> void serialize_default(const bool&, Serializer&);

    ///////////////////////////////////////////////////////////////////////////
    // serialize_default() container specializations                    //
    ///////////////////////////////////////////////////////////////////////////

    template <class Container>
    void describe_container_serialization(const Container& cont, Serializer& serializer) {
        serializer.serialize_start_array(cont.size());
        for (const auto& elem: cont) {
            serialize_default(elem, serializer);
        }
        serializer.serialize_end_array();
    }

    #define DEF_DESC_SER_FOR_CONTAINER(contname)                                  \
        template <typename T>                                                     \
        void serialize_default(const contname<T>& cont, Serializer& serializer) { \
            describe_container_serialization(cont, serializer);                   \
        }                                                                         \

    DEF_DESC_SER_FOR_CONTAINER(std::list)
    DEF_DESC_SER_FOR_CONTAINER(std::vector)

    ///////////////////////////////////////////////////////////////////////////
    // serialize_default() overloads                                    //
    //                                                                       //
    // The first is for virtual support of Serializable, the rest of the     //
    // overloads benefit performance/ease of use for cheaply copyable types  //
    ///////////////////////////////////////////////////////////////////////////

    void serialize_default(const Serializable*, Serializer&);
    void serialize_default(int64_t, Serializer&);
    void serialize_default(int32_t, Serializer&);
    void serialize_default(int16_t, Serializer&);
    void serialize_default(int8_t, Serializer&);
    void serialize_default(uint64_t, Serializer&);
    void serialize_default(uint32_t, Serializer&);
    void serialize_default(uint16_t, Serializer&);
    void serialize_default(uint8_t, Serializer&);
    void serialize_default(double, Serializer&);
    void serialize_default(bool, Serializer&);

    ///////////////////////////////////////////////////////////////////////////
    // serialize_as_blob() container specializations                         //
    ///////////////////////////////////////////////////////////////////////////

    // Describe any standard container whose storage isn't contiguous in memory as a blob
    template <class Container>
    void describe_cont_serialization_as_blob(const Container& cont, Serializer& serializer) {
        typedef typename Container::value_type value_type;
        static_assert(std::is_pod<value_type>::value);

        const size_t blob_size = cont.size() * sizeof(value_type);
        std::string blob(blob_size, '\0'); // fill constructor
        value_type* blob_ptr = reinterpret_cast<value_type*>(blob.data());

        for (const auto& elem: cont) {
            *blob_ptr = CONVERT_POD(elem);
            blob_ptr++;
        }

        serializer.serialize_string(blob);
    }

    // Describe any standard container whose storage IS contiguous in memory as a blob
    // contcont = contiguous container
    template <class Container>
    void describe_contcont_serialization_as_blob(const Container& cont, Serializer& serializer) {
        typedef typename Container::value_type value_type;
        static_assert(std::is_pod<value_type>::value);

        if (internal::should_convert_pod<value_type>()) {
            describe_cont_serialization_as_blob(cont, serializer);
        } else {
            const char* blob_bytes = reinterpret_cast<const char*>(&cont[0]);
            const size_t blob_size = cont.size() * sizeof(value_type);
            serializer.serialize_bytes(blob_bytes, blob_size);
        }
    }

    #define DEF_DESC_CONT_SER_AS_BLOB(contname)                                   \
        template <typename T>                                                     \
        void serialize_as_blob(const contname<T>& cont, Serializer& serializer) { \
            describe_cont_serialization_as_blob(cont, serializer);                \
        }                                                                         \
    
    #define DEF_DESC_CONTCONT_SER_AS_BLOB(contname)                               \
        template <typename T>                                                     \
        void serialize_as_blob(const contname<T>& cont, Serializer& serializer) { \
            describe_contcont_serialization_as_blob(cont, serializer);            \
        }                                                                         \

    DEF_DESC_CONT_SER_AS_BLOB(std::list)
    DEF_DESC_CONTCONT_SER_AS_BLOB(std::vector)
}
