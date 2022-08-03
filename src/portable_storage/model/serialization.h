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

        virtual void describe_serialization(Serializer& serializer) const = 0;
    };

    template <typename T>
    void describe_serialization(const T& value, Serializer& serializer) {
        value.describe_serialization(serializer);
    }

    template <typename T>
    void describe_serialization_as_blob(const T& value_, Serializer& serializer) {
        static_assert(std::is_pod<T>::value);
        T value = CONVERT_POD(value_);
        serializer.serialize_bytes(reinterpret_cast<const char*>(&value), sizeof(T));
    }

    ///////////////////////////////////////////////////////////////////////////
    // describe_serialization() basic specializations                        //
    ///////////////////////////////////////////////////////////////////////////

    template <> void describe_serialization(const int64_t&, Serializer&);
    template <> void describe_serialization(const int32_t&, Serializer&);
    template <> void describe_serialization(const int16_t&, Serializer&);
    template <> void describe_serialization(const int8_t&, Serializer&);
    template <> void describe_serialization(const uint64_t&, Serializer&);
    template <> void describe_serialization(const uint32_t&, Serializer&);
    template <> void describe_serialization(const uint16_t&, Serializer&);
    template <> void describe_serialization(const uint8_t&, Serializer&);
    template <> void describe_serialization(const double&, Serializer&);
    template <> void describe_serialization(const std::string&, Serializer&);
    template <> void describe_serialization(const bool&, Serializer&);

    ///////////////////////////////////////////////////////////////////////////
    // describe_serialization() container specializations                    //
    ///////////////////////////////////////////////////////////////////////////

    template <class Container>
    void describe_container_serialization(const Container& cont, Serializer& serializer) {
        serializer.serialize_start_array(cont.size());
        for (const auto& elem: cont) {
            describe_serialization(elem, serializer);
        }
        serializer.serialize_end_array();
    }

    #define DEF_DESC_SER_FOR_CONTAINER(contname)                                       \
        template <typename T>                                                          \
        void describe_serialization(const contname<T>& cont, Serializer& serializer) { \
            describe_container_serialization(cont, serializer);                        \
        }                                                                              \

    DEF_DESC_SER_FOR_CONTAINER(std::list)
    DEF_DESC_SER_FOR_CONTAINER(std::vector)

    ///////////////////////////////////////////////////////////////////////////
    // describe_serialization() overloads                                    //
    //                                                                       //
    // The first is for virtual support of Serializable, the rest of the     //
    // overloads benefit performance/ease of use for cheaply copyable types  //
    ///////////////////////////////////////////////////////////////////////////

    void describe_serialization(const Serializable*, Serializer&);
    void describe_serialization(int64_t, Serializer&);
    void describe_serialization(int32_t, Serializer&);
    void describe_serialization(int16_t, Serializer&);
    void describe_serialization(int8_t, Serializer&);
    void describe_serialization(uint64_t, Serializer&);
    void describe_serialization(uint32_t, Serializer&);
    void describe_serialization(uint16_t, Serializer&);
    void describe_serialization(uint8_t, Serializer&);
    void describe_serialization(double, Serializer&);
    void describe_serialization(bool, Serializer&);

    ///////////////////////////////////////////////////////////////////////////
    // describe_serialization_as_blob() container specializations            //
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

    #define DEF_DESC_CONT_SER_AS_BLOB(contname)                                                \
        template <typename T>                                                                  \
        void describe_serialization_as_blob(const contname<T>& cont, Serializer& serializer) { \
            describe_cont_serialization_as_blob(cont, serializer);                             \
        }
    
    #define DEF_DESC_CONTCONT_SER_AS_BLOB(contname)                                            \
        template <typename T>                                                                  \
        void describe_serialization_as_blob(const contname<T>& cont, Serializer& serializer) { \
            describe_contcont_serialization_as_blob(cont, serializer);                         \
        }

    DEF_DESC_CONT_SER_AS_BLOB(std::list)
    DEF_DESC_CONTCONT_SER_AS_BLOB(std::vector)
}
