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

#include <list>
#include <string>
#include <vector>

#include "serializer.h"
#include "../internal/endianness.h"

namespace serde::model
{
    ///////////////////////////////////////////////////////////////////////////
    // Main serialization interface                                          //
    ///////////////////////////////////////////////////////////////////////////

    struct Serializable
    {
        Serializable() = default;
        virtual ~Serializable() = default;

        virtual void serialize_default(Serializer& serializer) const = 0;
    };

    template <typename T>
    void serialize_default(const T& value, Serializer& serializer)
    {
        value.serialize_default(serializer);
    }

    template <typename T>
    void serialize_as_blob(const T& value_, Serializer& serializer)
    {
        static_assert(std::is_pod<T>::value);
        const T value = CONVERT_POD(value_);
        serializer.serialize_bytes({reinterpret_cast<const_byte_iterator>(&value), sizeof(T)});
    }

    ///////////////////////////////////////////////////////////////////////////
    // serialize_default() basic specializations                             //
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
    // serialize_default() container specializations                         //
    ///////////////////////////////////////////////////////////////////////////

    template <class Container>
    void describe_container_serialization(const Container& cont, Serializer& serializer)
    {
        serializer.serialize_start_array(cont.size());
        for (const auto& elem: cont)
        {
            serialize_default(elem, serializer);
        }
        serializer.serialize_end_array();
    }

    #define DEF_DESC_SER_FOR_CONTAINER(contname)                                \
        template <typename T>                                                   \
        void serialize_default(const contname<T>& cont, Serializer& serializer) \
        {                                                                       \
            describe_container_serialization(cont, serializer);                 \
        }                                                                       \

    DEF_DESC_SER_FOR_CONTAINER(std::list)
    DEF_DESC_SER_FOR_CONTAINER(std::vector)

    ///////////////////////////////////////////////////////////////////////////
    // serialize_default() overloads                                         //
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
    // serialize_as_blob() basic specializations                             //
    ///////////////////////////////////////////////////////////////////////////

    // Serializes string contents
    template <> void serialize_as_blob(const std::string&, Serializer&);

    ///////////////////////////////////////////////////////////////////////////
    // serialize_as_blob() container specializations                         //
    ///////////////////////////////////////////////////////////////////////////

    // Describe any standard container whose storage isn't contiguous in memory as a blob
    template <class Container>
    void describe_cont_serialization_as_blob(const Container& cont, Serializer& serializer)
    {
        typedef typename Container::value_type value_type;
        static_assert(std::is_pod<value_type>::value);

        const size_t blob_size = cont.size() * sizeof(value_type);
        std::string blob(blob_size, '\0'); // fill constructor
        value_type* blob_ptr = reinterpret_cast<value_type*>(blob.data());

        for (const auto& elem: cont)
        {
            *blob_ptr = CONVERT_POD(elem);
            blob_ptr++;
        }

        serializer.serialize_string(blob);
    }

    // Describe any standard container whose storage IS contiguous in memory as a blob
    // contcont = contiguous container
    template <class Container>
    void describe_contcont_serialization_as_blob(const Container& cont, Serializer& serializer)
    {
        typedef typename Container::value_type value_type;
        static_assert(std::is_pod<value_type>::value);

        if (internal::should_convert_pod<value_type>()) {
            describe_cont_serialization_as_blob(cont, serializer);
        } else {
            auto blob_bytes = reinterpret_cast<const_byte_iterator>(&cont[0]);
            const size_t blob_size = cont.size() * sizeof(value_type);
            serializer.serialize_bytes({blob_bytes, blob_size});
        }
    }

    #define DEF_DESC_CONT_SER_AS_BLOB(contname)                                 \
        template <typename T>                                                   \
        void serialize_as_blob(const contname<T>& cont, Serializer& serializer) \
        {                                                                       \
            describe_cont_serialization_as_blob(cont, serializer);              \
        }                                                                       \
    
    #define DEF_DESC_CONTCONT_SER_AS_BLOB(contname)                             \
        template <typename T>                                                   \
        void serialize_as_blob(const contname<T>& cont, Serializer& serializer) \
        {                                                                       \
            describe_contcont_serialization_as_blob(cont, serializer);          \
        }                                                                       \

    DEF_DESC_CONT_SER_AS_BLOB(std::list)
    DEF_DESC_CONTCONT_SER_AS_BLOB(std::vector)
}
