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

#include "serde/model/visitor.h"

#include "serde/internal/visitor_specializations.h"
#include "serde/model/deserialize_default.h"
#include "serde/model/serialize_default.h"

namespace serde::model
{
    ///////////////////////////////////////////////////////////////////////////
    // deserialize_default.h                                                 //
    ///////////////////////////////////////////////////////////////////////////

    #define DEF_DEFAULT_DESERIALIZE_NUM(tyname, mname)                      \
        bool deserialize_default(Deserializer& deserializer, tyname& value) \
        {                                                                   \
            internal::NumericVisitor<tyname> visitor(value);                \
            deserializer.deserialize_##mname(visitor);                      \
            return visitor.was_visited();                                   \
        }                                                                   \
    
    DEF_DEFAULT_DESERIALIZE_NUM(int64_t, int64)
    DEF_DEFAULT_DESERIALIZE_NUM(int32_t, int32)
    DEF_DEFAULT_DESERIALIZE_NUM(int16_t, int16)
    DEF_DEFAULT_DESERIALIZE_NUM(int8_t, int8)
    DEF_DEFAULT_DESERIALIZE_NUM(uint64_t, uint64)
    DEF_DEFAULT_DESERIALIZE_NUM(uint32_t, uint32)
    DEF_DEFAULT_DESERIALIZE_NUM(uint16_t, uint16)
    DEF_DEFAULT_DESERIALIZE_NUM(uint8_t, uint8)
    DEF_DEFAULT_DESERIALIZE_NUM(double, float64)
    DEF_DEFAULT_DESERIALIZE_NUM(bool, boolean)

    bool deserialize_default(Deserializer& deserializer, std::string& value)
    {
        internal::StringVisitor visitor(value);
        deserializer.deserialize_bytes(visitor);
        return visitor.was_visited();
    }

    ///////////////////////////////////////////////////////////////////////////
    // deserializer.h                                                        //
    ///////////////////////////////////////////////////////////////////////////

    Deserializer::~Deserializer() {}

    #define DEFER_DESER_SIMPLE_TO_ANY(mname)                                               \
        void SelfDescribingDeserializer::deserialize_##mname(model::BasicVisitor& visitor) \
            { return this->deserialize_any(visitor); }

    DEFER_DESER_SIMPLE_TO_ANY(int64)
    DEFER_DESER_SIMPLE_TO_ANY(int32)
    DEFER_DESER_SIMPLE_TO_ANY(int16)
    DEFER_DESER_SIMPLE_TO_ANY(int8)
    DEFER_DESER_SIMPLE_TO_ANY(uint64)
    DEFER_DESER_SIMPLE_TO_ANY(uint32)
    DEFER_DESER_SIMPLE_TO_ANY(uint16)
    DEFER_DESER_SIMPLE_TO_ANY(uint8)
    DEFER_DESER_SIMPLE_TO_ANY(float64)
    DEFER_DESER_SIMPLE_TO_ANY(bytes)
    DEFER_DESER_SIMPLE_TO_ANY(boolean)
    DEFER_DESER_SIMPLE_TO_ANY(key)
    DEFER_DESER_SIMPLE_TO_ANY(end_array)
    DEFER_DESER_SIMPLE_TO_ANY(end_object)

    void SelfDescribingDeserializer::deserialize_array(optional<size_t>, BasicVisitor& visitor)
    { this->deserialize_any(visitor); }

    void SelfDescribingDeserializer::deserialize_object(optional<size_t>, BasicVisitor& visitor)
    { this->deserialize_any(visitor); }

    ///////////////////////////////////////////////////////////////////////////
    // serialize_default.h                                                   //
    ///////////////////////////////////////////////////////////////////////////

    #define DEF_SERIALIZE_DEFAULT_COPIED(sername, tyname)            \
        void serialize_default(tyname value, Serializer& serializer) \
        {                                                            \
            serializer.serialize_##sername(value);                   \
        }                                                            \
    
    DEF_SERIALIZE_DEFAULT_COPIED(int64, int64_t)
    DEF_SERIALIZE_DEFAULT_COPIED(int32, int32_t)
    DEF_SERIALIZE_DEFAULT_COPIED(int16, int16_t)
    DEF_SERIALIZE_DEFAULT_COPIED(int8, int8_t)
    DEF_SERIALIZE_DEFAULT_COPIED(uint64, uint64_t)
    DEF_SERIALIZE_DEFAULT_COPIED(uint32, uint32_t)
    DEF_SERIALIZE_DEFAULT_COPIED(uint16, uint16_t)
    DEF_SERIALIZE_DEFAULT_COPIED(uint8, uint8_t)
    DEF_SERIALIZE_DEFAULT_COPIED(float64, double)
    DEF_SERIALIZE_DEFAULT_COPIED(boolean, bool)

    void serialize_default(const std::string& value, Serializer& serializer)
    {
        serializer.serialize_bytes(internal::string_to_byte_span(value));
    }

    ///////////////////////////////////////////////////////////////////////////
    // serializer.h                                                          //
    ///////////////////////////////////////////////////////////////////////////

    void Serializer::serialize_string(const std::string& value)
    {
        this->serialize_bytes(internal::string_to_byte_span(value));
    }

    ///////////////////////////////////////////////////////////////////////////
    // visitor.h                                                             //
    ///////////////////////////////////////////////////////////////////////////

    BasicVisitor::BasicVisitor() {}
    BasicVisitor::~BasicVisitor() {}

    #define DEF_BASIC_VISITOR_FALLBACK_METHOD(tyname, mname)                        \
        void BasicVisitor::visit_##mname(tyname)                                    \
        {                                                                           \
            ASSERT_MES_AND_THROW                                                    \
            (                                                                       \
                "called visit_" #mname "() but was expecting " << this->expecting() \
            );                                                                      \
        }                                                                           \
    
    DEF_BASIC_VISITOR_FALLBACK_METHOD(int64_t, int64)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(int32_t, int32)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(int16_t, int16)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(int8_t, int8)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(uint64_t, uint64)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(uint32_t, uint32)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(uint16_t, uint16)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(uint8_t, uint8)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(double, float64)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(const const_byte_span&, bytes)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(bool, boolean)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(optional<size_t>, array)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(void, end_array)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(optional<size_t>, object)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(const const_byte_span&, key)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(void, end_object)


} // namespace serde::model
