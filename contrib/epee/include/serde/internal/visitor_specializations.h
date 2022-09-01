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

#include <sstream>

#include "./container.h"
#include "./deps.h"
#include "./enable_if.h"
#include "../model/deserializer.h"
#include "../model/visitor.h"

namespace serde::internal
{
    // Default Visitor for types which can be coerced using boost::numeric_cast
    template <typename Numeric>
    struct NumericVisitor: public model::RefVisitor<Numeric>
    {
        NumericVisitor(Numeric& num_ref): model::RefVisitor<Numeric>(num_ref) {}

        std::string expecting() const override final
        {
            return "numeric type";
        }

        #define DEF_NUM_VISIT_METHOD(mname, numtype)                      \
            void visit_##mname(numtype value) override final              \
            {                                                             \
                this->visit(internal::safe_numeric_cast<Numeric>(value)); \
            }                                                             \

        DEF_NUM_VISIT_METHOD(int64, int64_t)
        DEF_NUM_VISIT_METHOD(int32, int32_t)
        DEF_NUM_VISIT_METHOD(int16, int16_t)
        DEF_NUM_VISIT_METHOD(int8, int8_t)
        DEF_NUM_VISIT_METHOD(uint64, uint64_t)
        DEF_NUM_VISIT_METHOD(uint32, uint32_t)
        DEF_NUM_VISIT_METHOD(uint16, uint16_t)
        DEF_NUM_VISIT_METHOD(uint8, uint8_t)
        DEF_NUM_VISIT_METHOD(float64, double)
        DEF_NUM_VISIT_METHOD(boolean, bool)

        void visit_bytes(const const_byte_span& bytes) override final
        {
            ASSERT_MES_AND_THROW("no lexical cast provided to parse this numeric type");
        }
    };

    #define DEF_EXPLICIT_SPECIALIZATION_FOR_NUMERIC_VISIT_BY_STRING(numtype)                     \
        template<>                                                                               \
        void NumericVisitor<numtype>::visit_bytes(const const_byte_span& bytes)                  \
        {                                                                                        \
            constexpr size_t MAX_NUMERIC_STRING_SIZE = 50;                                       \
            CHECK_AND_ASSERT_THROW_MES                                                           \
            (                                                                                    \
                bytes.size() < MAX_NUMERIC_STRING_SIZE,                                          \
                "potential numeric string is too long: " << internal::byte_span_to_string(bytes) \
            );                                                                                   \
            numtype value;                                                                       \
            std::istringstream ss(internal::byte_span_to_string(bytes));                         \
            ss >> value;                                                                         \
            CHECK_AND_ASSERT_THROW_MES                                                           \
            (                                                                                    \
                !ss.fail(),                                                                      \
                "could not parse numeric string: " << internal::byte_span_to_string(bytes)       \
            );                                                                                   \
            this->visit(std::move(value));                                                       \
        }                                                                                        \

    DEF_EXPLICIT_SPECIALIZATION_FOR_NUMERIC_VISIT_BY_STRING(int64_t)
    DEF_EXPLICIT_SPECIALIZATION_FOR_NUMERIC_VISIT_BY_STRING(int32_t)
    DEF_EXPLICIT_SPECIALIZATION_FOR_NUMERIC_VISIT_BY_STRING(int16_t)
    DEF_EXPLICIT_SPECIALIZATION_FOR_NUMERIC_VISIT_BY_STRING(int8_t)
    DEF_EXPLICIT_SPECIALIZATION_FOR_NUMERIC_VISIT_BY_STRING(uint64_t)
    DEF_EXPLICIT_SPECIALIZATION_FOR_NUMERIC_VISIT_BY_STRING(uint32_t)
    DEF_EXPLICIT_SPECIALIZATION_FOR_NUMERIC_VISIT_BY_STRING(uint16_t)
    DEF_EXPLICIT_SPECIALIZATION_FOR_NUMERIC_VISIT_BY_STRING(uint8_t)
    DEF_EXPLICIT_SPECIALIZATION_FOR_NUMERIC_VISIT_BY_STRING(double)

    struct StringVisitor: public model::RefVisitor<std::string>
    {
        StringVisitor(std::string& val_ref): model::RefVisitor<std::string>(val_ref) {}

        std::string expecting() const override final
        {
            return "string";
        }

        void visit_bytes(const const_byte_span& bytes) override final
        {
            this->visit(internal::byte_span_to_string(bytes));
        }
    };

    struct CollectionBoundVisitor: public model::BasicVisitor
    {
        using Deserializer = model::Deserializer;
        using SizeHint = optional<size_t>;

        enum struct BoundStatus
        {
            Unvisted,
            ArrayBegin,
            ArrayEnd,
            ObjectBegin,
            ObjectEnd
        };

        CollectionBoundVisitor(): bound_status(BoundStatus::Unvisted), size_hint() {}

        std::string expecting() const override final
        {
            return "the beginning or end of an array or object";
        }

        void visit_array(SizeHint hint) override final
        {
            CHECK_AND_ASSERT_THROW_MES(bound_status == BoundStatus::Unvisted, "already visited");
            bound_status = BoundStatus::ArrayBegin;
            size_hint = hint;
        }

        void visit_end_array() override final
        {
            CHECK_AND_ASSERT_THROW_MES(bound_status == BoundStatus::Unvisted, "already visited");
            bound_status = BoundStatus::ArrayEnd;
        }

        void visit_object(SizeHint hint) override final
        {
            CHECK_AND_ASSERT_THROW_MES(bound_status == BoundStatus::Unvisted, "already visited");
            bound_status = BoundStatus::ObjectBegin;
            size_hint = hint;
        }

        void visit_end_object() override final
        {
            CHECK_AND_ASSERT_THROW_MES(bound_status == BoundStatus::Unvisted, "already visited");
            bound_status = BoundStatus::ObjectEnd;
        }

        static SizeHint expect_array(SizeHint size_hint, Deserializer& deserializer)
        {
            CollectionBoundVisitor visitor;
            deserializer.deserialize_object(size_hint, visitor);
            CHECK_AND_ASSERT_THROW_MES
            (
                visitor.bound_status == BoundStatus::ArrayBegin,
                "Got some other bound besides ArrayBegin"
            );
            return visitor.size_hint;
        }

        static SizeHint expect_object(SizeHint size_hint, Deserializer& deserializer)
        {
            CollectionBoundVisitor visitor;
            deserializer.deserialize_object(size_hint, visitor);
            CHECK_AND_ASSERT_THROW_MES
            (
                visitor.bound_status == BoundStatus::ObjectBegin,
                "Got some other bound besides ObjectBegin"
            );
            return visitor.size_hint;
        }

        BoundStatus bound_status;
        SizeHint size_hint;
    };
} // namespace serde::model
