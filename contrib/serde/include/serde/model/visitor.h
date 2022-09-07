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

#include <string>
#include <list>

#include "../internal/deps.h"

namespace serde::model
{
    struct BasicVisitor
    {
        BasicVisitor();
        virtual ~BasicVisitor();

        virtual std::string expecting() const = 0;

        virtual void visit_int64(int64_t value);
        virtual void visit_int32(int32_t value);
        virtual void visit_int16 (int16_t value);
        virtual void visit_int8(int8_t value);
        virtual void visit_uint64(uint64_t value);
        virtual void visit_uint32(uint32_t value);
        virtual void visit_uint16(uint16_t value);
        virtual void visit_uint8(uint8_t value);
        virtual void visit_float64(double value);
        virtual void visit_bytes(const const_byte_span& value);
        virtual void visit_boolean(bool value);

        virtual void visit_array(optional<size_t> size_hint);
        virtual void visit_end_array();

        virtual void visit_object(optional<size_t> size_hint);
        virtual void visit_key(const const_byte_span& value);
        virtual void visit_end_object();
    }; // struct BasicVisitor

    template <typename Value>
    class RefVisitor: public BasicVisitor
    {
    public:

        RefVisitor(Value& value_ref): m_value_ref(value_ref), m_was_visited(false) {}
        virtual ~RefVisitor() = default;

        bool was_visited() const { return m_was_visited; }

        void visit_end_array() override final {}
        void visit_end_object() override final {}

    protected:

        void visit(Value&& value) { m_value_ref = value; m_was_visited = true; }
    
    private:

        Value& m_value_ref;
        bool m_was_visited;
    }; // class GetSetVisitor
} // namespace serde::model
