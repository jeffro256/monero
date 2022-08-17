#pragma once

#include "../internal/external/logging.h"

namespace serde::model
{
    template <typename Value>
    GetSetVisitor<Value>::GetSetVisitor(): m_value() {}

    template <typename Value>
    GetSetVisitor<Value>::~GetSetVisitor() {}

    template <typename Value>
    optional<Value> GetSetVisitor<Value>::get_visited()
    {
        return std::move(m_value);
    }

    template <typename Value>
    bool GetSetVisitor<Value>::was_visited() const
    {
        return m_value;
    }
    
    template <typename Value>
    void GetSetVisitor<Value>::set_visited(Value&& new_val)
    {
        m_value = new_val;
    }
}