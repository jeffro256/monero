#pragma once

#include "../internal/external/logging.h"

namespace serde::model
{
    template <typename Value>
    GetSetVisitor<Value>::GetSetVisitor(): m_val(), m_get(false), m_set(false) {}

    template <typename Value>
    GetSetVisitor<Value>::~GetSetVisitor() {}

    template <typename Value>
    Value GetSetVisitor<Value>::get_visited()
    {
        CHECK_AND_ASSERT_THROW_MES(m_set, "value in GetSetVisitor must be set before being got");
        CHECK_AND_ASSERT_THROW_MES(!m_get, "value in GetSetVisitor was already got");

        m_get = true;
        return std::move(m_val);
    }

    template <typename Value>
    void GetSetVisitor<Value>::set_visited(Value&& new_val)
    {
        CHECK_AND_ASSERT_THROW_MES(!m_set, "value in GetSetVisitor was already set");

        m_val = new_val;
        m_set = true;
    }
}