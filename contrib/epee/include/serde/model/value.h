#pragma once

#include <map>
#include <vector>

#include "constants.h"
#include "deserializer.h"
#include "../internal/deps.h"
#include "../internal/enable_if.h"

namespace serde::model
{
    struct ArrayValue;
    struct ObjectValue;

    typedef boost::variant<
        int64_t, int32_t, int16_t, int8_t,
        uint64_t, uint32_t, uint16_t, uint8_t,
        double, std::string, bool,
        boost::recursive_wrapper< ArrayValue >,
        boost::recursive_wrapper< ObjectValue > 
    > t_value_base;

    class ValueLimits
    {
    public:

        ValueLimits(size_t max_depth, size_t max_width):
            m_max_depth(max_depth), m_max_width(max_width)
        {}

        ValueLimits(): ValueLimits(PS_MAX_OBJECT_DEPTH, PS_MAX_ARRAY_LENGTH) {}

        ValueLimits(const ValueLimits& other):
            m_max_depth(other.m_max_depth), m_max_width(other.m_max_width)
        {}

        ValueLimits child() const
        {
            return { m_max_depth - 1, m_max_width };
        }

    protected:

        size_t m_max_depth;
        size_t m_max_width;
    };

    struct Value: public t_value_base, public ValueLimits
    {
    };

    struct ArrayValue: public std::vector<Value>, public ValueLimits
    {

    };

    struct ObjectValue: public std::map<std::string, Value>, public ValueLimits
    {

    };

    struct ValueIterator: public SelfDescribingDeserializer
    {
        void deserialize_any(BasicVisitor& visitor);
    };

    bool deserialize_default(Deserializer& deserializer, ArrayValue& value);
    bool deserialize_default(Deserializer& deserializer, ObjectValue& value);
} // namespace serde::model
