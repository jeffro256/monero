#pragma once

#include <string>
#include <list>

#include "../internal/external/byte_span.h"
#include "../internal/external/optional.h"
#include "../internal/model_fwd.h"

namespace portable_storage::model
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

        virtual void visit_array(optional<size_t> size_hint, Deserializer& deserializer);

        virtual void visit_object(optional<size_t> size_hint, Deserializer& deserializer);
        virtual void visit_key(const const_byte_span& value);
    }; // struct BasicVisitor

    template <typename Value>
    class GetSetVisitor: public BasicVisitor
    {
    public:

        GetSetVisitor();
        virtual ~GetSetVisitor();

        Value get_visited();
    
    protected:

        void set_visited(Value&& v);
    
    private:

        Value m_val;
        bool m_set;
        bool m_get;
    }; // class GetSetVisitor
} // namespace portable_storage::model

#include "visitor.inl"
