#pragma once

#include <string>

#include "../internal/external_libs.h"
#include "visitor.h"

namespace portable_storage::model {
    struct Deserializer
    {
        Deserializer() = default;
        virtual ~Deserializer() = default;

        virtual void deserialize_any(Visitor&) = 0;

        virtual void deserialize_int64  (Visitor&)                  = 0;
        virtual void deserialize_int32  (Visitor&)                  = 0;
        virtual void deserialize_int16  (Visitor&)                  = 0;
        virtual void deserialize_int8   (Visitor&)                  = 0;
        virtual void deserialize_uint64 (Visitor&)                  = 0;
        virtual void deserialize_uint32 (Visitor&)                  = 0;
        virtual void deserialize_uint16 (Visitor&)                  = 0;
        virtual void deserialize_uint8  (Visitor&)                  = 0;
        virtual void deserialize_float64(Visitor&)                  = 0;
        virtual void deserialize_bytes  (Visitor&)                  = 0;
        // deserialize_string() defers to deserialize_bytes(), for convenience
        virtual void deserialize_string (Visitor&)                     ;
        virtual void deserialize_boolean(Visitor&)                  = 0;

        virtual void deserialize_array(optional<size_t>, Visitor&)  = 0;
        // array_has_next() is used by visitors, not by Deserializables
        virtual bool array_has_next()                               = 0;

        virtual void deserialize_object(optional<size_t>, Visitor&) = 0;
        virtual void deserialize_key(Visitor&)                      = 0;
        // array_has_next() is used by visitors, not by Deserializables
        virtual bool object_has_next()                              = 0;

        virtual bool is_human_readable() const noexcept             = 0;
    };
} // namespace portable_storage::binary

