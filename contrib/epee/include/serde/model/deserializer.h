#pragma once

#include "../internal/external/optional.h"
#include "../internal/model_fwd.h"

namespace serde::model {
    struct Deserializer
    {
        Deserializer();
        virtual ~Deserializer();

        virtual void deserialize_any(BasicVisitor&) = 0;

        virtual void deserialize_int64  (BasicVisitor&) = 0;
        virtual void deserialize_int32  (BasicVisitor&) = 0;
        virtual void deserialize_int16  (BasicVisitor&) = 0;
        virtual void deserialize_int8   (BasicVisitor&) = 0;
        virtual void deserialize_uint64 (BasicVisitor&) = 0;
        virtual void deserialize_uint32 (BasicVisitor&) = 0;
        virtual void deserialize_uint16 (BasicVisitor&) = 0;
        virtual void deserialize_uint8  (BasicVisitor&) = 0;
        virtual void deserialize_float64(BasicVisitor&) = 0;
        virtual void deserialize_bytes  (BasicVisitor&) = 0;
        virtual void deserialize_boolean(BasicVisitor&) = 0;

        virtual void deserialize_array(optional<size_t>, BasicVisitor&) = 0;
        virtual void deserialize_end_array(BasicVisitor&) = 0;

        virtual void deserialize_object(optional<size_t>, BasicVisitor&) = 0;
        virtual void deserialize_key(BasicVisitor&) = 0;
        virtual void deserialize_end_object(BasicVisitor&) = 0;

        virtual bool is_human_readable() const noexcept = 0;
    };
} // namespace serde::binary

