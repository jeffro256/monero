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

        virtual void deserialize_object(optional<size_t>, BasicVisitor&) = 0;
        virtual void deserialize_key(BasicVisitor&) = 0;

        // This method is used by Visitors, not Deserializables. It signals to the Deserializer
        // that the Visitor wants to move to the next element / entry and lets the Visitor know
        // when to stop. Visitors should call this once each time before deserializing an
        // element/entry and once after the array/object is finished, at which point the return
        // value should be false.
        // Returns true if there element/entries left to deserialize, false if there is not
        // Once false is returned, it can be assumed that the Visitor knows the array/object is
        // over and the Deserializer can go up one level in recursion. This method is not
        // idempotent.
        virtual bool continue_collection() = 0;

        virtual bool is_human_readable() const noexcept = 0;
    };
} // namespace serde::binary

