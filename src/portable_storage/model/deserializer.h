#pragma once

namespace portable_storage::model {
    // fwd
    template <typename Value, class Deserializer> class Visitor;

    struct Deserializer
    {
        Deserializer();
        virtual ~Deserializer();

        // Deserializer interface
        /*
        template <typename Value>
        using Visitor = model::Visitor<Value, Deserializer>;

        template <typename Value> Value deserialize_any(Visitor<Value, Deserializer>&);

        template <typename Value> Value deserialize_int64  (Visitor<Value>&) { UNIMPL_DESER }
        template <typename Value> Value deserialize_int32  (Visitor<Value>&) { UNIMPL_DESER }
        template <typename Value> Value deserialize_int16  (Visitor<Value>&) { UNIMPL_DESER }
        template <typename Value> Value deserialize_int8   (Visitor<Value>&) { UNIMPL_DESER }
        template <typename Value> Value deserialize_uint64 (Visitor<Value>&) { UNIMPL_DESER }
        template <typename Value> Value deserialize_uint32 (Visitor<Value>&) { UNIMPL_DESER }
        template <typename Value> Value deserialize_uint16 (Visitor<Value>&) { UNIMPL_DESER }
        template <typename Value> Value deserialize_uint8  (Visitor<Value>&) { UNIMPL_DESER }
        template <typename Value> Value deserialize_float64(Visitor<Value>&) { UNIMPL_DESER }
        template <typename Value> Value deserialize_bytes  (Visitor<Value>&) { UNIMPL_DESER }
        template <typename Value> Value deserialize_boolean(Visitor<Value>&) { UNIMPL_DESER }

        template <typename Value> Value deserialize_array(optional<size_t>, Visitor<Value>&)
        { UNIMPL_DESER }

        template <typename Value> Value deserialize_object(optional<size_t>, Visitor<Value>&)
        { UNIMPL_DESER }
        template <typename Value> Value deserialize_key(Visitor<Value>&) { UNIMPL_DESER }
        */

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
} // namespace portable_storage::binary

