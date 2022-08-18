#pragma once

#include <string>

#include "../internal/deps.h"

namespace serde::model
{
    struct Serializer
    {
        Serializer() = default;
        virtual ~Serializer() {};

        virtual void serialize_int64  (int64_t)                   = 0;
        virtual void serialize_int32  (int32_t)                   = 0;
        virtual void serialize_int16  (int16_t)                   = 0;
        virtual void serialize_int8   (int8_t)                    = 0;
        virtual void serialize_uint64 (uint64_t)                  = 0;
        virtual void serialize_uint32 (uint32_t)                  = 0;
        virtual void serialize_uint16 (uint16_t)                  = 0;
        virtual void serialize_uint8  (uint8_t)                   = 0;
        virtual void serialize_float64(double)                    = 0;
        virtual void serialize_bytes  (const const_byte_span&)    = 0;
        // serialize_string() defers to serialize_bytes(), for convenience
        virtual void serialize_string (const std::string&)           ;
        virtual void serialize_boolean(bool)                      = 0;

        virtual void serialize_start_array(size_t)                = 0;
        virtual void serialize_end_array()                        = 0;

        virtual void serialize_start_object(size_t)               = 0;
        virtual void serialize_key(const const_byte_span&)        = 0;
        virtual void serialize_end_object()                       = 0;

        virtual bool is_human_readable() const noexcept = 0;
    };
} // namespace serde::binary

