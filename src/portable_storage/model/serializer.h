#pragma once

#include <string>

namespace portable_storage::model {
    ///////////////////////////////////////////////////////////////////////////
    // Serializer declaration                                                //
    ///////////////////////////////////////////////////////////////////////////

    struct Serializer
    {
        virtual ~Serializer()                           = 0;

        virtual void int64  (int64_t)                   = 0;
        virtual void int32  (int32_t)                   = 0;
        virtual void int16  (int16_t)                   = 0;
        virtual void int8   (int8_t)                    = 0;
        virtual void uint64 (uint64_t)                  = 0;
        virtual void uint32 (uint32_t)                  = 0;
        virtual void uint16 (uint16_t)                  = 0;
        virtual void uint8  (uint8_t)                   = 0;
        virtual void float64(double)                    = 0;
        virtual void string (const std::string&)        = 0;
        virtual void boolean(bool)                      = 0;

        virtual void start_array(size_t)                = 0;
        virtual void end_array()                        = 0;

        virtual void start_object(size_t)               = 0;
        virtual void key(const char*, uint8_t)          = 0;
        virtual void end_object()                       = 0;

        virtual bool is_human_readable() const noexcept = 0;
    };
} // namespace portable_storage::binary

