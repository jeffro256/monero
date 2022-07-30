#pragma once

#include <string>

#include "misc_log_ex.h"
#include "visitor_impls.h"

namespace portable_storage::model {
    template <class Value>
    struct Visitor {
        Visitor() = default;
        virtual ~Visitor() {};

        virtual Value visit_int64(int64_t value) {
            return this->visit_double(value);   
        }

        virtual Value visit_int32(int32_t value) {
            return this->visit_int64(value);
        }

        virtual Value visit_int16 (int16_t value) {
            return this->visit_int32(value);
        }

        virtual Value visit_int8(int8_t value) {
            return this->visit_int16(value);
        }

        virtual Value visit_uint64(uint64_t value) {
            return this->visit_double(value);
        }

        virtual Value visit_uint32(uint32_t value) {
            return this->visit_uint64(value);
        }

        virtual Value visit_uint16(uint16_t value) {
            return this->visit_uint32(value);
        }

        virtual Value visit_uint8(uint8_t value) {
            return this->visit_uint16(value);
        }

        virtual Value visit_double(double value) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_double()");
        }

        virtual Value visit_bytes(const char* buf, size_t length) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_bytes()");   
        }

        virtual Value visit_string(const std::string& value) {
            this->visit_bytes(value.c_str(), value.length());
        }

        virtual Value visit_bool(bool value) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_bool()");
        }

        virtual Value visit_object(Serializer& serializer) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_object()");
        }

        virtual Value visit_array(Serializer& serializer) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_array()");
        }
    }; // class Visitor
} // namespace portable_storage::model
