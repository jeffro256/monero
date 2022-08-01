#pragma once

#include <boost/numeric/conversion/cast.hpp>
#include <string>

#include "misc_log_ex.h"

namespace portable_storage::model {
    template <class Value>
    struct Visitor {
        Visitor() = default;
        virtual ~Visitor() {};

        virtual Value int64(int64_t value) {
            return this->visit_double(value);
        }

        virtual Value int32(int32_t value) {
            return this->visit_int64(value);
        }

        virtual Value int16 (int16_t value) {
            return this->visit_int32(value);
        }

        virtual Value int8(int8_t value) {
            return this->visit_int16(value);
        }

        virtual Value uint64(uint64_t value) {
            return this->visit_double(value);
        }

        virtual Value uint32(uint32_t value) {
            return this->visit_uint64(value);
        }

        virtual Value uint16(uint16_t value) {
            return this->visit_uint32(value);
        }

        virtual Value uint8(uint8_t value) {
            return this->visit_uint16(value);
        }

        virtual Value float64(double value) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_double()");
        }

        virtual Value bytes(const char* buf, size_t length) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_bytes()");
        }

        virtual Value string(const std::string& value) {
            this->visit_bytes(value.c_str(), value.length());
        }

        virtual Value boolean(bool value) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_bool()");
        }

        virtual Value array(Serializer& serializer) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_array()");
        }

        virtual Value object(Serializer& serializer) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_object()");
        }
    }; // class Visitor
} // namespace portable_storage::model

#include "../internal/visitor_specializations.h"
