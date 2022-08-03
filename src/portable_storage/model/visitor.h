#pragma once

#include <string>

#include "../internal/external_libs.h"

namespace portable_storage::model {
    class Deserializer;

    struct Visitor {
        Visitor() = default;
        virtual ~Visitor() {};

        virtual void visit_int64(int64_t value) {
            return this->visit_float64(value);
        }

        virtual void visit_int32(int32_t value) {
            return this->visit_int64(value);
        }

        virtual void visit_int16 (int16_t value) {
            return this->visit_int32(value);
        }

        virtual void visit_int8(int8_t value) {
            return this->visit_int16(value);
        }

        virtual void visit_uint64(uint64_t value) {
            return this->visit_float64(value);
        }

        virtual void visit_uint32(uint32_t value) {
            return this->visit_uint64(value);
        }

        virtual void visit_uint16(uint16_t value) {
            return this->visit_uint32(value);
        }

        virtual void visit_uint8(uint8_t value) {
            return this->visit_uint16(value);
        }

        virtual void visit_float64(double value) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_double()");
        }

        virtual void visit_bytes(const char* buf, size_t length) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_bytes()");
        }

        virtual void visit_string(const std::string& value) {
            this->visit_bytes(value.c_str(), value.length());
        }

        virtual void visit_boolean(bool value) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_bool()");
        }

        virtual void visit_array(optional<size_t> size_hint, Deserializer& deserializer) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_array()");
        }

        virtual void visit_object(optional<size_t> size_hint, Deserializer& deserializer) {
            ASSERT_MES_AND_THROW("unexpected visit in visit_object()");
        }
    }; // class Visitor
} // namespace portable_storage::model
