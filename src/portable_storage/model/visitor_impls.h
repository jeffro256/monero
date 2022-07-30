#pragma once

#include <sstream>
#include <string>

namespace portable_storage::model {
    // forward declaration of Visitor
    template <class Value>
    class Visitor;

    ///////////////////////////////////////////////////////////////////////////
    // Number visitor definitions                                            //
    ///////////////////////////////////////////////////////////////////////////

    #define DEF_NUM_VISITOR(numtype)                                                             \
        template<>                                                                               \
        struct Visitor<numtype> {                                                                \
            numtype visit_int64 (int64_t  value) { return static_cast<numtype>(value); } \
            numtype visit_int32 (int32_t  value) { return static_cast<numtype>(value); } \
            numtype visit_int16 (int16_t  value) { return static_cast<numtype>(value); } \
            numtype visit_int8  (int8_t   value) { return static_cast<numtype>(value); } \
            numtype visit_uint64(uint64_t value) { return static_cast<numtype>(value); } \
            numtype visit_uint32(uint32_t value) { return static_cast<numtype>(value); } \
            numtype visit_uint16(uint16_t value) { return static_cast<numtype>(value); } \
            numtype visit_uint8 (uint8_t  value) { return static_cast<numtype>(value); } \
            numtype visit_double(double   value) { return static_cast<numtype>(value); } \
            numtype visit_bool  (bool     value) { return value ? 1 : 0; }               \
            numtype visit_string(const std::string& value) {                             \
                std::stringstream ss(value); numtype val; ss >> val; return val;                 \
            }                                                                                    \
        };                                                                                       \

    DEF_NUM_VISITOR(int64_t)
    DEF_NUM_VISITOR(int32_t)
    DEF_NUM_VISITOR(int16_t)
    DEF_NUM_VISITOR(int8_t)
    DEF_NUM_VISITOR(uint64_t)
    DEF_NUM_VISITOR(uint32_t)
    DEF_NUM_VISITOR(uint16_t)
    DEF_NUM_VISITOR(uint8_t)
    DEF_NUM_VISITOR(double)
    DEF_NUM_VISITOR(float)

    ///////////////////////////////////////////////////////////////////////////
    // JsonObjectSerializer declaration                                      //
    ///////////////////////////////////////////////////////////////////////////

} // namespace portable_storage::model