#include "serde/model/visitor.h"

#include "serde/internal/external/logging.h"

namespace serde::model
{
    BasicVisitor::BasicVisitor() {}
    BasicVisitor::~BasicVisitor() {}

    #define DEF_BASIC_VISITOR_FALLBACK_METHOD(tyname, mname)                        \
        void BasicVisitor::visit_##mname(tyname)                                    \
        {                                                                           \
            ASSERT_MES_AND_THROW                                                    \
            (                                                                       \
                "called visit_" #mname "() but was expecting " << this->expecting() \
            );                                                                      \
        }                                                                           \
    
    DEF_BASIC_VISITOR_FALLBACK_METHOD(int64_t, int64)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(int32_t, int32)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(int16_t, int16)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(int8_t, int8)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(uint64_t, uint64)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(uint32_t, uint32)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(uint16_t, uint16)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(uint8_t, uint8)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(double, float64)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(const const_byte_span&, bytes)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(bool, boolean)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(optional<size_t>, array)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(void, end_array)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(optional<size_t>, object)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(const const_byte_span&, key)
    DEF_BASIC_VISITOR_FALLBACK_METHOD(void, end_object)
} // namespace serde::model