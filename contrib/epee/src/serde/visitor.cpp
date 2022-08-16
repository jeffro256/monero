#include "serde/model/visitor.h"

#include "serde/internal/external/logging.h"

namespace portable_storage::model
{
    BasicVisitor::BasicVisitor() {}
    BasicVisitor::~BasicVisitor() {}

    #define DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(tyname, mname)                 \
        void BasicVisitor::visit_##mname(tyname value)                              \
        {                                                                           \
            ASSERT_MES_AND_THROW                                                    \
            (                                                                       \
                "called visit_" #mname "() but was expecting " << this->expecting() \
            );                                                                      \
        }                                                                           \
    
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(int64_t, int64)
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(int32_t, int32)
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(int16_t, int16)
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(int8_t, int8)
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(uint64_t, uint64)
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(uint32_t, uint32)
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(uint16_t, uint16)
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(uint8_t, uint8)
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(double, float64)
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(const const_byte_span&, bytes)
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(bool, boolean)
    DEF_BASIC_VISITOR_FALLBACK_METHOD_SIMPLE(const const_byte_span&, key)

    void BasicVisitor::visit_array(optional<size_t>, Deserializer&)
    {
        ASSERT_MES_AND_THROW("called visit_array() but was expecting " << this->expecting());
    }

    void BasicVisitor::visit_object(optional<size_t>, Deserializer&)
    {
        ASSERT_MES_AND_THROW("called visit_object() but was expecting " << this->expecting());
    }
} // namespace portable_storage::model