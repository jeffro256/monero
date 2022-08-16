#include "serde/model/deserialization.h"
#include "serde/model/deserializer.h"
#include "serde/model/visitor_specializations.h"

namespace portable_storage::model
{
    #define DEF_DEFAULT_DESERIALIZE_NUM_SPECIALIZATION(tyname, mname)            \
        template <> tyname Deserialize<tyname>::dflt(Deserializer& deserializer) \
        {                                                                        \
            internal::NumericVisitor<tyname> visitor;                            \
            deserializer.deserialize_##mname(visitor);                           \
            return visitor.get_visited();                                        \
        }                                                                        \
    
    DEF_DEFAULT_DESERIALIZE_NUM_SPECIALIZATION(int64_t, int64)
    DEF_DEFAULT_DESERIALIZE_NUM_SPECIALIZATION(int32_t, int32)
    DEF_DEFAULT_DESERIALIZE_NUM_SPECIALIZATION(int16_t, int16)
    DEF_DEFAULT_DESERIALIZE_NUM_SPECIALIZATION(int8_t, int8)
    DEF_DEFAULT_DESERIALIZE_NUM_SPECIALIZATION(uint64_t, uint64)
    DEF_DEFAULT_DESERIALIZE_NUM_SPECIALIZATION(uint32_t, uint32)
    DEF_DEFAULT_DESERIALIZE_NUM_SPECIALIZATION(uint16_t, uint16)
    DEF_DEFAULT_DESERIALIZE_NUM_SPECIALIZATION(uint8_t, uint8)
    DEF_DEFAULT_DESERIALIZE_NUM_SPECIALIZATION(double, float64)
    DEF_DEFAULT_DESERIALIZE_NUM_SPECIALIZATION(bool, boolean)

    template <> std::string Deserialize<std::string>::dflt(Deserializer& deserializer)
    {
        internal::StringVisitor visitor;
        deserializer.deserialize_bytes(visitor);
        return visitor.get_visited();
    }

    ///////////////////////////////////////////////////////////////////////////
    // Deserialize::blob() basic specializations                             //
    ///////////////////////////////////////////////////////////////////////////

    template <> std::string Deserialize<std::string>::blob(Deserializer& deserializer)
    {
        internal::BlobStringVisitor blob_string_visitor;
        deserializer.deserialize_bytes(blob_string_visitor);
        return blob_string_visitor.get_visited();
    }
}
