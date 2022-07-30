#include "misc_log_ex.h"

namespace portable_storage::model {
    template <typename T>
    struct BlobVisitor: public Visitor<T> {
        T visit_bytes(const char* buf, size_t length) {
            CHECK_AND_ASSERT_THROW_MES(
                length == sizeof(T),
                "BlobVisitor got blob of length " << length << " for type of size " << sizeof(T)
            );
        }
    };

    template <typename T>
    struct BlobWrapper {
        T& m_val;

        void epee_serialize(Serializer& serializer) const {
            serializer.bytes(reinterpret_cast<const char*>(&m_val), sizeof(T));
        }

        static void
    };

    template <
}