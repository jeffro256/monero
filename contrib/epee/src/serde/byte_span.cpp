#include "serde/internal/external/byte_span.h"

namespace portable_storage::internal
{
    std::string byte_span_to_string(const const_byte_span& bytes)
    {
        return std::string(SPAN_TO_CSTR(bytes), bytes.size());
    }
}
