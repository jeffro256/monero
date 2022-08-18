#include "serde/internal/deps.h"

namespace serde::internal
{
    const_byte_span string_to_byte_span(const std::string& s) noexcept
    {
        return {reinterpret_cast<const_byte_iterator>(s.data()), s.size()};
    }

    std::string byte_span_to_string(const const_byte_span& bytes)
    {
        return std::string(SPAN_TO_CSTR(bytes), bytes.size());
    }
}
