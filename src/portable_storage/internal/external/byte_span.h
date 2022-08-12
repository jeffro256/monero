#pragma once

#include <string>

#include "span.h" // from epee

#define TO_CSTR(p) reinterpret_cast<const char*>(p)
#define SPAN_TO_CSTR(span) reinterpret_cast<const char*>(span.begin())

namespace portable_storage
{
    using byte_iterator = std::uint8_t*;
    using const_byte_iterator = const std::uint8_t*;
    // A Non-owning byte sequence for which .begin() and .end() return byte_iterator, .cbegin() and
    // .cend() return const_byte_iterator, and there is a constructor (byte_iterator src, size_t n)
    using byte_span = epee::span<std::uint8_t>;
    using const_byte_span = epee::span<const std::uint8_t>;
} // namespace portable_storage

namespace portable_storage::internal
{
    // make a byte_span from a std::string, same idea as epee::strspan
    template<typename U> inline
    const_byte_span string_to_byte_span(const U& s) noexcept
    {
        static_assert(std::is_same<typename U::value_type, char>(), "unexpected source type");
        return {reinterpret_cast<const_byte_iterator>(s.data()), s.size()};
    }

    // DOESN'T INCLUDE NULL TERMINATOR
    template <std::size_t N> inline
    const_byte_span cstr_to_byte_span(const char (&cstr)[N])
    {
        return {reinterpret_cast<const uint8_t*>(cstr), N - 1};
    }

    std::string byte_span_to_string(const const_byte_span& bytes);
} // namespace portable_storage::internal
