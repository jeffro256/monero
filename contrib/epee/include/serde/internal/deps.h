#pragma once

///////////////////////////////////////////////////////////////////////////////
// const_byte_span, const_byte_iterator                                      //
///////////////////////////////////////////////////////////////////////////////

#include <string>

#include "span.h" // from epee

#define TO_CSTR(p) reinterpret_cast<const char*>(p)
#define SPAN_TO_CSTR(span) reinterpret_cast<const char*>(span.begin())

namespace serde
{
    // A Non-owning byte sequence for which .begin() and .end() return byte_iterator, .cbegin() and
    // .cend() return const_byte_iterator, and there is a constructor (byte_iterator src, size_t n)
    using const_byte_span = ::epee::span<const std::uint8_t>;
    using const_byte_iterator = const std::uint8_t*;
} // namespace serde

namespace serde::internal
{
    // make a byte_span from a std::string, same idea as epee::strspan
    const_byte_span string_to_byte_span(const std::string& s) noexcept;

    // DOESN'T INCLUDE NULL TERMINATOR
    template <std::size_t N> inline
    const_byte_span cstr_to_byte_span(const char (&cstr)[N])
    {
        return {reinterpret_cast<const uint8_t*>(cstr), N - 1};
    }

    std::string byte_span_to_string(const const_byte_span& bytes);
} // namespace serde::internal


///////////////////////////////////////////////////////////////////////////////
// SWAP64LE, SWAP32LE, BIG_ENDIAN, ...                                       //
///////////////////////////////////////////////////////////////////////////////

#include "int-util.h" // from epee

///////////////////////////////////////////////////////////////////////////////
// CHECK_AND_ASSERT_THROW_MES, ...                                           //
///////////////////////////////////////////////////////////////////////////////

#include "misc_log_ex.h" // from epee

///////////////////////////////////////////////////////////////////////////////
// safe_numeric_cast, safe_numeric_cast_exception                            //
///////////////////////////////////////////////////////////////////////////////

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "serialization"

#include <boost/numeric/conversion/cast.hpp>
#include <sstream>
#include <stdexcept>

namespace serde::internal
{
    // wrapper exception
    class safe_numeric_cast_exception: public std::runtime_error
    {
    public:

        safe_numeric_cast_exception(const std::string& what)
            : std::runtime_error(what)
        {}
    };
    
    // wrapper for boost::mpl::numeric_cast
    template <typename Target, typename Source> inline
    Target safe_numeric_cast(Source arg)
    {
        try
        {
            return boost::numeric_cast<Target>(arg);
        }
        catch (const std::exception& e)
        {
            std::stringstream err_stream;
            err_stream << "Could not losslessly convert " << arg;
            throw safe_numeric_cast_exception(err_stream.str());
        }
    } // safe_numeric_cast
}

///////////////////////////////////////////////////////////////////////////////
// optional                                                                  //
///////////////////////////////////////////////////////////////////////////////

// @TODO: drop boost optional support when project standard requirement is relaxed to c++17
#if __cplusplus >= 201730 // if compiler's standard >= c++17 
	#include <optional>
#else
	#include <boost/optional.hpp>
#endif

namespace serde
{
#if __cplusplus >= 201730 // if compiler's standard >= c++17
    template <typename T>
    using optional = std::optional<T>;
#else
    template <typename T>
    using optional = boost::optional<T>;
#endif
}