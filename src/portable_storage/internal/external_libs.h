#pragma once

#include <boost/mpl/numeric_cast.hpp>

#include "int-util.h"
#include "misc_log_ex.h"
#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "serialization"

// @TODO: drop boost optional support when project standard requirement is relaxed to c++17

#if __cplusplus >= 201730 // if compiler's standard >= c++17 
	#include <optional>
#else
	#include <boost/optional.hpp>
#endif

namespace portable_storage
{
#if __cplusplus >= 201730 // if compiler's standard >= c++17
    template <typename T>
    using optional = std::optional<T>;
#else
    template <typename T>
    using optional = boost::optional<T>;
#endif

    namespace internal
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
                return boost::mpl::numeric_cast<Target>(arg);
            }
            catch (const std::exception& e)
            {
                std::stringstream err_stream;
                err_stream << "Could not losslessly convert " << arg;
                throw safe_numeric_cast_exception(err_stream.str());
            }
        } // safe_numeric_cast
    } // namespace internal
} // namespace portable_storage
