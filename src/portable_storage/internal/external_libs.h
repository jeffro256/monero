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

namespace portable_storage {
#if __cplusplus >= 201730 // if compiler's standard >= c++17
    template <typename T>
    using optional = std::optional<T>;
#else
    template <typename T>
    using optional = boost::optional<T>;
#endif

    template <typename Target, typename Source>
    using safe_numeric_cast = boost::mpl::numeric_cast<Target, Source>;
}
