#pragma once

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
