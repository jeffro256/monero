#include <cstddef>
#include <cstdint>
#include <limits>

namespace serde::binary
{
    constexpr bool uint64_fits_size(uint64_t v)
    {
        constexpr uintmax_t size_max   = static_cast<uintmax_t>(std::numeric_limits<  size_t>::max());
        constexpr uintmax_t uint64_max = static_cast<uintmax_t>(std::numeric_limits<uint64_t>::max());

        if (size_max >= uint64_max)
        {
            return true;
        }

        const uintmax_t value = static_cast<uintmax_t>(v);
        return value <= uint64_max;
    }
}