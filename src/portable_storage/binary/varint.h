#include "constants.h"
#include "misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "serialization"

#define VARINT_SIZE_MASK 0b00000011

namespace {
    constexpr bool uint64_fits_size(uint64_t v) {
        constexpr uintmax_t size_max   = static_cast<uintmax_t>(std::numeric_limits<  size_t>::max());
        constexpr uintmax_t uint64_max = static_cast<uintmax_t>(std::numeric_limits<uint64_t>::max());

        if (size_max >= uint64_max) {
            return true;
        }

        const uintmax_t value = static_cast<uintmax_t>(v);
        return value <= uint64_max;
    }
}

namespace portable_storage::binary {
    template <class istream_t>
    size_t read_varint(istream_t& stream, size_t& value) {
        const int first_byte = stream.peek();
        const size_t varint_size = 1 << (static_cast<size_t>(first_byte) & VARINT_SIZE_MASK);

        uint64_t value64 = 0;
        stream.read(reinterpret_cast<char*>(&value64), varint_size);
        value64 = CONVERT_POD(value64);
        value64 >>= 2;

        CHECK_AND_ASSERT_THROW_MES( // this should compile to nothing on most 64-bit systems
            uint64_fits_size(value64),
            "varint decoded from stream is too big for size_t: " << value64
        );

        value = static_cast<size_t>(value64);
        return varint_size;
    }
}