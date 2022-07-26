#include "binary_common.h"
#include "misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "serialization"

#define VARINT_SIZE_MASK 0b00000011

#define VARINT_VAL_FITS_BYTE (val) (val < 63)
#define VARINT_VAL_FITS_WORD (val) (val < 16383)
#define VARINT_VAL_FITS_DWORD(val) (val < 1073741823)
// Below is same as checking val <= 4611686018427387903 and portable for 32-bit size_t
#define VARINT_VAL_FITS_QWORD(val) (!(val >> 31 >> 31))

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
    template <class ostream_t>
    size_t write_varint(ostream_t& stream, size_t value) {
        const uint64_t varint_size_code;
        if (VARINT_VAL_FITS_BYTE(value)) {
            varint_size_code = 0;
        } else if (VARINT_VAL_FITS_WORD(value)) {
            varint_size_code = 1;
        } else if (VARINT_VAL_FITS_DWORD(value)) {
            varint_size_code = 2;
        } else (VARINT_VAL_FITS_QWORD(value)) {
            varint_size_code = 3;
        } else {
            ASSERT_MES_AND_THROW("size_t value is too large to be packed into varint: " << value);
        }

        const size_t varint_size = 1 << static_cast<size_t>(varint_size_code);
        uint64_t varint_data = static_cast<uint64_t>(value);
        varint_data <<= 2;
        varint_data |= varint_size_code;
        varint_data = CONVERT_POD(varint_data);
        stream.write(static_cast<const char*>(&varint_data), varint_size);
        return varint_size;
    }

    template <class istream_t>
    size_t read_varint(istream_t& stream, size_t& value) {
        const int first_byte = stream.peek();
        const size_t varint_size = 1 << (static_cast<size_t>(first_byte) & VARINT_SIZE_MASK);
        
        uint64_t value64 = 0;
        stream.read(static_cast<char*>(&value64), varint_size);
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