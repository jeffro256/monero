#pragma once

#include "binary_common.h"

namespace portable_storage::binary {
    template <class ostream_t>
    size_t write_varint(ostream_t& stream, size_t value);

    template <class istream_t>
    size_t read_varint(istream_t& stream, size_t& value);
}
