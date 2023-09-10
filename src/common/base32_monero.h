// Copyright (c) 2023, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/**
 *  Copyright (C) 2015 Topology LP
 *  All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 *  IN THE SOFTWARE.
 */

/**
 * @brief: cppcodec class for Jamtis-style base32
 *
 * adapted from https://github.com/tplgy/cppcodec/blob/master/cppcodec/base32_crockford.hpp.
 * differences:
 *  * prepended monero repo lisence
 *  * name CPPCODEC_BASE32_CROCKFORD -> CPPCODEC_BASE32_MONERO
 *  * name base32_crockford_base -> base32_monero_base
 *  * name base32_crockford -> base32_monero
 *  * name base32_crockford_alphabet -> base32_monero_alphabet
 *  * base32_monero_alphabet contains updated alphabet (see spec below)
 *  * base32_monero_base::normalized_symbol doesn't normalize 'i'/'I' to '1'
 *  * base32_monero_base::normalized_symbol now normalizes 'z'/'Z' to '2'
 *  * base32_monero_base::normalized_symbol now normalizes 'v'/'V' to 'u'
 *  * base32_monero_base::normalized_symbol now normalizes 'l'/'L' to 'i', not '1'
 *  * base32_monero_base::normalized_symbol now normalizes from uppercase to lowercase, not vice versa
 *  * this comment ;)
 *
 * see API usage documentation here: https://github.com/tplgy/cppcodec#api-1
 * see encoding scheme spec here: https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024#35-base32-encoding
*/

#ifndef CPPCODEC_BASE32_MONERO
#define CPPCODEC_BASE32_MONERO

#include "cppcodec/detail/codec.hpp"
#include "cppcodec/detail/base32.hpp"

namespace cppcodec {

namespace detail {

static constexpr const char base32_monero_alphabet[32] = {
    'x', 'm', 'r', 'b', 'a', 's', 'e', '3',
    '2', 'c', 'd', 'f', 'g', 'h', 'i', 'j',
    'k', 'n', 'p', 'q', 't', 'u', 'w', 'y',
    '0', '1', '4', '5', '6', '7', '8', '9'
};

class base32_monero_base
{
public:
    static CPPCODEC_ALWAYS_INLINE constexpr size_t alphabet_size() {
        static_assert(sizeof(base32_monero_alphabet) == 32, "base32 alphabet must have 32 values");
        return sizeof(base32_monero_alphabet);
    }
    static CPPCODEC_ALWAYS_INLINE constexpr char symbol(alphabet_index_t idx)
    {
        return base32_monero_alphabet[idx];
    }
    static CPPCODEC_ALWAYS_INLINE constexpr char normalized_symbol(char c)
    {
        // Hex decoding is always case-insensitive (even in RFC 4648), the question
        // is only for encoding whether to use upper-case or lower-case letters.
        return (c == 'O' || c == 'o') ? '0'
            : (c == 'L' || c == 'l') ? 'i'
            : (c == 'Z' || c == 'z') ? '2'
            : (c == 'V' || c == 'v') ? 'u'
            : (c >= 'A' && c <= 'Y') ? (c + ('a' - 'A'))
            : c;
    }

    static CPPCODEC_ALWAYS_INLINE constexpr bool generates_padding() { return false; }
    static CPPCODEC_ALWAYS_INLINE constexpr bool requires_padding() { return false; }
    static CPPCODEC_ALWAYS_INLINE constexpr bool is_padding_symbol(char) { return false; }
    static CPPCODEC_ALWAYS_INLINE constexpr bool is_eof_symbol(char c) { return c == '\0'; }

    static CPPCODEC_ALWAYS_INLINE constexpr bool should_ignore(char c) {
        return c == '-'; // "Hyphens (-) can be inserted into strings [for readability]."
    }
};

class base32_monero : public base32_monero_base
{
public:
    template <typename Codec> using codec_impl = stream_codec<Codec, base32_monero>;
};

} // namespace detail

using base32_monero = detail::codec<detail::base32<detail::base32_monero>>;

} // namespace cppcodec

#endif // CPPCODEC_BASE32_MONERO
