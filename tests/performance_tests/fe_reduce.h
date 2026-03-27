// Copyright (c) 2026, The Monero Project
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

#pragma once

#include <cassert>
#include <cstddef>

extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/crypto.h"

namespace 
{
static inline void fe_reduce_simple(fe reduced, const fe f)
{
    unsigned char f_bytes[32];
    fe_tobytes(f_bytes, f);
    const int r = fe_frombytes_vartime(reduced, f_bytes);
    (void) r;
    assert(0 == r);
}
} //anonymous namespace

template <bool fast_fe_reduce>
class test_fe_reduce
{
public:
  static const size_t loop_count = 10000;
  static const size_t subloop_count = 10000;

  bool init()
  {
    // generate random fe
    for (int i = 0; i < 10; ++i)
    {
        const int32_t limit = ((i & 1) ? (1 << 25) : (1 << 26)) * 11 / 10;
        this->a[i] = crypto::rand_range(-limit, limit);
    }

    return true;
  }

  bool test()
  {
    fe res;

    for (size_t i = 0; i < subloop_count; ++i)
    {
        if constexpr (fast_fe_reduce)
        {
            fe_reduce(res, this->a);
        }
        else
        {
            fe_reduce_simple(res, this->a);
        }
    }

    return true;
  }

protected:
  fe a;
};
