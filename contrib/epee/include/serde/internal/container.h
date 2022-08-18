// Copyright (c) 2022, The Monero Project
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

#include <cstddef>
#include <tuple>
#include <vector>

namespace serde::internal {
    template <class Container> inline
    void container_reserve(Container& container, size_t new_capacity) {
        // by default, do nothing
    }

    template<typename T> inline
    void container_reserve(std::vector<T>& vec, size_t new_capacity) {
        vec.reserve(new_capacity);
    }

    #define _ENABLE_CMP_INDEX(op) typename std::enable_if<I op std::tuple_size<Tuple>::value>::type

    template <class Tuple, class Functor, size_t I = 0> _ENABLE_CMP_INDEX(<) // returns void
    tuple_for_each(Tuple& tup, Functor& f)
    {
        const bool should_continue = f(std::get<I>(tup));
        if (should_continue) tuple_for_each<Tuple, Functor, I + 1>(tup, f);
    }

    template <class Tuple, class Functor, size_t I = 0> _ENABLE_CMP_INDEX(>=) // returns void
    tuple_for_each(Tuple& tup, Functor& f)
    {}
}
