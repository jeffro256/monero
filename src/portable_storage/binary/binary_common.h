// Copyright (c) 2019-2022, The Monero Project
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

#include "int-util.h"

template<typename T> T convert_swapper(T t) { return t; }
template<> inline uint16_t convert_swapper(uint16_t t) { return SWAP16LE(t); }
template<> inline int16_t convert_swapper(int16_t t) { return SWAP16LE((uint16_t&)t); }
template<> inline uint32_t convert_swapper(uint32_t t) { return SWAP32LE(t); }
template<> inline int32_t convert_swapper(int32_t t) { return SWAP32LE((uint32_t&)t); }
template<> inline uint64_t convert_swapper(uint64_t t) { return SWAP64LE(t); }
template<> inline int64_t convert_swapper(int64_t t) { return SWAP64LE((uint64_t&)t); }
template<> inline double convert_swapper(double t) { union { uint64_t u; double d; } u; u.d = t; u.u = SWAP64LE(u.u); return u.d; }

#if BYTE_ORDER == BIG_ENDIAN
#define CONVERT_POD(x) convert_swapper(x)
#else
#define CONVERT_POD(x) (x)
#endif

#define SERIALIZE_TYPE_INT64                1
#define SERIALIZE_TYPE_INT32                2
#define SERIALIZE_TYPE_INT16                3
#define SERIALIZE_TYPE_INT8                 4
#define SERIALIZE_TYPE_UINT64               5
#define SERIALIZE_TYPE_UINT32               6
#define SERIALIZE_TYPE_UINT16               7
#define SERIALIZE_TYPE_UINT8                8
#define SERIALIZE_TYPE_DOUBLE               9
#define SERIALIZE_TYPE_STRING               10
#define SERIALIZE_TYPE_BOOL                 11
#define SERIALIZE_TYPE_OBJECT               12

#define SERIALIZE_FLAG_ARRAY              0x80

#define SERIALIZE_FLAG_ARRAY 0x80



struct SectionEntryType {
    enum struct ScalarEntryType: uint8_t {
        int64 = 1,
        int32,
        int16,
        int8,
        uint64,
        uint32,
        uint16,
        uint8,
        DOUBLE,
        STRING,
        BOOL,
        OBJECT
    };

    ScalarEntryType scalar_type;
    bool is_array;
};


