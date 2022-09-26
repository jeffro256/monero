// Copyright (c) 2022, The Monero Project
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

#include <cstdint>

#include "int-util.h"

namespace wire
{
    static constexpr std::uint32_t PORTABLE_STORAGE_SIGNATUREA = 0x01011101;
    static constexpr std::uint32_t PORTABLE_STORAGE_SIGNATUREB = 0x01020101; // bender's nightmare 
    static constexpr std::uint8_t  PORTABLE_STORAGE_FORMAT_VER = 1;

#pragma pack(push)
#pragma pack(1)
    struct storage_block_header
    {
      uint32_t m_signature_a;
      uint32_t m_signature_b;
      uint8_t  m_ver;
    };
#pragma pack(pop)

    static constexpr std::size_t PORTABLE_RAW_SIZE_MARK_MASK  = 0b11;
    static constexpr std::size_t PORTABLE_RAW_SIZE_MARK_BYTE  = 0;
    static constexpr std::size_t PORTABLE_RAW_SIZE_MARK_WORD  = 1;
    static constexpr std::size_t PORTABLE_RAW_SIZE_MARK_DWORD = 2;
    static constexpr std::size_t PORTABLE_RAW_SIZE_MARK_INT64 = 3;

    static constexpr std::uint8_t SERIALIZE_TYPE_INT64  = 1;
    static constexpr std::uint8_t SERIALIZE_TYPE_INT32  = 2;
    static constexpr std::uint8_t SERIALIZE_TYPE_INT16  = 3;
    static constexpr std::uint8_t SERIALIZE_TYPE_INT8   = 4;
    static constexpr std::uint8_t SERIALIZE_TYPE_UINT64 = 5;
    static constexpr std::uint8_t SERIALIZE_TYPE_UINT32 = 6;
    static constexpr std::uint8_t SERIALIZE_TYPE_UINT16 = 7;
    static constexpr std::uint8_t SERIALIZE_TYPE_UINT8  = 8;
    static constexpr std::uint8_t SERIALIZE_TYPE_DOUBLE = 9;
    static constexpr std::uint8_t SERIALIZE_TYPE_STRING = 10;
    static constexpr std::uint8_t SERIALIZE_TYPE_BOOL   = 11;
    static constexpr std::uint8_t SERIALIZE_TYPE_OBJECT = 12;
    static constexpr std::uint8_t SERIALIZE_TYPE_ARRAY  = 13;

    static constexpr std::uint8_t SERIALIZE_FLAG_ARRAY  = 0x80;

    template<typename T> T convert_swapper(T t) { return t; }
    template<> inline uint16_t convert_swapper(uint16_t t) { return SWAP16LE(t); }
    template<> inline int16_t convert_swapper(int16_t t) { return SWAP16LE((uint16_t&)t); }
    template<> inline uint32_t convert_swapper(uint32_t t) { return SWAP32LE(t); }
    template<> inline int32_t convert_swapper(int32_t t) { return SWAP32LE((uint32_t&)t); }
    template<> inline uint64_t convert_swapper(uint64_t t) { return SWAP64LE(t); }
    template<> inline int64_t convert_swapper(int64_t t) { return SWAP64LE((uint64_t&)t); }
    template<> inline double convert_swapper(double t) { union { uint64_t u; double d; } u; u.d = t; u.u = SWAP64LE(u.u); return u.d; }

#   if BYTE_ORDER == BIG_ENDIAN
#       define CONVERT_POD(x) convert_swapper(x)
#   else
#       define CONVERT_POD(x) (x)
#   endif
}
