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

//paired header
#include "jamtis_support_types.h"

//local headers
#include "crypto/crypto.h"
#include "int-util.h"
#include "misc_log_ex.h"

//third party headers

//standard headers
#include <cstdint>
#include <cstddef>

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <std::size_t Sz>
static void xor_bytes(const unsigned char(&a)[Sz], const unsigned char(&b)[Sz], unsigned char(&c_out)[Sz])
{
    for (std::size_t i{0}; i < Sz; ++i)
        c_out[i] = a[i] ^ b[i];
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
static T xor_bytes(const T &a, const T &b)
{
    T temp;
    xor_bytes(a.bytes, b.bytes, temp.bytes);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
address_index_t::address_index_t()
{
    std::memset(this->bytes, 0, ADDRESS_INDEX_BYTES);
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const address_index_t &a, const address_index_t &b)
{
    return memcmp(a.bytes, b.bytes, sizeof(address_index_t)) == 0;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const address_tag_t &a, const address_tag_t &b)
{
    return memcmp(a.bytes, b.bytes, sizeof(address_tag_t)) == 0;
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t operator^(const address_tag_t &a, const address_tag_t &b)
{
    return xor_bytes(a, b);
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const encrypted_amount_t &a, const encrypted_amount_t &b)
{
    return memcmp(a.bytes, b.bytes, sizeof(encrypted_amount_t)) == 0;
}
//-------------------------------------------------------------------------------------------------------------------
encrypted_amount_t operator^(const encrypted_amount_t &a, const encrypted_amount_t &b)
{
    return xor_bytes(a, b);
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const payment_id_t &a, const payment_id_t &b)
{
    return memcmp(a.bytes, b.bytes, sizeof(payment_id_t)) == 0;
}
//-------------------------------------------------------------------------------------------------------------------
encrypted_payment_id_t operator^(const encrypted_payment_id_t &a, const encrypted_payment_id_t &b)
{
    return xor_bytes(a, b);
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const view_tag_t &a, const view_tag_t &b)
{
    return memcmp(a.bytes, b.bytes, sizeof(view_tag_t)) == 0;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const input_context_t &a, const input_context_t &b)
{
    return memcmp(a.bytes, b.bytes, sizeof(input_context_t)) == 0;
}
//-------------------------------------------------------------------------------------------------------------------
address_index_t max_address_index()
{
    address_index_t temp;
    std::memset(temp.bytes, static_cast<unsigned char>(-1), ADDRESS_INDEX_BYTES);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
address_index_t make_address_index(std::uint64_t half1, std::uint64_t half2)
{
    static_assert(sizeof(half1) + sizeof(half2) == sizeof(address_index_t), "");

    // copy each half of the index over (as little endian bytes)
    half1 = SWAP64LE(half1);
    half2 = SWAP64LE(half2);

    address_index_t temp;
    std::memset(temp.bytes, 0, ADDRESS_INDEX_BYTES);
    memcpy(temp.bytes, &half1, sizeof(half1));
    memcpy(temp.bytes + sizeof(half1), &half2, sizeof(half2));

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t make_address_tag(const address_index_t &enc_j)
{
    // addr_tag = enc(j)
    address_tag_t temp;
    memcpy(temp.bytes, &enc_j, ADDRESS_INDEX_BYTES);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
address_index_t gen_address_index()
{
    address_index_t temp;
    crypto::rand(ADDRESS_INDEX_BYTES, temp.bytes);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t gen_address_tag()
{
    address_tag_t temp;
    crypto::rand(ADDRESS_INDEX_BYTES, temp.bytes);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
payment_id_t gen_payment_id()
{
    payment_id_t temp;
    do
    {
        crypto::rand(PAYMENT_ID_BYTES, temp.bytes);
    } while (temp == null_payment_id);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
view_tag_t gen_view_tag()
{
    view_tag_t temp;
    crypto::rand(VIEW_TAG_BYTES, temp.bytes);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
input_context_t gen_input_context()
{
    input_context_t temp;
    crypto::generate_random_bytes_thread_safe(INPUT_CONTEXT_BYTES, temp.bytes);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_enote_type(const JamtisSelfSendType self_send_type, JamtisEnoteType &enote_type_out)
{
    switch (self_send_type)
    {
        case (JamtisSelfSendType::SELF_SPEND) : enote_type_out = JamtisEnoteType::SELF_SPEND; return true;
        case (JamtisSelfSendType::CHANGE)     : enote_type_out = JamtisEnoteType::CHANGE;     return true;
        default                               :                                               return false;
    };
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_self_send_type(const JamtisEnoteType enote_type, JamtisSelfSendType &self_send_type_out)
{
    switch (enote_type)
    {
        case (JamtisEnoteType::SELF_SPEND) : self_send_type_out = JamtisSelfSendType::SELF_SPEND; return true;
        case (JamtisEnoteType::CHANGE)     : self_send_type_out = JamtisSelfSendType::CHANGE;     return true;
        default                            :                                                      return false;
    };
}
//-------------------------------------------------------------------------------------------------------------------
bool is_jamtis_selfsend_type(const JamtisEnoteType enote_type)
{
    JamtisSelfSendType dummy;
    return try_get_jamtis_self_send_type(enote_type, dummy);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
