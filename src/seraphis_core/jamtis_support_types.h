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

//! @file Supporting types for Jamtis (address index, address tag, view tag, etc.).

#pragma once

//local headers

//third party headers
#include <boost/functional/hash.hpp>

//standard headers
#include <cstdint>
#include <cstddef>
#include <functional>

//forward declarations
namespace sp { class SpTranscriptBuilder; }

namespace sp
{
namespace jamtis
{

/// index (little-endian): j
constexpr std::size_t ADDRESS_INDEX_BYTES{16};
struct address_index_t final
{
    unsigned char bytes[ADDRESS_INDEX_BYTES];

    /// default constructor: default initialize to 0
    address_index_t();
};

/// index ciphered with a cipher key: addr_tag = enc[cipher_key](j)
struct address_tag_t final
{
    unsigned char bytes[ADDRESS_INDEX_BYTES];
};

/// address tag XORd with a user-defined secret: addr_tag_enc = addr_tag XOR addr_tag_enc_secret
using encrypted_address_tag_t = address_tag_t;
/// use in Janus protection as either a) random seed to rederive the ephemeral privkey or b) a hash
///   of the ephemeral pubkey and private viewkey for external selfsend enotes in 2-out txs
/// this should be the same size as the Jamtis address tag to prevent fingerprinting
using carrot_anchor_t = address_tag_t;
/// carrot janus anchor XORd with a user-defined secret, much like encrypted_address_tag_t
using carrot_encrypted_anchor_t = carrot_anchor_t;
static_assert(sizeof(carrot_anchor_t) >= 16,
    "Jamtis address tag not big enough for sufficient random entropy");

/// sizes must be consistent
static_assert(
    sizeof(address_index_t)    == ADDRESS_INDEX_BYTES              &&
    sizeof(address_tag_t)      == ADDRESS_INDEX_BYTES              &&
    sizeof(address_tag_t)      == sizeof(encrypted_address_tag_t),
    ""
);

/// jamtis enote types
enum class JamtisEnoteType : unsigned char
{
    SELF_SPEND = 0,
    CHANGE     = 1,
    PLAIN      = 2,
    MAX        = PLAIN
};

/// jamtis self-send types, used to define enote-construction procedure for self-sends
enum class JamtisSelfSendType : unsigned char
{
    SELF_SPEND = 0,
    CHANGE     = 1,
    MAX        = CHANGE
};

/// jamtis supported consensus-layer onetime address formats
enum class JamtisOnetimeAddressFormat : unsigned char
{
    RINGCT_V2,  // Ko = x G + y U
    SERAPHIS    // Ko = x G + y U + z X
};

/// jamtis encrypted amount
constexpr std::size_t ENCRYPTED_AMOUNT_BYTES{8};
struct encrypted_amount_t final
{
    unsigned char bytes[ENCRYPTED_AMOUNT_BYTES];
};

/// legacy payment ID
constexpr std::size_t PAYMENT_ID_BYTES{8};
struct payment_id_t final
{
    unsigned char bytes[PAYMENT_ID_BYTES];
};
static constexpr payment_id_t null_payment_id{{0}};

/// legacy encrypted payment ID
using encrypted_payment_id_t = payment_id_t;

/// jamtis view tags
constexpr std::size_t VIEW_TAG_BYTES{3};
struct view_tag_t final
{
    unsigned char bytes[VIEW_TAG_BYTES];
};

static_assert(sizeof(view_tag_t) < 32, "uint8_t cannot index all view tag bits");

/// jamtis input context
constexpr std::size_t INPUT_CONTEXT_BYTES{1 + 32};
struct input_context_t final
{
    unsigned char bytes[INPUT_CONTEXT_BYTES];
};

/// overloaded operators: address index
bool operator==(const address_index_t &a, const address_index_t &b);
inline bool operator!=(const address_index_t &a, const address_index_t &b) { return !(a == b); }
/// overloaded operators: address tag
bool operator==(const address_tag_t &a, const address_tag_t &b);
inline bool operator!=(const address_tag_t &a, const address_tag_t &b) { return !(a == b); }
address_tag_t operator^(const address_tag_t &a, const address_tag_t &b);

/// overloaded operators: encrypted amount
bool operator==(const encrypted_amount_t &a, const encrypted_amount_t &b);
inline bool operator!=(const encrypted_amount_t &a, const encrypted_amount_t &b) { return !(a == b); }
encrypted_amount_t operator^(const encrypted_amount_t &a, const encrypted_amount_t &b);

/// overloaded operators: payment ID
bool operator==(const payment_id_t &a, const payment_id_t &b);
inline bool operator!=(const payment_id_t &a, const payment_id_t &b) { return !(a == b); }
payment_id_t operator^(const payment_id_t &a, const payment_id_t &b);

/// overloaded operators: input context
bool operator==(const input_context_t &a, const input_context_t &b);
inline bool operator!=(const input_context_t &a, const input_context_t &b) { return !(a == b); }

/// overloaded operators: view tag
bool operator==(const view_tag_t &a, const view_tag_t &b);
inline bool operator!=(const view_tag_t &a, const view_tag_t &b) { return !(a == b); }

/// max address index
address_index_t max_address_index();
/// make an address index
address_index_t make_address_index(std::uint64_t half1, std::uint64_t half2);
inline address_index_t make_address_index(std::uint64_t half1) { return make_address_index(half1, 0); }
/// make an address tag
address_tag_t make_address_tag(const address_index_t &enc_j);
/// generate a random address index
address_index_t gen_address_index();
/// generate a random address tag
address_tag_t gen_address_tag();
/// generate a random (non-zero) payment ID
payment_id_t gen_payment_id();
/// generate a random view tag
view_tag_t gen_view_tag();
/// generate a random input context
input_context_t gen_input_context();

/// convert between jamtis enote types and self-send types
bool try_get_jamtis_enote_type(const JamtisSelfSendType self_send_type, JamtisEnoteType &enote_type_out);
bool try_get_jamtis_self_send_type(const JamtisEnoteType enote_type, JamtisSelfSendType &self_send_type_out);
bool is_jamtis_selfsend_type(const JamtisEnoteType enote_type);

} //namespace jamtis
} //namespace sp

namespace std
{
/// implement STL hashing for address_index_t
template<>
struct hash<sp::jamtis::address_index_t>
{
    std::size_t operator()(const sp::jamtis::address_index_t &_v) const
    {
        return boost::hash_range(_v.bytes, _v.bytes + sp::jamtis::ADDRESS_INDEX_BYTES);
    }
};
/// implement STL hashing for input_context_t
template<>
struct hash<sp::jamtis::input_context_t>
{
    std::size_t operator()(const sp::jamtis::input_context_t &_v) const
    {
        return boost::hash_range(_v.bytes, _v.bytes + sp::jamtis::INPUT_CONTEXT_BYTES);
    }
};
} //namespace std
