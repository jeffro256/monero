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
#include "jamtis_enote_utils.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/x25519.h"
#include "cryptonote_config.h"
#include "int-util.h"
#include "jamtis_support_types.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "sp_core_enote_utils.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
// derivation = privkey * DH_key (with X25519)
// note: X25519 DH derivations are implicitly mul 8
//-------------------------------------------------------------------------------------------------------------------
static auto make_derivation_with_wiper(const crypto::x25519_secret_key &privkey,
    const crypto::x25519_pubkey &DH_key,
    crypto::x25519_pubkey &derivation_out)
{
    auto a_wiper = epee::misc_utils::create_scope_leave_handler(
            [&derivation_out]()
            {
                memwipe(&derivation_out, sizeof(derivation_out));
            }
        );

    x25519_scmul_key(privkey, DH_key, derivation_out);

    return a_wiper;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static encrypted_amount_t enc_amount(const rct::xmr_amount amount, const encrypted_amount_t &mask)
{
    static_assert(sizeof(rct::xmr_amount) == sizeof(encrypted_amount_t), "");

    // little_endian(amount) XOR H_8(q, Ko)
    encrypted_amount_t amount_LE;
    memcpy_swap64le(amount_LE.bytes, &amount, 1);
    return amount_LE ^ mask;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount dec_amount(const encrypted_amount_t &encrypted_amount, const encrypted_amount_t &mask)
{
    static_assert(sizeof(rct::xmr_amount) == sizeof(encrypted_amount_t), "");

    // system_endian(encrypted_amount XOR H_8(q, Ko))
    const encrypted_amount_t decryptd_amount{encrypted_amount ^ mask};
    rct::xmr_amount amount;
    memcpy_swap64le(&amount, &decryptd_amount, 1);
    return amount;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static encrypted_amount_t jamtis_encrypted_amount_mask(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address)
{
    static_assert(sizeof(encrypted_amount_t) == 8, "");

    // H_8(q, Ko)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_ENCRYPTED_AMOUNT_MASK, 2*sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("Ko", onetime_address);

    encrypted_amount_t mask;
    sp_hash_to_8(transcript.data(), transcript.size(), mask.bytes);

    return mask;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static encrypted_address_tag_t jamtis_encrypted_address_tag_mask(const unsigned char x_fa[32],
    const unsigned char x_ir[32],
    const rct::key &onetime_address)
{
    static_assert(sizeof(encrypted_address_tag_t) == 16, "");

    // H_16(X_fa, X_ir, Ko)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_ENCRYPTED_ADDRESS_TAG, 3*sizeof(rct::key)};
    transcript.append("X_fa", x_fa);
    transcript.append("X_ir", x_ir);
    transcript.append("Ko", onetime_address);

    encrypted_address_tag_t mask;
    sp_hash_to_16(transcript.data(), transcript.size(), mask.bytes);

    return mask;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static encrypted_payment_id_t jamtis_encrypted_payment_id_mask(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address)
{
    static_assert(sizeof(encrypted_payment_id_t) == 8, "");

    // H_8(q, Ko)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_ENCRYPTED_PAYMENT_ID_MASK, 2*sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("Ko", onetime_address);

    encrypted_payment_id_t mask;
    sp_hash_to_8(transcript.data(), transcript.size(), mask.bytes);

    return mask;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static inline std::uint32_t vttou32(view_tag_t vt)
{
    // Interpret view tag as little-endian unsigned int bytes, returning uint32_t
    std::uint32_t u32;
    memcpy(&u32, vt.bytes, VIEW_TAG_BYTES);
    return SWAP32LE(u32);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_jamtis_naked_primary_view_tag(const unsigned char x_fa[32],
    const rct::key &onetime_address,
    view_tag_t &naked_primary_view_tag_out)
{
    static_assert(VIEW_TAG_BYTES == 3, "sp_hash_to_3/VIEW_TAG_BYTES output mismatch");

    // H_3(X_fa, Ko)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_VIEW_TAG_PRIMARY, 2*sizeof(rct::key)};
    transcript.append("X_fa", x_fa);
    transcript.append("Ko", onetime_address);
    sp_hash_to_3(transcript.data(), transcript.size(), naked_primary_view_tag_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_jamtis_naked_secondary_view_tag(const unsigned char x_ir[32],
    const rct::key &onetime_address,
    view_tag_t &naked_secondary_view_tag_out)
{
    static_assert(VIEW_TAG_BYTES == 3, "sp_hash_to_3/VIEW_TAG_BYTES output mismatch");

    // H_3(X_ir, Ko)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_VIEW_TAG_SECONDARY, 2*sizeof(rct::key)};
    transcript.append("X_ir", x_ir);
    transcript.append("Ko", onetime_address);
    sp_hash_to_3(transcript.data(), transcript.size(), naked_secondary_view_tag_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_enote_ephemeral_pubkey(const crypto::x25519_secret_key &enote_ephemeral_privkey,
    const crypto::x25519_pubkey &addr_Dbase,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out)
{
    // D_e = xr D^j_base
    x25519_scmul_key(enote_ephemeral_privkey, addr_Dbase, enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_view_tag(const unsigned char x_fa[32],
    const unsigned char x_ir[32],
    const rct::key &onetime_address,
    const std::uint8_t num_primary_view_tag_bits,
    view_tag_t &view_tag_out)
{
    CHECK_AND_ASSERT_THROW_MES(num_primary_view_tag_bits <= 8 * VIEW_TAG_BYTES,
        "num_primary_view_tag_bits is bigger than the size of the view tag");

    // naked_primary_view_tag = H_3(X_fa, Ko)
    view_tag_t naked_primary_view_tag;
    make_jamtis_naked_primary_view_tag(x_fa, onetime_address, naked_primary_view_tag);

    // naked_secondary_view_tag = H_3(X_ir, Ko)
    view_tag_t naked_secondary_view_tag;
    make_jamtis_naked_secondary_view_tag(x_ir, onetime_address, naked_secondary_view_tag);

    const std::uint32_t primary_mask = (1 << num_primary_view_tag_bits) - 1;
    const std::uint32_t comp_mask = ~primary_mask;

    // view_tag = naked_primary_view_tag[:npbits] || naked_secondary_view_tag[:ncbits]
    std::uint32_t combined_view_tag_u32 = (vttou32(naked_primary_view_tag) & primary_mask) |
        ((vttou32(naked_secondary_view_tag) << num_primary_view_tag_bits) & comp_mask);

    combined_view_tag_u32 = SWAP32LE(combined_view_tag_u32);
    memcpy(view_tag_out.bytes, &combined_view_tag_u32, VIEW_TAG_BYTES);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_input_context_coinbase(const std::uint64_t block_height, rct::key &input_context_out)
{
    // block height as varint
    SpFSTranscript transcript{config::HASH_KEY_JAMTIS_INPUT_CONTEXT_COINBASE, 4};
    transcript.append("height", block_height);

    // input_context (coinbase) = H_32(block height)
    sp_hash_to_32(transcript.data(), transcript.size(), input_context_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_input_context_standard(const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    rct::key &input_context_out)
{
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(legacy_input_key_images.begin(), legacy_input_key_images.end()),
        "jamtis input context (standard): legacy key images are not sorted.");
    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(sp_input_key_images.begin(), sp_input_key_images.end()),
        "jamtis input context (standard): seraphis key images are not sorted.");

    // {legacy KI} || {seraphis KI}
    SpFSTranscript transcript{
            config::HASH_KEY_JAMTIS_INPUT_CONTEXT_STANDARD,
            (legacy_input_key_images.size() + sp_input_key_images.size())*sizeof(crypto::key_image)
        };
    transcript.append("legacy_input_KI", legacy_input_key_images);
    transcript.append("sp_input_KI", sp_input_key_images);

    // input_context (standard) = H_32({legacy KI}, {seraphis KI})
    sp_hash_to_32(transcript.data(), transcript.size(), input_context_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret(const crypto::x25519_pubkey &x_fa,
    const unsigned char x_ir[32],
    const unsigned char x_ur[32],
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    rct::key &sender_receiver_secret_out)
{
    // q = H_32(X_fa, X_ir, X_ur, D_e, input_context)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET, 5*sizeof(rct::key)};
    transcript.append("X_fa", x_fa);
    transcript.append("X_ir", x_ir);
    transcript.append("X_ur", x_ur);
    transcript.append("D_e", enote_ephemeral_pubkey);
    transcript.append("input_context", input_context);

    sp_hash_to_32(transcript.data(), transcript.size(), sender_receiver_secret_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_extension_g(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out)
{
    // k_{g, sender} = H_n("..g..", K^j_s, q, C)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SENDER_ONETIME_ADDRESS_EXTENSION_G, 3*sizeof(rct::key)};
    transcript.append("K^j_s", recipient_address_spend_key);
    transcript.append("q", sender_receiver_secret);
    transcript.append("C", amount_commitment);

    sp_hash_to_scalar(transcript.data(), transcript.size(), to_bytes(sender_extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_extension_x(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out)
{
    // k_{x, sender} = H_n("..x..", K^j_s, q, C)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SENDER_ONETIME_ADDRESS_EXTENSION_X, 3*sizeof(rct::key)};
    transcript.append("K^j_s", recipient_address_spend_key);
    transcript.append("q", sender_receiver_secret);
    transcript.append("C", amount_commitment);

    sp_hash_to_scalar(transcript.data(), transcript.size(), to_bytes(sender_extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_extension_u(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out)
{
    // k_{u, sender} = H_n("..u..", K^j_s, q, C)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SENDER_ONETIME_ADDRESS_EXTENSION_U, 3*sizeof(rct::key)};
    transcript.append("K^j_s", recipient_address_spend_key);
    transcript.append("q", sender_receiver_secret);
    transcript.append("C", amount_commitment);

    sp_hash_to_scalar(transcript.data(), transcript.size(), to_bytes(sender_extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &onetime_address_out)
{
    // Ko = k^o_g G + k^o_x X + k^o_u U + K^j_s
    crypto::secret_key extension_g;
    crypto::secret_key extension_x;
    crypto::secret_key extension_u;
    make_jamtis_onetime_address_extension_g(recipient_address_spend_key,
        sender_receiver_secret,
        amount_commitment,
        extension_g);  //k^o_g
    make_jamtis_onetime_address_extension_x(recipient_address_spend_key,
        sender_receiver_secret,
        amount_commitment,
        extension_x);  //k^o_x
    make_jamtis_onetime_address_extension_u(recipient_address_spend_key,
        sender_receiver_secret,
        amount_commitment,
        extension_u);  //k^o_u

    onetime_address_out = recipient_address_spend_key;  //K^j_s
    extend_seraphis_spendkey_u(extension_u, onetime_address_out);  //k^o_u U + K^j_s
    extend_seraphis_spendkey_x(extension_x, onetime_address_out);  //k^o_x X + k^o_u U + K^j_s
    mask_key(extension_g,
        onetime_address_out,
        onetime_address_out);  //k^o_g G + k^o_x X + k^o_u U + K^j_s
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_blinding_factor(const rct::key &sender_receiver_secret,
    const rct::key &baked_key,
    crypto::secret_key &mask_out)
{
    // x = H_n(q, baked_key)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR, 2*sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("baked_key", baked_key);

    sp_hash_to_scalar(transcript.data(), transcript.size(), to_bytes(mask_out));
}
//-------------------------------------------------------------------------------------------------------------------
encrypted_amount_t encode_jamtis_amount(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret,
    const rct::key &baked_key)
{
    // a_enc = little_endian(a) XOR H_8(q, baked_key)
    return enc_amount(amount, jamtis_encrypted_amount_mask(sender_receiver_secret, baked_key));
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount decrypt_jamtis_amount(const encrypted_amount_t &encrypted_amount,
    const rct::key &sender_receiver_secret,
    const rct::key &baked_key)
{
    // a = system_endian( a_enc XOR H_8(q, baked_key) )
    return dec_amount(encrypted_amount, jamtis_encrypted_amount_mask(sender_receiver_secret, baked_key));
}
//-------------------------------------------------------------------------------------------------------------------
bool test_jamtis_onetime_address(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &expected_onetime_address)
{
    // compute a nominal onetime address: K'o
    rct::key nominal_onetime_address;
    make_jamtis_onetime_address(recipient_address_spend_key,
        sender_receiver_secret,
        amount_commitment,
        nominal_onetime_address);

    // check if the nominal onetime address matches the real onetime address: K'o ?= Ko
    return nominal_onetime_address == expected_onetime_address;
}
//-------------------------------------------------------------------------------------------------------------------
bool test_jamtis_primary_view_tag(const unsigned char x_fa[32],
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    const std::uint8_t num_primary_view_tag_bits)
{
    // npbits can't be greater than total tag size (duh)
    CHECK_AND_ASSERT_THROW_MES(num_primary_view_tag_bits <= 8 * VIEW_TAG_BYTES,
        "num_primary_view_tag_bits is too large: " << num_primary_view_tag_bits);

    // primary_view_tag' = H_3(X_fa, Ko)
    view_tag_t naked_primary_view_tag;
    make_jamtis_naked_primary_view_tag(x_fa,
        onetime_address,
        naked_primary_view_tag);

    // primary_view_tag' ?= primary_view_tag
    const std::uint32_t partial_recomputed_view_tag = vttou32(naked_primary_view_tag);
    const std::uint32_t primary_mask = (1 << num_primary_view_tag_bits) - 1;
    return 0 == ((partial_recomputed_view_tag ^ vttou32(view_tag)) & primary_mask);
}
//-------------------------------------------------------------------------------------------------------------------
bool test_jamtis_primary_view_tag(const crypto::x25519_secret_key &d_filter_assist,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    const std::uint8_t num_primary_view_tag_bits)
{
    // X_fa = d_fa D_e
    crypto::x25519_pubkey x_fa;
    crypto::x25519_scmul_key(d_filter_assist, enote_ephemeral_pubkey, x_fa);

    return test_jamtis_primary_view_tag(to_bytes(x_fa),
        onetime_address,
        view_tag,
        num_primary_view_tag_bits);
}
//-------------------------------------------------------------------------------------------------------------------
bool test_jamtis_secondary_view_tag(const unsigned char x_ir[32],
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    const std::uint8_t num_primary_view_tag_bits)
{
    // npbits can't be greater than total tag size (duh)
    CHECK_AND_ASSERT_THROW_MES(num_primary_view_tag_bits <= 8 * VIEW_TAG_BYTES,
        "num_primary_view_tag_bits is too large: " << num_primary_view_tag_bits);

    // secondary_view_tag' = H_3(X_ir, Ko)
    view_tag_t naked_secondary_view_tag;
    make_jamtis_naked_secondary_view_tag(x_ir, onetime_address, naked_secondary_view_tag);

    // secondary_view_tag' ?= secondary_view_tag
    const std::uint32_t ncbits = 8 * VIEW_TAG_BYTES - num_primary_view_tag_bits;
    const std::uint32_t secondary_mask = ((1ul << ncbits) - 1) << num_primary_view_tag_bits;
    const std::uint32_t partial_recomputed_view_tag = vttou32(naked_secondary_view_tag) << num_primary_view_tag_bits;
    return 0 == ((partial_recomputed_view_tag ^ vttou32(view_tag)) & secondary_mask);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_amount(const rct::key &sender_receiver_secret,
    const rct::key &baked_key,
    const rct::key &amount_commitment,
    const encrypted_amount_t &encrypted_amount,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // 1. a' = dec(enc_a)
    const rct::xmr_amount nominal_amount{decrypt_jamtis_amount(encrypted_amount, sender_receiver_secret, baked_key)};

    // 2. C' = x' G + a' H
    make_jamtis_amount_blinding_factor(sender_receiver_secret, baked_key, amount_blinding_factor_out);  //x'
    const rct::key nominal_amount_commitment{rct::commit(nominal_amount, rct::sk2rct(amount_blinding_factor_out))};

    // 3. check that recomputed commitment matches original commitment
    // note: this defends against the Janus attack, and against malformed amount commitments
    if (!(nominal_amount_commitment == amount_commitment))
        return false;

    // 4. save the amount
    amount_out = nominal_amount;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
