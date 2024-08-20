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
#include "cryptonote_basic/subaddress_index.h"
#include "cryptonote_config.h"
#include "int-util.h"
#include "jamtis_account_secrets.h"
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
static boost::string_ref s256ptr_to_strref(const secret256_ptr_t sp)
{
    return {reinterpret_cast<const char*>(sp), 32};
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
static encrypted_address_tag_t jamtis_encrypted_address_tag_mask(const secret256_ptr_t x_fa,
    const secret256_ptr_t x_ir,
    const rct::key &onetime_address)
{
    static_assert(sizeof(encrypted_address_tag_t) == 16, "");

    // H_16(X_fa, X_ir, Ko)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_ENCRYPTED_ADDRESS_TAG, 3*sizeof(rct::key)};
    transcript.append("X_fa", s256ptr_to_strref(x_fa));
    transcript.append("X_ir", s256ptr_to_strref(x_ir));
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
static void make_jamtis_naked_primary_view_tag(const secret256_ptr_t x_fa,
    const rct::key &onetime_address,
    view_tag_t &naked_primary_view_tag_out)
{
    static_assert(VIEW_TAG_BYTES == 3, "sp_hash_to_3/VIEW_TAG_BYTES output mismatch");

    // H_3(X_fa, Ko)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_VIEW_TAG_PRIMARY, 2*sizeof(rct::key)};
    transcript.append("X_fa", s256ptr_to_strref(x_fa));
    transcript.append("Ko", onetime_address);
    sp_hash_to_3(transcript.data(), transcript.size(), naked_primary_view_tag_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_jamtis_naked_secondary_view_tag(const secret256_ptr_t x_ir,
    const rct::key &onetime_address,
    view_tag_t &naked_secondary_view_tag_out)
{
    static_assert(VIEW_TAG_BYTES == 3, "sp_hash_to_3/VIEW_TAG_BYTES output mismatch");

    // H_3(X_ir, Ko)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_VIEW_TAG_SECONDARY, 2*sizeof(rct::key)};
    transcript.append("X_ir", s256ptr_to_strref(x_ir));
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
void make_carrot_enote_ephemeral_privkey(const carrot_randomness_t &n,
    const rct::xmr_amount &amount,
    const crypto::public_key &address_spend_pubkey,
    const crypto::public_key &address_view_pubkey,
    const payment_id_t payment_id,
    crypto::secret_key &enote_ephemeral_privkey_out)
{
    // k_e = (H_64(n, b, K^j_s, K^j_v, pid)) mod l
    SpKDFTranscript transcript{config::HASH_KEY_CARROT_ENOTE_EPHEMERAL_PRIVKEY,
        sizeof(carrot_randomness_t) + sizeof(rct::xmr_amount) + 2*sizeof(rct::key) + PAYMENT_ID_BYTES};
    transcript.append("n", n.bytes);
    transcript.append("b", amount);
    transcript.append("K^j_s", address_spend_pubkey);
    transcript.append("K^j_v", address_view_pubkey);
    transcript.append("pid", payment_id.bytes);
    sp_hash_to_scalar(transcript.data(), transcript.size(), enote_ephemeral_privkey_out.data);

    assert(transcript.size() < 128); // for performance (should be 1 block size transcript)
}
//-------------------------------------------------------------------------------------------------------------------
void make_carrot_enote_ephemeral_pubkey(const crypto::secret_key &enote_ephemeral_privkey,
    const crypto::public_key &address_spend_pubkey,
    const bool is_subaddress,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out)
{
    // K_ebase = [subaddress K^j_s] [primary address G]
    const crypto::public_key ephemeral_base_key{is_subaddress ? address_spend_pubkey : rct::rct2pk(rct::G)};

    // K_e = k_e K_ebase
    ge_p3 enote_ephemeral_pubkey_ed25519;
    ge_frombytes_vartime(&enote_ephemeral_pubkey_ed25519, to_bytes(ephemeral_base_key));
    ge_scalarmult_p3(&enote_ephemeral_pubkey_ed25519,
        to_bytes(enote_ephemeral_privkey),
        &enote_ephemeral_pubkey_ed25519);

    // D_e = ConvertPubkey2(K_e)
    ge_p3_to_x25519(enote_ephemeral_pubkey_out.data, &enote_ephemeral_pubkey_ed25519);
}
//-------------------------------------------------------------------------------------------------------------------
bool make_carrot_x_all_recipient(const crypto::secret_key &k_view,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    crypto::public_key &x_all_out)
{
    // @TODO: this is slow as hell, replace with accelerated SUPERCOP impl
    // @TODO: HW device support

    ge_p3 p3;
    if (0 != ge_fromx25519_vartime(&p3, enote_ephemeral_pubkey.data)) // K_e
        return false;

    ge_p2 p2;
    ge_scalarmult(&p2, to_bytes(k_view), &p3); // k_v K_e

    ge_p1p1 p1p1;
    ge_mul8(&p1p1, &p2); // 8 k_v K_e

    ge_p1p1_to_p2(&p2, &p1p1);

    ge_tobytes(to_bytes(x_all_out), &p2);

    normalize_x(x_all_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_view_tag(const secret256_ptr_t x_fa,
    const secret256_ptr_t x_ir,
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

    const std::uint32_t primary_mask{(static_cast<std::uint32_t>(1) << num_primary_view_tag_bits) - 1};

    // view_tag = naked_primary_view_tag[:npbits] || naked_secondary_view_tag[:ncbits]
    const std::uint32_t combined_view_tag_u32{SWAP32LE((vttou32(naked_primary_view_tag) & primary_mask) |
        (vttou32(naked_secondary_view_tag) & ~primary_mask))};
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
void make_jamtis_sender_receiver_secret(const secret256_ptr_t x_fa,
    const secret256_ptr_t x_ir,
    const secret256_ptr_t x_ur,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    rct::key &sender_receiver_secret_out)
{
    // q = H_32(X_fa, X_ir, X_ur, D_e, input_context)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET, 5*sizeof(rct::key)};
    transcript.append("X_fa", s256ptr_to_strref(x_fa));
    transcript.append("X_ir", s256ptr_to_strref(x_ir));
    transcript.append("X_ur", s256ptr_to_strref(x_ur));
    transcript.append("D_e", enote_ephemeral_pubkey);
    transcript.append("input_context", input_context);

    sp_hash_to_32(transcript.data(), transcript.size(), sender_receiver_secret_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_extension_g(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out)
{
    // k_{g, sender} = H_n("..g..", q, C)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SENDER_ONETIME_ADDRESS_EXTENSION_G, 2*sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("C", amount_commitment);

    sp_hash_to_scalar(transcript.data(), transcript.size(), to_bytes(sender_extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_extension_x(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out)
{
    // k_{x, sender} = H_n("..x..", q, C)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SENDER_ONETIME_ADDRESS_EXTENSION_X, 2*sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("C", amount_commitment);

    sp_hash_to_scalar(transcript.data(), transcript.size(), to_bytes(sender_extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_extension_u(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out)
{
    // k_{u, sender} = H_n("..u..", q, C)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_SENDER_ONETIME_ADDRESS_EXTENSION_U, 2*sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("C", amount_commitment);

    sp_hash_to_scalar(transcript.data(), transcript.size(), to_bytes(sender_extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_extension_pubkey_sp(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &sender_extension_pubkey_out)
{
    crypto::secret_key extension_g;
    crypto::secret_key extension_x;
    crypto::secret_key extension_u;
    make_jamtis_onetime_address_extension_g(sender_receiver_secret,
        amount_commitment,
        extension_g);  //k^o_g
    make_jamtis_onetime_address_extension_x(sender_receiver_secret,
        amount_commitment,
        extension_x);  //k^o_x
    make_jamtis_onetime_address_extension_u(sender_receiver_secret,
        amount_commitment,
        extension_u);  //k^o_u

    rct::scalarmultBase(sender_extension_pubkey_out, rct::sk2rct(extension_g)); // k^o_g G
    extend_seraphis_spendkey_u(extension_u, sender_extension_pubkey_out);  //k^o_u U + k^o_g G
    extend_seraphis_spendkey_x(extension_x, sender_extension_pubkey_out);  //k^o_x X + k^o_u U + k^o_g G = K^o_ext
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_extension_pubkey_rct(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &sender_extension_pubkey_out)
{
    crypto::secret_key extension_g;
    crypto::secret_key extension_u;
    make_jamtis_onetime_address_extension_g(sender_receiver_secret,
        amount_commitment,
        extension_g);  //k^o_g
    make_jamtis_onetime_address_extension_u(sender_receiver_secret,
        amount_commitment,
        extension_u);  //k^o_u

    rct::scalarmultBase(sender_extension_pubkey_out, rct::sk2rct(extension_g)); // k^o_g G
    extend_seraphis_spendkey_u(extension_u, sender_extension_pubkey_out);  //k^o_u U + k^o_g G = K^o_ext
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_sp(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &onetime_address_out)
{
    // K^o_ext = k^o_g G + k^o_x X + k^o_u U
    rct::key sender_extension_pubkey;
    make_jamtis_onetime_address_extension_pubkey_sp(sender_receiver_secret,
        amount_commitment,
        sender_extension_pubkey);

    // Ko = K^o_ext + K^j_s
    rct::addKeys(onetime_address_out, sender_extension_pubkey, recipient_address_spend_key);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_rct(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &onetime_address_out)
{
    // K^o_ext = k^o_g G + k^o_u U
    rct::key sender_extension_pubkey;
    make_jamtis_onetime_address_extension_pubkey_rct(sender_receiver_secret,
        amount_commitment,
        sender_extension_pubkey);

    // Ko = K^o_ext + K^j_s
    rct::addKeys(onetime_address_out, sender_extension_pubkey, recipient_address_spend_key);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address(const JamtisOnetimeAddressFormat onetime_address_format,
    const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &onetime_address_out)
{
    switch (onetime_address_format)
    {
    case JamtisOnetimeAddressFormat::RINGCT_V2:
        make_jamtis_onetime_address_rct(recipient_address_spend_key,
            sender_receiver_secret, amount_commitment, onetime_address_out);
        break;
    case JamtisOnetimeAddressFormat::SERAPHIS:
        make_jamtis_onetime_address_sp(recipient_address_spend_key,
            sender_receiver_secret, amount_commitment, onetime_address_out);
        break;
    default:
        ASSERT_MES_AND_THROW("make jamtis onetime address: unrecognized onetime address format");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_blinding_factor(const rct::key &sender_receiver_secret,
    const JamtisEnoteType enote_type,
    crypto::secret_key &amount_blinding_factor_out)
{
    // y = H_n(q, enote_type)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR, 2*sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("enote_type", static_cast<unsigned char>(enote_type));

    sp_hash_to_scalar(transcript.data(), transcript.size(), to_bytes(amount_blinding_factor_out));
}
//-------------------------------------------------------------------------------------------------------------------
encrypted_address_tag_t encrypt_jamtis_address_tag(const address_tag_t &addr_tag,
    const secret256_ptr_t x_fa,
    const secret256_ptr_t x_ir,
    const rct::key &onetime_address)
{
    // addr_tag_enc = addr_tag XOR H_16(X_fa, X_ir, Ko)
    return addr_tag ^ jamtis_encrypted_address_tag_mask(x_fa, x_ir, onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t decrypt_jamtis_address_tag(const encrypted_address_tag_t &enc_addr_tag,
    const secret256_ptr_t x_fa,
    const secret256_ptr_t x_ir,
    const rct::key &onetime_address)
{
    // addr_tag = addr_tag_enc XOR H_16(X_fa, X_ir, Ko)
    return enc_addr_tag ^ jamtis_encrypted_address_tag_mask(x_fa, x_ir, onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
encrypted_amount_t encrypt_jamtis_amount(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret,
    const rct::key &baked_key)
{
    // a_enc = little_endian(a) XOR H_8(q, baked_key)
    return enc_amount(amount, jamtis_encrypted_amount_mask(sender_receiver_secret, baked_key));
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount decrypt_jamtis_amount(const encrypted_amount_t &encrypted_amount,
    const rct::key &sender_receiver_secret,
    const rct::key &onetime_address)
{
    // a = system_endian( a_enc XOR H_8(q, Ko) )
    return dec_amount(encrypted_amount, jamtis_encrypted_amount_mask(sender_receiver_secret, onetime_address));
}
//-------------------------------------------------------------------------------------------------------------------
encrypted_payment_id_t encrypt_legacy_payment_id(const payment_id_t pid,
    const rct::key &sender_receiver_secret,
    const rct::key &onetime_address)
{
    // pid_enc = pid XOR H_8(q, Ko)
    return pid ^ jamtis_encrypted_payment_id_mask(sender_receiver_secret, onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
payment_id_t decrypt_legacy_payment_id(const encrypted_payment_id_t pid_enc,
    const rct::key &sender_receiver_secret,
    const rct::key &onetime_address)
{
    // pid = pid_enc XOR H_8(q, Ko)
    return pid_enc ^ jamtis_encrypted_payment_id_mask(sender_receiver_secret, onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
void recover_recipient_address_spend_key_sp(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &onetime_address,
    rct::key &recipient_address_spend_key_out)
{
    // K^o_ext = k^o_g G + k^o_x X + k^o_u U
    rct::key sender_extension_pubkey;
    make_jamtis_onetime_address_extension_pubkey_sp(sender_receiver_secret,
        amount_commitment,
        sender_extension_pubkey);

    // K^j_s = Ko - K^o_ext
    rct::subKeys(recipient_address_spend_key_out, onetime_address, sender_extension_pubkey);
}
//-------------------------------------------------------------------------------------------------------------------
void recover_recipient_address_spend_key_rct(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &onetime_address,
    crypto::public_key &recipient_address_spend_key_out)
{
    // K^o_ext = k^o_g G + k^o_u U
    rct::key sender_extension_pubkey;
    make_jamtis_onetime_address_extension_pubkey_rct(sender_receiver_secret,
        amount_commitment,
        sender_extension_pubkey);

    // K^j_s = Ko - K^o_ext
    rct::key recipient_address_spend_key_rct;
    rct::subKeys(recipient_address_spend_key_rct, onetime_address, sender_extension_pubkey);
    recipient_address_spend_key_out = rct::rct2pk(recipient_address_spend_key_rct);
}
//-------------------------------------------------------------------------------------------------------------------
bool test_jamtis_onetime_address_sp(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &expected_onetime_address)
{
    // compute a nominal onetime address: K'o
    rct::key nominal_onetime_address;
    make_jamtis_onetime_address_sp(recipient_address_spend_key,
        sender_receiver_secret,
        amount_commitment,
        nominal_onetime_address);

    // check if the nominal onetime address matches the real onetime address: K'o ?= Ko
    return nominal_onetime_address == expected_onetime_address;
}
//-------------------------------------------------------------------------------------------------------------------
bool test_jamtis_onetime_address_rct(const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &expected_onetime_address)
{
    // compute a nominal onetime address: K'o
    rct::key nominal_onetime_address;
    make_jamtis_onetime_address_rct(recipient_address_spend_key,
        sender_receiver_secret,
        amount_commitment,
        nominal_onetime_address);

    // check if the nominal onetime address matches the real onetime address: K'o ?= Ko
    return nominal_onetime_address == expected_onetime_address;
}
//-------------------------------------------------------------------------------------------------------------------
bool test_jamtis_onetime_address(const jamtis::JamtisOnetimeAddressFormat onetime_address_format,
    const rct::key &recipient_address_spend_key,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &expected_onetime_address)
{
    switch (onetime_address_format)
    {
    case JamtisOnetimeAddressFormat::RINGCT_V2:
        return test_jamtis_onetime_address_rct(recipient_address_spend_key,
            sender_receiver_secret,
            amount_commitment,
            expected_onetime_address);
    case JamtisOnetimeAddressFormat::SERAPHIS:
        return test_jamtis_onetime_address_sp(recipient_address_spend_key,
            sender_receiver_secret,
            amount_commitment,
            expected_onetime_address);
    default:
        ASSERT_MES_AND_THROW("test jamtis onetime address: unrecognized onetime address format");
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool test_jamtis_primary_view_tag(const secret256_ptr_t x_fa,
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
    const std::uint32_t primary_mask = (static_cast<std::uint32_t>(1) << num_primary_view_tag_bits) - 1;
    return 0 == ((vttou32(naked_primary_view_tag) ^ vttou32(view_tag)) & primary_mask);
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
    auto dhe_wiper = make_derivation_with_wiper(d_filter_assist, enote_ephemeral_pubkey, x_fa);

    return test_jamtis_primary_view_tag(to_bytes(x_fa),
        onetime_address,
        view_tag,
        num_primary_view_tag_bits);
}
//-------------------------------------------------------------------------------------------------------------------
bool test_jamtis_secondary_view_tag(const secret256_ptr_t x_ir,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    const std::uint8_t num_primary_view_tag_bits,
    bool &matched_all_secondary_bits_out)
{
    // npbits can't be greater than total tag size (duh)
    CHECK_AND_ASSERT_THROW_MES(num_primary_view_tag_bits <= 8 * VIEW_TAG_BYTES,
        "num_primary_view_tag_bits is too large: " << num_primary_view_tag_bits);

    // secondary_view_tag' = H_3(X_ir, Ko)
    view_tag_t naked_secondary_view_tag;
    make_jamtis_naked_secondary_view_tag(x_ir, onetime_address, naked_secondary_view_tag);

    // secondary_view_tag' ?= secondary_view_tag
    const std::uint32_t secondary_mask{~((static_cast<std::uint32_t>(1) << num_primary_view_tag_bits) - 1)};

    matched_all_secondary_bits_out = naked_secondary_view_tag == view_tag;
    return 0 == ((vttou32(naked_secondary_view_tag) ^ vttou32(view_tag)) & secondary_mask);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_amount(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    const JamtisEnoteType enote_type,
    const rct::key &amount_commitment,
    const encrypted_amount_t &encrypted_amount,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // 1. a' = dec(enc_a)
    const rct::xmr_amount nominal_amount{decrypt_jamtis_amount(encrypted_amount, sender_receiver_secret, onetime_address)};

    // 2. C' = y' G + a' H
    make_jamtis_amount_blinding_factor(sender_receiver_secret, enote_type, amount_blinding_factor_out);  //y'
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
bool verify_carrot_janus_protection(const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::xmr_amount &amount,
    const crypto::public_key &nominal_address_spend_pubkey,
    const carrot_randomness_t &nominal_n,
    const crypto::secret_key &k_view,
    const crypto::public_key &primary_address_spend_pubkey,
    payment_id_t &nominal_payment_id_inout)
{
    // 1. K^change_s = K_s + k^change_g G + k^change_u U
    crypto::public_key secret_change_spend_pubkey;
    make_carrot_secret_change_spend_pubkey(primary_address_spend_pubkey,
            k_view,
            secret_change_spend_pubkey);

    // 2. PASS: if enote is addressed to secret change pubkey
    if (nominal_address_spend_pubkey == secret_change_spend_pubkey)
    {
        // set payment id to null on a selfsend
        nominal_payment_id_inout = null_payment_id;

        return true;
    }

    // 3. recompute K^j_v
    const bool is_to_subaddress{nominal_address_spend_pubkey != primary_address_spend_pubkey};
    crypto::public_key nominal_address_view_pubkey;
    if (is_to_subaddress)
    {
        // K^j_v = k_v K^j_s
        nominal_address_view_pubkey = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(nominal_address_spend_pubkey),
            rct::sk2rct(k_view)));
    }
    else // is to primary address
    {
        // K^j_v = k_v G
        nominal_address_view_pubkey = rct::rct2pk(rct::scalarmultBase(rct::sk2rct(k_view)));
    }

    // first attempt with passed nominal_payment_id_inout, second attempt with null...
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        // 4. recompte k_e' = (H_64(n', a, K^j_s', K^j_v', pid')) mod l
        crypto::secret_key recomputed_enote_ephemeral_privkey;
        make_carrot_enote_ephemeral_privkey(nominal_n,
            amount,
            nominal_address_spend_pubkey,
            nominal_address_view_pubkey,
            nominal_payment_id_inout,
            recomputed_enote_ephemeral_privkey);

        // 5. recompute D_e' = ConvertPubkey2(k_e' ([subaddress: K^j_s'] [primary address: G])
        crypto::x25519_pubkey recomputed_enote_ephemeral_pubkey;
        make_carrot_enote_ephemeral_pubkey(recomputed_enote_ephemeral_privkey,
            nominal_address_spend_pubkey,
            is_to_subaddress,
            recomputed_enote_ephemeral_pubkey);

        // 6. PASS: if D_e' ?= D_e
        if (recomputed_enote_ephemeral_pubkey == enote_ephemeral_pubkey)
            return true;

        // set payment id to null on next run 
        nominal_payment_id_inout = null_payment_id;
    }

    // FAIL
    return false;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
