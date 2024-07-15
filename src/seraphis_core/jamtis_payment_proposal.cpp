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
#include "jamtis_payment_proposal.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "jamtis_account_secrets.h"
#include "jamtis_address_tag_utils.h"
#include "jamtis_address_utils.h"
#include "jamtis_enote_utils.h"
#include "jamtis_support_types.h"
#include "memwipe.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_extra.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
static auto auto_wiper(T &obj)
{
    return epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&obj, sizeof(T)); });
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_output_proposal_plain_root_secrets_and_ephem_pubkey(const JamtisPaymentProposalV1 &proposal,
    const rct::key &input_context,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    crypto::x25519_pubkey &x_fa_out,
    crypto::x25519_pubkey &x_ir_out,
    rct::key &q_out)
{
    // 1. enote ephemeral pubkey: D_e = xr D^j_base
    get_enote_ephemeral_pubkey(proposal, enote_ephemeral_pubkey_out);

    // 2. derived key: X_fa = xr * D^j_fa
    crypto::x25519_scmul_key(proposal.enote_ephemeral_privkey, proposal.destination.addr_Dfa, x_fa_out);

    // 3. derived key: X_ir = xr * D^j_ir
    crypto::x25519_scmul_key(proposal.enote_ephemeral_privkey, proposal.destination.addr_Dir, x_ir_out);

    // 4. derived key: X_ur = xr G
    crypto::x25519_pubkey x_ur; auto dhe_wiper = auto_wiper(x_ur);
    crypto::x25519_scmul_base(proposal.enote_ephemeral_privkey, x_ur);

    // 5. q = H_32(X_fa, X_ir, X_ur, D_e, input_context)
    make_jamtis_sender_receiver_secret(x_fa_out.data,
        x_ir_out.data,
        x_ur.data,
        enote_ephemeral_pubkey_out,
        input_context,
        q_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_output_proposal_address_parts_v1(const JamtisOnetimeAddressFormat onetime_address_format,
    const rct::key &q,
    const secret256_ptr_t x_fa,
    const secret256_ptr_t x_ir,
    const JamtisDestinationV1 &output_destination,
    const std::uint8_t num_primary_view_tag_bits,
    const rct::key &amount_commitment,
    rct::key &onetime_address_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out)
{
    // 1. onetime address: Ko = ... + K^j_s
    make_jamtis_onetime_address(onetime_address_format,
        output_destination.addr_Ks,
        q,
        amount_commitment,
        onetime_address_out);

    // 2. encrypt address tag: addr_tag_enc = addr_tag XOR H_16(X_fa, X_ir, Ko)
    addr_tag_enc_out = encrypt_jamtis_address_tag(output_destination.addr_tag, x_fa, x_ir, onetime_address_out);

    // 3. view tag
    jamtis::make_jamtis_view_tag(x_fa,
        x_ir,
        onetime_address_out,
        num_primary_view_tag_bits,
        view_tag_out);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_enote_ephemeral_pubkey(const crypto::x25519_secret_key &enote_ephemeral_privkey,
    const JamtisDestinationV1 &destination,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out)
{
    // sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(enote_ephemeral_privkey.data),
        "jamtis payment proposal: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(enote_ephemeral_privkey),
        "jamtis payment proposal: invalid enote ephemeral privkey (not canonical).");

    // enote ephemeral pubkey: D_e = xr D^j_base
    make_jamtis_enote_ephemeral_pubkey(enote_ephemeral_privkey,
        destination.addr_Dbase,
        enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------    
//-------------------------------------------------------------------------------------------------------------------
/// equality operators
bool operator==(const JamtisPaymentProposalV1 a, const JamtisPaymentProposalV1 b)
{
    return a.destination == b.destination &&
        a.amount == b.amount &&
        a.onetime_address_format == b.onetime_address_format &&
        a.enote_ephemeral_privkey == b.enote_ephemeral_privkey &&
        a.num_primary_view_tag_bits == b.num_primary_view_tag_bits &&
        a.partial_memo == b.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const JamtisPaymentProposalSelfSendV1 a, const JamtisPaymentProposalSelfSendV1 b)
{
    return a.destination == b.destination &&
        a.amount == b.amount &&
        a.onetime_address_format == b.onetime_address_format &&
        a.type == b.type &&
        a.enote_ephemeral_privkey == b.enote_ephemeral_privkey &&
        a.num_primary_view_tag_bits == b.num_primary_view_tag_bits &&
        a.partial_memo == b.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_ephemeral_pubkey(const JamtisPaymentProposalV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out)
{
    get_enote_ephemeral_pubkey(proposal.enote_ephemeral_privkey, proposal.destination, enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_ephemeral_pubkey(const JamtisPaymentProposalSelfSendV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out)
{
    get_enote_ephemeral_pubkey(proposal.enote_ephemeral_privkey, proposal.destination, enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_coinbase_output_proposal_v1(const JamtisPaymentProposalV1 &proposal,
    const std::uint64_t block_height,
    SpCoinbaseEnoteCore &output_enote_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.enote_ephemeral_privkey.data),
        "jamtis payment proposal: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.enote_ephemeral_privkey),
        "jamtis payment proposal: invalid enote ephemeral privkey (not canonical).");

    // 2. coinbase input context
    rct::key input_context;
    make_jamtis_input_context_coinbase(block_height, input_context);

    // 3. plain enote ephemeral pubkey and root secrets: D_e, X_fa, X_ir, q
    crypto::x25519_pubkey x_fa; auto dhe1_wiper = auto_wiper(x_fa);
    crypto::x25519_pubkey x_ir; auto dhe2_wiper = auto_wiper(x_ir);
    rct::key q; auto q_wiper = auto_wiper(q);
    get_output_proposal_plain_root_secrets_and_ephem_pubkey(proposal,
        input_context, enote_ephemeral_pubkey_out, x_fa, x_ir, q);

    // 4. build the output enote address pieces
    get_output_proposal_address_parts_v1(proposal.onetime_address_format,
        q,
        x_fa.data,
        x_ir.data,
        proposal.destination,
        proposal.num_primary_view_tag_bits,
        rct::commit(proposal.amount, rct::I),
        output_enote_core_out.onetime_address,
        addr_tag_enc_out,
        view_tag_out);

    // 5. save the amount and parial memo
    output_enote_core_out.amount = proposal.amount;
    partial_memo_out             = proposal.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void get_output_proposal_v1(const JamtisPaymentProposalV1 &proposal,
    const rct::key &input_context,
    SpOutputProposalCore &output_proposal_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encrypted_amount_t &encrypted_amount_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.enote_ephemeral_privkey.data),
        "jamtis payment proposal: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.enote_ephemeral_privkey),
        "jamtis payment proposal: invalid enote ephemeral privkey (not canonical).");

    // 2. plain enote ephemeral pubkey and root secrets: D_e, X_fa, X_ir, q
    crypto::x25519_pubkey x_fa; auto dhe1_wiper = auto_wiper(x_fa);
    crypto::x25519_pubkey x_ir; auto dhe2_wiper = auto_wiper(x_ir);
    rct::key q; auto q_wiper = auto_wiper(q);
    get_output_proposal_plain_root_secrets_and_ephem_pubkey(proposal,
        input_context, enote_ephemeral_pubkey_out, x_fa, x_ir, q);

    // 3. amount blinding factor: y = Hn(q, enote_type)
    make_jamtis_amount_blinding_factor(q, JamtisEnoteType::PLAIN, output_proposal_core_out.amount_blinding_factor);

    // 4. build the output enote address pieces
    get_output_proposal_address_parts_v1(proposal.onetime_address_format,
        q,
        x_fa.data,
        x_ir.data,
        proposal.destination,
        proposal.num_primary_view_tag_bits,
        rct::commit(proposal.amount, rct::sk2rct(output_proposal_core_out.amount_blinding_factor)),
        output_proposal_core_out.onetime_address,
        addr_tag_enc_out,
        view_tag_out);
    
    // 5. make encryped amount
    encrypted_amount_out = encrypt_jamtis_amount(proposal.amount, q, output_proposal_core_out.onetime_address);

    // 6. save the amount and partial memo
    output_proposal_core_out.amount = proposal.amount;
    partial_memo_out                = proposal.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void get_output_proposal_v1(const JamtisPaymentProposalSelfSendV1 &proposal,
    const crypto::secret_key &s_view_balance,
    const rct::key &input_context,
    SpOutputProposalCore &output_proposal_core_out,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out,
    encrypted_amount_t &encrypted_amount_out,
    encrypted_address_tag_t &addr_tag_enc_out,
    view_tag_t &view_tag_out,
    TxExtra &partial_memo_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.enote_ephemeral_privkey.data),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.enote_ephemeral_privkey),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(s_view_balance)),
        "jamtis payment proposal self-send: invalid view-balance privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(s_view_balance)) == 0,
        "jamtis payment proposal self-send: invalid view-balance privkey (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(proposal.type <= JamtisSelfSendType::MAX,
        "jamtis payment proposal self-send: unknown self-send type.");

    // 2. enote ephemeral pubkey: D_e = xr D^j_base
    get_enote_ephemeral_pubkey(proposal, enote_ephemeral_pubkey_out);

    // 3. derived key: X_fa = xr * D^j_fa
    crypto::x25519_pubkey x_fa; auto dhe1_wiper = auto_wiper(x_fa);
    crypto::x25519_scmul_key(proposal.enote_ephemeral_privkey, proposal.destination.addr_Dfa, x_fa);

    // 4. sender-receiver shared secret (selfsend): q = H_32(xr * D^j_fa, s_vb, s_vb, D_e, input_context)
    rct::key q; auto q_wiper = auto_wiper(q);
    make_jamtis_sender_receiver_secret(x_fa.data,
        reinterpret_cast<secret256_ptr_t>(s_view_balance.data),
        reinterpret_cast<secret256_ptr_t>(s_view_balance.data),
        enote_ephemeral_pubkey_out,
        input_context,
        q);
    
    // 5. self-send type -> enote type
    JamtisEnoteType proposal_enote_type;
    CHECK_AND_ASSERT_THROW_MES(try_get_jamtis_enote_type(proposal.type, proposal_enote_type),
        "jamtis payment proposal self-send: failed to convert payment send self type to enote type");

    // 6. amount blinding factor: y = Hn(q, enote_type)
    make_jamtis_amount_blinding_factor(q, proposal_enote_type, output_proposal_core_out.amount_blinding_factor);

    // 7. build the output enote address pieces
    get_output_proposal_address_parts_v1(proposal.onetime_address_format,
        q,
        x_fa.data,
        reinterpret_cast<secret256_ptr_t>(s_view_balance.data),
        proposal.destination,
        proposal.num_primary_view_tag_bits,
        rct::commit(proposal.amount, rct::sk2rct(output_proposal_core_out.amount_blinding_factor)),
        output_proposal_core_out.onetime_address,
        addr_tag_enc_out,
        view_tag_out);

    // 8. make encryped amount
    encrypted_amount_out = encrypt_jamtis_amount(proposal.amount, q, output_proposal_core_out.onetime_address);

    // 9. save the amount and partial memo
    output_proposal_core_out.amount = proposal.amount;
    partial_memo_out                = proposal.partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
JamtisPaymentProposalV1 gen_jamtis_payment_proposal_v1(const JamtisOnetimeAddressFormat onetime_address_format,
    const rct::xmr_amount amount,
    const std::size_t num_random_memo_elements,
    const std::uint8_t num_primary_view_tag_bits)
{
    JamtisPaymentProposalV1 temp;

    temp.destination               = gen_jamtis_destination_v1();
    temp.amount                    = amount;
    temp.onetime_address_format    = onetime_address_format;
    temp.enote_ephemeral_privkey   = crypto::x25519_secret_key_gen();
    temp.num_primary_view_tag_bits = num_primary_view_tag_bits;

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element = gen_extra_field_element();
    make_tx_extra(std::move(memo_elements), temp.partial_memo);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
JamtisPaymentProposalSelfSendV1 gen_jamtis_selfsend_payment_proposal_v1(
    const JamtisOnetimeAddressFormat onetime_address_format,
    const rct::xmr_amount amount,
    const JamtisSelfSendType type,
    const std::size_t num_random_memo_elements)
{
    JamtisPaymentProposalSelfSendV1 temp;

    temp.destination               = gen_jamtis_destination_v1();
    temp.amount                    = amount;
    temp.onetime_address_format    = onetime_address_format;
    temp.type                      = type;
    temp.enote_ephemeral_privkey   = crypto::x25519_secret_key_gen();
    temp.num_primary_view_tag_bits = crypto::rand_idx<size_t>(8 * VIEW_TAG_BYTES);

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element = gen_extra_field_element();
    make_tx_extra(std::move(memo_elements), temp.partial_memo);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
