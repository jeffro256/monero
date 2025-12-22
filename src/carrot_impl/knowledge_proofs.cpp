// Copyright (c) 2025, The Monero Project
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
#include "knowledge_proofs.h"

//local headers
#include "address_device_ram_borrowed.h"
#include "address_utils.h"
#include "carrot_core/config.h"
#include "carrot_core/exceptions.h"
#include "common/apply_permutation.h"
#include "common/threadpool.h"
extern "C"
{
#include "crypto/blake2b.h"
#include "crypto/crypto-ops.h"
}
#include "crypto/generators.h"
#include "fcmp_pp/prove.h"
#include "int-util.h"
#include "key_image_device_composed.h"
#include "misc_log_ex.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "serialization/crypto.h"

//third party headers
#include <boost/multiprecision/cpp_int.hpp>

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "carrot_impl.knowledge_proofs"

#define assert_blake_op(x) { int r = (x); assert(0 == r); (void) r; }

namespace
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
boost::optional<T> coerce_optional(const std::optional<T> &v)
{
    return v ? boost::optional<T>(*v) : boost::optional<T>{};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::public_key x25519_to_edwardsY(const unsigned char * const x)
{
    // y = (x_mont - 1) / (x_mont + 1)
    // x positive

    fe tmp0;
    fe tmp1;
    CARROT_CHECK_AND_THROW(0 == fe_frombytes_vartime(tmp0, x),
        carrot::invalid_point, "Invalid X25519 point");
    fe_add(tmp1, tmp0, fe_one);    // x_mont + 1
    fe_sub(tmp0, tmp0, fe_one);    // x_mont - 1
    fe_invert(tmp1, tmp1);         // 1/(x_mont + 1)
    fe_mul(tmp0, tmp0, tmp1);      // (x_mont - 1) / (x_mont + 1)

    crypto::public_key P;
    fe_tobytes(to_bytes(P), tmp0); // tobytes((x_mont - 1) / (x_mont + 1))
    // top bit (determining whether x is positive in compressed form) should be set to 0 in fe_tobytes()
    assert(0 == (to_bytes(P)[31] & 0x80));
    return P;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static int blake2b_update_u64(blake2b_state *S, uint64_t x)
{
    x = SWAP64LE(x);
    return blake2b_update(S, &x, sizeof(x));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::hash get_reserve_proof_prefix_hash(
    const rct::xmr_amount threshold_amount,
    const std::vector<crypto::key_image> &key_images)
{
    static_assert(sizeof(carrot::CARROT_DOMAIN_SEP_RESERVE_PROOF_PREFIX) > sizeof(void*));
    static_assert(sizeof(carrot::CARROT_DOMAIN_SEP_RESERVE_PROOF_PREFIX) < sizeof(crypto::hash));

    blake2b_state S;
    assert_blake_op(blake2b_init(&S, sizeof(crypto::hash)));
    assert_blake_op(blake2b_update(&S, carrot::CARROT_DOMAIN_SEP_RESERVE_PROOF_PREFIX,
        sizeof(carrot::CARROT_DOMAIN_SEP_RESERVE_PROOF_PREFIX)));
    assert_blake_op(blake2b_update_u64(&S, threshold_amount));
    assert_blake_op(blake2b_update_u64(&S, key_images.size()));
    for (const crypto::key_image &key_image : key_images)
        assert_blake_op(blake2b_update(&S, &key_image, sizeof(key_image)));

    crypto::hash h;
    assert_blake_op(blake2b_final(&S, &h, sizeof(h)));
    return h;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool get_reserve_proof_remaining_commitment(const rct::xmr_amount threshold_amount,
    const std::vector<rct::key> &rerandomized_amount_commitments,
    rct::key &C_rem_out)
{
    static ge_p3 H = crypto::get_H_p3();

    // C_rem = -a H
    rct::key a = rct::d2h(threshold_amount);
    sc_sub(a.bytes, to_bytes(crypto::null_skey), a.bytes);
    ge_p3 C_rem;
    ge_scalarmult_p3(&C_rem, a.bytes, &H);

    // for each C~ in inputs...
    for (const auto &rerandomized_amount_commitment : rerandomized_amount_commitments)
    {
        // C~
        ge_p3 C;
        if (0 != ge_frombytes_vartime(&C, rerandomized_amount_commitment.bytes))
            return false;
        ge_cached C_cached;
        ge_p3_to_cached(&C_cached, &C);

        // C_rem += C~
        ge_p1p1 C_rem_p1p1;
        ge_add(&C_rem_p1p1, &C_rem, &C_cached);
        ge_p1p1_to_p3(&C_rem, &C_rem_p1p1);
    }

    ge_p3_tobytes(C_rem_out.bytes, &C_rem);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::tuple<
    fcmp_pp::OutputBlinds,
    std::vector<fcmp_pp::SeleneBranchBlind>,
    std::vector<fcmp_pp::HeliosBranchBlind>
> get_path_blinds(const FcmpRerandomizedOutputCompressed &rerandomized_output, const std::uint8_t n_tree_layers)
{
    CARROT_CHECK_AND_THROW(n_tree_layers, carrot::carrot_logic_error, "n_tree_layers must be at least 1");

    tools::threadpool &tpool = tools::threadpool::getInstanceForCompute();
    tools::threadpool::waiter waiter(tpool);

    // O~
    fcmp_pp::BlindedOBlind blinded_o_blind;
    tpool.submit(&waiter, [&blinded_o_blind, &rerandomized_output](){
            blinded_o_blind = fcmp_pp::blind_o_blind(fcmp_pp::o_blind(rerandomized_output)); }, /*leaf=*/true);
    // I~
    fcmp_pp::BlindedIBlind blinded_i_blind;
    tpool.submit(&waiter, [&blinded_i_blind, &rerandomized_output](){
            blinded_i_blind = fcmp_pp::blind_i_blind(fcmp_pp::i_blind(rerandomized_output)); }, /*leaf=*/true);
    // R
    fcmp_pp::BlindedIBlindBlind blinded_i_blind_blind;
    tpool.submit(&waiter, [&blinded_i_blind_blind, &rerandomized_output](){
            blinded_i_blind_blind = fcmp_pp::blind_i_blind_blind(fcmp_pp::i_blind_blind(rerandomized_output));
        }, /*leaf=*/true);
    // C~
    fcmp_pp::BlindedCBlind blinded_c_blind;
    tpool.submit(&waiter, [&blinded_c_blind, &rerandomized_output](){
            blinded_c_blind = fcmp_pp::blind_c_blind(fcmp_pp::c_blind(rerandomized_output)); }, /*leaf=*/true);

    // selene
    const std::size_t n_selene_branch_blinds = n_tree_layers / 2;
    std::vector<fcmp_pp::SeleneBranchBlind> selene_branch_blinds(n_selene_branch_blinds);
    for (std::size_t i = 0; i < n_selene_branch_blinds; ++i)
    {
        tpool.submit(&waiter, [&selene_branch_blinds, i](){
            selene_branch_blinds.at(i) = fcmp_pp::gen_selene_branch_blind(); }, /*leaf=*/true);
    }

    // helios
    const std::size_t n_helios_branch_blinds = (n_tree_layers - 1) / 2;
    std::vector<fcmp_pp::HeliosBranchBlind> helios_branch_blinds;
    helios_branch_blinds.resize(n_helios_branch_blinds);
    for (std::size_t i = 0; i < n_helios_branch_blinds; ++i)
    {
        tpool.submit(&waiter, [&helios_branch_blinds, i](){
            helios_branch_blinds.at(i) = fcmp_pp::gen_helios_branch_blind(); }, /*leaf=*/true);
    }

    // wait for tasks to finish
    CARROT_CHECK_AND_THROW(waiter.wait(),
        carrot::carrot_runtime_error, "Threadpool waiter failed for path blind tasks");

    return {
        fcmp_pp::output_blinds_new(blinded_o_blind, blinded_i_blind, blinded_i_blind_blind, blinded_c_blind),
        std::move(selene_branch_blinds),
        std::move(helios_branch_blinds)
    };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template<bool W, template <bool> class Archive>
bool serialize_bpp_exact_outputs(Archive<W> &ar, rct::BulletproofPlus &v, const std::size_t n_outputs)
{
    ar.begin_object();

    if (n_outputs == 0 || n_outputs > FCMP_PLUS_PLUS_MAX_OUTPUTS)
        return false;
    std::size_t lr_size = 0;
    while (n_outputs > (1u << lr_size))
        ++lr_size;
    lr_size += 6;

    // A, A1, B, r1, s1, d1
    FIELD_F(A)
    FIELD_F(A1)
    FIELD_F(B)
    FIELD_F(r1)
    FIELD_F(s1)
    FIELD_F(d1)

    // L
    PREPARE_CUSTOM_VECTOR_SERIALIZATION(lr_size, v.L);
    if (v.L.size() != lr_size)
        return false;
    ar.tag("L");
    ar.begin_array();
    bool first = true;
    for (rct::key &Li : v.L)
    {
        if (!first)
            ar.delimit_array();
        FIELDS(Li)
        first = false;
    }
    ar.end_array();

    // R
    PREPARE_CUSTOM_VECTOR_SERIALIZATION(lr_size, v.R);
    if (v.R.size() != lr_size)
        return false;
    ar.tag("R");
    ar.begin_array();
    first = true;
    for (rct::key &Ri : v.R)
    {
        if (!first)
            ar.delimit_array();
        FIELDS(Ri)
        first = false;
    }
    ar.end_array();

    ar.end_object();

    return ar.good();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
} //anonymous namespace

namespace carrot
{
//-------------------------------------------------------------------------------------------------------------------
void generate_carrot_tx_proof_normal(const crypto::hash &prefix_hash,
    const crypto::public_key &A,
    const std::optional<crypto::public_key> &B,
    crypto::secret_key r,
    crypto::signature &sig_out)
{
    // calculate R in Ed25519
    crypto::public_key R_ed25519;
    {
        if (B)
        {
            ge_p3 B_p3;
            CARROT_CHECK_AND_THROW(0 == ge_frombytes_vartime(&B_p3, to_bytes(*B)),
                carrot::invalid_point, "Invalid point B");

            // R_ed = r B
            ge_p2 R_p2;
            ge_scalarmult(&R_p2, to_bytes(r), &B_p3);
            ge_tobytes(to_bytes(R_ed25519), &R_p2);
        }
        else
        {
            // R_ed = r G_ed
            ge_p3 R_p3;
            ge_scalarmult_base(&R_p3, to_bytes(r));
            ge_p3_tobytes(to_bytes(R_ed25519), &R_p3);
        }
    }

    // always force R's Ed25519 map to be positive, which means negating `r` if appropriate
    // WARNING: vartime in `r`
    const bool R_is_negative = to_bytes(R_ed25519)[31] & 0x80;
    if (R_is_negative)
    {
        R_ed25519.data[31] &= 0x7f;                                    // R = -R
        sc_sub(to_bytes(r), to_bytes(crypto::null_skey), to_bytes(r)); // r = -r
    }

    // calculate D in Ed25519 according to possibly negated `r`
    crypto::public_key D_ed25519;
    {
        ge_p3 A_p3;
        CARROT_CHECK_AND_THROW(0 == ge_frombytes_vartime(&A_p3, to_bytes(A)),
            carrot::invalid_point, "Invalid point A");

        // D_ed = r A
        ge_p2 D_p2;
        ge_scalarmult(&D_p2, to_bytes(r), &A_p3);
        ge_tobytes(to_bytes(D_ed25519), &D_p2);
    }

    crypto::generate_tx_proof(prefix_hash, R_ed25519, A, coerce_optional(B), D_ed25519, r, sig_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool check_carrot_tx_proof_normal(const crypto::hash &prefix_hash,
    const mx25519_pubkey &R,
    const crypto::public_key &A,
    const std::optional<crypto::public_key> &B,
    const mx25519_pubkey &D,
    const crypto::signature &sig)
{
    const crypto::public_key R_ed25519 = x25519_to_edwardsY(R.data);
    crypto::public_key D_ed25519 = x25519_to_edwardsY(D.data);

    for (int negate_D = 0; negate_D < 2; ++negate_D)
    {
        if (crypto::check_tx_proof(prefix_hash, R_ed25519, A, coerce_optional(B), D_ed25519, sig, /*version=*/2))
            return true;

        to_bytes(D_ed25519)[31] ^= 0x80;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
void generate_carrot_tx_proof_receiver(const crypto::hash &prefix_hash,
    const mx25519_pubkey &R,
    const std::optional<crypto::public_key> &B,
    crypto::secret_key a,
    crypto::signature &sig_out)
{
    // convert R to Ed25519
    const crypto::public_key R_ed25519 = x25519_to_edwardsY(R.data);

    // calculate A in Ed25519
    crypto::public_key A;
    if (B)
    {
        ge_p3 B_p3;
        CARROT_CHECK_AND_THROW(0 == ge_frombytes_vartime(&B_p3, to_bytes(*B)),
            carrot::invalid_point, "Invalid point B");

        // A = a B
        ge_p2 A_p2;
        ge_scalarmult(&A_p2, to_bytes(a), &B_p3);
        ge_tobytes(to_bytes(A), &A_p2);
    }
    else
    {
        // A = a G_ed
        CARROT_CHECK_AND_THROW(crypto::secret_key_to_public_key(a, A),
            invalid_point, "Secret key to public key failed");
    }

    // calculate D in Ed25519
    crypto::public_key D_ed25519;
    {
        ge_p3 R_p3;
        CARROT_CHECK_AND_THROW(0 == ge_frombytes_vartime(&R_p3, to_bytes(R_ed25519)),
            carrot::invalid_point, "Invalid point R");

        // D_ed = a R
        ge_p2 D_p2;
        ge_scalarmult(&D_p2, to_bytes(a), &R_p3);
        ge_tobytes(to_bytes(D_ed25519), &D_p2);
    }

    crypto::generate_tx_proof(prefix_hash, A, R_ed25519, coerce_optional(B), D_ed25519, a, sig_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool check_carrot_tx_proof_receiver(const crypto::hash &prefix_hash,
    const mx25519_pubkey &R,
    const crypto::public_key &A,
    const std::optional<crypto::public_key> &B,
    const mx25519_pubkey &D,
    const crypto::signature &sig)
{
    const crypto::public_key R_ed25519 = x25519_to_edwardsY(R.data);
    crypto::public_key D_ed25519 = x25519_to_edwardsY(D.data);

    for (int negate_D = 0; negate_D < 2; ++negate_D)
    {
        if (crypto::check_tx_proof(prefix_hash, A, R_ed25519, coerce_optional(B), D_ed25519, sig, /*version=*/2))
            return true;

        to_bytes(D_ed25519)[31] ^= 0x80;
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
void generate_fcmp_reserve_proof(const rct::xmr_amount threshold_amount,
    std::vector<OutputOpeningHintVariant> opening_hints,
    std::vector<fcmp_pp::Path> input_paths,
    const std::uint64_t reference_block,
    const std::uint8_t n_tree_layers,
    std::shared_ptr<view_incoming_key_device> k_view_incoming_dev,
    std::shared_ptr<view_balance_secret_device> s_view_balance_dev,
    std::shared_ptr<address_device> addr_dev,
    const crypto::secret_key &privkey_g,
    const crypto::secret_key &privkey_t,
    FcmpReserveProof &reserve_proof_out)
{
    const std::size_t n_inputs = opening_hints.size();
    CARROT_CHECK_AND_THROW(input_paths.size() == n_inputs,
        component_out_of_order, "Wrong number of FCMP paths");

    crypto::public_key main_address_spend_pubkeys_arr[2];
    const epee::span<const crypto::public_key> main_address_spend_pubkeys =
        get_all_main_address_spend_pubkeys_span(*addr_dev, main_address_spend_pubkeys_arr);

    // derive amount openings [(a, z), ...] where C = z G + a H
    boost::multiprecision::uint128_t input_amount_total = 0;
    rct::key amount_blinding_factor_sum{};
    std::vector<std::pair<rct::xmr_amount, rct::key>> amount_openings;
    amount_openings.reserve(n_inputs);
    for (const OutputOpeningHintVariant &opening_hint : opening_hints)
    {
        auto &amount_opening = amount_openings.emplace_back();
        CARROT_CHECK_AND_THROW(try_scan_opening_hint_amount(opening_hint,
                main_address_spend_pubkeys,
                k_view_incoming_dev.get(),
                s_view_balance_dev.get(),
                amount_opening.first,
                amount_opening.second),
            unexpected_scan_failure,
            "Failed to scan for amount opening");
        input_amount_total += amount_opening.first;
        sc_add(amount_blinding_factor_sum.bytes, amount_blinding_factor_sum.bytes, amount_opening.second.bytes);
    }

    // check amount
    CARROT_CHECK_AND_THROW(input_amount_total >= threshold_amount,
        too_few_inputs, "Not enough money in inputs for threshold amount");
    CARROT_CHECK_AND_THROW(input_amount_total - threshold_amount <= std::numeric_limits<rct::xmr_amount>::max(),
        too_many_inputs, "Too much money in inputs for threshold amount");
    const rct::xmr_amount remaining_amount = boost::numeric_cast<rct::xmr_amount>(input_amount_total - threshold_amount);

    // form key image device
    const auto k_generate_image_dev = std::make_shared<generate_image_key_ram_borrowed_device>(privkey_g);
    key_image_device_composed key_image_dev(k_generate_image_dev,
        addr_dev,
        s_view_balance_dev,
        k_view_incoming_dev);

    // derive key images
    std::vector<crypto::key_image> input_key_images;
    input_key_images.reserve(n_inputs);
    for (const OutputOpeningHintVariant &opening_hint : opening_hints)
        input_key_images.push_back(key_image_dev.derive_key_image(opening_hint));

    // sort data in key image order
    std::vector<std::size_t> key_image_order;
    key_image_order.reserve(n_inputs);
    for (std::size_t i = 0; i < n_inputs; ++i)
        key_image_order.push_back(i);
    std::sort(key_image_order.begin(), key_image_order.end(),
        [&input_key_images](const std::size_t a, const std::size_t b)
        {
            return input_key_images.at(a) > input_key_images.at(b);
        }
    );
    tools::apply_permutation(key_image_order, opening_hints);
    tools::apply_permutation(key_image_order, input_paths);
    tools::apply_permutation(key_image_order, amount_openings);
    tools::apply_permutation(key_image_order, input_key_images);

    // rerandomize inputs
    std::vector<FcmpRerandomizedOutputCompressed> rerandomized_inputs;
    rerandomized_inputs.reserve(n_inputs);
    for (std::size_t input_idx = 0; input_idx < n_inputs; ++input_idx)
    {
        const crypto::public_key onetime_address = onetime_address_ref(opening_hints.at(input_idx));

        // copy O, I, C
        fcmp_pp::OutputBytes output_bytes{};
        memcpy(&output_bytes.O_bytes, onetime_address.data, sizeof(onetime_address));
        crypto::ec_point I;
        crypto::derive_key_image_generator(onetime_address, I);
        memcpy(&output_bytes.I_bytes, I.data, sizeof(I));
        memcpy(&output_bytes.C_bytes, amount_commitment_ref(opening_hints.at(input_idx)).bytes, sizeof(rct::key));

        // rerandomize
        FcmpRerandomizedOutputCompressed rerandomized_output = fcmp_pp::rerandomize_output(output_bytes);
        rerandomized_inputs.push_back(rerandomized_output);

        // k_rem += r_c
        sc_add(amount_blinding_factor_sum.bytes, amount_blinding_factor_sum.bytes, rerandomized_output.r_c);
        // k_i += r_c
        rct::key &individual_amount_opening = amount_openings.at(input_idx).second;
        sc_add(individual_amount_opening.bytes, individual_amount_opening.bytes, rerandomized_output.r_c);
    }

    // make prefix hash
    const crypto::hash prefix_hash = get_reserve_proof_prefix_hash(threshold_amount, input_key_images);

    // collect [C~, ...]
    std::vector<rct::key> rerandomized_amount_commitments;
    rerandomized_amount_commitments.reserve(n_inputs);
    for (const FcmpRerandomizedOutputCompressed &rerandomized_input : rerandomized_inputs)
    {
        rct::key &rerandomized_amount_commitment = rerandomized_amount_commitments.emplace_back();
        memcpy(rerandomized_amount_commitment.bytes, rerandomized_input.input.C_tilde, sizeof(rct::key));
    }

    // make C_rem
    const rct::key C_rem_prover = rct::commit(remaining_amount, amount_blinding_factor_sum);
    rct::key C_rem_validator;
    CARROT_CHECK_AND_THROW(get_reserve_proof_remaining_commitment(
            threshold_amount, rerandomized_amount_commitments, C_rem_validator),
        invalid_point, "Rerandomized input C~ failed to decompress");
    CARROT_CHECK_AND_THROW(C_rem_prover == C_rem_validator,
        invalid_point, "Failed to re-compute C_rem the same as a validator");

    // make C_rem range proof
    rct::BulletproofPlus bpp = rct::bulletproof_plus_PROVE(remaining_amount, amount_blinding_factor_sum);

    // make SA/Ls
    std::vector<fcmp_pp::FcmpPpSalProof> sal_proofs;
    sal_proofs.reserve(n_inputs);
    for (std::size_t input_idx = 0; input_idx < n_inputs; ++input_idx)
    {
        const OutputOpeningHintVariant &opening_hint = opening_hints.at(input_idx);

        // x = (k_g + k^j_subext) * k^j_subscal
        // y = k_t * k^j_subscal
        crypto::secret_key x;
        crypto::secret_key y;
        addr_dev->get_address_openings(subaddress_index_ref(opening_hint), x, y);
        sc_add(to_bytes(x), to_bytes(x), to_bytes(privkey_g));
        sc_mul(to_bytes(x), to_bytes(x), to_bytes(y));
        sc_mul(to_bytes(y), to_bytes(y), to_bytes(privkey_t));

        // x += k^g_o
        // y += k^t_o
        crypto::secret_key sender_extension_g;
        crypto::secret_key sender_extension_t;
        CARROT_CHECK_AND_THROW(try_scan_opening_hint_sender_extensions(opening_hint,
                main_address_spend_pubkeys,
                k_view_incoming_dev.get(),
                s_view_balance_dev.get(),
                sender_extension_g, sender_extension_t),
            unexpected_scan_failure, "Failed to scan for one-time opening");
        sc_add(to_bytes(x), to_bytes(x), to_bytes(sender_extension_g));
        sc_add(to_bytes(y), to_bytes(y), to_bytes(sender_extension_t));

        // sign
        fcmp_pp::FcmpPpSalProof &sal_proof = sal_proofs.emplace_back();
        crypto::key_image recomputed_key_image;
        std::tie(sal_proof, recomputed_key_image) = fcmp_pp::prove_sal(prefix_hash, x, y, rerandomized_inputs.at(input_idx));
        CARROT_CHECK_AND_THROW(recomputed_key_image == input_key_images.at(input_idx),
            invalid_point, "FCMP++ SA/L proving code returned different key image than key image device");
    }

    // prove FCMP membership using given paths
    std::vector<fcmp_pp::FcmpPpProveMembershipInput> fcmp_membership_inputs;
    fcmp_membership_inputs.reserve(n_inputs);
    for (std::size_t input_idx = 0; input_idx < n_inputs; ++input_idx)
    {
        MDEBUG("Generating blinds for path " << (input_idx+1)
            << "/" << n_inputs << " with n_tree_layers=" << static_cast<int>(n_tree_layers));
        const auto path_blinds = get_path_blinds(rerandomized_inputs.at(input_idx), n_tree_layers);
        fcmp_membership_inputs.push_back(fcmp_pp::fcmp_pp_prove_input_new(
            input_paths.at(input_idx),
            std::get<0>(path_blinds),
            std::get<1>(path_blinds),
            std::get<2>(path_blinds)));
    }
    const fcmp_pp::FcmpMembershipProof membership_proof = fcmp_pp::prove_membership(fcmp_membership_inputs, n_tree_layers);

    // format SA/Ls and FCMPs into FCMP++s
    fcmp_pp::FcmpPpProof fcmp_pp = fcmp_pp::fcmp_pp_proof_from_parts_v1(rerandomized_inputs,
        sal_proofs,
        membership_proof,
        n_tree_layers);

    reserve_proof_out = FcmpReserveProof{
        .threshold_amount = threshold_amount,
        .key_images = std::move(input_key_images),
        .rerandomized_amount_commitments = std::move(rerandomized_amount_commitments),
        .reference_block = reference_block,
        .n_tree_layers = n_tree_layers,
        .fcmp_pp = std::move(fcmp_pp),
        .bpp = std::move(bpp)
    };
}
//-------------------------------------------------------------------------------------------------------------------
bool check_fcmp_reserve_proof_non_exclusion(const FcmpReserveProof &reserve_proof,
    const fcmp_pp::TreeRootShared &fcmp_tree_root)
{
    const std::size_t n_inputs = reserve_proof.key_images.size();
    CHECK_AND_ASSERT_MES(reserve_proof.rerandomized_amount_commitments.size() == n_inputs,
        false, "Reserve proof wrong number of rerandomized amount commitments");

    // make C_rem
    rct::key C_rem;
    CHECK_AND_ASSERT_MES(get_reserve_proof_remaining_commitment(
            reserve_proof.threshold_amount,
            reserve_proof.rerandomized_amount_commitments,
            C_rem),
        false, "Reserve proof remaining amount commitment calculation failed");

    // expand BP+ and check range over C_rem
    rct::BulletproofPlus bpp = reserve_proof.bpp;
    bpp.V = {rct::scalarmultKey(C_rem, rct::INV_EIGHT)}; // IMPORTANT: do not let user specify V
    CHECK_AND_ASSERT_MES(rct::bulletproof_plus_VERIFY(bpp),
        false, "Reserve proof's range proof verification failed");

    // make prefix hash
    const crypto::hash prefix_hash = get_reserve_proof_prefix_hash(reserve_proof.threshold_amount,
        reserve_proof.key_images);

    // collect rerandomized_amount_commitments as crypto::ec_point's
    std::vector<crypto::ec_point> rerandomized_amount_commitments;
    rerandomized_amount_commitments.reserve(n_inputs);
    for (const rct::key &rerandomized_amount_commitment : reserve_proof.rerandomized_amount_commitments)
        rerandomized_amount_commitments.push_back(rct::rct2pt(rerandomized_amount_commitment));

    // check FCMP++
    const bool ver = fcmp_pp::verify(prefix_hash,
        reserve_proof.fcmp_pp,
        reserve_proof.n_tree_layers,
        fcmp_tree_root,
        rerandomized_amount_commitments,
        reserve_proof.key_images);
    CHECK_AND_ASSERT_MES(ver, false, "Reserve proof's FCMP++ verification failed");

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(FcmpReserveProof)
    VERSION_FIELD(3)
    // a
    VARINT_FIELD_F(threshold_amount)
    // [L]
    FIELD_F(key_images)
    const std::size_t n_inputs = v.key_images.size();
    // [C~]
    PREPARE_CUSTOM_VECTOR_SERIALIZATION(n_inputs, v.rerandomized_amount_commitments);
    if (v.rerandomized_amount_commitments.size() != n_inputs)
        return false;
    ar.tag("rerandomized_amount_commitments");
    ar.begin_array();
    bool first = true;
    for (rct::key &rerandomized_amount_commitment : v.rerandomized_amount_commitments)
    {
        if (!first)
            ar.delimit_array();
        FIELDS(rerandomized_amount_commitment)
    }
    ar.end_array();
    // reference_block, n_tree_layers
    VARINT_FIELD_F(reference_block)
    FIELD_F(n_tree_layers)
    // FCMP++
    ar.tag("fcmp_pp");
    if (n_inputs == 0)
        return false;
    if (n_inputs > FCMP_PLUS_PLUS_MAX_INPUTS)
        return false;
    if (v.n_tree_layers == 0)
        return false;
    if (v.n_tree_layers > FCMP_PLUS_PLUS_MAX_LAYERS)
        return false;
    const std::size_t proof_len = fcmp_pp::fcmp_pp_proof_len(n_inputs, v.n_tree_layers);
    if (!typename Archive<W>::is_saving())
        v.fcmp_pp.resize(proof_len);
    if (v.fcmp_pp.size() != proof_len)
        return false;
    ar.serialize_blob(v.fcmp_pp.data(), proof_len);
    if (!ar.good())
        return false;
    // BP+
    ar.tag("bpp");
    if (!serialize_bpp_exact_outputs(ar, v.bpp, 1))
        return false;
END_SERIALIZE()
template bool do_serialize_object<true, binary_archive>(binary_archive<true> &ar, FcmpReserveProof &v);
template bool do_serialize_object<false, binary_archive>(binary_archive<false> &ar, FcmpReserveProof &v);
//-------------------------------------------------------------------------------------------------------------------
} //namespace carrot
