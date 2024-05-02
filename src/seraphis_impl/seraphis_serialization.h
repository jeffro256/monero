// Copyright (c) 2024, The Monero Project
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

// Serialization implementations for seraphis transaction components and transactions.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_crypto/math_utils.h"
#include "seraphis_crypto/sp_legacy_proof_helpers.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/serialization.h"
#include "seraphis_main/txtype_coinbase_v1.h"
#include "seraphis_main/txtype_squashed_v1.h"

//third party headers

//standard headers

//forward declarations

namespace sp
{
namespace serialization
{
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
template <bool W, template <bool> class Archive, typename ValueType, typename... Args>
bool do_serialize_vec_exact(Archive<W> &ar, std::vector<ValueType> &v, const size_t implied_size,
    Args&&... args)
{
    // sanity check: there cannot be more elements remaining than bytes
    if constexpr (!W)
    {
        if (implied_size > ar.remaining_bytes())
            return false;
    }

    if (v.size() != implied_size)
    {
        if constexpr (W)
            return false;
        else
            v.resize(implied_size);
    }

    ar.begin_array();

    // Serialize each element
    for (size_t i{0}; i < v.size(); ++i)
    {
        if (i)
            ar.delimit_array();
        if (!do_serialize(ar, v[i], args...))
            return false;
    }

    ar.end_array();
    return ar.good();
}
} // namespace serialization
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
#define VEC_FIELD_EXACT_F(f, s, ...)                                     \
    do {                                                                 \
        ar.tag(#f);                                                      \
        const bool dsve_res{::sp::serialization::do_serialize_vec_exact( \
                ar, v.f, s VA_ARGS_COMMAPREFIX(__VA_ARGS__))};           \
        if (!dsve_res || !ar.good()) return false;                       \
    } while (0);
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
#define VEC_FIELD_OPT_EXACT_F(f, s, ...) \
    if (s == SIZE_MAX)                   \
        FIELD_F(f)                       \
    else if (s < 1024)                   \
        VEC_FIELD_EXACT_F(f, s)          \
    else                                 \
        return false;
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_FN(DiscretizedFee)
    static_assert(sizeof(v.fee_encoding) == 1, "should use a varint if int size != 1");
    FIELDS(v.fee_encoding)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpCoinbaseEnoteCore)
    FIELD_F(onetime_address)
    VARINT_FIELD_F(amount)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpEnoteCore)
    FIELD_F(onetime_address)
    FIELD_F(amount_commitment)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpEnoteImageCore)
    FIELD_F(masked_address)
    FIELD_F(masked_commitment)
    FIELD_F(key_image)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(BulletproofPlus2Proof, const size_t implied_lr_size = SIZE_MAX)
    FIELD_F(A)
    FIELD_F(A1)
    FIELD_F(B)
    FIELD_F(r1)
    FIELD_F(s1)
    FIELD_F(d1)
    VEC_FIELD_OPT_EXACT_F(L, implied_lr_size)
    VEC_FIELD_OPT_EXACT_F(R, implied_lr_size)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyClsagProof, const size_t implied_s_size = SIZE_MAX)
    VEC_FIELD_OPT_EXACT_F(s, implied_s_size)
    FIELD_F(c1)
    FIELD_F(D)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpCompositionProof)
    FIELD_F(c)
    FIELD_F(r_t1)
    FIELD_F(r_t2)
    FIELD_F(r_ki)
    FIELD_F(K_t1)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(GrootleProof)
    FIELD_F(A)
    FIELD_F(B)
    FIELD_F(f) // @TODO: sizeless f serialization
    FIELD_F(X) // @TODO: sizeless X serialization
    FIELD_F(zA)
    FIELD_F(z)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyEnoteImageV2)
    FIELD_F(masked_commitment)
    FIELD_F(key_image)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpEnoteImageV1)
    FIELD_F(core)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpCoinbaseEnoteV1)
    FIELD_F(core)
    FIELD_F(addr_tag_enc)
    VARINT_FIELD_F(view_tag)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpEnoteV1)
    FIELD_F(core)
    FIELD_F(encoded_amount)
    FIELD_F(addr_tag_enc)
    VARINT_FIELD_F(view_tag)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpBalanceProofV1, const size_t implied_lr_size = SIZE_MAX)
    FIELD_F(bpp2_proof, implied_lr_size)
    FIELD_F(remainder_blinding_factor)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyRingSignatureV4, const size_t implied_ring_size = SIZE_MAX)
    FIELD_F(clsag_proof, implied_ring_size)
    // @TODO: accumlate/decumulate CLSAG ref set offsets
    VEC_FIELD_OPT_EXACT_F(reference_set, implied_ring_size)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpImageProofV1)
    // @TODO: sizeless f, X serialization
    FIELD_F(composition_proof)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpMembershipProofV1, const size_t implied_num_bins = SIZE_MAX)
    FIELD_F(grootle_proof)
    VEC_FIELD_OPT_EXACT_F(bin_loci, implied_num_bins)
    VARINT_FIELD_F(bin_rotation_factor)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpTxSupplementV1, const size_t implied_num_outputs = SIZE_MAX)
    const size_t implied_num_ephem_pubkeys{(2 == implied_num_outputs) ? 1 : implied_num_outputs};
    VEC_FIELD_OPT_EXACT_F(output_enote_ephemeral_pubkeys, implied_num_ephem_pubkeys)
    FIELD_F(tx_extra)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpTxCoinbaseV1)
    VARINT_FIELD_F(tx_semantic_rules_version)
    VARINT_FIELD_F(block_height)
    FIELD_F(outputs)
    FIELD_F(tx_supplement, v.outputs.size())
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpTxSquashedV1)
    VARINT_FIELD_F(tx_semantic_rules_version)

    FIELD_F(legacy_input_images)
    FIELD_F(sp_input_images)
    FIELD_F(outputs)

    const size_t num_legacy_inputs   = v.legacy_input_images.size();
    const size_t num_sp_inputs       = v.sp_input_images.size();
    const size_t num_outputs         = v.outputs.size();
    const size_t num_range_proofs    = num_sp_inputs + num_outputs;
    const size_t implied_bpp_lr_size = bpp_lr_length(num_range_proofs);

    FIELD_F(balance_proof, implied_bpp_lr_size)

    size_t clsag_ring_size = v.legacy_ring_signatures.size() ?
        v.legacy_ring_signatures[0].reference_set.size() : 0;
    VARINT_FIELD(clsag_ring_size)

    VEC_FIELD_EXACT_F(legacy_ring_signatures, num_legacy_inputs, clsag_ring_size)
    VEC_FIELD_EXACT_F(sp_image_proofs, num_sp_inputs)

    // we can skip storing # of bins by calcing (n^m)/num_bin_members if using static config
    size_t num_bins{SIZE_MAX};
    if (v.tx_semantic_rules_version != SpTxSquashedV1::SemanticRulesVersion::MOCK)
    {
        const SemanticConfigSpRefSetV1 sp_ref_set_config{
            static_semantic_config_sp_ref_sets_v1(v.tx_semantic_rules_version)
        };
        num_bins = math::uint_pow(sp_ref_set_config.decomp_n, sp_ref_set_config.decomp_m)
            / sp_ref_set_config.num_bin_members;
    }

    VEC_FIELD_EXACT_F(sp_membership_proofs, num_sp_inputs, num_bins)
    FIELD_F(tx_supplement, num_outputs)
    FIELD_F(tx_fee)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
namespace jamtis
{
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(JamtisDestinationV1)
    FIELD_F(addr_K1)
    FIELD_F(addr_K2)
    FIELD_F(addr_K3)
    FIELD_F(addr_tag)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(JamtisPaymentProposalV1)
    FIELD_F(destination)
    FIELD_F(amount)
    FIELD_F(enote_ephemeral_privkey)
    FIELD_F(partial_memo)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(JamtisPaymentProposalSelfSendV1)
    FIELD_F(destination)
    FIELD_F(amount)
    VARINT_FIELD_F(type)
    FIELD_F(enote_ephemeral_privkey)
    FIELD_F(partial_memo)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
} // namespace jamtis
} // namespace sp

BLOB_SERIALIZER(sp::jamtis::address_index_t);
BLOB_SERIALIZER(sp::jamtis::address_tag_t);
BLOB_SERIALIZER(sp::jamtis::encoded_amount_t);
