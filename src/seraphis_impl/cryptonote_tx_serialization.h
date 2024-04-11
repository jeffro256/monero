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

//local headers
#include "monero_tx_type.h"
#include "seraphis_serialization.h"

//third party headers

//standard headers

//forward declarations

namespace sp
{
template <bool W, template <bool> class Archive, class Cont, class ElementSerializer>
bool do_serialize_seq_exact(Archive<W> &ar, Cont &v, ElementSerializer &&el_ser_f,
    const char * const tag = nullptr, const size_t enforce_size = (size_t)-1)
{
    if (enforce_size != (size_t)-1)
    {
        if constexpr (!W && std::is_same_v<Cont, std::vector<typename Cont::value_type>>)
            v.resize(enforce_size); // if loading into vector, resize to correct size
        else if (v.size() != enforce_size)
            return false; // otherwise if the container is the wrong size, then fail
    }

    if (tag)
        ar.tag(tag);

    bool first = true;
    ar.begin_array();
    for (auto &el : v)
    {
        if (!first)
            ar.delimit_array();
        if (!el_ser_f(ar, el))
            return false;
        first = false;
    }
    ar.end_array();
    return ar.good();
}

template <bool W, template <bool> class Archive, class Cont>
bool do_serialize_seq_exact(Archive<W> &ar, Cont &v, const char * const tag = nullptr,
    const size_t enforce_size = (size_t)-1)
{
    return do_serialize_seq_exact(ar, v,
        [](Archive<W> &ar, typename Cont::value_type &el) -> bool { return do_serialize(ar, el); },
        tag, enforce_size);
}

template <bool W, template <bool> class Archive>
bool do_serialize_mlsag(Archive<W> &ar,
    RingCTMlsag &mlsag,
    const size_t ring_size,
    const size_t num_inputs,
    const bool simple)
{
    // 1. check/prepare dimensions
    const size_t num_cols = simple ? 2 : num_inputs + 1;
    const size_t ss_size = ring_size * num_cols;
    if (!W)
        mlsag.ss.resize(ss_size);
    else if (mlsag.ss.size() != ss_size)
        return false;

    // 2. begin object
    ar.begin_object();

    // 3. serialize ss matrix. we do this manually so we're not serializing size info
    ar.tag("ss");
    ar.begin_array();
    for (size_t n = 0; n < mlsag.ss.size(); ++n)
    {
        if (n % num_cols == 0 && n)
            ar.delimit_array();
        if (n % num_cols == 0)
            ar.begin_array();
        else
            ar.delimit_array();
        if (!do_serialize(ar, mlsag.ss[n]))
            return false;
        if (n % num_cols == num_cols - 1)
            ar.end_array();
    }
    ar.end_array();

    // 4. serialize cc
    FIELD_N("cc", mlsag.cc)

    // 5. finish object
    ar.end_object();
    return ar.good();
}

template <bool W, template <bool> class Archive>
bool do_serialize_clsag(Archive<W> &ar,
    RingCTClsag &clsag,
    const size_t ring_size)
{
    // 1. begin object
    ar.begin_object();

    // 2. serialize s vector. we do this manually so we're not serializing size info
    if (!do_serialize_seq_exact(ar, clsag.s, "s", ring_size))
        return false;

    // 3. serialize c1
    FIELD_N("c1", clsag.c1);

    // 4. serialize D
    FIELD_N("D", clsag.D);

    // 5. finish object;
    ar.end_object();
    return ar.good();
}

BEGIN_SERIALIZE_OBJECT_FN(RingCTBulletproof)
    FIELD_F(A)
    FIELD_F(S)
    FIELD_F(T1)
    FIELD_F(T2)
    FIELD_F(taux)
    FIELD_F(mu)
    FIELD_F(L)
    FIELD_F(R)
    FIELD_F(a)
    FIELD_F(b)
    FIELD_F(t)
    if (v.L.empty() || v.L.size() != v.R.size())
        return false;
END_SERIALIZE()

BEGIN_SERIALIZE_OBJECT_FN(RingCTBulletproofPlus)
    FIELD_F(A)
    FIELD_F(A1)
    FIELD_F(B)
    FIELD_F(r1)
    FIELD_F(s1)
    FIELD_F(d1)
    FIELD_F(L)
    FIELD_F(R)
    if (v.L.empty() || v.L.size() != v.R.size())
        return false;
END_SERIALIZE()

template <typename T> struct is_tagged_enote: std::false_type {};
template<> struct is_tagged_enote<LegacyEnoteV4>: std::true_type {};
template<> struct is_tagged_enote<LegacyEnoteV5>: std::true_type {};

template <typename T> struct is_confidential_enote: std::false_type {};
template<> struct is_confidential_enote<LegacyEnoteV2>: std::true_type {};
template<> struct is_confidential_enote<LegacyEnoteV3>: std::true_type {};
template<> struct is_confidential_enote<LegacyEnoteV5>: std::true_type {};

template <bool W, class LegacyEnote>
bool adapt_txout(LegacyEnote &enote, cryptonote::tx_out &out)
{
    // A double visitor would be really nice right about now

    if constexpr (is_confidential_enote<LegacyEnote>())
    {
        if (W)
            out.amount = 0;
        else if (out.amount)
            return false;
    }
    else
    {
        if constexpr (W)
            out.amount = enote.amount;
        else
            enote.amount = out.amount;
    }

    if constexpr (is_tagged_enote<LegacyEnote>())
    {
        if constexpr (W)
        {
            out.target = cryptonote::txout_to_tagged_key(rct::rct2pk(enote.onetime_address), enote.view_tag);
        }
        else
        {
            if (out.target.type() != typeid(cryptonote::txout_to_tagged_key))
                return false;
            enote.onetime_address = rct::pk2rct(boost::get<cryptonote::txout_to_tagged_key>(out.target).key);
            enote.view_tag = boost::get<cryptonote::txout_to_tagged_key>(out.target).view_tag;
        }
    }
    else
    {
        if constexpr (W)
        {
            out.target = cryptonote::txout_to_key(rct::rct2pk(enote.onetime_address));
        }
        else
        {
            if (out.target.type() != typeid(cryptonote::txout_to_key))
                return false;
            enote.onetime_address = rct::pk2rct(boost::get<cryptonote::txout_to_key>(out.target).key);
        }
    }
    return true;
}

template <bool W, class LegacyEnoteVec>
bool adapt_vout(LegacyEnoteVec &enotes, std::vector<cryptonote::tx_out> &vout)
{
    if constexpr (W)
        vout.resize(enotes.size());
    else
        enotes.resize(vout.size());

    for (size_t i = 0; i < enotes.size(); ++i)
        if (!adapt_txout<W>(enotes[i], vout[i]))
            return false;

    return true;
}

template <bool W>
bool adapt_vout_clearamount(LegacyClearAmountTxOutputList &enotes, std::vector<cryptonote::tx_out> &vout)
{
    if constexpr (!W)
        enotes = std::vector<LegacyEnoteV4>(vout.size());
    const bool res1 = enotes.visit([&vout](auto& ev) { return adapt_vout<W>(ev, vout); });
    if (W || res1)
        return res1;
    enotes = std::vector<LegacyEnoteV1>(vout.size());
    return enotes.visit([&vout](auto& ev) { return adapt_vout<W>(ev, vout); });
}

template <bool W, template <bool> class Archive>
bool do_serialize_vout_ecdh_el(Archive<W> &ar, LegacyEnoteV2 &enote)
{
    ar.begin_object();
    FIELD_N("mask", enote.encoded_amount_blinding_factor);
    FIELD_N("amount", enote.encoded_amount);
    ar.end_object();
    return ar.good();
}

template <bool W, template <bool> class Archive, class CompactECDHEnote>
bool do_serialize_vout_ecdh_el(Archive<W> &ar, CompactECDHEnote &enote)
{
    static_assert(sizeof(enote.encoded_amount) == 8, "truncated/Jamtis amount wrong size");

    ar.begin_object();
    ar.tag("trunc_amount");
    ar.serialize_blob(&enote.encoded_amount, 8);
    ar.end_object();
    return ar.good();
}

template <bool W, template <bool> class Archive, class RingCTBody>
bool do_serialize_rct_base(Archive<W> &ar, RingCTBody& rct_body, const size_t num_inputs,
    const size_t num_outputs, std::vector<cryptonote::tx_out> &prefix_vout_src)
{
    static constexpr std::uint8_t RCT_TYPE = RingCTBody::rct_type;

    if constexpr (RCT_TYPE == rct::RCTTypeSimple)
    {
        if (!do_serialize_seq_exact(ar, rct_body.pseudo_commitments, "pseudoOuts", num_inputs))
            return false;
    }

    if (!W && !adapt_vout<false>(rct_body.vout, prefix_vout_src))
        return false;

    if (!do_serialize_seq_exact(ar, rct_body.vout, [](Archive<W> &ar, auto &en) -> bool {
        return do_serialize_vout_ecdh_el(ar, en);
    }, "ecdhInfo", num_outputs))
        return false;

    return do_serialize_seq_exact(ar, rct_body.vout, [](Archive<W> &ar, auto &en) -> bool {
        return do_serialize(ar, en.amount_commitment);
    }, "outPk", num_outputs);
}

template <bool W, template <bool> class Archive>
bool do_serialize_rct_base(Archive<W> &ar, RingCTBodyVariant &rct_body, rct::xmr_amount &txn_fee,
    const size_t num_inputs, const size_t num_outputs, std::vector<cryptonote::tx_out> &prefix_vout)
{
    ar.tag("rct_signatures");
    ar.begin_object();

    uint8_t type = ringct_type(rct_body);
    FIELD(type);
    if (type == rct::RCTTypeNull || type > rct::RCTTypeBulletproofPlus)
        return false;

    VARINT_FIELD_N("txnFee", txn_fee);

    if (!W)
    {
        const std::uint8_t variant_index = type - 1;
        rct_body.value_initialize_to_type_index(variant_index);
    }
    if (!rct_body.visit([&ar, num_inputs, num_outputs, &prefix_vout](auto &body) -> bool
            { return do_serialize_rct_base(ar, body, num_inputs, num_outputs, prefix_vout); }))
        return false;
    
    ar.end_object();
    return ar.good();
}

template <bool W, template <bool> class Archive, class RingCTBody>
bool do_serialize_rct_prunable(Archive<W> &ar, RingCTBody& rct_body, const size_t num_inputs,
    const size_t num_outputs, const size_t ring_size)
{
    static constexpr std::uint8_t RCT_TYPE = RingCTBody::rct_type;

    ar.tag("rctsig_prunable");
    ar.begin_object();

    // Balance proofs
    static constexpr bool HAS_BORO_SIGS = RCT_TYPE && RCT_TYPE < rct::RCTTypeBulletproof;
    static constexpr bool HAS_BP_PLUS = RCT_TYPE == rct::RCTTypeBulletproofPlus;
    static constexpr bool HAS_BP = !HAS_BORO_SIGS && !HAS_BP_PLUS && RCT_TYPE;
    if constexpr (HAS_BP_PLUS)
    {
        uint32_t nbp = rct_body.bulletproofs_plus.size();
        VARINT_FIELD(nbp)

        if (!do_serialize_seq_exact(ar, rct_body.bulletproofs_plus, "bpp", nbp))
            return false;
    }
    else if constexpr (HAS_BP)
    {
        uint32_t nbp = rct_body.bulletproofs.size();
        if constexpr (RCT_TYPE != rct::RCTTypeBulletproof)
            VARINT_FIELD(nbp)
        else
            FIELD(nbp)

        if (!do_serialize_seq_exact(ar, rct_body.bulletproofs, "bp", nbp))
            return false;
    }
    else if constexpr (HAS_BORO_SIGS)
    {
        if (!do_serialize_seq_exact(ar, rct_body.range_sigs, "rangeSigs", num_outputs))
            return false;
    }

    // Ring signatures
    static constexpr bool HAS_CLSAG = RCT_TYPE >= rct::RCTTypeCLSAG;
    static constexpr bool HAS_MLSAG_FULL = RCT_TYPE == rct::RCTTypeFull;
    if constexpr (HAS_CLSAG)
    {
        if (!do_serialize_seq_exact(ar, rct_body.clsags, [ring_size](Archive<W> &ar, RingCTClsag &clsag) -> bool {
                return do_serialize_clsag(ar, clsag, ring_size); }, "CLSAGs", num_inputs))
            return false;
    }
    else if constexpr (HAS_MLSAG_FULL)
    {
        ar.tag("MGs");
        ar.begin_array();
        if (!do_serialize_mlsag(ar, rct_body.mlsag_full, ring_size, num_inputs, false))
            return false;
        ar.end_array();
    }
    else // simple mlsag
    {
        if (!do_serialize_seq_exact(ar, rct_body.mlsags_simple,
                [ring_size](Archive<W> &ar, auto &mlsag) -> bool {
                    return do_serialize_mlsag(ar, mlsag, ring_size, 0, true);
                }, "MGs", num_inputs))
            return false;
    }

    // Pseudo output commitments
    static constexpr bool HAS_PRUNABLE_PSEUDO_OUTS = !HAS_BORO_SIGS && RCT_TYPE;
    if constexpr (HAS_PRUNABLE_PSEUDO_OUTS)
    {
        if (!do_serialize_seq_exact(ar, rct_body.pseudo_commitments, "pseudoOuts", num_inputs))
            return false;
    }

    ar.end_object();
    return ar.good();
}

struct cn_txprefix_nver
{
    // version is handled elsewhere
    uint64_t unlock_time;
    std::vector<cryptonote::txin_v> vin;
    std::vector<cryptonote::tx_out> vout;
    std::vector<uint8_t> extra;

    BEGIN_SERIALIZE()
        VARINT_FIELD(unlock_time)
        FIELD(vin)
        FIELD(vout)
        FIELD(extra)
    END_SERIALIZE()
};

template <template <bool> class Archive>
bool do_serialize_cryptonote_tx(Archive<false> &ar, MoneroTxVariant &tx, const bool pruned,
    const bool v2)
{
    cn_txprefix_nver tx_prefix;
    FIELDS(tx_prefix);

    const size_t num_inputs = tx_prefix.vin.size();
    if (!num_inputs)
        return false;

    const bool is_coinbase = num_inputs == 1 && tx_prefix.vin[0].type() == typeid(cryptonote::txin_gen);
    const uint64_t coinbase_height = is_coinbase ? boost::get<cryptonote::txin_gen>(tx_prefix.vin[0]).height : 0;
    if (is_coinbase && tx_prefix.unlock_time != coinbase_height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW)
        return false;

    std::vector<cryptonote::txin_to_key> non_coinbase_vin;
    non_coinbase_vin.reserve(num_inputs);
    if (!is_coinbase)
    {
        for (const auto &txin : tx_prefix.vin)
        {
            if (txin.type() != typeid(cryptonote::txin_to_key))
                return false;
            non_coinbase_vin.push_back(boost::get<cryptonote::txin_to_key>(txin));
        }
    }

    if (v2)
    {
        if (is_coinbase)
        {
            LegacyClearAmountTxOutputList vout;
            if (!adapt_vout_clearamount<false>(vout, tx_prefix.vout))
                return false;

            std::uint8_t rct_type;
            VARINT_FIELD_N("type", rct_type);
            if (rct_type != rct::RCTTypeNull)
                return false;

            tx = RingCTTxCoinbaseV2 {
                .height = coinbase_height,
                .vout = std::move(vout),
                .extra = std::move(tx_prefix.extra)
            };
        }
        else // v2 non-coinbase
        {
            const size_t nouts = tx_prefix.vout.size();

            rct::xmr_amount txn_fee;
            RingCTBodyVariant rct_body;
            if (!do_serialize_rct_base(ar, rct_body, txn_fee, num_inputs, nouts, tx_prefix.vout))
                return false;

            const size_t ring_size = non_coinbase_vin[0].key_offsets.size();
            if (!pruned && !rct_body.visit([&ar, num_inputs, nouts, ring_size](auto &b)
                    { return do_serialize_rct_prunable(ar, b, num_inputs, nouts, ring_size); }))
                return false;

            tx = RingCTTxV2 {
                .unlock_time = tx_prefix.unlock_time,
                .vin = std::move(non_coinbase_vin),
                .extra = std::move(tx_prefix.extra),
                .fee = txn_fee,
                .body = std::move(rct_body)
            };
        }
    }
    else // v1
    {
        if (is_coinbase)
        {
            std::vector<LegacyEnoteV1> vout;
            if (!adapt_vout<false>(vout, tx_prefix.vout))
                return false;

            tx = CryptonoteTxCoinbaseV1 {
                .height = coinbase_height,
                .vout = std::move(vout),
                .extra = std::move(tx_prefix.extra)
            };
        }
        else // v1 non-coinbase
        {
            LegacyClearAmountTxOutputList vout;
            if (!adapt_vout_clearamount<false>(vout, tx_prefix.vout))
                return false;

            // We create a pre-sized jagged array for signatures before serializing because of the
            // custom do_serialize() free function in serialization/crypto.h which takes existing
            // size into account.
            std::vector<std::vector<crypto::signature>> signatures;
            if (!pruned)
            {
                signatures.resize(num_inputs);
                for (size_t i = 0; i < num_inputs; ++i)
                    signatures[i].resize(non_coinbase_vin[i].key_offsets.size());

                if (!do_serialize_seq_exact(ar, signatures, "signatures", num_inputs))
                    return false;
            }

            tx = CryptonoteTxV1 {
                .unlock_time = tx_prefix.unlock_time,
                .vin = std::move(non_coinbase_vin),
                .vout = std::move(vout),
                .extra = std::move(tx_prefix.extra),
                .signatures = std::move(signatures)
            };
        }
    }

    return true;
}

struct get_vout_visitor: tools::variant_static_visitor<std::vector<cryptonote::tx_out>>
{
    result_type operator()(CryptonoteTxCoinbaseV1 &cnv1cb) const
    { result_type vout; adapt_vout<true>(cnv1cb.vout, vout); return vout; }
    result_type operator()(CryptonoteTxV1 &cnv1) const
    { result_type vout; adapt_vout_clearamount<true>(cnv1.vout, vout); return vout; }
    result_type operator()(RingCTTxCoinbaseV2 &rctv2cb) const
    { result_type vout; adapt_vout_clearamount<true>(rctv2cb.vout, vout); return vout; }
    result_type operator()(RingCTTxV2 &rctv2) const
    {
        result_type vout;
        rctv2.body.visit([&vout](auto &b) { adapt_vout<true>(b.vout, vout); });
        return vout;
    }
    result_type operator()(SpTxCoinbaseV1&) const { return {}; }
    result_type operator()(SpTxSquashedV1&) const { return {}; }
};

template <template <bool> class Archive>
bool do_serialize_cryptonote_tx(Archive<true> &ar, MoneroTxVariant &tx, const bool pruned,
    const bool v2)
{
    CHECK_AND_ASSERT_MES(tx_version_ref(tx) == static_cast<std::uint8_t>(v2) + 1, false,
        "BUG: v2 passed does not match contained tx version");

    std::uint64_t unlock_time = unlock_time_ref(tx);
    VARINT_FIELD(unlock_time);

    std::vector<cryptonote::txin_v> vin;
    if (is_coinbase(tx))
    {
        vin.emplace_back(cryptonote::txin_gen{block_height_ref(tx)});
    }
    else
    {
        const std::vector<cryptonote::txin_to_key> &vin_new = tx.is_type<CryptonoteTxV1>() ?
            tx.unwrap<CryptonoteTxV1>().vin : tx.unwrap<RingCTTxV2>().vin;
        vin.reserve(vin_new.size());
        for (const cryptonote::txin_to_key &txin : vin_new)
            vin.push_back(txin);
    }
    FIELD(vin);

    std::vector<cryptonote::tx_out> vout = tx.visit(get_vout_visitor());
    FIELD(vout)

    FIELD_N("extra", const_cast<std::vector<std::uint8_t>&>(extra_ref(tx)));

    const size_t num_inputs = vin.size();
    CHECK_AND_ASSERT_MES(num_inputs, false, "transaction cannot have no inputs");

    if (tx.is_type<CryptonoteTxCoinbaseV1>())
    {
        ar.tag("signatures");
        ar.begin_array();
        ar.end_array();
    }
    else if (tx.is_type<CryptonoteTxV1>())
    {
        std::vector<std::vector<crypto::signature>> dummy_sig;
        if (!do_serialize_seq_exact(ar, pruned ? dummy_sig : tx.unwrap<CryptonoteTxV1>().signatures,
                "signatures"))
            return false;
    }
    else if (tx.is_type<RingCTTxCoinbaseV2>())
    {
        ar.tag("rct_signatures");
        ar.begin_object();
        std::uint8_t rct_type = rct::RCTTypeNull;
        VARINT_FIELD_N("type", rct_type);
        ar.end_object();
    }
    else if (tx.is_type<RingCTTxV2>())
    {
        const size_t nouts = vout.size();

        RingCTTxV2 &rct_tx = tx.unwrap<RingCTTxV2>();
        RingCTBodyVariant &rct_body = rct_tx.body;
        rct::xmr_amount &txn_fee = rct_tx.fee;

        if (!do_serialize_rct_base(ar, rct_body, txn_fee, num_inputs, nouts, vout))
            return false;

        const size_t ring_size = rct_tx.vin.front().key_offsets.size();
        if (!pruned && !rct_body.visit([&ar, num_inputs, nouts, ring_size](auto &b)
                { return do_serialize_rct_prunable(ar, b, num_inputs, nouts, ring_size); }))
            return false;
    }

    return true;
}

template <bool W, template <bool> class Archive>
bool do_serialize(Archive<W> &ar,
    MoneroTxVariant &tx,
    const bool pruned = false,
    const std::size_t mock_num_bins = 0)
{
    ar.begin_object();

    std::uint8_t version = tx_version_ref(tx);
    FIELD(version);

    switch (version)
    {
    case 1:
    case 2:
        if (!do_serialize_cryptonote_tx(ar, tx, pruned, version == 2))
            return false;
        break;
    case 3:
        if constexpr (!W)
        {
            tx = SpTxCoinbaseV1{};
        }
        if (!do_serialize_object(ar, tx.unwrap<SpTxCoinbaseV1>()))
            return false;
        break;
    case 4:
        if constexpr (!W)
        {
            tx = SpTxSquashedV1{};
        }
        if (!do_serialize_object(ar, tx.unwrap<SpTxSquashedV1>()))
            return false;
        break;
    default:
        return false;
    }

    ar.end_object();
    return ar.good();
}
} // namespace sp
