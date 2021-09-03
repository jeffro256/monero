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

#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_impl/seraphis_serialization.h"
#include "seraphis_main/txtype_base.h"
#include "seraphis_main/txtype_coinbase_v1.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/seraphis_mocks.h"
#include "serialization/binary_utils.h"
#include "span.h"

#include "gtest/gtest.h"

using namespace sp;
using namespace jamtis;
using namespace sp::mocks;

//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_coinbase_empty)
{
    // make empty tx
    SpTxCoinbaseV1 tx{};

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    SpTxCoinbaseV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check that the original tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_coinbase_v1_size_bytes(tx) == sp_tx_coinbase_v1_size_bytes(recovered_tx)));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_squashed_empty)
{
    // make empty tx
    SpTxSquashedV1 tx{};

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    SpTxSquashedV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check that the original tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_squashed_v1_size_bytes(tx) == sp_tx_squashed_v1_size_bytes(recovered_tx)));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_coinbase_standard)
{
    // ledger context
    MockLedgerContext ledger_context{0, 10000};
    const TxValidationContextMock tx_validation_context{ledger_context, {}};

    // make a tx
    SpTxCoinbaseV1 tx;
    make_mock_tx<SpTxCoinbaseV1>(SpTxParamPackV1{.output_amounts = {1}}, ledger_context, tx);

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    SpTxCoinbaseV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check the tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_coinbase_v1_size_bytes(tx) == sp_tx_coinbase_v1_size_bytes(recovered_tx)));
    EXPECT_TRUE(validate_tx(tx, tx_validation_context));
    EXPECT_TRUE(validate_tx(recovered_tx, tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_squashed_standard)
{
    // config
    SpTxParamPackV1 tx_params;

    tx_params.legacy_ring_size = 2;
    tx_params.ref_set_decomp_n = 2;
    tx_params.ref_set_decomp_m = 2;
    tx_params.bin_config =
        SpBinnedReferenceSetConfigV1{
            .bin_radius = 1,
            .num_bin_members = 1
        };
    tx_params.legacy_input_amounts = {1};
    tx_params.sp_input_amounts = {2, 3};
    tx_params.output_amounts = {3};
    tx_params.discretized_fee = discretize_fee(3);

    const SemanticConfigSpRefSetV1 sp_ref_set_config{
            .decomp_n = tx_params.ref_set_decomp_n,
            .decomp_m = tx_params.ref_set_decomp_m,
            .bin_radius = tx_params.bin_config.bin_radius,
            .num_bin_members = tx_params.bin_config.num_bin_members,
        };

    // ledger context
    MockLedgerContext ledger_context{0, 10000};
    const TxValidationContextMock tx_validation_context{ledger_context, sp_ref_set_config};

    // make a tx
    SpTxSquashedV1 tx;
    make_mock_tx<SpTxSquashedV1>(tx_params, ledger_context, tx);

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    SpTxSquashedV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check the tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_squashed_v1_size_bytes(tx) == sp_tx_squashed_v1_size_bytes(recovered_tx)));
    EXPECT_TRUE(validate_tx(tx, tx_validation_context));
    EXPECT_TRUE(validate_tx(recovered_tx, tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, jamtis_destination_v1)
{
    // generate
    JamtisDestinationV1 dest{gen_jamtis_destination_v1()};

    // serialize
    std::string serialized_dest;
    EXPECT_TRUE(::serialization::dump_binary(dest, serialized_dest));

    // deserialize
    JamtisDestinationV1 recovered_dest;
    EXPECT_TRUE(::serialization::parse_binary(serialized_dest, recovered_dest));

    // compare
    EXPECT_EQ(dest, recovered_dest);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, jamtis_payment_proposal_v1)
{
    // generate
    JamtisPaymentProposalV1 payprop{gen_jamtis_payment_proposal_v1(7, 3, 9)};

    // serialize
    std::string serialized_payprop;
    EXPECT_TRUE(::serialization::dump_binary(payprop, serialized_payprop));

    // deserialize
    JamtisPaymentProposalV1 recovered_payprop;
    EXPECT_TRUE(::serialization::parse_binary(serialized_payprop, recovered_payprop));

    // compare
    EXPECT_EQ(payprop, recovered_payprop);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, jamtis_payment_proposal_self_send_v1)
{
    // generate
    JamtisPaymentProposalSelfSendV1 payprop{
            gen_jamtis_selfsend_payment_proposal_v1(7, JamtisSelfSendType::EXCLUSIVE_SELF_SPEND, 3)
        };

    // serialize
    std::string serialized_payprop;
    EXPECT_TRUE(::serialization::dump_binary(payprop, serialized_payprop));

    // deserialize
    JamtisPaymentProposalSelfSendV1 recovered_payprop;
    EXPECT_TRUE(::serialization::parse_binary(serialized_payprop, recovered_payprop));

    // compare
    EXPECT_EQ(payprop, recovered_payprop);
}
//-------------------------------------------------------------------------------------------------------------------
template <typename... Ts> void match_tools_variant(const tools::variant<Ts...>&) {}
VARIANT_TAG(binary_archive, sp::SpEnoteCore, 0x37);
VARIANT_TAG(binary_archive, sp::SpCoinbaseEnoteCore, 0x88);
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, tools_variant)
{
    sp::SpEnoteCoreVariant enote_core{
            sp::SpEnoteCore{
                    .onetime_address = rct::pkGen(),
                    .amount_commitment = rct::zeroCommit(420)
                }
        };

    match_tools_variant(enote_core); // throws compile error if enote_core stops being of tools::variant type

    // serialize
    std::string serialized;
    EXPECT_TRUE(::serialization::dump_binary(enote_core, serialized));

    // deserialize
    sp::SpEnoteCoreVariant enote_core_recovered;
    EXPECT_TRUE(::serialization::parse_binary(serialized, enote_core_recovered));

    // test equal
    EXPECT_EQ(enote_core, enote_core_recovered);
}
//-------------------------------------------------------------------------------------------------------------------
