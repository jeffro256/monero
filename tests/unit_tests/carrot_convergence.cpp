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

#include "gtest/gtest.h"

#include "carrot_core/account_secrets.h"
#include "carrot_core/address_utils.h"
#include "carrot_core/destination.h"
#include "carrot_core/device_ram_borrowed.h"
#include "carrot_core/enote_utils.h"
#include "ringct/rctOps.h"
#include "string_tools.h"

using namespace carrot;

namespace
{
bool operator==(const mx25519_pubkey &lhs, const mx25519_pubkey &rhs)
{
    return 0 == memcmp(lhs.data, rhs.data, sizeof(mx25519_pubkey));
}

template <typename T>
const T &pod_unwrap(const T &v) { return v; }
template <typename T>
T &pod_unwrap(T &v) { return v; }
const crypto::ec_scalar &pod_unwrap(const crypto::secret_key &v) { return v; }
crypto::ec_scalar &pod_unwrap(crypto::secret_key &v) { return v; }

template <typename T>
std::string pod_to_hex(const T &v)
{
    return epee::string_tools::pod_to_hex(pod_unwrap(v));
}

template <typename T>
T hex_to_pod(const boost::string_ref hex)
{
    T val{};
    if (!epee::string_tools::hex_to_pod(hex, pod_unwrap(val)))
        throw std::runtime_error("hex failed to decode to value");
    return val;
}

template <typename T>
struct hex_value_t
{
    hex_value_t(const boost::string_ref hex):
        hex(hex),
        value(hex_to_pod<T>(hex))
    {}

    const std::string hex;
    const T value;

    testing::AssertionResult matches(const T &actual) const
    {
        const std::string actual_hex = pod_to_hex(actual);

        const bool matches = this->value == actual;
        const bool matches_hex = this->hex == actual_hex;
        if (matches != matches_hex)
            throw std::logic_error("Type is not practically POD-like");

        if (!matches)
        {
            return testing::AssertionFailure() << "actual hex is " << actual_hex;
        }

        return testing::AssertionSuccess();
    }
};

static const hex_value_t<crypto::secret_key> s_master("6e02e67b303dc713276bb1a4d70b0083b78e4f50e34e209da9f0377cdc3d376e"); // chosen by fair dice roll.
                                                                                                                     // guaranteed to be random.
static const hex_value_t<crypto::secret_key> k_prove_spend("c9651fc906015afeefdb8d3bf7be621c36e035de2a85cb22dd4b869a22086f0e");
static const hex_value_t<crypto::secret_key> s_view_balance("59b2ee8646923309384704613418f5982b0167eb3cd87c6c067ee10700c3af91");
static const hex_value_t<crypto::secret_key> k_generate_image("2ec40d3dd3a06b2f9a580c41e852be26950b7398d27f248efad5a81cdeead70b");
static const hex_value_t<crypto::secret_key> k_view_incoming("12624c702b4c1a22fd710a836894ed0705955502e6498e5c6e3ad6f5920bb00f");
static const hex_value_t<crypto::secret_key> s_generate_address("039f0744fb138954072ee6bcbda4b5c085fd05e09b476a7b34ad20bf9ad440bc");
static const hex_value_t<crypto::public_key> account_spend_pubkey("674a9892b538aaaafa2412dabf13a2e3f843c7e323810630d05c10cc64077077");
static const hex_value_t<crypto::public_key> account_view_pubkey("55960ccffdfb5e596b867658ac881f4d378e45bb76395964f2402037ec4685ff");
static const std::uint32_t address_index_major = 5;
static const std::uint32_t address_index_minor = 16;
static const hex_value_t<crypto::secret_key> address_index_generator("fa26210179cdf94ae6ca2a7c93620909cb77e4923478a204ebe93794ab30bc7a");
static const hex_value_t<crypto::secret_key> subaddress_scalar("70b70912ffa1c01e073ef1e0a7cd46c810f839fe57ca3d0af1f3451194d56408");
static const hex_value_t<crypto::public_key> subaddress_spend_pubkey("837744f1da3cbefcf64214b88e1a4c6dbbac5d18965d8052648486a74a2b08bb");
static const hex_value_t<crypto::public_key> subaddress_view_pubkey("d8b83883dd375b3a7536d9a9ceffa6c6505fbffbee883d825d32c25b99a9a450");

static const hex_value_t<carrot::janus_anchor_t> anchor_norm("caee1381775487a0982557f0d2680b55");
static const hex_value_t<carrot::janus_anchor_t> anchor_special("cea1a83cbe3b2c82f36fbcb4d5af85d8");
static const hex_value_t<carrot::input_context_t> input_context("9423f74f3e869dc8427d8b35bb24c917480409c3f4750bff3c742f8e4d5af7bef7");
static const hex_value_t<carrot::payment_id_t> payment_id("4321734f56621440");
static const hex_value_t<crypto::secret_key> enote_ephemeral_privkey("7c2fbbe9d38ecc35fdeab8be7ed9659c05407a2c96d6fe251229cb8274305b07");
static const hex_value_t<mx25519_pubkey> enote_ephemeral_pubkey_cryptonote("81f59f8d2207ce0403a552c7069d8b35945d25bb1426417d71860be2c2efbc44");
static const hex_value_t<mx25519_pubkey> enote_ephemeral_pubkey_subaddress("68b04386b14657aa221ac63b6b008d123e8dbd84814abcdb660997cbfa837c65");
static const hex_value_t<mx25519_pubkey> s_sender_receiver_unctx("ae62faa4d5b1277fe9c4777a950969f56deee7bfba7b2c2921e301e12f46411d");
static const hex_value_t<crypto::hash> s_sender_receiver("300f88e1626c74c97e8b2f3d627a0444a34d515d8657c2e7dc2291e75727e268");
static const rct::xmr_amount amount = 67000000000000;
static const hex_value_t<crypto::secret_key> amount_blinding_factor_payment("ee02780bf4b4a90a9577e694bbba25264f2604e4933590bd1efffd2a558a4d0a");
static const hex_value_t<crypto::secret_key> amount_blinding_factor_change("abac509b18e04c39a70a3e1e72b4c06b7b21c43dd95c2d2e97ceace6c44ba90c");
static const hex_value_t<rct::key> amount_commitment("edd30d1b0808defb3c5a33dcc55dd05a1b197242f427f88f80b4dda63ed39958");
static const hex_value_t<crypto::public_key> onetime_address("1e3c78039277f79d373e21c629291e49d64a36dd1948c6913227da1088e66280");
static const hex_value_t<carrot::view_tag_t> view_tag("93096d");
static const hex_value_t<carrot::encrypted_janus_anchor_t> anchor_encryption_mask("c6df4ecdfe1beed0cdadf0483467391e");
static const hex_value_t<carrot::encrypted_amount_t> amount_encryption_mask("2a982ec96a940a5d");
static const hex_value_t<carrot::encrypted_payment_id_t> payment_id_encryption_mask("39b004624a1170d4");
} //anonymous namespace

//---------------------------------------------------------------------------------------------------------------------
// ACCOUNT
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_provespend_key)
{
    crypto::secret_key k_prove_spend_rc;
    make_carrot_provespend_key(s_master.value, k_prove_spend_rc);
    EXPECT_TRUE(k_prove_spend.matches(k_prove_spend_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_viewbalance_secret)
{
    crypto::secret_key s_view_balance_rc;
    make_carrot_viewbalance_secret(s_master.value, s_view_balance_rc);
    EXPECT_TRUE(s_view_balance.matches(s_view_balance_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_generateimage_key)
{
    crypto::secret_key k_generate_image_rc;
    make_carrot_generateimage_key(s_view_balance.value, k_generate_image_rc);
    EXPECT_TRUE(k_generate_image.matches(k_generate_image_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_viewincoming_key)
{
    crypto::secret_key k_view_incoming_rc;
    make_carrot_viewincoming_key(s_view_balance.value, k_view_incoming_rc);
    EXPECT_TRUE(k_view_incoming.matches(k_view_incoming_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_generateaddress_secret)
{
    crypto::secret_key s_generate_address_rc;
    make_carrot_generateaddress_secret(s_view_balance.value, s_generate_address_rc);
    EXPECT_TRUE(s_generate_address.matches(s_generate_address_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_spend_pubkey)
{
    crypto::public_key account_spend_pubkey_rc;
    make_carrot_spend_pubkey(k_generate_image.value, k_prove_spend.value, account_spend_pubkey_rc);
    EXPECT_TRUE(account_spend_pubkey.matches(account_spend_pubkey_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_view_pubkey)
{
    const crypto::public_key account_view_pubkey_rc = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(account_spend_pubkey.value),
        rct::sk2rct(k_view_incoming.value)));
    EXPECT_TRUE(account_view_pubkey.matches(account_view_pubkey_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_index_extension_generator)
{
    crypto::secret_key address_index_generator_rc;
    make_carrot_index_extension_generator(s_generate_address.value, address_index_major, address_index_minor,
        address_index_generator_rc);
    EXPECT_TRUE(address_index_generator.matches(address_index_generator_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_subaddress_scalar)
{
    crypto::secret_key subaddress_scalar_rc;
    make_carrot_subaddress_scalar(account_spend_pubkey.value,
        account_view_pubkey.value, address_index_generator.value, address_index_major, address_index_minor,
        subaddress_scalar_rc);
    EXPECT_TRUE(subaddress_scalar.matches(subaddress_scalar_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_subaddress_v1)
{
    CarrotDestinationV1 subaddress_rc;
    make_carrot_subaddress_v1(account_spend_pubkey.value,
        account_view_pubkey.value,
        generate_address_secret_ram_borrowed_device(s_generate_address.value),
        address_index_major,
        address_index_minor,
        subaddress_rc);
    EXPECT_TRUE(subaddress_spend_pubkey.matches(subaddress_rc.address_spend_pubkey));
    EXPECT_TRUE(subaddress_view_pubkey.matches(subaddress_rc.address_view_pubkey));
}
//---------------------------------------------------------------------------------------------------------------------
// ENOTE
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_enote_ephemeral_privkey)
{
    crypto::secret_key enote_ephemeral_privkey_rc;
    make_carrot_enote_ephemeral_privkey(anchor_norm.value,
        input_context.value,
        subaddress_spend_pubkey.value,
        payment_id.value,
        enote_ephemeral_privkey_rc);
    EXPECT_TRUE(enote_ephemeral_privkey.matches(enote_ephemeral_privkey_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_enote_ephemeral_pubkey_cryptonote)
{
    mx25519_pubkey enote_ephemeral_pubkey_rc;
    make_carrot_enote_ephemeral_pubkey_cryptonote(enote_ephemeral_privkey.value,
        enote_ephemeral_pubkey_rc);
    EXPECT_TRUE(enote_ephemeral_pubkey_cryptonote.matches(enote_ephemeral_pubkey_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_enote_ephemeral_pubkey_subaddress)
{
    mx25519_pubkey enote_ephemeral_pubkey_rc;
    make_carrot_enote_ephemeral_pubkey_subaddress(enote_ephemeral_privkey.value,
        subaddress_spend_pubkey.value,
        enote_ephemeral_pubkey_rc);
    EXPECT_TRUE(enote_ephemeral_pubkey_subaddress.matches(enote_ephemeral_pubkey_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_uncontextualized_shared_key_receiver)
{
    mx25519_pubkey s_sender_receiver_unctx_rc;
    make_carrot_uncontextualized_shared_key_receiver(k_view_incoming.value,
        enote_ephemeral_pubkey_subaddress.value,
        s_sender_receiver_unctx_rc);
    EXPECT_TRUE(s_sender_receiver_unctx.matches(s_sender_receiver_unctx_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_uncontextualized_shared_key_sender)
{
    mx25519_pubkey s_sender_receiver_unctx_rc;
    make_carrot_uncontextualized_shared_key_sender(enote_ephemeral_privkey.value,
        subaddress_view_pubkey.value,
        s_sender_receiver_unctx_rc);
    EXPECT_TRUE(s_sender_receiver_unctx.matches(s_sender_receiver_unctx_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_sender_receiver_secret)
{
    crypto::hash s_sender_receiver_rc;
    make_carrot_sender_receiver_secret(s_sender_receiver_unctx.value.data,
        enote_ephemeral_pubkey_subaddress.value,
        input_context.value,
        s_sender_receiver_rc);
    EXPECT_TRUE(s_sender_receiver.matches(s_sender_receiver_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_amount_blinding_factor_payment)
{
    crypto::secret_key amount_blinding_factor_rc;
    make_carrot_amount_blinding_factor(s_sender_receiver.value,
        amount,
        subaddress_spend_pubkey.value,
        CarrotEnoteType::PAYMENT,
        amount_blinding_factor_rc);
    EXPECT_TRUE(amount_blinding_factor_payment.matches(amount_blinding_factor_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_amount_blinding_factor_change)
{
    crypto::secret_key amount_blinding_factor_rc;
    make_carrot_amount_blinding_factor(s_sender_receiver.value,
        amount,
        subaddress_spend_pubkey.value,
        CarrotEnoteType::CHANGE,
        amount_blinding_factor_rc);
    EXPECT_TRUE(amount_blinding_factor_change.matches(amount_blinding_factor_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, commit)
{
    const rct::key amount_commitment_rc = rct::commit(amount, rct::sk2rct(amount_blinding_factor_payment.value));
    EXPECT_TRUE(amount_commitment.matches(amount_commitment_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_onetime_address)
{
    crypto::public_key onetime_address_rc;
    make_carrot_onetime_address(subaddress_spend_pubkey.value,
        s_sender_receiver.value,
        amount_commitment.value,
        onetime_address_rc);
    EXPECT_TRUE(onetime_address.matches(onetime_address_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_view_tag)
{
    view_tag_t view_tag_rc;
    make_carrot_view_tag(s_sender_receiver_unctx.value.data,
        input_context.value,
        onetime_address.value,
        view_tag_rc);
    EXPECT_TRUE(view_tag.matches(view_tag_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_anchor_encryption_mask)
{
    encrypted_janus_anchor_t anchor_encryption_mask_rc;
    make_carrot_anchor_encryption_mask(s_sender_receiver.value,
        onetime_address.value,
        anchor_encryption_mask_rc);
    EXPECT_TRUE(anchor_encryption_mask.matches(anchor_encryption_mask_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_amount_encryption_mask)
{
    encrypted_amount_t amount_encryption_mask_rc;
    make_carrot_amount_encryption_mask(s_sender_receiver.value,
        onetime_address.value,
        amount_encryption_mask_rc);
    EXPECT_TRUE(amount_encryption_mask.matches(amount_encryption_mask_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_payment_id_encryption_mask)
{
    encrypted_payment_id_t payment_id_encryption_mask_rc;
    make_carrot_payment_id_encryption_mask(s_sender_receiver.value,
        onetime_address.value,
        payment_id_encryption_mask_rc);
    EXPECT_TRUE(payment_id_encryption_mask.matches(payment_id_encryption_mask_rc));
}
//---------------------------------------------------------------------------------------------------------------------
TEST(carrot_convergence, make_carrot_janus_anchor_special)
{
    janus_anchor_t anchor_special_rc;
    make_carrot_janus_anchor_special(enote_ephemeral_pubkey_cryptonote.value,
        input_context.value,
        onetime_address.value,
        k_view_incoming.value,
        anchor_special_rc);
    EXPECT_TRUE(anchor_special.matches(anchor_special_rc));
}
//---------------------------------------------------------------------------------------------------------------------
