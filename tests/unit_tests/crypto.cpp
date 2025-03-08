// Copyright (c) 2017-2024, The Monero Project
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

#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>

extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/generators.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/merge_mining.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"

namespace
{
  static constexpr const std::uint8_t source[] = {
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea
  };

  static constexpr const char expected[] =
    "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
    "6c7251d54154cfa92c173a0dd39c1f948b655970153799af2aeadc9ff1add0ea";

  template<typename T> void *addressof(T &t) { return &t; }
  template<> void *addressof(crypto::secret_key &k) { return addressof(unwrap(unwrap(k))); }

  template<typename T>
  bool is_formatted()
  {
    T value{};

    static_assert(alignof(T) == 1, "T must have 1 byte alignment");
    static_assert(sizeof(T) <= sizeof(source), "T is too large for source");
    static_assert(sizeof(T) * 2 <= sizeof(expected), "T is too large for destination");
    std::memcpy(addressof(value), source, sizeof(T));

    std::stringstream out;
    out << "BEGIN" << value << "END";  
    return out.str() == "BEGIN<" + std::string{expected, sizeof(T) * 2} + ">END";
  }
}

TEST(Crypto, Ostream)
{
  EXPECT_TRUE(is_formatted<crypto::hash8>());
  EXPECT_TRUE(is_formatted<crypto::hash>());
  EXPECT_TRUE(is_formatted<crypto::public_key>());
  EXPECT_TRUE(is_formatted<crypto::signature>());
  EXPECT_TRUE(is_formatted<crypto::key_derivation>());
  EXPECT_TRUE(is_formatted<crypto::key_image>());
  EXPECT_TRUE(is_formatted<rct::key>());
}

TEST(Crypto, null_keys)
{
  char zero[32];
  memset(zero, 0, 32);
  ASSERT_EQ(memcmp(crypto::null_skey.data, zero, 32), 0);
  ASSERT_EQ(memcmp(crypto::null_pkey.data, zero, 32), 0);
}

TEST(Crypto, verify_32)
{
  // all bytes are treated the same, so we can brute force just one byte
  unsigned char k0[32] = {0}, k1[32] = {0};
  for (unsigned int i0 = 0; i0 < 256; ++i0)
  {
    k0[0] = i0;
    for (unsigned int i1 = 0; i1 < 256; ++i1)
    {
      k1[0] = i1;
      ASSERT_EQ(!crypto_verify_32(k0, k1), i0 == i1);
    }
  }
}

TEST(Crypto, tree_branch)
{
  crypto::hash inputs[6];
  crypto::hash branch[8];
  crypto::hash branch_1[8 + 1];
  crypto::hash root, root2;
  size_t depth;
  uint32_t path, path2;

  auto hasher = [](const crypto::hash &h0, const crypto::hash &h1) -> crypto::hash
  {
    char buffer[64];
    memcpy(buffer, &h0, 32);
    memcpy(buffer + 32, &h1, 32);
    crypto::hash res;
    cn_fast_hash(buffer, 64, res);
    return res;
  };

  for (int n = 0; n < 6; ++n)
  {
    memset(&inputs[n], 0, 32);
    inputs[n].data[0] = n + 1;
  }

  // empty
  ASSERT_FALSE(crypto::tree_branch((const char(*)[32])inputs, 0, crypto::null_hash.data, (char(*)[32])branch, &depth, &path));

  // one, matching
  ASSERT_TRUE(crypto::tree_branch((const char(*)[32])inputs, 1, inputs[0].data, (char(*)[32])branch, &depth, &path));
  ASSERT_EQ(depth, 0);
  ASSERT_EQ(path, 0);
  ASSERT_TRUE(crypto::tree_path(1, 0, &path2));
  ASSERT_EQ(path, path2);
  crypto::tree_hash((const char(*)[32])inputs, 1, root.data);
  ASSERT_EQ(root, inputs[0]);
  ASSERT_TRUE(crypto::is_branch_in_tree(inputs[0].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[1].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(crypto::null_hash.data, root.data, (const char(*)[32])branch, depth, path));

  // one, not found
  ASSERT_FALSE(crypto::tree_branch((const char(*)[32])inputs, 1, inputs[1].data, (char(*)[32])branch, &depth, &path));

  // two, index 0
  ASSERT_TRUE(crypto::tree_branch((const char(*)[32])inputs, 2, inputs[0].data, (char(*)[32])branch, &depth, &path));
  ASSERT_EQ(depth, 1);
  ASSERT_EQ(path, 0);
  ASSERT_TRUE(crypto::tree_path(2, 0, &path2));
  ASSERT_EQ(path, path2);
  ASSERT_EQ(branch[0], inputs[1]);
  crypto::tree_hash((const char(*)[32])inputs, 2, root.data);
  ASSERT_EQ(root, hasher(inputs[0], inputs[1]));
  ASSERT_TRUE(crypto::is_branch_in_tree(inputs[0].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[1].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[2].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(crypto::null_hash.data, root.data, (const char(*)[32])branch, depth, path));

  // two, index 1
  ASSERT_TRUE(crypto::tree_branch((const char(*)[32])inputs, 2, inputs[1].data, (char(*)[32])branch, &depth, &path));
  ASSERT_EQ(depth, 1);
  ASSERT_EQ(path, 1);
  ASSERT_TRUE(crypto::tree_path(2, 1, &path2));
  ASSERT_EQ(path, path2);
  ASSERT_EQ(branch[0], inputs[0]);
  crypto::tree_hash((const char(*)[32])inputs, 2, root.data);
  ASSERT_EQ(root, hasher(inputs[0], inputs[1]));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[0].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_TRUE(crypto::is_branch_in_tree(inputs[1].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[2].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(crypto::null_hash.data, root.data, (const char(*)[32])branch, depth, path));

  // two, not found
  ASSERT_FALSE(crypto::tree_branch((const char(*)[32])inputs, 2, inputs[2].data, (char(*)[32])branch, &depth, &path));

  // a b c 0
  //  x   y
  //    z

  // three, index 0
  ASSERT_TRUE(crypto::tree_branch((const char(*)[32])inputs, 3, inputs[0].data, (char(*)[32])branch, &depth, &path));
  ASSERT_GE(depth, 1);
  ASSERT_LE(depth, 2);
  ASSERT_TRUE(crypto::tree_path(3, 0, &path2));
  ASSERT_EQ(path, path2);
  crypto::tree_hash((const char(*)[32])inputs, 3, root.data);
  ASSERT_EQ(root, hasher(inputs[0], hasher(inputs[1], inputs[2])));
  ASSERT_TRUE(crypto::is_branch_in_tree(inputs[0].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[1].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[2].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[3].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(crypto::null_hash.data, root.data, (const char(*)[32])branch, depth, path));

  // three, index 1
  ASSERT_TRUE(crypto::tree_branch((const char(*)[32])inputs, 3, inputs[1].data, (char(*)[32])branch, &depth, &path));
  ASSERT_GE(depth, 1);
  ASSERT_LE(depth, 2);
  ASSERT_TRUE(crypto::tree_path(3, 1, &path2));
  ASSERT_EQ(path, path2);
  crypto::tree_hash((const char(*)[32])inputs, 3, root.data);
  ASSERT_EQ(root, hasher(inputs[0], hasher(inputs[1], inputs[2])));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[0].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_TRUE(crypto::is_branch_in_tree(inputs[1].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[2].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[3].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(crypto::null_hash.data, root.data, (const char(*)[32])branch, depth, path));

  // three, index 2
  ASSERT_TRUE(crypto::tree_branch((const char(*)[32])inputs, 3, inputs[2].data, (char(*)[32])branch, &depth, &path));
  ASSERT_GE(depth, 1);
  ASSERT_LE(depth, 2);
  ASSERT_TRUE(crypto::tree_path(3, 2, &path2));
  ASSERT_EQ(path, path2);
  crypto::tree_hash((const char(*)[32])inputs, 3, root.data);
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[0].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[1].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_TRUE(crypto::is_branch_in_tree(inputs[2].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[3].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(crypto::null_hash.data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_TRUE(crypto::tree_branch_hash(inputs[2].data, (const char(*)[32])branch, depth, path, root2.data));
  ASSERT_EQ(root, root2);

  // three, not found
  ASSERT_FALSE(crypto::tree_branch((const char(*)[32])inputs, 3, inputs[3].data, (char(*)[32])branch, &depth, &path));

  // a b c d e 0 0 0
  //    x   y
  //      z
  //    w

  // five, index 0
  ASSERT_TRUE(crypto::tree_branch((const char(*)[32])inputs, 5, inputs[0].data, (char(*)[32])branch, &depth, &path));
  ASSERT_GE(depth, 2);
  ASSERT_LE(depth, 3);
  ASSERT_TRUE(crypto::tree_path(5, 0, &path2));
  ASSERT_EQ(path, path2);
  crypto::tree_hash((const char(*)[32])inputs, 5, root.data);
  ASSERT_TRUE(crypto::is_branch_in_tree(inputs[0].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[1].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[2].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[3].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[4].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[5].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(crypto::null_hash.data, root.data, (const char(*)[32])branch, depth, path));

  // five, index 1
  ASSERT_TRUE(crypto::tree_branch((const char(*)[32])inputs, 5, inputs[1].data, (char(*)[32])branch, &depth, &path));
  ASSERT_GE(depth, 2);
  ASSERT_LE(depth, 3);
  ASSERT_TRUE(crypto::tree_path(5, 1, &path2));
  ASSERT_EQ(path, path2);
  crypto::tree_hash((const char(*)[32])inputs, 5, root.data);
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[0].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_TRUE(crypto::is_branch_in_tree(inputs[1].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[2].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[3].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[4].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[5].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(crypto::null_hash.data, root.data, (const char(*)[32])branch, depth, path));

  // five, index 2
  ASSERT_TRUE(crypto::tree_branch((const char(*)[32])inputs, 5, inputs[2].data, (char(*)[32])branch, &depth, &path));
  ASSERT_GE(depth, 2);
  ASSERT_LE(depth, 3);
  ASSERT_TRUE(crypto::tree_path(5, 2, &path2));
  ASSERT_EQ(path, path2);
  crypto::tree_hash((const char(*)[32])inputs, 5, root.data);
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[0].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[1].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_TRUE(crypto::is_branch_in_tree(inputs[2].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[3].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[4].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[5].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(crypto::null_hash.data, root.data, (const char(*)[32])branch, depth, path));

  // five, index 4
  ASSERT_TRUE(crypto::tree_branch((const char(*)[32])inputs, 5, inputs[4].data, (char(*)[32])branch, &depth, &path));
  ASSERT_GE(depth, 2);
  ASSERT_LE(depth, 3);
  ASSERT_TRUE(crypto::tree_path(5, 4, &path2));
  ASSERT_EQ(path, path2);
  crypto::tree_hash((const char(*)[32])inputs, 5, root.data);
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[0].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[1].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[2].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[3].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_TRUE(crypto::is_branch_in_tree(inputs[4].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[5].data, root.data, (const char(*)[32])branch, depth, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(crypto::null_hash.data, root.data, (const char(*)[32])branch, depth, path));

  // a version with an extra (dummy) hash
  memcpy(branch_1, branch, sizeof(branch));
  branch_1[depth] = crypto::null_hash;

  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[4].data, root.data, (const char(*)[32])branch, depth - 1, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[4].data, root.data, (const char(*)[32])branch_1, depth + 1, path));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[4].data, root.data, (const char(*)[32])branch, depth, path ^ 1));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[4].data, root.data, (const char(*)[32])branch, depth, path ^ 2));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[4].data, root.data, (const char(*)[32])branch, depth, path ^ 3));
  ASSERT_FALSE(crypto::is_branch_in_tree(inputs[4].data, root.data, (const char(*)[32])(branch_1 + 1), depth, path));

  // five, not found
  ASSERT_FALSE(crypto::tree_branch((const char(*)[32])inputs, 5, crypto::null_hash.data, (char(*)[32])branch, &depth, &path));

  // depth encoding roundtrip
  for (uint32_t n_chains = 1; n_chains <= 256; ++n_chains)
  {
    for (uint32_t nonce = 0xffffffff - 512; nonce != 1025; ++nonce)
    {
      const uint64_t depth = cryptonote::encode_mm_depth(n_chains, nonce);
      uint32_t n_chains_2, nonce_2;
      ASSERT_TRUE(cryptonote::decode_mm_depth(depth, n_chains_2, nonce_2));
      ASSERT_EQ(n_chains, n_chains_2);
      ASSERT_EQ(nonce, nonce_2);
    }
  }

  // 257 chains is too much
  try { cryptonote::encode_mm_depth(257, 0); ASSERT_TRUE(false); }
  catch (...) {}
}

TEST(Crypto, generator_consistency)
{
  // crypto/generators.h
  const crypto::public_key G{crypto::get_G()};
  const crypto::public_key H{crypto::get_H()};
  const ge_p3 H_p3 = crypto::get_H_p3();

  // crypto/crypto-ops.h
  ASSERT_TRUE(memcmp(&H_p3, &ge_p3_H, sizeof(ge_p3)) == 0);

  // ringct/rctOps.h
  ASSERT_TRUE(memcmp(G.data, rct::G.bytes, 32) == 0);

  // ringct/rctTypes.h
  ASSERT_TRUE(memcmp(H.data, rct::H.bytes, 32) == 0);
}

class discrete_log_oracle
{
  // Map of Q -> (a, P) s.t. Q = a P
  std::unordered_map<rct::key, std::pair<rct::key, rct::key>> data;

public:
  void add(const rct::key &a, const rct::key &P)
  {
    const rct::key Q = rct::scalarmultKey(P, a);
    data.insert({Q, {a, P}});
  }

  std::optional<std::pair<rct::key, rct::key>> get(const rct::key &Q) const
  {
    const auto it = data.find(Q);
    if (it == data.cend())
      return std::nullopt;
    return it->second;
  }
};

// Most known quantum scanning attacks need (K^j_s, K^j_v). This only needs K^j_s
bool try_quantum_viewkey_less_scan(const discrete_log_oracle &dlog,
  const rct::key &onetime_address,
  const rct::key &amount_commitment,
  const rct::key &encrypted_amount,
  const rct::key &address_spend_pubkey,
  rct::xmr_amount &amount_out)
{
  // K_ext = K_o - K^j_s
  rct::key sender_extension_pubkey;
  rct::subKeys(sender_extension_pubkey, onetime_address, address_spend_pubkey);

  // peek at k_ext s.t. K_ext = k_ext G
  const auto dlog_res = dlog.get(sender_extension_pubkey);
  if (!dlog_res || dlog_res->second != rct::G)
    return false;
  const rct::key sender_extension_privkey = dlog_res->first;

  // a = a_enc XOR H("amount" || k_ext)
  // z = H("commitment_mask" || k_ext)
  rct::ecdhTuple ecdh_tuple{.amount = encrypted_amount};
  rct::ecdhDecode(ecdh_tuple, sender_extension_privkey, /*v2=*/true);
  amount_out = rct::h2d(ecdh_tuple.amount);

  // check that C ?= z G + a H
  const rct::key recomputed_amount_commitment = rct::commit(amount_out, ecdh_tuple.mask);
  if (recomputed_amount_commitment != amount_commitment)
    return false;

  return true;
}

TEST(Crypto, try_quantum_viewkey_less_scan)
{
  cryptonote::account_base acb;
  acb.generate();

  hw::device &hwdev = hw::get_device("default");

  // (r, R = r G)
  crypto::secret_key ephemeral_tx_privkey;
  crypto::public_key ephemeral_tx_pubkey;
  crypto::generate_keys(ephemeral_tx_pubkey, ephemeral_tx_privkey);

  const rct::xmr_amount fake_fee = 21;
  const rct::xmr_amount amount = crypto::rand_range<rct::xmr_amount>(10, MONEY_SUPPLY - fake_fee);

  const std::size_t output_index = crypto::rand_idx<std::size_t>(16);

  // destination with main address
  const cryptonote::tx_destination_entry dest(amount, acb.get_keys().m_account_address, false);

  std::vector<rct::key> amount_keys;
  std::vector<crypto::public_key> dummy_additional_tx_pubkeys;
  crypto::view_tag dummy_view_tag;
  crypto::public_key onetime_address;
  ASSERT_TRUE(hwdev.generate_output_ephemeral_keys(/*tx_version=*/2,
    acb.get_keys(),
    ephemeral_tx_pubkey,
    ephemeral_tx_privkey,
    dest,
    /*change_addr=*/boost::none,
    output_index,
    /*need_additional_txkeys=*/false,
    /*additional_tx_privkeys=*/{},
    dummy_additional_tx_pubkeys,
    amount_keys,
    onetime_address,
    /*use_view_tag=*/false,
    dummy_view_tag));

  const rct::key message = crypto::rand<rct::key>();
  const int mixin = 15;
  const rct::xmr_amount fee = 21;
  const rct::RCTConfig rct_config{
    .range_proof_type = rct::RangeProofPaddedBulletproof,
    .bp_version = 4
  };

  // generate a bunch of information about our fake input
  crypto::secret_key fake_in_privkey;
  crypto::public_key fake_in_pubkey;
  crypto::generate_keys(fake_in_pubkey, fake_in_privkey);
  const rct::key fake_in_amount_blinding_factor = rct::skGen();
  const rct::xmr_amount fake_in_amount = fake_fee + amount;
  const rct::key fake_in_amount_commitment = rct::commit(fake_in_amount, fake_in_amount_blinding_factor);

  const rct::rctSig rct_sig = rct::genRctSimple(message,
    {{rct::sk2rct(fake_in_privkey), fake_in_amount_blinding_factor}},
    {{rct::pk2rct(fake_in_pubkey), fake_in_amount_commitment}},
    {rct::pk2rct(onetime_address)},
    {fake_in_amount},
    {amount},
    amount_keys,
    fee,
    mixin,
    rct_config,
    hwdev);

  // double-check that the "amount key" (terrible name) is equal to the sender extension privkey
  rct::key recomputed_onetime_address;
  rct::addKeys1(recomputed_onetime_address,
    amount_keys.at(0),
    rct::pk2rct(dest.addr.m_spend_public_key));
  ASSERT_EQ(onetime_address, rct::rct2pk(recomputed_onetime_address));

  // add K_ext = k_ext G to the discrete log oracle
  discrete_log_oracle dlog;
  dlog.add(amount_keys.at(0), rct::G);

  rct::xmr_amount rescanned_amount;
  ASSERT_TRUE(try_quantum_viewkey_less_scan(dlog,
    rct_sig.outPk.at(0).dest,
    rct_sig.outPk.at(0).mask,
    rct_sig.ecdhInfo.at(0).amount,
    rct::pk2rct(dest.addr.m_spend_public_key),
    rescanned_amount));

  EXPECT_EQ(amount, rescanned_amount);
}
