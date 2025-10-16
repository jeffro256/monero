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

#include "cryptonote_core/tx_verification_utils.h"

TEST(tx_verification_utils, make_input_verification_id)
{
    rct::key key1, key2, key3;
    epee::from_hex::to_buffer(epee::as_mut_byte_span(key1), "e50f476129d40af31e0938743f7f2d60e867aab31294f7acaf6e38f0976f0228");
    epee::from_hex::to_buffer(epee::as_mut_byte_span(key2), "e50f476129d40af31e0938743f7f2d60e867aab31294f7acaf6e38f0976f0227");
    epee::from_hex::to_buffer(epee::as_mut_byte_span(key3), "d50f476129d40af31e0938743f7f2d60e867aab31294f7acaf6e38f0976f0228");

    const crypto::hash hash1 = cryptonote::make_input_verification_id(rct::rct2hash(key1), {});
    const crypto::hash hash2 = cryptonote::make_input_verification_id(rct::rct2hash(key2), {});    
    const crypto::hash hash3 = cryptonote::make_input_verification_id(rct::rct2hash(key3), {});
    ASSERT_NE(hash1, hash2);
    ASSERT_NE(hash1, hash3);
    ASSERT_NE(hash2, hash3);

    const crypto::hash hash4 = cryptonote::make_input_verification_id(rct::rct2hash(key1), {{{key1, key1}}});
    const crypto::hash hash5 = cryptonote::make_input_verification_id(rct::rct2hash(key1), {{{key1, key2}}});
    const crypto::hash hash6 = cryptonote::make_input_verification_id(rct::rct2hash(key1), {{{key1, key3}}});
    ASSERT_NE(hash4, hash5);
    ASSERT_NE(hash4, hash6);
    ASSERT_NE(hash5, hash6);

    const crypto::hash hash7 = cryptonote::make_input_verification_id(rct::rct2hash(key1), {{{key1, key1},{key1, key1}}});
    const crypto::hash hash8 = cryptonote::make_input_verification_id(rct::rct2hash(key1), {{{key1, key1}},{{key1, key1}}});
    ASSERT_NE(hash7, hash8);

    const crypto::hash hash1_eq = cryptonote::make_input_verification_id(rct::rct2hash(key1), {});
    const crypto::hash hash2_eq = cryptonote::make_input_verification_id(rct::rct2hash(key2), {});    
    const crypto::hash hash3_eq = cryptonote::make_input_verification_id(rct::rct2hash(key3), {});
    const crypto::hash hash4_eq = cryptonote::make_input_verification_id(rct::rct2hash(key1), {{{key1, key1}}});
    const crypto::hash hash5_eq = cryptonote::make_input_verification_id(rct::rct2hash(key1), {{{key1, key2}}});
    const crypto::hash hash6_eq = cryptonote::make_input_verification_id(rct::rct2hash(key1), {{{key1, key3}}});
    const crypto::hash hash7_eq = cryptonote::make_input_verification_id(rct::rct2hash(key1), {{{key1, key1},{key1, key1}}});
    const crypto::hash hash8_eq = cryptonote::make_input_verification_id(rct::rct2hash(key1), {{{key1, key1}},{{key1, key1}}});

    ASSERT_EQ(hash1, hash1_eq);
    ASSERT_EQ(hash2, hash2_eq);
    ASSERT_EQ(hash3, hash3_eq);
    ASSERT_EQ(hash4, hash4_eq);
    ASSERT_EQ(hash5, hash5_eq);
    ASSERT_EQ(hash6, hash6_eq);
    ASSERT_EQ(hash7, hash7_eq);
    ASSERT_EQ(hash8, hash8_eq);
}
