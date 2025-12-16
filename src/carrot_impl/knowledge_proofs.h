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

#pragma once

//local headers
#include "crypto/crypto.h"
#include "mx25519.h"

//third party headers

//standard headers
#include <optional>

//forward declarations

namespace carrot
{
/**
 * brief: Generate a PoK of `r` s.t. `D = r ConvertPointE(A)` and (`R = r G` or `R = r ConvertPointE(B)`)
 *            where G is the X25519 base point, and ConvertPointE() is the Ed25519->X25519 conversion function
 * param: prefix_hash - challenge message
 * param: A - A [Ed25519]
 * param: B - B [Ed25519] [Optional]
 * param: r - r in scalar field (mod l)
 * outparam: sig_out - Schnorr proof of knowledge of discrete log `r`
 *
 * This handles use cases for both standard addresses and subaddresses.
 * Generates only proofs for InProofV2 and OutProofV2.
*/
void generate_carrot_tx_proof_normal(const crypto::hash &prefix_hash,
    const crypto::public_key &A,
    const std::optional<crypto::public_key> &B,
    crypto::secret_key r,
    crypto::signature &sig_out);
/**
 * @TODO: doc
 */
bool check_carrot_tx_proof_normal(const crypto::hash &prefix_hash,
    const mx25519_pubkey &R,
    const crypto::public_key &A,
    const std::optional<crypto::public_key> &B,
    const mx25519_pubkey &D,
    const crypto::signature &sig);
/**
 * brief: Generate a PoK of `a` s.t. `D = a R` and (`A = a G_ed` or `A = a B`)
 *            where G_ed is the *Ed25519* base point
 * param: prefix_hash - challenge message
 * param: R - R [X25519]
 * param: B - B [Ed25519] [Optional]
 * param: a - a in scalar field (mod l)
 * outparam: sig_out - Schnorr proof of knowledge of discrete log `a`
 *
 * This handles use cases for both standard addresses and subaddresses.
 * Generates only proofs for InProofV2 and OutProofV2.
*/
void generate_carrot_tx_proof_receiver(const crypto::hash &prefix_hash,
    const mx25519_pubkey &R,
    const std::optional<crypto::public_key> &B,
    crypto::secret_key a,
    crypto::signature &sig_out);
/**
 * @TODO: doc
 */
bool check_carrot_tx_proof_receiver(const crypto::hash &prefix_hash,
    const mx25519_pubkey &R,
    const crypto::public_key &A,
    const std::optional<crypto::public_key> &B,
    const mx25519_pubkey &D,
    const crypto::signature &sig);
} //namespace carrot
