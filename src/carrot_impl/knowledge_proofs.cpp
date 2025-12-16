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
#include "carrot_core/exceptions.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "misc_log_ex.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "carrot_impl.knowledge_proofs"

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
} //namespace carrot
