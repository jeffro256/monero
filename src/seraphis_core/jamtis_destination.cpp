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

//paired header
#include "jamtis_destination.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "jamtis_address_tag_utils.h"
#include "jamtis_address_utils.h"
#include "jamtis_secret_utils.h"
#include "jamtis_support_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const JamtisDestinationV1 &a, const JamtisDestinationV1 &b)
{
    return (a.addr_Ks  == b.addr_Ks) &&
           (a.addr_Ddv == b.addr_Ddv) &&
           (a.addr_Dsv == b.addr_Dsv) &&
           (a.addr_tag == b.addr_tag);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_destination_v1(const rct::key &spend_pubkey,
    const crypto::x25519_pubkey &unlockamounts_pubkey,
    const crypto::x25519_pubkey &denseview_pubkey,
    const crypto::x25519_pubkey &sparseview_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    JamtisDestinationV1 &destination_out)
{
    make_jamtis_address_pubkeys(spend_pubkey,
        denseview_pubkey,
        sparseview_pubkey,
        unlockamounts_pubkey,
        s_generate_address,
        j,
        destination_out.addr_Ks,
        destination_out.addr_Ddv,
        destination_out.addr_Dsv,
        destination_out.addr_Dua);

    // addr_tag = cipher[k](j)
    crypto::secret_key ciphertag_secret;
    make_jamtis_ciphertag_secret(s_generate_address, ciphertag_secret);

    destination_out.addr_tag = cipher_address_index(ciphertag_secret, j);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_index_from_destination_v1(const JamtisDestinationV1 &destination,
    const rct::key &spend_pubkey,
    const crypto::x25519_pubkey &unlockamounts_pubkey,
    const crypto::x25519_pubkey &denseview_pubkey,
    const crypto::x25519_pubkey &sparseview_pubkey,
    const crypto::secret_key &s_generate_address,
    address_index_t &j_out)
{
    // ciphertag secret
    crypto::secret_key ciphertag_secret;
    make_jamtis_ciphertag_secret(s_generate_address, ciphertag_secret);

    // get the nominal address index from the destination's address tag
    address_index_t nominal_address_index;
    decipher_address_index(ciphertag_secret, destination.addr_tag, nominal_address_index);

    // recreate the destination
    JamtisDestinationV1 test_destination;

    make_jamtis_destination_v1(spend_pubkey,
        unlockamounts_pubkey,
        denseview_pubkey,
        sparseview_pubkey,
        s_generate_address,
        nominal_address_index,
        test_destination);

    // check the destinations are the same
    // note: partial equality will return false
    if (!(test_destination == destination))
        return false;

    j_out = nominal_address_index;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
JamtisDestinationV1 gen_jamtis_destination_v1()
{
    JamtisDestinationV1 temp;
    temp.addr_Ks = rct::pkGen();
    temp.addr_Ddv = crypto::x25519_pubkey_gen();
    temp.addr_Dsv = crypto::x25519_pubkey_gen();
    temp.addr_Dua = crypto::x25519_pubkey_gen();
    crypto::rand(sizeof(address_tag_t), temp.addr_tag.bytes);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
