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
#include "jamtis_account_secrets.h"
#include "jamtis_address_tag_utils.h"
#include "jamtis_address_utils.h"
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
    return (a.addr_Ks    == b.addr_Ks)    &&
           (a.addr_Dfa   == b.addr_Dfa)   &&
           (a.addr_Dir   == b.addr_Dir)   &&
           (a.addr_Dbase == b.addr_Dbase) &&
           (a.addr_tag   == b.addr_tag);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_destination_v1_sp(const rct::key &spend_pubkey,
    const crypto::x25519_pubkey &filterassist_pubkey,
    const crypto::x25519_pubkey &identifyreceived_pubkey,
    const crypto::x25519_pubkey &exchangebase_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    JamtisDestinationV1 &destination_out)
{
    make_jamtis_destination_v1(JamtisOnetimeAddressFormat::SERAPHIS,
        spend_pubkey,
        filterassist_pubkey,
        identifyreceived_pubkey,
        exchangebase_pubkey,
        s_generate_address,
        j,
        destination_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_destination_v1_rct(const rct::key &spend_pubkey,
    const crypto::x25519_pubkey &filterassist_pubkey,
    const crypto::x25519_pubkey &identifyreceived_pubkey,
    const crypto::x25519_pubkey &exchangebase_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    JamtisDestinationV1 &destination_out)
{
    make_jamtis_destination_v1(JamtisOnetimeAddressFormat::RINGCT_V2,
        spend_pubkey,
        filterassist_pubkey,
        identifyreceived_pubkey,
        exchangebase_pubkey,
        s_generate_address,
        j,
        destination_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_destination_v1(const JamtisOnetimeAddressFormat onetime_address_format,
    const rct::key &spend_pubkey,
    const crypto::x25519_pubkey &filterassist_pubkey,
    const crypto::x25519_pubkey &identifyreceived_pubkey,
    const crypto::x25519_pubkey &exchangebase_pubkey,
    const crypto::secret_key &s_generate_address,
    const address_index_t &j,
    JamtisDestinationV1 &destination_out)
{
    // K^j_s = ... + K_s
    make_jamtis_address_spend_key(onetime_address_format, spend_pubkey, s_generate_address, j, destination_out.addr_Ks);

    // d^j_a = H_n_x25519(K_s, j, s^j_gen)
    crypto::x25519_secret_key address_privkey;
    make_jamtis_address_privkey(spend_pubkey, s_generate_address, j, address_privkey);

    // D^j_fa = d^j_a * D_fa
    x25519_scmul_key(address_privkey, filterassist_pubkey, destination_out.addr_Dfa);

    // D^j_ir = d^j_a * D_vr
    x25519_scmul_key(address_privkey, identifyreceived_pubkey, destination_out.addr_Dir);

    // D^j_base = d^j_a * D_base
    x25519_scmul_key(address_privkey, exchangebase_pubkey, destination_out.addr_Dbase);

    // s_ct = H32[s_ga]()
    crypto::secret_key ciphertag_secret;
    make_jamtis_ciphertag_secret(s_generate_address, ciphertag_secret);

    // addr_tag = cipher[s_ct](j)
    destination_out.addr_tag = cipher_address_index(ciphertag_secret, j);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_index_from_destination_v1(const JamtisOnetimeAddressFormat onetime_address_format,
    const JamtisDestinationV1 &destination,
    const rct::key &spend_pubkey,
    const crypto::x25519_pubkey &filterassist_pubkey,
    const crypto::x25519_pubkey &identifyreceived_pubkey,
    const crypto::x25519_pubkey &exchangebase_pubkey,
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

    make_jamtis_destination_v1(onetime_address_format,
        spend_pubkey,
        filterassist_pubkey,
        identifyreceived_pubkey,
        exchangebase_pubkey,
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
    temp.addr_Dfa = crypto::x25519_pubkey_gen();
    temp.addr_Dir = crypto::x25519_pubkey_gen();
    temp.addr_Dbase = crypto::x25519_pubkey_gen();
    crypto::rand(sizeof(address_tag_t), temp.addr_tag.bytes);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp
