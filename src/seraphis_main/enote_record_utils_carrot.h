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

// Utilities for making enote records from enotes.

#pragma once

//local headers
#include "enote_record_types.h"

//third party headers

//standard headers
#include <optional>

//forward declarations


namespace sp
{

/**
* brief: try_get_carrot_intermediate_enote_record_v1 - try to extract an intermediate enote record from an enote
* param: enote -
* param: enote_ephemeral_pubkey -
* param: payment 
* param: input_context -
* param: k_view
* outparam: record_out -
* return: true if extraction succeeded
*/
bool try_get_carrot_intermediate_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::optional<jamtis::encrypted_payment_id_t> &payment_id_enc,
    const jamtis::input_context_t &input_context,
    const crypto::secret_key &k_view,
    const crypto::public_key &primary_address_spend_pubkey,
    CarrotIntermediateEnoteRecordV1 &record_out);
/**
* brief: try_get_carrot_enote_record_v1 - try to extract an enote record from an enote
*/
bool try_get_carrot_enote_record_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const std::optional<jamtis::encrypted_payment_id_t> &payment_id_enc,
    const jamtis::input_context_t &input_context,
    const crypto::secret_key &k_view,
    const crypto::secret_key &k_spend,
    const crypto::public_key &primary_address_spend_pubkey,
    CarrotEnoteRecordV1 &record_out);

} //namespace sp
