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
#include "legacy_enote_types.h"

//local headers
#include "ringct/rctOps.h"

//third party headers

//standard headers

namespace carrot
{
//-------------------------------------------------------------------------------------------------------------------
LegacyEnoteV1 gen_legacy_enote_v1()
{
    LegacyEnoteV1 temp;
    temp.onetime_address = rct::rct2pk(rct::pkGen());
    temp.amount          = crypto::rand_idx<rct::xmr_amount>(0);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyEnoteV2 gen_legacy_enote_v2()
{
    LegacyEnoteV2 temp;
    temp.onetime_address                  = rct::rct2pk(rct::pkGen());
    temp.amount_commitment                = rct::pkGen();
    temp.encrypted_amount_blinding_factor = rct::skGen();
    temp.encrypted_amount                 = rct::skGen();
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyEnoteV3 gen_legacy_enote_v3()
{
    LegacyEnoteV3 temp;
    temp.onetime_address   = rct::rct2pk(rct::pkGen());
    temp.amount_commitment = rct::pkGen();
    crypto::rand(sizeof(temp.encrypted_amount), temp.encrypted_amount.bytes);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyEnoteV4 gen_legacy_enote_v4()
{
    LegacyEnoteV4 temp;
    temp.onetime_address = rct::rct2pk(rct::pkGen());
    temp.amount          = crypto::rand_idx<rct::xmr_amount>(0);
    temp.view_tag.data   = static_cast<char>(crypto::rand_idx<unsigned char>(0));
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyEnoteV5 gen_legacy_enote_v5()
{
    LegacyEnoteV5 temp;
    temp.onetime_address   = rct::rct2pk(rct::pkGen());
    temp.amount_commitment = rct::pkGen();
    crypto::rand(sizeof(temp.encrypted_amount), temp.encrypted_amount.bytes);
    temp.view_tag.data     = static_cast<char>(crypto::rand_idx<unsigned char>(0));
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace carrot
