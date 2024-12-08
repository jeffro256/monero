// Copyright (c) 2024, The Monero Project
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

#ifndef MONERO_CLSAG_C_API_H
#define MONERO_CLSAG_C_API_H

#include <stddef.h>

struct monero_c_key
{
    unsigned char data[32];
};

struct monero_c_clsag;

monero_c_clsag* monero_c_clsag_prove(const monero_c_key *m,
    const monero_c_key *pubkeys,
    const monero_c_key *privkey,
    const monero_c_key *commits_to_zero,
    const monero_c_key *commits,
    const monero_c_key *pseudo_out,
    const monero_c_key *blinding_factor_diff,
    size_t index_in_ring,
    size_t mixring_size);

int monero_c_clsag_verify(const monero_c_key *m,
    const monero_c_clsag *sig,
    const monero_c_key *mixring_pubkeys,
    const monero_c_key *mixring_commitments,
    const monero_c_key *pseudo_out,
    size_t mixring_len);

void monero_c_clsag_destroy(monero_c_clsag* clsag);

#endif
