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

//paired header
#include "key_image_device_composed.h"

//local headers
#include "address_utils.h"
#include "carrot_core/address_utils.h"
#include "carrot_core/exceptions.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "carrot_impl.device"

namespace
{
struct make_local_device_error
{
    int code;
    std::string func;

    make_local_device_error(int code, std::string func): code(code), func(std::move(func)) {}

    carrot::device_error operator()(std::string msg)
    {
        return carrot::device_error("Default", "key_image_device_composed", std::move(func), std::move(msg), code);
    }
};
} //anonymous namespace

namespace carrot
{
//-------------------------------------------------------------------------------------------------------------------
key_image_device_composed::key_image_device_composed(const generate_image_key_device &k_generate_image_dev,
    const hybrid_hierarchy_address_device &addr_dev,
    const view_balance_secret_device *s_view_balance_dev,
    const view_incoming_key_device *k_view_incoming_dev):
        m_k_generate_image_dev(k_generate_image_dev),
        m_addr_dev(addr_dev),
        m_s_view_balance_dev(s_view_balance_dev),
        m_k_view_incoming_dev(k_view_incoming_dev)
{}
//-------------------------------------------------------------------------------------------------------------------
crypto::key_image key_image_device_composed::derive_key_image(const OutputOpeningHintVariant &opening_hint) const
{
    const crypto::public_key onetime_address = onetime_address_ref(opening_hint);
    const subaddress_index_extended subaddr_index = subaddress_index_ref(opening_hint);

    crypto::public_key main_address_spend_pubkeys[2];
    const std::size_t n_main_addrs = get_all_main_address_spend_pubkeys(m_addr_dev, main_address_spend_pubkeys);
    CARROT_CHECK_AND_THROW(n_main_addrs > 0, make_local_device_error(-4, "derive_key_image"),
        "Address device supports no known address derivation scheme");

    // get k^g_o, k^t_o
    crypto::secret_key sender_extension_g;
    crypto::secret_key sender_extension_t;
    if (!try_scan_opening_hint_sender_extensions(opening_hint,
        {main_address_spend_pubkeys, n_main_addrs},
        m_k_view_incoming_dev,
        m_s_view_balance_dev,
        sender_extension_g,
        sender_extension_t))
    {
        throw make_local_device_error{-3, "derive_key_image"}("enote scan failed");
    }

    return this->derive_key_image_prescanned(sender_extension_g, onetime_address, subaddr_index);
}
//-------------------------------------------------------------------------------------------------------------------
crypto::key_image key_image_device_composed::derive_key_image_prescanned(const crypto::secret_key &sender_extension_g,
    const crypto::public_key &onetime_address,
    const subaddress_index_extended &subaddr_index) const
{
    AddressDeriveType resolved_derive_type = subaddr_index.derive_type;
    resolved_derive_type = resolved_derive_type != AddressDeriveType::Auto
        ? resolved_derive_type
        : m_addr_dev.supports_address_derivation_type(AddressDeriveType::Carrot)
            ? AddressDeriveType::Carrot
            : AddressDeriveType::PreCarrot;
    CARROT_CHECK_AND_THROW(m_addr_dev.supports_address_derivation_type(resolved_derive_type),
        make_local_device_error(-1, "derive_key_image_prescanned"), "Address derive type not supported");

    // [legacy] L_partial = k_s Hp(K_o)
    // [carrot] L_partial = k_gi Hp(K_o)
    rct::key partial_key_image
        = rct::pt2rct(m_k_generate_image_dev.generate_image_scalar_mult_hash_to_point(onetime_address));

    // I = Hp(K_o)
    crypto::ec_point key_image_generator;
    crypto::derive_key_image_generator(onetime_address, key_image_generator);

    // get K_s, modify L_partial
    crypto::secret_key subaddr_extension_g;
    crypto::secret_key carrot_address_index_extension_generator;
    crypto::secret_key carrot_subaddr_scalar;
    rct::key tmp;
    switch (resolved_derive_type)
    {
        case AddressDeriveType::PreCarrot:
            // L_partial += k^j_subext Hp(O)
            m_addr_dev.access_cryptonote_hierarchy_device().make_legacy_subaddress_extension(subaddr_index.index.major,
                subaddr_index.index.minor, subaddr_extension_g);
            tmp = rct::scalarmultKey(rct::pt2rct(key_image_generator), rct::sk2rct(subaddr_extension_g));
            partial_key_image = rct::addKeys(tmp, partial_key_image);
            break;
        case AddressDeriveType::Carrot:
            if (subaddr_index.index.is_subaddress())
            {
                // L_partial *= k^j_subscal
                m_addr_dev.access_carrot_hierarchy_device().make_index_extension_generator(subaddr_index.index.major,
                    subaddr_index.index.minor,
                    carrot_address_index_extension_generator);
                make_carrot_subaddress_scalar(
                    m_addr_dev.access_carrot_hierarchy_device().get_carrot_account_spend_pubkey(),
                    m_addr_dev.access_carrot_hierarchy_device().get_carrot_account_view_pubkey(),
                    carrot_address_index_extension_generator,
                    subaddr_index.index.major,
                    subaddr_index.index.minor,
                    carrot_subaddr_scalar);
                partial_key_image = rct::scalarmultKey(partial_key_image, rct::sk2rct(carrot_subaddr_scalar));
            }
            break;
        default:
            throw make_local_device_error{-2, "derive_key_image_prescanned"}("unrecognized address derive type");
    }

    // L = K^g_o Hp(K_o) + L_partial
    tmp = rct::scalarmultKey(rct::pt2rct(key_image_generator), rct::sk2rct(sender_extension_g));
    return rct::rct2ki(rct::addKeys(tmp, partial_key_image));
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace carrot
