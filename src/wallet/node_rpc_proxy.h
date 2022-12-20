// Copyright (c) 2017-2022, The Monero Project
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

#include <string>

#include "include_base_utils.h"
#include "net/http.h"
#include "rpc_payment_state.h"
#include "storages/http_abstract_invoke.h"

#define NODERPCPROXY_ACCESS_INVOKE_BODY(invsimp, name, req, res, costcb, ...) \
  do {                                                                        \
    set_req_payment_signature(req);                                           \
    const auto tg = m_rpc_payment_state.start_rpc_call(name, 0);              \
    const bool r = invsimp(name, req, res, ##__VA_ARGS__);                    \
    if (r)                                                                    \
    {                                                                         \
      const uint64_t expected_cost = costcb(res);                             \
      m_rpc_payment_state.update_expected_cost(tg, expected_cost);            \
    }                                                                         \
    m_rpc_payment_state.end_rpc_call(tg, res);                                \
    return r;                                                                 \
  } while (0);                                                                \

#define NODERPCPROXY_CONST_COST_F(tres, expcost) [=](const tres&) -> uint64_t {return expcost;}

namespace tools
{
class NodeRPCProxy
{
public:
  template <class Res>
  using cost_cb_t = std::function<uint64_t(const Res&)>;

  NodeRPCProxy();

  void set_persistent_client_secret_key(const crypto::secret_key &skey);
  void randomize_client_secret_key();
  void invalidate();
  bool is_offline() const;
  void set_offline(bool offline);
  bool set_daemon(std::string daemon_address, boost::optional<epee::net_utils::http::login> daemon_login, bool trusted_daemon, epee::net_utils::ssl_options_t ssl_options);
  bool set_proxy(const std::string &address);
  uint64_t get_bytes_sent() const;
  uint64_t get_bytes_received() const;
  bool try_connection_start(bool* using_ssl = nullptr);

  uint64_t credits() const;
  void credit_report(uint64_t &expected_spent, uint64_t &discrepancy) const;

  boost::optional<std::string> get_rpc_version(uint32_t &rpc_version, std::vector<std::pair<uint8_t, uint64_t>> &daemon_hard_forks, uint64_t &height, uint64_t &target_height);
  boost::optional<std::string> get_height(uint64_t &height);
  void set_height(uint64_t h);
  boost::optional<std::string> get_target_height(uint64_t &height);
  boost::optional<std::string> get_block_weight_limit(uint64_t &block_weight_limit);
  boost::optional<std::string> get_adjusted_time(uint64_t &adjusted_time);
  boost::optional<std::string> get_earliest_height(uint8_t version, uint64_t &earliest_height);
  boost::optional<std::string> get_dynamic_base_fee_estimate(uint64_t grace_blocks, uint64_t &fee);
  boost::optional<std::string> get_dynamic_base_fee_estimate_2021_scaling(uint64_t grace_blocks, std::vector<uint64_t> &fees);
  boost::optional<std::string> get_fee_quantization_mask(uint64_t &fee_quantization_mask);
  boost::optional<std::string> get_rpc_payment_info(bool mining, bool &payment_required, uint64_t &credits, uint64_t &diff, uint64_t &credits_per_hash_found, cryptonote::blobdata &blob, uint64_t &height, uint64_t &seed_height, crypto::hash &seed_hash, crypto::hash &next_seed_hash, uint32_t &cookie);

  template <class Req, class Res>
  bool invoke_json(const std::string& uri, Req& req, Res& res)
  {
    res.status.clear();
    return epee::net_utils::invoke_http_json(uri, req, res, get_transport_ref(), rpc_timeout);
  }

  template <class Req, class Res>
  bool invoke_json_with_access(const std::string& uri, Req& req, Res& res, const cost_cb_t<Res>& cost_f)
  {
    NODERPCPROXY_ACCESS_INVOKE_BODY(invoke_json, uri, req, res, cost_f)
  }

  template <class Req, class Res>
  bool invoke_json_with_access(const std::string& uri, Req& req, Res& res, uint64_t expected_cost)
  {
    cost_cb_t<Res> cost_f = NODERPCPROXY_CONST_COST_F(Res, expected_cost);
    return invoke_json_with_access(uri, req, res, cost_f);
  }

  template <class Req, class Res>
  bool invoke_json_rpc(const std::string& rpc_method, Req& req, Res& res, epee::json_rpc::error& error)
  {
    res.status.clear();
    return epee::net_utils::invoke_http_json_rpc("/json_rpc", rpc_method, req, res, error, get_transport_ref(), rpc_timeout);
  }

  template <class Req, class Res>
  bool invoke_json_rpc_with_access(const std::string& rpc_method, Req& req, Res& res, epee::json_rpc::error& error, const cost_cb_t<Res>& cost_f)
  {
    NODERPCPROXY_ACCESS_INVOKE_BODY(invoke_json_rpc, rpc_method, req, res, cost_f, error)
  }

  template <class Req, class Res>
  bool invoke_json_rpc_with_access(const std::string& rpc_method, Req& req, Res& res, epee::json_rpc::error& error, uint64_t expected_cost)
  {
    cost_cb_t<Res> cost_f = NODERPCPROXY_CONST_COST_F(Res, expected_cost);
    return invoke_json_rpc_with_access(rpc_method, req, res, error, cost_f);
  }

  template <class Req, class Res>
  bool invoke_bin(const std::string& uri, Req& req, Res& res)
  {
    res.status.clear();
    return epee::net_utils::invoke_http_bin(uri, req, res, get_transport_ref(), rpc_timeout);
  }

  template <class Req, class Res>
  bool invoke_bin_with_access(const std::string& uri, Req& req, Res& res, const cost_cb_t<Res>& cost_f)
  {
    NODERPCPROXY_ACCESS_INVOKE_BODY(invoke_bin, uri, req, res, cost_f)
  }

  template <class Req, class Res>
  bool invoke_bin_with_access(const std::string& uri, Req& req, Res& res, uint64_t expected_cost)
  {
    cost_cb_t<Res> cost_f = NODERPCPROXY_CONST_COST_F(Res, expected_cost);
    return invoke_bin_with_access(uri, req, res, cost_f);
  }

private:
  boost::optional<std::string> get_info();

  void set_req_payment_signature(::cryptonote::rpc_access_request_base& req) const;

  epee::net_utils::http::abstract_http_transport& get_transport_ref();

  static constexpr std::chrono::seconds rpc_timeout = std::chrono::seconds(120);

  net::http::client m_http_client;
  std::string m_daemon_address;
  bool m_trusted_daemon;
  boost::optional<epee::net_utils::http::login> m_daemon_login;
  RpcPaymentState m_rpc_payment_state;
  crypto::secret_key m_client_id_secret_key;
  bool m_client_id_is_persistent;
  bool m_offline;

  uint64_t m_height;
  uint64_t m_earliest_height[256];
  uint64_t m_dynamic_base_fee_estimate;
  uint64_t m_dynamic_base_fee_estimate_cached_height;
  uint64_t m_dynamic_base_fee_estimate_grace_blocks;
  std::vector<uint64_t> m_dynamic_base_fee_estimate_vector;
  uint64_t m_fee_quantization_mask;
  uint64_t m_adjusted_time;
  uint32_t m_rpc_version;
  uint64_t m_target_height;
  uint64_t m_block_weight_limit;
  time_t m_get_info_time;
  time_t m_rpc_payment_info_time;
  uint64_t m_rpc_payment_diff;
  uint64_t m_rpc_payment_credits_per_hash_found;
  cryptonote::blobdata m_rpc_payment_blob;
  uint64_t m_rpc_payment_height;
  uint64_t m_rpc_payment_seed_height;
  crypto::hash m_rpc_payment_seed_hash;
  crypto::hash m_rpc_payment_next_seed_hash;
  uint32_t m_rpc_payment_cookie;
  time_t m_height_time;
  time_t m_target_height_time;
  std::vector<std::pair<uint8_t, uint64_t>> m_daemon_hard_forks;
};

} // namespace tools
