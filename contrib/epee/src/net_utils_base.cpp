
#include "net/net_utils_base.h"

#include <boost/uuid/uuid_io.hpp>

#include "string_tools.h"
#include "net/local_ip.h"

static inline uint32_t make_address_v4_from_v6(const boost::asio::ip::address_v6& a)
{
  const auto &bytes = a.to_bytes();
  uint32_t v4 = 0;
  v4 = (v4 << 8) | bytes[12];
  v4 = (v4 << 8) | bytes[13];
  v4 = (v4 << 8) | bytes[14];
  v4 = (v4 << 8) | bytes[15];
  return htonl(v4);
}

namespace
{
	struct network_address_deserialize_variant
	{
		std::string host;
		uint16_t port; // when serialized for tor becomes lexical string
		uint32_t m_ip;
		uint16_t m_port;
		boost::asio::ip::address_v6 addr;

		BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE_OPT(host, {})
			KV_SERIALIZE_OPT(port, {})
			KV_SERIALIZE_OPT(m_ip, {})
			KV_SERIALIZE_OPT(m_port, {})
			KV_SERIALIZE_OPT(m_address, {})
		END_KV_SERIALIZE_MAP()
	};

	struct deserialized_network_address
	{
		uint8_t type;
		network_address_deserialize_variant addr;

		BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(type)
			KV_SERIALIZE(addr)
		END_KV_SERIALIZE_MAP()
	};
}

namespace epee { namespace net_utils
{
	bool ipv4_network_address::equal(const ipv4_network_address& other) const noexcept
	{ return is_same_host(other) && port() == other.port(); }

	bool ipv4_network_address::less(const ipv4_network_address& other) const noexcept
	{ return is_same_host(other) ? port() < other.port() : ip() < other.ip(); }

	std::string ipv4_network_address::str() const
	{ return string_tools::get_ip_string_from_int32(ip()) + ":" + std::to_string(port()); }

	std::string ipv4_network_address::host_str() const { return string_tools::get_ip_string_from_int32(ip()); }
	bool ipv4_network_address::is_loopback() const { return net_utils::is_ip_loopback(ip()); }
	bool ipv4_network_address::is_local() const { return net_utils::is_ip_local(ip()); }

	bool ipv6_network_address::equal(const ipv6_network_address& other) const noexcept
	{ return is_same_host(other) && port() == other.port(); }

	bool ipv6_network_address::less(const ipv6_network_address& other) const noexcept
	{ return is_same_host(other) ? port() < other.port() : m_address < other.m_address; }

	std::string ipv6_network_address::str() const
	{ return std::string("[") + host_str() + "]:" + std::to_string(port()); }

	std::string ipv6_network_address::host_str() const { return m_address.to_string(); }
	bool ipv6_network_address::is_loopback() const { return m_address.is_loopback(); }
	bool ipv6_network_address::is_local() const { return m_address.is_link_local(); }


	bool ipv4_network_subnet::equal(const ipv4_network_subnet& other) const noexcept
	{ return is_same_host(other) && m_mask == other.m_mask; }

	bool ipv4_network_subnet::less(const ipv4_network_subnet& other) const noexcept
	{ return subnet() < other.subnet() ? true : (other.subnet() < subnet() ? false : (m_mask < other.m_mask)); }

	std::string ipv4_network_subnet::str() const
	{ return string_tools::get_ip_string_from_int32(subnet()) + "/" + std::to_string(m_mask); }

	std::string ipv4_network_subnet::host_str() const { return string_tools::get_ip_string_from_int32(subnet()) + "/" + std::to_string(m_mask); }
	bool ipv4_network_subnet::is_loopback() const { return net_utils::is_ip_loopback(subnet()); }
	bool ipv4_network_subnet::is_local() const { return net_utils::is_ip_local(subnet()); }
	bool ipv4_network_subnet::matches(const ipv4_network_address &address) const
	{
		return (address.ip() & ~(0xffffffffull << m_mask)) == subnet();
	}


	bool network_address::equal(const network_address& other) const
	{
		// clang typeid workaround
		network_address::interface const* const self_ = self.get();
		network_address::interface const* const other_self = other.self.get();
		if (self_ == other_self) return true;
		if (!self_ || !other_self) return false;
		if (typeid(*self_) != typeid(*other_self)) return false;
		return self_->equal(*other_self);
	}

	bool network_address::less(const network_address& other) const
	{
		// clang typeid workaround
		network_address::interface const* const self_ = self.get();
		network_address::interface const* const other_self = other.self.get();
		if (self_ == other_self) return false;
		if (!self_ || !other_self) return self == nullptr;
		if (typeid(*self_) != typeid(*other_self))
			return self_->get_type_id() < other_self->get_type_id();
		return self_->less(*other_self);
	}

	bool network_address::is_same_host(const network_address& other) const
	{
		// clang typeid workaround
		network_address::interface const* const self_ = self.get();
		network_address::interface const* const other_self = other.self.get();
		if (self_ == other_self) return true;
		if (!self_ || !other_self) return false;
		if (typeid(*self_) == typeid(*other_self))
			return self_->is_same_host(*other_self);
		const auto this_id = get_type_id();
		if (this_id == ipv4_network_address::get_type_id() && other.get_type_id() == ipv6_network_address::get_type_id())
		{
			const boost::asio::ip::address_v6 &actual_ip = other.as<const epee::net_utils::ipv6_network_address>().ip();
			if (actual_ip.is_v4_mapped())
			{
				const uint32_t v4ip = make_address_v4_from_v6(actual_ip);
				return is_same_host(ipv4_network_address(v4ip, 0));
			}
		}
		else if (this_id == ipv6_network_address::get_type_id() && other.get_type_id() == ipv4_network_address::get_type_id())
		{
			const boost::asio::ip::address_v6 &actual_ip = this->as<const epee::net_utils::ipv6_network_address>().ip();
			if (actual_ip.is_v4_mapped())
			{
				const uint32_t v4ip = make_address_v4_from_v6(actual_ip);
				return other.is_same_host(ipv4_network_address(v4ip, 0));
			}
		}
		return false;
	}

	void serialize_default(const network_address& value, serde::model::Serializer& serializer)
	{
		serializer.serialize_start_object(2); // number of fields is 2: type and addr
		serializer.serialize_key(serde::internal::cstr_to_byte_span("type"));
		serializer.serialize_uint8(static_cast<uint8_t>(value.get_type_id()));
		serializer.serialize_key(serde::internal::cstr_to_byte_span("addr"));
		
		switch (value.get_type_id())
		{
		case address_type::ipv4:
			serialize_default(value.as<ipv4_network_address>(), serializer);
			break;
		case address_type::ipv6:
			serialize_default(value.as<ipv6_network_address>(), serializer);
			break;
		case address_type::tor:
			serialize_default(value.as<net::tor_address>(), serializer);
			break;
		case address_type::i2p:
			serialize_default(value.as<net::tor_address>(), serializer);
			break;
		default:
			MERROR("invalid address type while serializing: " << (int) value.get_type_id());
			return;
		}

		serializer.serialize_end_object();
	}

	template <class AddrType>
	network_address make_addr_with_type(network_address_deserialize_variant&& addr_variant)
	{
		return {AddrType::make_addr_from_variant(addr_variant)};
	}

	bool deserialize_default(serde::model::Deserializer& deserializer, network_address& value)
	{
		deserialized_network_address net_addr;
		if (!deserialize_default(deserializer, net_addr))
		{
			return false;
		}

		const address_type net_addr_type_as_enum = static_cast<address_type>(net_addr.type);
		switch (net_addr_type_as_enum)
		{
		case address_type::ipv4:
			value = make_addr_with_type<ipv4_network_address>(std::move(net_addr.addr));
			break;
		case address_type::ipv6:
			value = make_addr_with_type<ipv6_network_address>(std::move(net_addr.addr));
			break;
		case address_type::tor:
			value = make_addr_with_type<net::tor_address>(std::move(net_addr.addr));
			break;
		case address_type::i2p:
			value = make_addr_with_type<net::i2p_address>(std::move(net_addr.addr));
			break;
		default:
			ASSERT_MES_AND_THROW("invalid address type while deserializing: " << (int) net_addr.type);
		}

		return true;
	}

  std::string print_connection_context(const connection_context_base& ctx)
  {
    std::stringstream ss;
    ss << ctx.m_remote_address.str() << " " << ctx.m_connection_id << (ctx.m_is_income ? " INC":" OUT");
    return ss.str();
  }

  std::string print_connection_context_short(const connection_context_base& ctx)
  {
    std::stringstream ss;
    ss << ctx.m_remote_address.str() << (ctx.m_is_income ? " INC":" OUT");
    return ss.str();
  }

  const char* zone_to_string(zone value) noexcept
  {
    switch (value)
    {
    case zone::public_:
      return "public";
    case zone::i2p:
      return "i2p";
    case zone::tor:
      return "tor";
    default:
      break;
    }
    return "invalid";
  }

  zone zone_from_string(const boost::string_ref value) noexcept
  {
    if (value == "public")
      return zone::public_;
    if (value == "i2p")
      return zone::i2p;
    if (value == "tor")
      return zone::tor;
    return zone::invalid;
  }
}}

