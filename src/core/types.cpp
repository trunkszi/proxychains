#include "core/types.hpp"

#include <charconv>
#include <string>
#include <string_view>

namespace proxychains {
namespace {

std::error_code InvalidArgumentError() noexcept {
  return make_error_code(ErrorCode::kInvalidArgument);
}

bool IsSpace(char c) noexcept { return c == ' ' || c == '\t'; }

std::string_view TrimSpaces(std::string_view text) noexcept {
  while (!text.empty() && IsSpace(text.front())) {
    text.remove_prefix(1);
  }
  while (!text.empty() && IsSpace(text.back())) {
    text.remove_suffix(1);
  }
  return text;
}

bool ParsePort(std::string_view text, uint16_t* port) noexcept {
  const auto value = TrimSpaces(text);
  if (value.empty()) {
    return false;
  }
  uint32_t parsed = 0;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
  if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
    return false;
  }
  if (parsed == 0 || parsed > 65535) {
    return false;
  }
  *port = static_cast<uint16_t>(parsed);
  return true;
}

struct HostPort {
  std::string_view host;
  uint16_t port_host{0};
  bool has_port{false};
};

// Splits "addr", "addr:port", "[v6]" or "[v6]:port". A bare literal with
// multiple colons is treated as IPv6 without a port.
Result<HostPort> SplitHostPort(std::string_view spec) noexcept {
  spec = TrimSpaces(spec);
  if (spec.empty()) {
    return std::unexpected(InvalidArgumentError());
  }
  HostPort result;
  if (spec.front() == '[') {
    const auto close = spec.find(']');
    if (close == std::string_view::npos || close <= 1) {
      return std::unexpected(InvalidArgumentError());
    }
    result.host = spec.substr(1, close - 1);
    const auto rest = spec.substr(close + 1);
    if (!rest.empty()) {
      if (rest.front() != ':' || !ParsePort(rest.substr(1), &result.port_host)) {
        return std::unexpected(InvalidArgumentError());
      }
      result.has_port = true;
    }
    return result;
  }
  const auto first_colon = spec.find(':');
  if (first_colon == std::string_view::npos) {
    result.host = spec;
    return result;
  }
  const auto last_colon = spec.rfind(':');
  if (first_colon == last_colon) {
    if (first_colon == 0) {
      return std::unexpected(InvalidArgumentError());
    }
    result.host = spec.substr(0, first_colon);
    if (!ParsePort(spec.substr(first_colon + 1), &result.port_host)) {
      return std::unexpected(InvalidArgumentError());
    }
    result.has_port = true;
    return result;
  }
  result.host = spec;
  return result;
}

Result<uint32_t> ParseDecimal(std::string_view text) noexcept {
  const auto value = TrimSpaces(text);
  if (value.empty()) {
    return std::unexpected(InvalidArgumentError());
  }
  uint32_t parsed = 0;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
  if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
    return std::unexpected(InvalidArgumentError());
  }
  return parsed;
}

Result<uint8_t> ParsePrefix(std::string_view text, uint32_t max_prefix) noexcept {
  const auto parsed = ParseDecimal(text);
  if (!parsed || *parsed > max_prefix) {
    return std::unexpected(InvalidArgumentError());
  }
  return static_cast<uint8_t>(*parsed);
}

Result<uint8_t> PrefixFromDottedMask(std::string_view text) noexcept {
  const auto value = TrimSpaces(text);
  std::array<char, INET_ADDRSTRLEN> buffer{};
  if (value.empty() || value.size() >= buffer.size()) {
    return std::unexpected(InvalidArgumentError());
  }
  std::memcpy(buffer.data(), value.data(), value.size());
  struct in_addr address{};
  if (::inet_pton(AF_INET, buffer.data(), &address) != 1) {
    return std::unexpected(InvalidArgumentError());
  }
  const uint32_t mask = ntohl(address.s_addr);
  uint8_t prefix = 0;
  bool saw_zero = false;
  for (int bit = 31; bit >= 0; --bit) {
    const bool one = ((mask >> bit) & 1U) != 0;
    if (one) {
      if (saw_zero) {
        return std::unexpected(InvalidArgumentError());
      }
      ++prefix;
    } else {
      saw_zero = true;
    }
  }
  return prefix;
}

bool PrefixMatches(const uint8_t* left, const uint8_t* right, uint8_t prefix_len) noexcept {
  const uint8_t full_bytes = static_cast<uint8_t>(prefix_len / 8U);
  for (uint8_t index = 0; index < full_bytes; ++index) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  const uint8_t remaining = static_cast<uint8_t>(prefix_len % 8U);
  if (remaining == 0) {
    return true;
  }
  const auto mask = static_cast<uint8_t>(0xFFU << (8U - remaining));
  return (left[full_bytes] & mask) == (right[full_bytes] & mask);
}

}  // namespace

IpAddress IpAddress::FromV4Bytes(std::array<uint8_t, 4> bytes) noexcept {
  IpAddress address;
  address.v4_ = bytes;
  return address;
}

IpAddress IpAddress::FromV4NetOrder(uint32_t net_addr) noexcept {
  const uint32_t host = ntohl(net_addr);
  return FromV4Bytes({
      static_cast<uint8_t>(host >> 24),
      static_cast<uint8_t>(host >> 16),
      static_cast<uint8_t>(host >> 8),
      static_cast<uint8_t>(host),
  });
}

IpAddress IpAddress::FromIpt4(IpType4 ip4) noexcept {
  return FromV4Bytes({ip4.octet[0], ip4.octet[1], ip4.octet[2], ip4.octet[3]});
}

IpAddress IpAddress::FromV6Bytes(std::array<uint8_t, 16> bytes) noexcept {
  IpAddress address;
  address.is_v6_ = true;
  address.v6_ = bytes;
  return address;
}

IpAddress IpAddress::LocalhostV4() noexcept {
  return FromV4Bytes({127, 0, 0, 1});
}

Result<IpAddress> IpAddress::Parse(std::string_view text) noexcept {
  if (text.empty() || text.size() >= INET6_ADDRSTRLEN ||
      text.find('\0') != std::string_view::npos) {
    return std::unexpected(InvalidArgumentError());
  }
  std::array<char, INET6_ADDRSTRLEN> buffer{};
  std::memcpy(buffer.data(), text.data(), text.size());
  if (std::strchr(buffer.data(), ':') != nullptr) {
    std::array<uint8_t, 16> bytes{};
    if (::inet_pton(AF_INET6, buffer.data(), bytes.data()) != 1) {
      return std::unexpected(InvalidArgumentError());
    }
    return FromV6Bytes(bytes);
  }
  std::array<uint8_t, 4> bytes{};
  if (::inet_pton(AF_INET, buffer.data(), bytes.data()) != 1) {
    return std::unexpected(InvalidArgumentError());
  }
  return FromV4Bytes(bytes);
}

bool IpAddress::IsV4MappedV6() const noexcept {
  if (!is_v6_) {
    return false;
  }
  for (std::size_t index = 0; index < 10; ++index) {
    if (v6_[index] != 0) {
      return false;
    }
  }
  return v6_[10] == 0xFF && v6_[11] == 0xFF;
}

IpAddress IpAddress::NormalizeV4Mapped() const noexcept {
  if (!IsV4MappedV6()) {
    return *this;
  }
  return FromV4Bytes({v6_[12], v6_[13], v6_[14], v6_[15]});
}

bool IpAddress::IsZeroV4() const noexcept {
  const IpAddress normalized = NormalizeV4Mapped();
  if (normalized.IsV6()) {
    return false;
  }
  const auto& bytes = normalized.V4Bytes();
  return bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0;
}

bool IpAddress::IsFakeDnsIp(uint8_t remote_subnet) const noexcept {
  const IpAddress normalized = NormalizeV4Mapped();
  if (normalized.IsV6()) {
    return false;
  }
  return normalized.V4Bytes()[0] == remote_subnet;
}

IpType4 IpAddress::ToIpt4() const noexcept {
  const IpAddress normalized = NormalizeV4Mapped();
  if (normalized.IsV6()) {
    return IPT4_INVALID;
  }
  const auto& bytes = normalized.V4Bytes();
  IpType4 result{};
  result.octet[0] = bytes[0];
  result.octet[1] = bytes[1];
  result.octet[2] = bytes[2];
  result.octet[3] = bytes[3];
  return result;
}

uint32_t IpAddress::V4NetOrder() const noexcept {
  const IpAddress normalized = NormalizeV4Mapped();
  if (normalized.IsV6()) {
    return 0;
  }
  const auto& bytes = normalized.V4Bytes();
  const uint32_t host = (static_cast<uint32_t>(bytes[0]) << 24) |
                        (static_cast<uint32_t>(bytes[1]) << 16) |
                        (static_cast<uint32_t>(bytes[2]) << 8) |
                        static_cast<uint32_t>(bytes[3]);
  return htonl(host);
}

std::string IpAddress::ToString() const noexcept {
  std::array<char, INET6_ADDRSTRLEN> buffer{};
  const int family = is_v6_ ? AF_INET6 : AF_INET;
  const void* source = is_v6_ ? static_cast<const void*>(v6_.data())
                              : static_cast<const void*>(v4_.data());
  if (::inet_ntop(family, source, buffer.data(), static_cast<socklen_t>(buffer.size())) == nullptr) {
    return "<invalid>";
  }
  return std::string(buffer.data());
}

bool IpAddress::operator==(const IpAddress& other) const noexcept {
  if (is_v6_ != other.is_v6_) {
    return false;
  }
  return is_v6_ ? v6_ == other.v6_ : v4_ == other.v4_;
}

Result<CidrRule> CidrRule::Parse(std::string_view spec) noexcept {
  const auto value = TrimSpaces(spec);
  const auto slash = value.find('/');
  if (slash == std::string_view::npos || slash == 0 || slash + 1 >= value.size()) {
    return std::unexpected(InvalidArgumentError());
  }
  const auto address_text = TrimSpaces(value.substr(0, slash));
  const auto mask_text = TrimSpaces(value.substr(slash + 1));
  const auto host_port = SplitHostPort(address_text);
  if (!host_port) {
    return std::unexpected(host_port.error());
  }
  const auto network = IpAddress::Parse(host_port->host);
  if (!network) {
    return std::unexpected(network.error());
  }
  uint8_t prefix = 0;
  if (network->IsV6()) {
    if (mask_text.find('.') != std::string_view::npos) {
      return std::unexpected(InvalidArgumentError());
    }
    const auto parsed = ParsePrefix(mask_text, 128);
    if (!parsed) {
      return std::unexpected(parsed.error());
    }
    prefix = *parsed;
  } else if (mask_text.find('.') != std::string_view::npos) {
    const auto parsed = PrefixFromDottedMask(mask_text);
    if (!parsed) {
      return std::unexpected(parsed.error());
    }
    prefix = *parsed;
  } else {
    const auto parsed = ParsePrefix(mask_text, 32);
    if (!parsed) {
      return std::unexpected(parsed.error());
    }
    prefix = *parsed;
  }
  CidrRule rule;
  rule.network = *network;
  rule.prefix_len = prefix;
  rule.port_host = host_port->has_port ? host_port->port_host : 0;
  return rule;
}

bool CidrRule::Matches(const IpAddress& target_ip, uint16_t target_port_host) const noexcept {
  if (port_host != 0 && port_host != target_port_host) {
    return false;
  }
  if (!network.IsV6() && !target_ip.IsV6()) {
    return prefix_len <= 32 &&
           PrefixMatches(network.V4Bytes().data(), target_ip.V4Bytes().data(), prefix_len);
  }
  if (network.IsV6() && target_ip.IsV6()) {
    return prefix_len <= 128 &&
           PrefixMatches(network.V6Bytes().data(), target_ip.V6Bytes().data(), prefix_len);
  }
  if (network.IsV6() && !target_ip.IsV6() && network.IsV4MappedV6()) {
    if (prefix_len < 96 || prefix_len > 128) {
      return false;
    }
    const auto normalized = network.NormalizeV4Mapped();
    return PrefixMatches(normalized.V4Bytes().data(), target_ip.V4Bytes().data(),
                         static_cast<uint8_t>(prefix_len - 96));
  }
  if (!network.IsV6() && target_ip.IsV6() && target_ip.IsV4MappedV6()) {
    if (prefix_len > 32) {
      return false;
    }
    const auto normalized = target_ip.NormalizeV4Mapped();
    return PrefixMatches(network.V4Bytes().data(), normalized.V4Bytes().data(), prefix_len);
  }
  return false;
}

Result<DnatRule> DnatRule::Parse(std::string_view orig_spec,
                                 std::string_view new_spec) noexcept {
  const auto orig = SplitHostPort(orig_spec);
  if (!orig) {
    return std::unexpected(orig.error());
  }
  const auto replacement = SplitHostPort(new_spec);
  if (!replacement) {
    return std::unexpected(replacement.error());
  }
  const auto orig_ip = IpAddress::Parse(orig->host);
  if (!orig_ip) {
    return std::unexpected(orig_ip.error());
  }
  const auto new_ip = IpAddress::Parse(replacement->host);
  if (!new_ip) {
    return std::unexpected(new_ip.error());
  }
  DnatRule rule;
  rule.orig_ip = *orig_ip;
  rule.orig_port_host = orig->has_port ? orig->port_host : 0;
  rule.new_ip = *new_ip;
  rule.new_port_host = replacement->has_port ? replacement->port_host : 0;
  return rule;
}

bool DnatRule::Matches(const IpAddress& target_ip, uint16_t target_port_host) const noexcept {
  if (orig_port_host != 0 && orig_port_host != target_port_host) {
    return false;
  }
  return orig_ip.NormalizeV4Mapped() == target_ip.NormalizeV4Mapped();
}

}  // namespace proxychains
