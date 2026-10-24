#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

#include "core/error.hpp"

namespace proxychains {

/** @file
 *  @brief Value types shared by proxy selection, DNS and protocol layers.
 */

/** @brief Legacy IPv4 storage: four address-order octets or one 32-bit word. */
union IpType4 {
  unsigned char octet[4];
  uint32_t as_int;
};

inline constexpr IpType4 IPT4_INVALID = {.as_int = static_cast<uint32_t>(-1)};
inline constexpr IpType4 IPT4_LOCALHOST = {.octet = {127, 0, 0, 1}};

/** @brief Builds an IpType4 from a raw 32-bit word without byte swapping. */
[[nodiscard]] constexpr IpType4 MakeIpt4Int(uint32_t x) noexcept {
  IpType4 r{};
  r.as_int = x;
  return r;
}

/** @brief Proxy protocols supported by the tunnel handshakes. */
enum class ProxyType : uint8_t {
  kHttp = 0,
  kSocks4 = 1,
  kSocks5 = 2,
  kRaw = 3,
};

/** @brief Proxy selection strategies. */
enum class ChainType : uint8_t {
  kDynamic = 0,
  kStrict = 1,
  kRandom = 2,
  kRoundRobin = 3,
};

/** @brief Runtime health of a single proxy entry. */
enum class ProxyState : uint8_t {
  kPlay = 0,
  kDown = 1,
  kBlocked = 2,
  kBusy = 3,
};

/** @brief Remote DNS strategies. */
enum class DnsMethod : uint8_t {
  kOff = 0,
  kThread = 1,
  kDaemon = 2,
};

/** @brief Returns the configuration token for a proxy protocol. */
[[nodiscard]] constexpr std::string_view ToStringView(ProxyType type) noexcept {
  switch (type) {
    case ProxyType::kHttp:
      return "http";
    case ProxyType::kSocks4:
      return "socks4";
    case ProxyType::kSocks5:
      return "socks5";
    case ProxyType::kRaw:
      return "raw";
  }
  return "unknown";
}

/** @brief Returns the configuration token for a chain strategy. */
[[nodiscard]] constexpr std::string_view ToStringView(ChainType type) noexcept {
  switch (type) {
    case ChainType::kDynamic:
      return "dynamic";
    case ChainType::kStrict:
      return "strict";
    case ChainType::kRandom:
      return "random";
    case ChainType::kRoundRobin:
      return "round_robin";
  }
  return "unknown";
}

/** @brief Returns the configuration token for a proxy state. */
[[nodiscard]] constexpr std::string_view ToStringView(ProxyState state) noexcept {
  switch (state) {
    case ProxyState::kPlay:
      return "play";
    case ProxyState::kDown:
      return "down";
    case ProxyState::kBlocked:
      return "blocked";
    case ProxyState::kBusy:
      return "busy";
  }
  return "unknown";
}

/** @brief Returns the configuration token for a remote DNS method. */
[[nodiscard]] constexpr std::string_view ToStringView(DnsMethod method) noexcept {
  switch (method) {
    case DnsMethod::kOff:
      return "off";
    case DnsMethod::kThread:
      return "thread";
    case DnsMethod::kDaemon:
      return "daemon";
  }
  return "unknown";
}

/**
 * @brief IPv4 or IPv6 address in host memory order.
 *
 * Equality compares the stored family and bytes exactly. Callers that must
 * treat an IPv4-mapped IPv6 address as its IPv4 counterpart normalize it
 * explicitly with NormalizeV4Mapped().
 */
class IpAddress {
 public:
  constexpr IpAddress() noexcept = default;
  [[nodiscard]] static IpAddress FromV4Bytes(std::array<uint8_t, 4> bytes) noexcept;
  [[nodiscard]] static IpAddress FromV4NetOrder(uint32_t net_addr) noexcept;
  [[nodiscard]] static IpAddress FromIpt4(IpType4 ip4) noexcept;
  [[nodiscard]] static IpAddress FromV6Bytes(std::array<uint8_t, 16> bytes) noexcept;
  [[nodiscard]] static IpAddress LocalhostV4() noexcept;
  /** @brief Parses an unbracketed IPv4 or IPv6 literal. */
  [[nodiscard]] static Result<IpAddress> Parse(std::string_view text) noexcept;

  [[nodiscard]] constexpr bool IsV6() const noexcept { return is_v6_; }
  [[nodiscard]] bool IsV4MappedV6() const noexcept;
  [[nodiscard]] IpAddress NormalizeV4Mapped() const noexcept;
  /** @brief True for 0.0.0.0 and for the V4-mapped form of 0.0.0.0. */
  [[nodiscard]] bool IsZeroV4() const noexcept;
  /** @brief True when the first IPv4 octet equals remote_subnet. */
  [[nodiscard]] bool IsFakeDnsIp(uint8_t remote_subnet) const noexcept;

  /** @brief IPv4 view; IPT4_INVALID for a real IPv6 address. */
  [[nodiscard]] IpType4 ToIpt4() const noexcept;
  /** @brief Network-order IPv4 word; zero for a real IPv6 address. */
  [[nodiscard]] uint32_t V4NetOrder() const noexcept;
  [[nodiscard]] const std::array<uint8_t, 4>& V4Bytes() const noexcept { return v4_; }
  [[nodiscard]] const std::array<uint8_t, 16>& V6Bytes() const noexcept { return v6_; }
  [[nodiscard]] std::string ToString() const noexcept;

  bool operator==(const IpAddress& other) const noexcept;

 private:
  bool is_v6_{false};
  std::array<uint8_t, 4> v4_{0, 0, 0, 0};
  std::array<uint8_t, 16> v6_{};
};

/** @brief Localnet exclusion rule; port_host 0 matches every port. */
struct CidrRule {
  IpAddress network{};
  uint8_t prefix_len{0};
  uint16_t port_host{0};  // 0 means any port

  /** @brief Parses "addr[/prefix|/dotted-mask]" with an optional ":port". */
  [[nodiscard]] static Result<CidrRule> Parse(std::string_view spec) noexcept;
  [[nodiscard]] bool Matches(const IpAddress& target_ip, uint16_t target_port_host) const noexcept;
};

/** @brief Destination NAT rule; zero ports mean "any" or "keep original". */
struct DnatRule {
  IpAddress orig_ip{};
  uint16_t orig_port_host{0};  // 0 means any port
  IpAddress new_ip{};
  uint16_t new_port_host{0};  // 0 means keep original port

  /** @brief Parses the original and replacement "addr[:port]" specs. */
  [[nodiscard]] static Result<DnatRule> Parse(std::string_view orig_spec,
                                              std::string_view new_spec) noexcept;
  [[nodiscard]] bool Matches(const IpAddress& target_ip,
                             uint16_t target_port_host) const noexcept;
};

/** @brief One configured hop in the proxy chain. */
struct ProxyEndpoint {
  IpAddress ip{};
  std::string host{};  // Non-empty when hostname is deferred for strict chain + remote DNS
  uint16_t port_host{0};
  ProxyType type{ProxyType::kSocks5};
  ProxyState state{ProxyState::kPlay};
  std::string user{};
  std::string pass{};
};

inline constexpr std::size_t kMaxChain = 512;
inline constexpr std::size_t kMaxLocalnet = 64;
inline constexpr std::size_t kMaxDnat = 64;
inline constexpr std::size_t kMaxHostLen = 255;

}  // namespace proxychains
