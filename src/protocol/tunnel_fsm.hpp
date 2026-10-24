#pragma once

/// @file tunnel_fsm.hpp
/// @brief Explicit handshake state machine for RAW/HTTP/SOCKS4/SOCKS5 proxies.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "core/error.hpp"
#include "core/types.hpp"

namespace proxychains {

/// Maps a fake DNS address back to its hostname, or `nullopt` when unknown.
using ReverseDnsLookupFn = std::optional<std::string> (*)(IpType4 fake_ip) noexcept;

/// Runs the proxy handshake on an already-connected `sock_fd`.
///
/// `target_domain` is non-empty when the peer must resolve the name itself
/// (remote DNS); otherwise `target_ip` is used. IPv6 targets are bracketed for
/// HTTP CONNECT and rejected for SOCKS4.
///
/// @return Success, kProxyBlocked when the proxy refuses, kProtocolError for a
///         malformed or unexpected reply, kTimeout, or kSocketError.
[[nodiscard]] Result<void> EstablishProxyTunnel(int sock_fd,
                                                const ProxyEndpoint& proxy,
                                                const IpAddress& target_ip,
                                                uint16_t target_port_host,
                                                std::string_view target_domain,
                                                int read_timeout_ms) noexcept;

}  // namespace proxychains
