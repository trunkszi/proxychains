#pragma once

/// @file chain_scheduler.hpp
/// @brief Thread-safe proxy chain selection and connection scheduling.

#include <unistd.h>

#include <cstdint>
#include <mutex>
#include <vector>

#include "config/config.hpp"
#include "core/error.hpp"
#include "core/types.hpp"
#include "protocol/socket_io.hpp"
#include "protocol/tunnel_fsm.hpp"

namespace proxychains {

/// Selects a proxy chain and replaces an application socket with the tunnel.
///
/// Proxy states and the round-robin cursor are guarded by a mutex so concurrent
/// `connect` calls from application threads cannot race. Random selection uses
/// a thread-local engine seeded from `std::random_device`, never the host's
/// `rand()` state.
class ChainScheduler {
 public:
  ChainScheduler() noexcept = default;

  /// Copies the proxy list and scheduling policy from `config`.
  void Configure(const ProxychainsConfig& config) noexcept;

  /// Connects `app_sock_fd` through the chain and `dup2`s the tunnel onto it.
  ///
  /// `real_connect_fn` performs the proxy-side TCP connect (tests inject it).
  /// `rdns_lookup_fn` maps a fake DNS address back to a hostname for remote
  /// DNS; pass `nullptr` to disable.
  ///
  /// @return Success, kChainEmpty, kChainDown, kProxyBlocked, kTimeout, or
  ///         kSocketError.
  [[nodiscard]] Result<void> ConnectThroughChain(
      int app_sock_fd,
      const IpAddress& target_ip,
      uint16_t target_port_host,
      ConnectSyscallFn real_connect_fn,
      ReverseDnsLookupFn rdns_lookup_fn,
      int (*real_close_fn)(int) = ::close) noexcept;

  /// Returns a copy of the configured proxies for diagnostics and tests.
  [[nodiscard]] std::vector<ProxyEndpoint> SnapshotProxies() const noexcept;

 private:
  mutable std::mutex mutex_{};
  std::vector<ProxyEndpoint> proxies_{};
  ChainType chain_type_{ChainType::kDynamic};
  uint32_t max_chain_{1};
  uint32_t rr_offset_{0};
  int connect_timeout_ms_{10000};
  int read_timeout_ms_{4000};
  uint8_t remote_dns_subnet_{224};
};

}  // namespace proxychains
