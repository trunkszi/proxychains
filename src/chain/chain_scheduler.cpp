#include "chain/chain_scheduler.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace proxychains {
namespace {

std::mt19937& ThreadEngine() noexcept {
  thread_local std::mt19937 engine{std::random_device{}()};
  return engine;
}

Result<std::vector<IpAddress>> ResolveProxyHost(const std::string& host) noexcept {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* resolved = nullptr;
  if (::getaddrinfo(host.c_str(), nullptr, &hints, &resolved) != 0) {
    return std::unexpected(make_error_code(ErrorCode::kDnsFailure));
  }
  std::vector<IpAddress> addresses;
  for (const addrinfo* entry = resolved; entry != nullptr; entry = entry->ai_next) {
    if (entry->ai_family == AF_INET) {
      const auto* address = reinterpret_cast<const sockaddr_in*>(entry->ai_addr);
      addresses.push_back(IpAddress::FromV4NetOrder(address->sin_addr.s_addr));
    } else if (entry->ai_family == AF_INET6) {
      const auto* address = reinterpret_cast<const sockaddr_in6*>(entry->ai_addr);
      std::array<uint8_t, 16> bytes{};
      std::memcpy(bytes.data(), address->sin6_addr.s6_addr, bytes.size());
      addresses.push_back(IpAddress::FromV6Bytes(bytes));
    }
  }
  ::freeaddrinfo(resolved);
  return addresses;
}

bool IsOffline(const ProxyEndpoint& proxy) noexcept {
  return proxy.state == ProxyState::kBlocked || proxy.state == ProxyState::kDown;
}

}  // namespace

void ChainScheduler::Configure(const ProxychainsConfig& config) noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  proxies_ = config.proxies;
  if (proxies_.size() > kMaxChain) {
    proxies_.resize(kMaxChain);
  }
  chain_type_ = config.chain_type;
  max_chain_ = config.max_chain;
  connect_timeout_ms_ = config.tcp_connect_timeout_ms > 0 ? config.tcp_connect_timeout_ms : 10000;
  read_timeout_ms_ = config.tcp_read_timeout_ms > 0 ? config.tcp_read_timeout_ms : 4000;
  remote_dns_subnet_ = config.remote_dns_subnet;
  rr_offset_ = 0;
}

Result<void> ChainScheduler::ConnectThroughChain(int app_sock_fd,
                                                 const IpAddress& target_ip,
                                                 uint16_t target_port_host,
                                                 ConnectSyscallFn real_connect_fn,
                                                 ReverseDnsLookupFn rdns_lookup_fn,
                                                 int (*real_close_fn)(int)) noexcept {
  if (app_sock_fd < 0 || real_connect_fn == nullptr) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }
  if (real_close_fn == nullptr) {
    real_close_fn = ::close;
  }

  std::vector<ProxyEndpoint> snapshot;
  ChainType chain_type = ChainType::kDynamic;
  uint32_t max_chain = 1;
  int connect_timeout_ms = 10000;
  int read_timeout_ms = 4000;
  uint32_t round_robin_offset = 0;
  uint8_t remote_dns_subnet = 224;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    snapshot = proxies_;
    chain_type = chain_type_;
    max_chain = max_chain_;
    connect_timeout_ms = connect_timeout_ms_;
    read_timeout_ms = read_timeout_ms_;
    round_robin_offset = rr_offset_;
    remote_dns_subnet = remote_dns_subnet_;
  }
  if (snapshot.empty()) {
    return std::unexpected(make_error_code(ErrorCode::kChainEmpty));
  }

  std::optional<std::string> resolved_domain;
  if (rdns_lookup_fn != nullptr && target_ip.IsFakeDnsIp(remote_dns_subnet)) {
    resolved_domain = rdns_lookup_fn(target_ip.ToIpt4());
  }
  const std::string_view target_domain =
      resolved_domain.has_value() ? std::string_view(*resolved_domain) : std::string_view{};

  struct Outcome {
    bool ok{false};
    std::error_code error{make_error_code(ErrorCode::kChainDown)};
    std::size_t failed{0};
  };

  // Establishes the full ordered chain over one socket, then hands the tunnel
  // to `app_sock_fd`. Each hop handshake addresses the next hop, and the last
  // hop addresses the final target.
  auto attempt = [&](const std::vector<std::size_t>& chain) noexcept -> Outcome {
    Outcome outcome{};
    outcome.failed = chain.empty() ? 0 : chain[0];
    if (chain.empty()) {
      outcome.error = make_error_code(ErrorCode::kChainEmpty);
      return outcome;
    }
    const ProxyEndpoint& first = snapshot[chain[0]];
    std::vector<IpAddress> candidates;
    if (first.ip.IsZeroV4() && !first.host.empty()) {
      auto resolved = ResolveProxyHost(first.host);
      if (!resolved.has_value()) {
        outcome.error = resolved.error();
        return outcome;
      }
      candidates = std::move(resolved.value());
    } else {
      candidates.push_back(first.ip);
    }
    if (candidates.empty()) {
      outcome.error = make_error_code(ErrorCode::kDnsFailure);
      return outcome;
    }

    for (const IpAddress& first_ip : candidates) {
      const int work_fd = ::socket(first_ip.IsV6() ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
      if (work_fd < 0) {
        outcome.error = make_error_code(ErrorCode::kSocketError);
        continue;
      }
      const auto connected =
          TimedConnect(work_fd, first_ip, first.port_host, connect_timeout_ms, real_connect_fn);
      if (!connected.has_value()) {
        outcome.error = connected.error();
        real_close_fn(work_fd);
        continue;
      }

      bool chain_ok = true;
      for (std::size_t hop = 0; hop + 1 < chain.size(); ++hop) {
        const ProxyEndpoint& proxy = snapshot[chain[hop]];
        const ProxyEndpoint& next = snapshot[chain[hop + 1]];
        if (next.ip.IsZeroV4() && next.host.empty()) {
          outcome.error = make_error_code(ErrorCode::kProtocolError);
          outcome.failed = chain[hop + 1];
          chain_ok = false;
          break;
        }
        const auto handshake = EstablishProxyTunnel(work_fd, proxy, next.ip, next.port_host,
                                                    next.host, read_timeout_ms);
        if (!handshake.has_value()) {
          outcome.error = handshake.error();
          outcome.failed = chain[hop + 1];
          chain_ok = false;
          break;
        }
      }
      if (!chain_ok) {
        real_close_fn(work_fd);
        continue;
      }

      const ProxyEndpoint& last = snapshot[chain.back()];
      const auto final_handshake = EstablishProxyTunnel(work_fd, last, target_ip, target_port_host,
                                                        target_domain, read_timeout_ms);
      if (!final_handshake.has_value()) {
        outcome.error = final_handshake.error();
        outcome.failed = chain.back();
        real_close_fn(work_fd);
        continue;
      }

      const int app_flags = ::fcntl(app_sock_fd, F_GETFL, 0);
      if (work_fd != app_sock_fd && ::dup2(work_fd, app_sock_fd) < 0) {
        outcome.error = make_error_code(ErrorCode::kSocketError);
        outcome.failed = chain.back();
        real_close_fn(work_fd);
        continue;
      }
      if (work_fd != app_sock_fd) {
        real_close_fn(work_fd);
      }
      if (app_flags >= 0) {
        (void)::fcntl(app_sock_fd, F_SETFL, app_flags);
      }
      outcome.ok = true;
      return outcome;
    }
    return outcome;
  };

  auto mark_blocked = [&](std::size_t index) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= proxies_.size() || index >= snapshot.size()) {
      return;
    }
    if (proxies_[index].host != snapshot[index].host ||
        proxies_[index].port_host != snapshot[index].port_host) {
      return;
    }
    proxies_[index].state = ProxyState::kBlocked;
  };

  std::error_code last_error = make_error_code(ErrorCode::kChainDown);

  switch (chain_type) {
    case ChainType::kStrict: {
      std::vector<std::size_t> chain;
      chain.reserve(snapshot.size());
      for (std::size_t i = 0; i < snapshot.size(); ++i) {
        chain.push_back(i);
      }
      const Outcome outcome = attempt(chain);
      if (outcome.ok) {
        return {};
      }
      mark_blocked(outcome.failed);
      return std::unexpected(outcome.error);
    }

    case ChainType::kDynamic: {
      std::vector<std::size_t> online;
      online.reserve(snapshot.size());
      for (std::size_t i = 0; i < snapshot.size(); ++i) {
        if (!IsOffline(snapshot[i])) {
          online.push_back(i);
        }
      }
      while (!online.empty()) {
        const Outcome outcome = attempt(online);
        if (outcome.ok) {
          return {};
        }
        last_error = outcome.error;
        mark_blocked(outcome.failed);
        const auto failed =
            std::find(online.begin(), online.end(), outcome.failed);
        if (failed == online.end()) {
          break;
        }
        online.erase(failed);
      }
      return std::unexpected(last_error);
    }

    case ChainType::kRandom: {
      std::vector<std::size_t> online;
      online.reserve(snapshot.size());
      for (std::size_t i = 0; i < snapshot.size(); ++i) {
        if (!IsOffline(snapshot[i])) {
          online.push_back(i);
        }
      }
      const std::size_t required =
          max_chain == 0 ? online.size() : static_cast<std::size_t>(max_chain);
      if (online.empty() || online.size() < required) {
        return std::unexpected(make_error_code(ErrorCode::kChainDown));
      }
      std::shuffle(online.begin(), online.end(), ThreadEngine());
      online.resize(required);
      const Outcome outcome = attempt(online);
      if (outcome.ok) {
        return {};
      }
      mark_blocked(outcome.failed);
      return std::unexpected(outcome.error);
    }

    case ChainType::kRoundRobin: {
      std::vector<std::size_t> online;
      online.reserve(snapshot.size());
      for (std::size_t i = 0; i < snapshot.size(); ++i) {
        if (!IsOffline(snapshot[i])) {
          online.push_back(i);
        }
      }
      const std::size_t length =
          max_chain == 0 ? online.size() : static_cast<std::size_t>(max_chain);
      if (online.empty() || online.size() < length) {
        return std::unexpected(make_error_code(ErrorCode::kChainDown));
      }
      std::vector<std::size_t> chain;
      chain.reserve(length);
      const std::size_t start = static_cast<std::size_t>(round_robin_offset) % online.size();
      for (std::size_t i = 0; i < length; ++i) {
        chain.push_back(online[(start + i) % online.size()]);
      }
      const Outcome outcome = attempt(chain);
      if (!outcome.ok) {
        mark_blocked(outcome.failed);
        return std::unexpected(outcome.error);
      }
      std::lock_guard<std::mutex> lock(mutex_);
      rr_offset_ = static_cast<uint32_t>((start + 1) % online.size());
      return {};
    }
  }
  return std::unexpected(last_error);
}

std::vector<ProxyEndpoint> ChainScheduler::SnapshotProxies() const noexcept {
  std::lock_guard<std::mutex> lock(mutex_);
  return proxies_;
}

}  // namespace proxychains
