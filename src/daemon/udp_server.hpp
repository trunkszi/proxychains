#pragma once

#include <atomic>
#include <cstdint>
#include <string_view>

#include "core/error.hpp"
#include "core/fd.hpp"
#include "dns/fake_ip_table.hpp"

namespace proxychains {

/// UDP front end for the remote fake-IP table.
///
/// Accepts the legacy `AtMsgHeader` framing (`datalen` in network byte order)
/// and standard DNS query messages. Both are answered from the same table:
/// legacy `kGetIp`/`kGetName` requests and DNS A/PTR questions share the fake
/// IP allocation. `ServeOne` answers one request and returns; the caller owns
/// the accept loop.
class UdpServer {
 public:
  explicit UdpServer(uint8_t remote_subnet = 224) noexcept;

  UdpServer(const UdpServer&) = delete;
  UdpServer& operator=(const UdpServer&) = delete;

  [[nodiscard]] Result<void> Listen(std::string_view listen_ip, uint16_t port) noexcept;
  [[nodiscard]] uint16_t BoundPort() const noexcept;
  [[nodiscard]] bool StopRequested() const noexcept;
  [[nodiscard]] Result<void> ServeOne() noexcept;
  void RequestStop() noexcept;

 private:
  FakeIpTable table_;
  ScopedFd fd_{};
  uint16_t bound_port_{0};
  std::atomic<bool> stop_{false};
};

}  // namespace proxychains
