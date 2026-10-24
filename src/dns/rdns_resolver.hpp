#pragma once

#include <netdb.h>
#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "core/error.hpp"
#include "core/types.hpp"
#include "dns/fake_ip_table.hpp"

namespace proxychains {

struct GethostbynameData {
  struct hostent hostent_space{};
  in_addr_t resolved_addr{0};
  char* resolved_addr_p[2]{nullptr, nullptr};
  char addr_name[256]{};
};

class RdnsResolver {
 public:
  RdnsResolver() noexcept = default;

  void Configure(DnsMethod method,
                 uint8_t remote_subnet,
                 const IpAddress& daemon_ip = IpAddress::LocalhostV4(),
                 uint16_t daemon_port_host = 1053) noexcept;

  [[nodiscard]] DnsMethod GetMethod() const noexcept { return method_; }
  [[nodiscard]] uint8_t GetRemoteSubnet() const noexcept { return remote_subnet_; }
  [[nodiscard]] std::string_view MethodName() const noexcept;

  [[nodiscard]] Result<IpType4> ResolveHostToIp(std::string_view hostname) noexcept;
  [[nodiscard]] std::optional<std::string> ResolveIpToHost(IpType4 fake_ip) noexcept;

  [[nodiscard]] struct hostent* ProxyGethostbyname(
      const char* name, GethostbynameData* data) noexcept;

  [[nodiscard]] int ProxyGethostbynameR(
      const char* name,
      struct hostent* ret,
      char* buf,
      std::size_t buflen,
      struct hostent** result,
      int* h_errnop) noexcept;

  [[nodiscard]] struct hostent* ProxyGethostbyname2(
      const char* name, int af, GethostbynameData* data) noexcept;

  [[nodiscard]] int ProxyGethostbyname2R(
      const char* name,
      int af,
      struct hostent* ret,
      char* buf,
      std::size_t buflen,
      struct hostent** result,
      int* h_errnop) noexcept;

  [[nodiscard]] int ProxyGetaddrinfo(
      const char* node,
      const char* service,
      const struct addrinfo* hints,
      struct addrinfo** res) noexcept;

  void ProxyFreeaddrinfo(struct addrinfo* res) noexcept;

  [[nodiscard]] int ProxyGetnameinfo(
      const struct sockaddr* sa,
      socklen_t salen,
      char* host,
      socklen_t hostlen,
      char* serv,
      socklen_t servlen,
      int flags) noexcept;

 private:
  DnsMethod method_{DnsMethod::kThread};
  uint8_t remote_subnet_{224};
  IpAddress daemon_ip_{IpAddress::LocalhostV4()};
  uint16_t daemon_port_host_{1053};
  FakeIpTable table_{224};
};

}  // namespace proxychains
