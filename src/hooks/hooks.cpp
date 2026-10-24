#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <array>
#include <atomic>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <fmt/format.h>

#include "chain/chain_scheduler.hpp"
#include "config/config.hpp"
#include "core/fd.hpp"
#include "core/log.hpp"
#include "core/types.hpp"
#include "dns/rdns_resolver.hpp"

#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN 0x20000000
#endif

#define PC_HOOK extern "C" __attribute__((visibility("default")))

namespace proxychains {
namespace {

constexpr int kEarlyFdCap = 16;

struct EarlyRange {
  unsigned int first;
  unsigned int last;
  int flags;
};

struct Endpoint {
  IpAddress ip{};
  uint16_t port_host{0};
};

struct AddrHostentStorage {
  hostent ent{};
  char name[INET6_ADDRSTRLEN]{};
  char addr[16]{};
  char* list[2]{nullptr, nullptr};
  char* aliases[1]{nullptr};
};

using ConnectFn = int (*)(int, const sockaddr*, socklen_t);
using SendtoFn = ssize_t (*)(int, const void*, size_t, int, const sockaddr*, socklen_t);
using GethostbynameFn = hostent* (*)(const char*);
using Gethostbyname2Fn = hostent* (*)(const char*, int);
using GethostbynameRFn = int (*)(const char*, hostent*, char*, size_t, hostent**, int*);
using Gethostbyname2RFn = int (*)(const char*, int, hostent*, char*, size_t, hostent**, int*);
using GetaddrinfoFn = int (*)(const char*, const char*, const addrinfo*, addrinfo**);
using FreeaddrinfoFn = void (*)(addrinfo*);
using GetnameinfoFn = int (*)(const sockaddr*, socklen_t, char*, socklen_t, char*, socklen_t, int);
using GethostbyaddrFn = hostent* (*)(const void*, socklen_t, int);
using GethostbyaddrRFn = int (*)(const void*, socklen_t, int, hostent*, char*, size_t, hostent**, int*);
using CloseFn = int (*)(int);
using CloseRangeFn = int (*)(unsigned int, unsigned int, int);
using GetIdFn = unsigned int (*)();
using GetResFn = int (*)(unsigned int*, unsigned int*, unsigned int*);

// 101 runs before the preload constructor at 102. The default priority is
// shared with dynamic initialization, so that constructor otherwise fills a
// zero-initialized vector and the later real constructor orphans its buffer.
constexpr int kStateInitPriority = 101;

std::once_flag init_once __attribute__((init_priority(kStateInitPriority)));
std::atomic<bool> init_ready{false};
std::mutex early_fd_mu __attribute__((init_priority(kStateInitPriority)));
int early_closes[kEarlyFdCap]{};
int early_close_count = 0;
EarlyRange early_ranges[kEarlyFdCap]{};
int early_range_count = 0;

ConnectFn real_connect = nullptr;
SendtoFn real_sendto = nullptr;
GethostbynameFn real_gethostbyname = nullptr;
Gethostbyname2Fn real_gethostbyname2 = nullptr;
GethostbynameRFn real_gethostbyname_r = nullptr;
Gethostbyname2RFn real_gethostbyname2_r = nullptr;
GetaddrinfoFn real_getaddrinfo = nullptr;
FreeaddrinfoFn real_freeaddrinfo = nullptr;
GetnameinfoFn real_getnameinfo = nullptr;
GethostbyaddrFn real_gethostbyaddr = nullptr;
GethostbyaddrRFn real_gethostbyaddr_r = nullptr;
CloseFn real_close = nullptr;
CloseRangeFn real_close_range = nullptr;
GetIdFn real_getuid = nullptr;
GetIdFn real_geteuid = nullptr;
GetIdFn real_getgid = nullptr;
GetIdFn real_getegid = nullptr;
GetResFn real_getresuid = nullptr;
GetResFn real_getresgid = nullptr;

ProxychainsConfig loaded_config __attribute__((init_priority(kStateInitPriority)));
RdnsResolver resolver __attribute__((init_priority(kStateInitPriority)));
ChainScheduler scheduler __attribute__((init_priority(kStateInitPriority)));

template <typename Fn>
Fn LoadSymbol(const char* name, Fn wrapper, bool mandatory) noexcept {
  void* found = dlsym(RTLD_NEXT, name);
  if (found == nullptr) {
    if (mandatory) {
      const char* error = dlerror();
      LogError(fmt::format("Cannot load symbol '{}' {}", name, error != nullptr ? error : ""));
      std::_Exit(1);
    }
    return nullptr;
  }
  if (found == reinterpret_cast<void*>(wrapper)) {
    LogError("circular reference detected, aborting!");
    std::abort();
  }
  return reinterpret_cast<Fn>(found);
}

std::optional<uint32_t> ReadEnvId(const char* key) noexcept {
  const char* text = std::getenv(key);
  if (text == nullptr || text[0] == '\0') {
    return std::nullopt;
  }
  uint32_t value = 0;
  const char* end = text + std::strlen(text);
  const auto parsed = std::from_chars(text, end, value);
  if (parsed.ec != std::errc{} || parsed.ptr != end) {
    return std::nullopt;
  }
  return value;
}

std::optional<uid_t> ReadFakeUid() noexcept {
  const auto value = ReadEnvId(kFakeUidEnvVar);
  if (!value.has_value()) {
    return std::nullopt;
  }
  return static_cast<uid_t>(*value);
}

std::optional<gid_t> ReadFakeGid() noexcept {
  if (const auto gid = ReadEnvId(kFakeGidEnvVar)) {
    return static_cast<gid_t>(*gid);
  }
  if (const auto uid = ReadEnvId(kFakeUidEnvVar)) {
    return static_cast<gid_t>(*uid);
  }
  return std::nullopt;
}

void PublishConfiguredId(const char* key, std::optional<uint32_t> value) noexcept {
  if (!value.has_value() || std::getenv(key) != nullptr) {
    return;
  }
  char text[16];
  const auto written = std::to_chars(text, text + sizeof text - 1, *value);
  if (written.ec != std::errc{}) {
    return;
  }
  *written.ptr = '\0';
  setenv(key, text, 0);
}

void LoadRealSymbols() noexcept {
  real_connect = LoadSymbol("connect", static_cast<ConnectFn>(&connect), true);
  real_sendto = LoadSymbol("sendto", static_cast<SendtoFn>(&sendto), true);
  real_close = LoadSymbol("close", static_cast<CloseFn>(&close), true);
  real_gethostbyname = LoadSymbol("gethostbyname", static_cast<GethostbynameFn>(&gethostbyname), true);
  real_gethostbyname2 = LoadSymbol("gethostbyname2", static_cast<Gethostbyname2Fn>(&gethostbyname2), true);
  real_gethostbyname_r = LoadSymbol("gethostbyname_r", static_cast<GethostbynameRFn>(&gethostbyname_r), true);
  real_gethostbyname2_r = LoadSymbol("gethostbyname2_r", static_cast<Gethostbyname2RFn>(&gethostbyname2_r), true);
  real_getaddrinfo = LoadSymbol("getaddrinfo", static_cast<GetaddrinfoFn>(&getaddrinfo), true);
  real_freeaddrinfo = LoadSymbol("freeaddrinfo", static_cast<FreeaddrinfoFn>(&freeaddrinfo), true);
  real_getnameinfo = LoadSymbol("getnameinfo", static_cast<GetnameinfoFn>(&getnameinfo), true);
  real_gethostbyaddr = LoadSymbol("gethostbyaddr", static_cast<GethostbyaddrFn>(&gethostbyaddr), true);
  real_gethostbyaddr_r = LoadSymbol("gethostbyaddr_r", static_cast<GethostbyaddrRFn>(&gethostbyaddr_r), true);
  real_close_range = LoadSymbol("close_range", static_cast<CloseRangeFn>(&close_range), false);
  real_getuid = LoadSymbol("getuid", static_cast<GetIdFn>(&getuid), false);
  real_geteuid = LoadSymbol("geteuid", static_cast<GetIdFn>(&geteuid), false);
  real_getgid = LoadSymbol("getgid", static_cast<GetIdFn>(&getgid), false);
  real_getegid = LoadSymbol("getegid", static_cast<GetIdFn>(&getegid), false);
  real_getresuid = LoadSymbol("getresuid", static_cast<GetResFn>(&getresuid), false);
  real_getresgid = LoadSymbol("getresgid", static_cast<GetResFn>(&getresgid), false);
}

bool LoadConfiguration() noexcept {
  const char* proxy_url = std::getenv(kProxyUrlEnvVar);
  if (proxy_url != nullptr && proxy_url[0] != '\0') {
    auto proxy = ParseProxyUrl(proxy_url);
    if (!proxy) {
      LogError("invalid PROXYCHAINS_PROXY_URL");
      return false;
    }
    loaded_config = ProxychainsConfig{};
    loaded_config.proxies.push_back(std::move(*proxy));
    loaded_config.chain_type = ChainType::kDynamic;
    loaded_config.max_chain = 1;
  } else {
    const char* explicit_path = std::getenv(kConfFileEnvVar);
    const std::string_view requested = explicit_path != nullptr ? std::string_view{explicit_path} : std::string_view{};
    auto path = ResolveConfigPath(requested);
    if (!path) {
      LogError("configuration file not found");
      return false;
    }
    auto loaded = LoadConfigFromFile(*path);
    if (!loaded) {
      LogError(loaded.error().message());
      return false;
    }
    loaded_config = std::move(*loaded);
  }
  if (loaded_config.proxies.empty()) {
    LogError("no valid proxy found in config");
    return false;
  }
  const char* quiet = std::getenv(kQuietModeEnvVar);
  if (quiet != nullptr && quiet[0] == '1') {
    loaded_config.quiet_mode = true;
  }
  SetQuietMode(loaded_config.quiet_mode);
  PublishConfiguredId(kFakeUidEnvVar, loaded_config.fake_uid);
  PublishConfiguredId(kFakeGidEnvVar, loaded_config.fake_gid);
  resolver.Configure(loaded_config.dns_method, loaded_config.remote_dns_subnet, loaded_config.dns_daemon_ip,
                     loaded_config.dns_daemon_port_host);
  scheduler.Configure(loaded_config);
  return true;
}

void ReplayEarlyFds() noexcept {
  std::lock_guard lock(early_fd_mu);
  while (early_close_count > 0) {
    const int fd = early_closes[--early_close_count];
    if (real_close != nullptr) {
      real_close(fd);
    }
  }
  while (early_range_count > 0) {
    const EarlyRange item = early_ranges[--early_range_count];
    if (real_close_range != nullptr) {
      real_close_range(item.first, item.last, item.flags);
    }
  }
  init_ready.store(true, std::memory_order_release);
}

void DoInit() noexcept {
  LoadRealSymbols();
  if (!LoadConfiguration()) {
    std::_Exit(1);
  }
  ReplayEarlyFds();
}

void EnsureInitialized() noexcept { std::call_once(init_once, DoInit); }

#ifndef PROXYCHAINS_HOOKS_NO_CONSTRUCTOR
__attribute__((constructor(102))) void ProxychainsHooksInit() { EnsureInitialized(); }
#endif

std::optional<std::string> LookupFakeHost(IpType4 fake_ip) noexcept { return resolver.ResolveIpToHost(fake_ip); }

bool EndpointFromSockaddr(const sockaddr* addr, socklen_t len, Endpoint* out) noexcept {
  if (addr == nullptr || out == nullptr) {
    return false;
  }
  if (addr->sa_family == AF_INET) {
    if (len < static_cast<socklen_t>(sizeof(sockaddr_in))) {
      return false;
    }
    sockaddr_in in{};
    std::memcpy(&in, addr, sizeof in);
    out->ip = IpAddress::FromV4NetOrder(in.sin_addr.s_addr);
    out->port_host = ntohs(in.sin_port);
    return true;
  }
  if (addr->sa_family == AF_INET6) {
    if (len < static_cast<socklen_t>(sizeof(sockaddr_in6))) {
      return false;
    }
    sockaddr_in6 in6{};
    std::memcpy(&in6, addr, sizeof in6);
    std::array<uint8_t, 16> bytes{};
    std::memcpy(bytes.data(), in6.sin6_addr.s6_addr, bytes.size());
    out->ip = IpAddress::FromV6Bytes(bytes);
    if (out->ip.IsV4MappedV6()) {
      out->ip = out->ip.NormalizeV4Mapped();
    }
    out->port_host = ntohs(in6.sin6_port);
    return true;
  }
  return false;
}

void ApplyDnat(Endpoint* endpoint) noexcept {
  const DnatRule* matched = nullptr;
  for (const auto& rule : loaded_config.dnat_rules) {
    if (rule.orig_port_host != 0 && rule.Matches(endpoint->ip, endpoint->port_host)) {
      matched = &rule;
      break;
    }
  }
  if (matched == nullptr) {
    for (const auto& rule : loaded_config.dnat_rules) {
      if (rule.orig_port_host == 0 && rule.Matches(endpoint->ip, endpoint->port_host)) {
        matched = &rule;
        break;
      }
    }
  }
  if (matched == nullptr) {
    return;
  }
  endpoint->ip = matched->new_ip;
  if (matched->new_port_host != 0) {
    endpoint->port_host = matched->new_port_host;
  }
}

bool MatchesLocalnet(const Endpoint& endpoint) noexcept {
  for (const auto& rule : loaded_config.localnet_rules) {
    if (rule.Matches(endpoint.ip, endpoint.port_host)) {
      return true;
    }
  }
  return false;
}

int DirectConnect(int sock, const Endpoint& endpoint) noexcept {
  sockaddr_storage storage{};
  socklen_t out_len = 0;
  if (!endpoint.ip.IsV6()) {
    auto* in = reinterpret_cast<sockaddr_in*>(&storage);
    in->sin_family = AF_INET;
    in->sin_port = htons(endpoint.port_host);
    in->sin_addr.s_addr = endpoint.ip.V4NetOrder();
    out_len = static_cast<socklen_t>(sizeof(sockaddr_in));
  } else {
    auto* in6 = reinterpret_cast<sockaddr_in6*>(&storage);
    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons(endpoint.port_host);
    const auto& bytes = endpoint.ip.V6Bytes();
    std::memcpy(in6->sin6_addr.s6_addr, bytes.data(), bytes.size());
    out_len = static_cast<socklen_t>(sizeof(sockaddr_in6));
  }
  return real_connect(sock, reinterpret_cast<sockaddr*>(&storage), out_len);
}

bool FillAddrHostent(AddrHostentStorage* storage, const void* addr, socklen_t len, int type) noexcept {
  if (storage == nullptr || addr == nullptr) {
    return false;
  }
  const bool v4 = type == AF_INET && len == 4;
  const bool v6 = type == AF_INET6 && len == 16;
  if (!v4 && !v6) {
    return false;
  }
  if (inet_ntop(type, addr, storage->name, sizeof storage->name) == nullptr) {
    return false;
  }
  const std::size_t addr_len = v4 ? 4 : 16;
  std::memcpy(storage->addr, addr, addr_len);
  storage->list[0] = storage->addr;
  storage->list[1] = nullptr;
  storage->aliases[0] = nullptr;
  storage->ent.h_name = storage->name;
  storage->ent.h_aliases = storage->aliases;
  storage->ent.h_addrtype = type;
  storage->ent.h_length = static_cast<int>(addr_len);
  storage->ent.h_addr_list = storage->list;
  return true;
}

int FillAddrHostentR(const void* addr, socklen_t len, int type, hostent* ret, char* buf, std::size_t buflen,
                     hostent** result, int* h_errnop) noexcept {
  if (result != nullptr) {
    *result = nullptr;
  }
  if (ret == nullptr || buf == nullptr || result == nullptr || h_errnop == nullptr) {
    return EINVAL;
  }
  const bool v4 = type == AF_INET && len == 4;
  const bool v6 = type == AF_INET6 && len == 16;
  if (addr == nullptr || (!v4 && !v6)) {
    *h_errnop = NO_RECOVERY;
    return EINVAL;
  }
  char numeric[INET6_ADDRSTRLEN];
  if (inet_ntop(type, addr, numeric, sizeof numeric) == nullptr) {
    *h_errnop = NO_RECOVERY;
    return EINVAL;
  }
  const std::size_t name_len = std::strlen(numeric) + 1;
  const std::size_t addr_len = v4 ? 4 : 16;
  const auto align_up = [](std::uintptr_t value, std::uintptr_t alignment) noexcept {
    return (value + alignment - 1) & ~(alignment - 1);
  };
  const auto base = reinterpret_cast<std::uintptr_t>(buf);
  const auto addr_at = align_up(base + name_len, alignof(char*));
  const auto ptr_at = align_up(addr_at + addr_len, alignof(char*));
  if (ptr_at + 3 * sizeof(char*) > base + buflen) {
    *h_errnop = NETDB_INTERNAL;
    errno = ERANGE;
    return ERANGE;
  }
  auto* name = reinterpret_cast<char*>(base);
  auto* addr_bytes = reinterpret_cast<char*>(addr_at);
  auto* ptrs = reinterpret_cast<char**>(ptr_at);
  std::memcpy(name, numeric, name_len);
  std::memcpy(addr_bytes, addr, addr_len);
  ptrs[0] = addr_bytes;
  ptrs[1] = nullptr;
  ptrs[2] = nullptr;
  ret->h_name = name;
  ret->h_aliases = &ptrs[2];
  ret->h_addrtype = type;
  ret->h_length = static_cast<int>(addr_len);
  ret->h_addr_list = ptrs;
  *result = ret;
  *h_errnop = 0;
  return 0;
}

template <typename Id>
Id RealOrSyscall(Id fake_unused, GetIdFn real, long sysno, bool use_fake, Id fake) noexcept {
  (void)fake_unused;
  if (use_fake) {
    return fake;
  }
  if (real != nullptr) {
    return static_cast<Id>(real());
  }
  const long value = syscall(sysno);
  if (value >= 0) {
    return static_cast<Id>(value);
  }
  LogErrno("failed to query the real identity", errno);
  return static_cast<Id>(-1);
}

}  // namespace
}  // namespace proxychains

PC_HOOK int close(int fd) {
  using namespace proxychains;
  if (!init_ready.load(std::memory_order_acquire)) {
    std::lock_guard lock(early_fd_mu);
    if (!init_ready.load(std::memory_order_relaxed)) {
      if (early_close_count >= kEarlyFdCap) {
        errno = EBADF;
        return -1;
      }
      early_closes[early_close_count++] = fd;
      errno = 0;
      return 0;
    }
  }
  if (real_close == nullptr) {
    errno = EBADF;
    return -1;
  }
  return real_close(fd);
}

PC_HOOK int close_range(unsigned int first, unsigned int last, int flags) {
  using namespace proxychains;
  if (!init_ready.load(std::memory_order_acquire)) {
    std::lock_guard lock(early_fd_mu);
    if (!init_ready.load(std::memory_order_relaxed)) {
      if (early_range_count >= kEarlyFdCap) {
        errno = ENOMEM;
        return -1;
      }
      early_ranges[early_range_count++] = EarlyRange{first, last, flags};
      errno = 0;
      return 0;
    }
  }
  if (real_close_range == nullptr) {
    LogError("Calling close_range, but this platform does not provide this system call.");
    errno = ENOSYS;
    return -1;
  }
  return real_close_range(first, last, flags);
}

PC_HOOK int connect(int sock, const sockaddr* addr, socklen_t len) {
  using namespace proxychains;
  EnsureInitialized();
  if (addr == nullptr || real_connect == nullptr) {
    errno = EINVAL;
    return -1;
  }
  int socktype = 0;
  socklen_t optlen = sizeof socktype;
  if (getsockopt(sock, SOL_SOCKET, SO_TYPE, &socktype, &optlen) != 0 ||
      (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) || socktype != SOCK_STREAM) {
    return real_connect(sock, addr, len);
  }
  Endpoint endpoint;
  if (!EndpointFromSockaddr(addr, len, &endpoint)) {
    errno = EINVAL;
    return -1;
  }
  if (endpoint.ip.IsZeroV4()) {
    errno = ECONNREFUSED;
    return -1;
  }
  // A fake DNS address is a remote-DNS token, not a routable local destination.
  const bool fake_dns = endpoint.ip.IsFakeDnsIp(loaded_config.remote_dns_subnet);
  const Endpoint original = endpoint;
  if (!fake_dns) {
    ApplyDnat(&endpoint);
  }
  if (!fake_dns && MatchesLocalnet(endpoint)) {
    if (endpoint.ip == original.ip && endpoint.port_host == original.port_host) {
      return real_connect(sock, addr, len);
    }
    return DirectConnect(sock, endpoint);
  }
  BlockingSocketGuard blocking{sock};
  const auto connected = scheduler.ConnectThroughChain(sock, endpoint.ip, endpoint.port_host, real_connect,
                                                       &LookupFakeHost, real_close);
  if (!connected) {
    errno = ECONNREFUSED;
    return -1;
  }
  return 0;
}

PC_HOOK ssize_t sendto(int sockfd, const void* buf, size_t len, int flags, const sockaddr* dest_addr,
                       socklen_t addrlen) {
  using namespace proxychains;
  EnsureInitialized();
  if ((flags & MSG_FASTOPEN) != 0) {
    if (dest_addr != nullptr) {
      // connect() returns 0 on success. EINPROGRESS is the only non-fatal failure.
      const int connected = connect(sockfd, dest_addr, addrlen);
      if (connected != 0 && errno != EINPROGRESS) {
        return -1;
      }
    }
    dest_addr = nullptr;
    addrlen = 0;
    flags &= ~MSG_FASTOPEN;
  }
  if (real_sendto == nullptr) {
    errno = EFAULT;
    return -1;
  }
  return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

PC_HOOK hostent* gethostbyname(const char* name) {
  using namespace proxychains;
  EnsureInitialized();
  if (resolver.GetMethod() == DnsMethod::kOff) {
    return real_gethostbyname(name);
  }
  if (name == nullptr) {
    h_errno = HOST_NOT_FOUND;
    return nullptr;
  }
  thread_local GethostbynameData tls_ghbn_data{};
  hostent* ent = resolver.ProxyGethostbyname(name, &tls_ghbn_data);
  if (ent == nullptr) {
    h_errno = HOST_NOT_FOUND;
  }
  return ent;
}

PC_HOOK int gethostbyname_r(const char* name, hostent* ret, char* buf, size_t buflen, hostent** result, int* h_errnop) {
  using namespace proxychains;
  EnsureInitialized();
  if (resolver.GetMethod() == DnsMethod::kOff) {
    return real_gethostbyname_r(name, ret, buf, buflen, result, h_errnop);
  }
  return resolver.ProxyGethostbynameR(name, ret, buf, buflen, result, h_errnop);
}

PC_HOOK hostent* gethostbyname2(const char* name, int af) {
  using namespace proxychains;
  EnsureInitialized();
  if (resolver.GetMethod() == DnsMethod::kOff) {
    return real_gethostbyname2(name, af);
  }
  if (name == nullptr) {
    h_errno = HOST_NOT_FOUND;
    return nullptr;
  }
  thread_local GethostbynameData tls_ghbn2_data{};
  hostent* ent = resolver.ProxyGethostbyname2(name, af, &tls_ghbn2_data);
  if (ent == nullptr) {
    h_errno = HOST_NOT_FOUND;
  }
  return ent;
}

PC_HOOK int gethostbyname2_r(const char* name, int af, hostent* ret, char* buf, size_t buflen, hostent** result,
                            int* h_errnop) {
  using namespace proxychains;
  EnsureInitialized();
  if (resolver.GetMethod() == DnsMethod::kOff) {
    return real_gethostbyname2_r(name, af, ret, buf, buflen, result, h_errnop);
  }
  return resolver.ProxyGethostbyname2R(name, af, ret, buf, buflen, result, h_errnop);
}

PC_HOOK int getaddrinfo(const char* node, const char* service, const addrinfo* hints, addrinfo** res) {
  using namespace proxychains;
  EnsureInitialized();
  if (resolver.GetMethod() == DnsMethod::kOff) {
    return real_getaddrinfo(node, service, hints, res);
  }
  return resolver.ProxyGetaddrinfo(node, service, hints, res);
}

PC_HOOK void freeaddrinfo(addrinfo* res) {
  using namespace proxychains;
  EnsureInitialized();
  if (resolver.GetMethod() == DnsMethod::kOff) {
    real_freeaddrinfo(res);
    return;
  }
  resolver.ProxyFreeaddrinfo(res);
}

PC_HOOK int getnameinfo(const sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen, char* serv,
                        socklen_t servlen, int flags) {
  using namespace proxychains;
  EnsureInitialized();
  if (resolver.GetMethod() == DnsMethod::kOff) {
    return real_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
  }
  return resolver.ProxyGetnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}

PC_HOOK hostent* gethostbyaddr(const void* addr, socklen_t len, int type) {
  using namespace proxychains;
  EnsureInitialized();
  if (resolver.GetMethod() == DnsMethod::kOff) {
    return real_gethostbyaddr(addr, len, type);
  }
  thread_local AddrHostentStorage tls_ghba_data{};
  if (!FillAddrHostent(&tls_ghba_data, addr, len, type)) {
    h_errno = NO_RECOVERY;
    return nullptr;
  }
  return &tls_ghba_data.ent;
}

PC_HOOK int gethostbyaddr_r(const void* addr, socklen_t len, int type, hostent* ret, char* buf, size_t buflen,
                           hostent** result, int* h_errnop) {
  using namespace proxychains;
  EnsureInitialized();
  if (resolver.GetMethod() == DnsMethod::kOff) {
    return real_gethostbyaddr_r(addr, len, type, ret, buf, buflen, result, h_errnop);
  }
  return FillAddrHostentR(addr, len, type, ret, buf, buflen, result, h_errnop);
}

PC_HOOK uid_t getuid(void) {
  using namespace proxychains;
  EnsureInitialized();
  const auto fake = ReadFakeUid();
  return RealOrSyscall(uid_t{}, real_getuid, SYS_getuid, fake.has_value(), fake.value_or(0));
}

PC_HOOK uid_t geteuid(void) {
  using namespace proxychains;
  EnsureInitialized();
  const auto fake = ReadFakeUid();
  return RealOrSyscall(uid_t{}, real_geteuid, SYS_geteuid, fake.has_value(), fake.value_or(0));
}

PC_HOOK gid_t getgid(void) {
  using namespace proxychains;
  EnsureInitialized();
  const auto fake = ReadFakeGid();
  return RealOrSyscall(gid_t{}, real_getgid, SYS_getgid, fake.has_value(), fake.value_or(0));
}

PC_HOOK gid_t getegid(void) {
  using namespace proxychains;
  EnsureInitialized();
  const auto fake = ReadFakeGid();
  return RealOrSyscall(gid_t{}, real_getegid, SYS_getegid, fake.has_value(), fake.value_or(0));
}

PC_HOOK int getresuid(uid_t* ruid, uid_t* euid, uid_t* suid) {
  using namespace proxychains;
  EnsureInitialized();
  if (const auto fake = ReadFakeUid()) {
    if (ruid == nullptr || euid == nullptr || suid == nullptr) {
      errno = EFAULT;
      return -1;
    }
    *ruid = *fake;
    *euid = *fake;
    *suid = *fake;
    return 0;
  }
  if (real_getresuid != nullptr) {
    return real_getresuid(ruid, euid, suid);
  }
  return static_cast<int>(syscall(SYS_getresuid, ruid, euid, suid));
}

PC_HOOK int getresgid(gid_t* rgid, gid_t* egid, gid_t* sgid) {
  using namespace proxychains;
  EnsureInitialized();
  if (const auto fake = ReadFakeGid()) {
    if (rgid == nullptr || egid == nullptr || sgid == nullptr) {
      errno = EFAULT;
      return -1;
    }
    *rgid = *fake;
    *egid = *fake;
    *sgid = *fake;
    return 0;
  }
  if (real_getresgid != nullptr) {
    return real_getresgid(rgid, egid, sgid);
  }
  return static_cast<int>(syscall(SYS_getresgid, rgid, egid, sgid));
}
