#include "dns/rdns_resolver.hpp"

#include <ares.h>
#include <ares_dns_record.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <vector>

#include <fmt/format.h>

#include "core/fd.hpp"
#include "core/log.hpp"
#include "dns/dns_protocol.hpp"
#include "dns/hosts_cache.hpp"

namespace proxychains {
namespace {

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#ifndef EAI_ADDRFAMILY
#define EAI_ADDRFAMILY EAI_FAMILY
#endif

// glibc 2.39 does not publish RFC 4007's numeric-scope flag. 256 is the
// value later glibc assigns, and it does not overlap NI_IDN (32/64/128).
#ifndef NI_NUMERICSCOPE
#define NI_NUMERICSCOPE 256
#endif

struct HostBytes {
  int af{AF_UNSPEC};
  int length{0};
  uint8_t data[16]{};
  int herr{HOST_NOT_FOUND};
  bool ok{false};
};

struct AddrinfoBlock {
  addrinfo info{};
  sockaddr_storage storage{};
  char canon[256]{};
};

static_assert(offsetof(AddrinfoBlock, info) == 0);
static_assert(sizeof(AtMsgHeader) == 4);
static_assert(offsetof(AtMsg, m) == sizeof(AtMsgHeader));

[[nodiscard]] int HerrFrom(std::error_code error) noexcept {
  if (error == make_error_code(ErrorCode::kTimeout)) {
    return TRY_AGAIN;
  }
  if (error == make_error_code(ErrorCode::kInvalidArgument) ||
      error == make_error_code(ErrorCode::kDnsFailure)) {
    return HOST_NOT_FOUND;
  }
  return NO_RECOVERY;
}

void MapV4ToV6(const uint8_t v4[4], uint8_t v6[16]) noexcept {
  std::memset(v6, 0, 16);
  v6[10] = 0xff;
  v6[11] = 0xff;
  std::memcpy(v6 + 12, v4, 4);
}

[[nodiscard]] bool IsMappedV6(const uint8_t bytes[16]) noexcept {
  for (int i = 0; i < 10; ++i) {
    if (bytes[i] != 0) {
      return false;
    }
  }
  return bytes[10] == 0xff && bytes[11] == 0xff;
}

[[nodiscard]] bool ParseV4Literal(const char* text, uint8_t out[4]) noexcept {
  in_addr address{};
  if (::inet_pton(AF_INET, text, &address) != 1) {
    return false;
  }
  std::memcpy(out, &address, 4);
  return true;
}

[[nodiscard]] bool ParseV6Literal(const char* text, uint8_t out[16]) noexcept {
  in6_addr address{};
  if (::inet_pton(AF_INET6, text, &address) != 1) {
    return false;
  }
  std::memcpy(out, &address, 16);
  return true;
}

void StoreV4(HostBytes* out, const uint8_t v4[4], int af) noexcept {
  if (af == AF_INET6) {
    MapV4ToV6(v4, out->data);
    out->af = AF_INET6;
    out->length = 16;
  } else {
    std::memcpy(out->data, v4, 4);
    out->af = AF_INET;
    out->length = 4;
  }
  out->ok = true;
  out->herr = 0;
}

[[nodiscard]] bool ApplyAddress(const IpAddress& address, int af, HostBytes* out) noexcept {
  if (!address.IsV6()) {
    StoreV4(out, address.V4Bytes().data(), af);
    return true;
  }
  if (address.IsV4MappedV6()) {
    const IpType4 v4 = address.ToIpt4();
    StoreV4(out, v4.octet, af);
    return true;
  }
  if (af != AF_INET6) {
    return false;
  }
  std::memcpy(out->data, address.V6Bytes().data(), 16);
  out->af = AF_INET6;
  out->length = 16;
  out->ok = true;
  out->herr = 0;
  return true;
}

[[nodiscard]] bool IsLocalHostname(const char* name) noexcept {
  char buffer[256];
  if (::gethostname(buffer, sizeof(buffer)) != 0) {
    return false;
  }
  buffer[sizeof(buffer) - 1] = '\0';
  return std::strcmp(buffer, name) == 0;
}

void LogDaemonFailure(std::string_view action, std::string_view subject,
                      std::string_view detail) noexcept {
  LogError(fmt::format("failed while {} '{}' via remote DNS daemon: {}", action, subject, detail));
}

[[nodiscard]] uint16_t NextQueryId() noexcept {
  static std::atomic<uint16_t> next_id{1};
  return next_id.fetch_add(1, std::memory_order_relaxed);
}

[[nodiscard]] Result<DnsAnswer> QueryDaemonViaCares(const IpAddress& daemon_ip, uint16_t port,
                                                    std::string_view qname, uint16_t qtype,
                                                    std::string_view action,
                                                    std::string_view subject) noexcept {
  if (qname.empty() || daemon_ip.IsV6() || port == 0) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }
  CaresSocketState state{};
  ares_channel_t* channel = CreateCaresDaemonChannel(daemon_ip, port, &state);
  if (channel == nullptr) {
    LogDaemonFailure(action, subject, "ares_init_options");
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  ares_dns_record_t* dnsrec = nullptr;
  const uint16_t id = NextQueryId();
  if (ares_dns_record_create(&dnsrec, id, static_cast<unsigned short>(ARES_FLAG_RD),
                             ARES_OPCODE_QUERY, ARES_RCODE_NOERROR) != ARES_SUCCESS ||
      dnsrec == nullptr) {
    ares_destroy(channel);
    return std::unexpected(make_error_code(ErrorCode::kProtocolError));
  }
  const std::string owned_name(qname);
  if (ares_dns_record_query_add(dnsrec, owned_name.c_str(),
                                static_cast<ares_dns_rec_type_t>(qtype),
                                ARES_CLASS_IN) != ARES_SUCCESS) {
    ares_dns_record_destroy(dnsrec);
    ares_destroy(channel);
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }
  CaresDnsrecResult result{};
  result.expected_qtype = qtype;
  unsigned short qid = 0;
  const ares_status_t sent =
      ares_send_dnsrec(channel, dnsrec, &CaresDnsrecCallback, &result, &qid);
  ares_dns_record_destroy(dnsrec);
  if (sent != ARES_SUCCESS) {
    ares_destroy(channel);
    LogDaemonFailure(action, subject, ares_strerror(static_cast<int>(sent)));
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  const bool completed = DriveCares(channel, &state, &result.done);
  ares_destroy(channel);
  if (!completed || result.status == ARES_ETIMEOUT) {
    LogDaemonFailure(action, subject, "timeout");
    return std::unexpected(make_error_code(ErrorCode::kTimeout));
  }
  if (result.status != ARES_SUCCESS || !result.answer.found) {
    return std::unexpected(make_error_code(ErrorCode::kDnsFailure));
  }
  return result.answer;
}

[[nodiscard]] Result<IpType4> DaemonGetIp(const IpAddress& daemon_ip, uint16_t port,
                                          std::string_view hostname) noexcept {
  const Result<DnsAnswer> answer = QueryDaemonViaCares(
      daemon_ip, port, hostname, static_cast<uint16_t>(ARES_REC_TYPE_A), "resolving hostname",
      hostname);
  if (!answer.has_value()) {
    return std::unexpected(answer.error());
  }
  if (answer->address.as_int == IPT4_INVALID.as_int) {
    return std::unexpected(make_error_code(ErrorCode::kDnsFailure));
  }
  return answer->address;
}

[[nodiscard]] std::optional<std::string> DaemonGetName(const IpAddress& daemon_ip, uint16_t port,
                                                       IpType4 fake_ip) noexcept {
  const std::string ptr_name = MakePtrName(fake_ip);
  char subject[INET_ADDRSTRLEN] = "fake-ip";
  (void)::inet_ntop(AF_INET, fake_ip.octet, subject, sizeof(subject));
  const Result<DnsAnswer> answer = QueryDaemonViaCares(
      daemon_ip, port, ptr_name, static_cast<uint16_t>(ARES_REC_TYPE_PTR), "resolving fake IP",
      subject);
  if (!answer.has_value() || answer->name.empty() || answer->name.size() > kMaxHostLen) {
    return std::nullopt;
  }
  return answer->name;
}

[[nodiscard]] Result<IpType4> ResolveFake(DnsMethod method, FakeIpTable& table, const IpAddress& daemon_ip,
                                          uint16_t port, std::string_view hostname) noexcept {
  if (hostname.empty() || hostname.size() > kMaxHostLen || hostname.find('\0') != std::string_view::npos) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }
  switch (method) {
    case DnsMethod::kOff:
      return ResolveAddressWithCares(hostname);
    case DnsMethod::kThread:
      return table.GetOrAllocateIp(hostname);
    case DnsMethod::kDaemon:
      return DaemonGetIp(daemon_ip, port, hostname);
  }
  return std::unexpected(make_error_code(ErrorCode::kDnsFailure));
}

[[nodiscard]] std::optional<std::string> ResolveReverse(DnsMethod method, FakeIpTable& table,
                                                        const IpAddress& daemon_ip, uint16_t port,
                                                        IpType4 fake_ip) noexcept {
  switch (method) {
    case DnsMethod::kOff:
      return ResolveNameWithCares(fake_ip);
    case DnsMethod::kThread:
      return table.GetHostnameForIp(fake_ip);
    case DnsMethod::kDaemon:
      return DaemonGetName(daemon_ip, port, fake_ip);
  }
  return std::nullopt;
}

[[nodiscard]] HostBytes LookupByFamily(DnsMethod method, FakeIpTable& table, const IpAddress& daemon_ip,
                                       uint16_t port, const char* name, int af, bool numeric_only) noexcept {
  HostBytes out;
  if (name == nullptr || name[0] == '\0' || (af != AF_INET && af != AF_INET6)) {
    out.herr = name == nullptr || name[0] == '\0' ? HOST_NOT_FOUND : NO_RECOVERY;
    return out;
  }
  if (std::strlen(name) > kMaxHostLen) {
    out.herr = HOST_NOT_FOUND;
    return out;
  }

  uint8_t v4[4]{};
  uint8_t v6[16]{};
  const bool literal_v4 = ParseV4Literal(name, v4);
  const bool literal_v6 = !literal_v4 && ParseV6Literal(name, v6);
  if (literal_v4) {
    StoreV4(&out, v4, af);
    return out;
  }
  if (literal_v6) {
    if (IsMappedV6(v6)) {
      StoreV4(&out, v6 + 12, af);
      return out;
    }
    if (af == AF_INET6) {
      std::memcpy(out.data, v6, 16);
      out.af = AF_INET6;
      out.length = 16;
      out.ok = true;
      out.herr = 0;
      return out;
    }
    out.herr = NO_DATA;
    return out;
  }
  if (numeric_only || std::strchr(name, ':') != nullptr) {
    out.herr = HOST_NOT_FOUND;
    return out;
  }
  if (IsLocalHostname(name)) {
    const uint8_t loopback[4] = {127, 0, 0, 1};
    if (af == AF_INET6) {
      std::memset(out.data, 0, 16);
      out.data[15] = 1;
      out.af = AF_INET6;
      out.length = 16;
      out.ok = true;
      out.herr = 0;
      return out;
    }
    StoreV4(&out, loopback, AF_INET);
    return out;
  }

  const std::optional<IpAddress> hosts = LookupEtcHosts(name);
  if (hosts.has_value()) {
    if (!ApplyAddress(*hosts, af, &out)) {
      out.ok = false;
      out.herr = NO_DATA;
    }
    return out;
  }

  const Result<IpType4> fake = ResolveFake(method, table, daemon_ip, port, name);
  if (!fake.has_value()) {
    out.herr = HerrFrom(fake.error());
    return out;
  }
  StoreV4(&out, (*fake).octet, af);
  return out;
}

[[nodiscard]] hostent* FillData(GethostbynameData* data, const char* name, const HostBytes& found) noexcept {
  const std::size_t name_len = std::strlen(name);
  if (name_len >= sizeof(data->addr_name)) {
    h_errno = NO_RECOVERY;
    return nullptr;
  }
  std::memcpy(data->addr_name, name, name_len + 1);
  data->hostent_space.h_name = data->addr_name;
  data->resolved_addr_p[1] = nullptr;
  data->hostent_space.h_aliases = &data->resolved_addr_p[1];
  data->hostent_space.h_addr_list = data->resolved_addr_p;
  data->hostent_space.h_addrtype = found.af;
  data->hostent_space.h_length = found.length;

  if (found.af == AF_INET && found.length == 4) {
    std::memcpy(&data->resolved_addr, found.data, 4);
    data->resolved_addr_p[0] = reinterpret_cast<char*>(&data->resolved_addr);
    h_errno = 0;
    return &data->hostent_space;
  }
  if (found.af == AF_INET6 && found.length == 16) {
    constexpr auto kAlign = static_cast<std::uintptr_t>(alignof(void*));
    const auto base = reinterpret_cast<std::uintptr_t>(data->addr_name);
    const auto aligned = ((base + name_len + 1 + kAlign - 1) & ~(kAlign - 1));
    const auto slot_off = static_cast<std::size_t>(aligned - base);
    if (slot_off > sizeof(data->addr_name) || sizeof(data->addr_name) - slot_off < 16) {
      h_errno = NO_RECOVERY;
      return nullptr;
    }
    char* const slot = data->addr_name + slot_off;
    std::memcpy(slot, found.data, 16);
    data->resolved_addr_p[0] = slot;
    h_errno = 0;
    return &data->hostent_space;
  }
  h_errno = NO_RECOVERY;
  return nullptr;
}

[[nodiscard]] int PackHostent(const char* name, const HostBytes& found, hostent* ret, char* buf,
                              std::size_t buflen, hostent** result, int* h_errnop) noexcept {
  *result = nullptr;
  if (buf == nullptr) {
    *h_errnop = NETDB_INTERNAL;
    errno = ERANGE;
    return ERANGE;
  }
  const std::size_t name_len = std::strlen(name);
  const auto base = reinterpret_cast<std::uintptr_t>(buf);
  std::size_t cursor = 0;
  const auto fail_range = [&]() noexcept {
    *h_errnop = NETDB_INTERNAL;
    errno = ERANGE;
    return ERANGE;
  };
  const auto align_cursor = [&]() noexcept {
    constexpr auto kAlign = static_cast<std::uintptr_t>(alignof(void*));
    const auto aligned = (base + static_cast<std::uintptr_t>(cursor) + kAlign - 1) & ~(kAlign - 1);
    cursor = static_cast<std::size_t>(aligned - base);
  };
  if (name_len + 1 > buflen) {
    return fail_range();
  }
  const std::size_t name_off = cursor;
  cursor = name_len + 1;
  align_cursor();
  if (cursor > buflen || sizeof(char*) * 3 > buflen - cursor) {
    return fail_range();
  }
  const std::size_t alias_off = cursor;
  cursor += sizeof(char*);
  const std::size_t list_off = cursor;
  cursor += sizeof(char*) * 2;
  align_cursor();
  const auto addr_len = static_cast<std::size_t>(found.length);
  if (cursor > buflen || addr_len > buflen - cursor) {
    return fail_range();
  }
  const std::size_t addr_off = cursor;

  std::memcpy(buf + name_off, name, name_len + 1);
  auto* aliases = reinterpret_cast<char**>(buf + alias_off);
  aliases[0] = nullptr;
  auto* list = reinterpret_cast<char**>(buf + list_off);
  std::memcpy(buf + addr_off, found.data, addr_len);
  list[0] = buf + addr_off;
  list[1] = nullptr;
  ret->h_name = buf + name_off;
  ret->h_aliases = aliases;
  ret->h_addrtype = found.af;
  ret->h_length = found.length;
  ret->h_addr_list = list;
  *result = ret;
  *h_errnop = 0;
  return 0;
}

[[nodiscard]] bool ParseService(const char* service, uint16_t* port) noexcept {
  if (service == nullptr || service[0] == '\0') {
    *port = 0;
    return true;
  }
  char* end = nullptr;
  errno = 0;
  const unsigned long value = std::strtoul(service, &end, 10);
  if (end != service && *end == '\0' && errno == 0) {
    if (value > 65535UL) {
      return false;
    }
    *port = static_cast<uint16_t>(value);
    return true;
  }
  servent service_buf{};
  servent* found = nullptr;
  char storage[1024];
  const int rc = ::getservbyname_r(service, nullptr, &service_buf, storage, sizeof(storage), &found);
  if (rc == 0 && found != nullptr) {
    *port = ntohs(static_cast<std::uint16_t>(found->s_port));
    return true;
  }
  return false;
}

[[nodiscard]] int GaiFromHerr(int herr) noexcept {
  if (herr == TRY_AGAIN) {
    return EAI_AGAIN;
  }
  if (herr == NO_DATA) {
    return EAI_ADDRFAMILY;
  }
  if (herr == NO_RECOVERY) {
    return EAI_FAIL;
  }
  return EAI_NONAME;
}

void PublishAddrinfo(AddrinfoBlock* block, const HostBytes& found, const char* node, uint16_t port,
                     int flags, int socktype, int protocol) noexcept {
  if (found.af == AF_INET6) {
    auto* address = reinterpret_cast<sockaddr_in6*>(&block->storage);
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(port);
    std::memcpy(&address->sin6_addr, found.data, 16);
    block->info.ai_family = AF_INET6;
    block->info.ai_addrlen = sizeof(sockaddr_in6);
  } else {
    auto* address = reinterpret_cast<sockaddr_in*>(&block->storage);
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    std::memcpy(&address->sin_addr, found.data, 4);
    block->info.ai_family = AF_INET;
    block->info.ai_addrlen = sizeof(sockaddr_in);
  }
  block->info.ai_addr = reinterpret_cast<sockaddr*>(&block->storage);
  block->info.ai_next = nullptr;
  if (node != nullptr) {
    const std::size_t length = std::strlen(node);
    if (length < sizeof(block->canon)) {
      std::memcpy(block->canon, node, length + 1);
    }
  }
  block->info.ai_canonname = block->canon;
  block->info.ai_flags = flags;
  block->info.ai_socktype = socktype;
  block->info.ai_protocol = protocol;
  if (block->info.ai_socktype == 0 && block->info.ai_protocol == IPPROTO_TCP) {
    block->info.ai_socktype = SOCK_STREAM;
  }
}

[[nodiscard]] bool WriteDecimal(char* dest, socklen_t dest_len, unsigned value) noexcept {
  char tmp[8];
  const int wrote = std::snprintf(tmp, sizeof(tmp), "%u", value);
  if (wrote < 0 || dest == nullptr || static_cast<std::size_t>(wrote) >= dest_len) {
    return false;
  }
  std::memcpy(dest, tmp, static_cast<std::size_t>(wrote) + 1);
  return true;
}

}  // namespace

void RdnsResolver::Configure(DnsMethod method, uint8_t remote_subnet, const IpAddress& daemon_ip,
                             uint16_t daemon_port_host) noexcept {
  method_ = method;
  remote_subnet_ = remote_subnet;
  daemon_ip_ = daemon_ip;
  daemon_port_host_ = daemon_port_host;
  table_.SetRemoteSubnet(remote_subnet);
}

std::string_view RdnsResolver::MethodName() const noexcept {
  switch (method_) {
    case DnsMethod::kOff:
      return "off";
    case DnsMethod::kThread:
      return "thread";
    case DnsMethod::kDaemon:
      return "daemon";
  }
  return "off";
}

Result<IpType4> RdnsResolver::ResolveHostToIp(std::string_view hostname) noexcept {
  return ResolveFake(method_, table_, daemon_ip_, daemon_port_host_, hostname);
}

std::optional<std::string> RdnsResolver::ResolveIpToHost(IpType4 fake_ip) noexcept {
  return ResolveReverse(method_, table_, daemon_ip_, daemon_port_host_, fake_ip);
}

hostent* RdnsResolver::ProxyGethostbyname(const char* name, GethostbynameData* data) noexcept {
  return ProxyGethostbyname2(name, AF_INET, data);
}

int RdnsResolver::ProxyGethostbynameR(const char* name, hostent* ret, char* buf, std::size_t buflen,
                                      hostent** result, int* h_errnop) noexcept {
  return ProxyGethostbyname2R(name, AF_INET, ret, buf, buflen, result, h_errnop);
}

hostent* RdnsResolver::ProxyGethostbyname2(const char* name, int af, GethostbynameData* data) noexcept {
  if (data == nullptr) {
    h_errno = NO_RECOVERY;
    return nullptr;
  }
  const HostBytes found = LookupByFamily(method_, table_, daemon_ip_, daemon_port_host_, name, af, false);
  if (!found.ok) {
    h_errno = found.herr;
    return nullptr;
  }
  return FillData(data, name, found);
}

int RdnsResolver::ProxyGethostbyname2R(const char* name, int af, hostent* ret, char* buf, std::size_t buflen,
                                       hostent** result, int* h_errnop) noexcept {
  if (result == nullptr || h_errnop == nullptr || ret == nullptr) {
    if (result != nullptr) {
      *result = nullptr;
    }
    if (h_errnop != nullptr) {
      *h_errnop = NO_RECOVERY;
    }
    return EINVAL;
  }
  *result = nullptr;
  if (af != AF_INET && af != AF_INET6) {
    *h_errnop = NO_RECOVERY;
    return EAFNOSUPPORT;
  }
  const HostBytes found = LookupByFamily(method_, table_, daemon_ip_, daemon_port_host_, name, af, false);
  if (!found.ok) {
    *h_errnop = found.herr;
    if (found.herr == TRY_AGAIN) {
      return EAGAIN;
    }
    if (found.herr == NO_RECOVERY) {
      return ENOENT;
    }
    return found.herr == 0 ? HOST_NOT_FOUND : found.herr;
  }
  return PackHostent(name, found, ret, buf, buflen, result, h_errnop);
}

int RdnsResolver::ProxyGetaddrinfo(const char* node, const char* service, const addrinfo* hints,
                                   addrinfo** res) noexcept {
  if (res == nullptr) {
    return EAI_FAIL;
  }
  *res = nullptr;
  const int flags = hints != nullptr ? hints->ai_flags : (AI_V4MAPPED | AI_ADDRCONFIG);
  const int family = hints != nullptr ? hints->ai_family : AF_UNSPEC;
  const int socktype = hints != nullptr ? hints->ai_socktype : 0;
  const int protocol = hints != nullptr ? hints->ai_protocol : 0;
  if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) {
    return EAI_FAMILY;
  }

  uint16_t port = 0;
  if (!ParseService(service, &port)) {
    return EAI_SERVICE;
  }

  HostBytes found;
  const char* canon = node;
  if (node == nullptr || node[0] == '\0') {
    found.af = family == AF_INET6 ? AF_INET6 : AF_INET;
    found.length = found.af == AF_INET6 ? 16 : 4;
    found.ok = true;
    if ((flags & AI_PASSIVE) == 0) {
      if (found.af == AF_INET6) {
        found.data[15] = 1;
      } else {
        found.data[0] = 127;
        found.data[3] = 1;
      }
    }
    canon = nullptr;
  } else {
    const int want = family == AF_UNSPEC ? AF_INET : family;
    const bool numeric_v6 = family == AF_UNSPEC && std::strchr(node, ':') != nullptr;
    const int lookup_af = numeric_v6 ? AF_INET6 : want;
    found = LookupByFamily(method_, table_, daemon_ip_, daemon_port_host_, node, lookup_af,
                           (flags & AI_NUMERICHOST) != 0);
    if (!found.ok && family == AF_UNSPEC && lookup_af == AF_INET && found.herr == NO_DATA) {
      found = LookupByFamily(method_, table_, daemon_ip_, daemon_port_host_, node, AF_INET6,
                             (flags & AI_NUMERICHOST) != 0);
    }
    if (!found.ok) {
      return GaiFromHerr(found.herr);
    }
  }

  auto* block = new (std::nothrow) AddrinfoBlock{};
  if (block == nullptr) {
    return EAI_MEMORY;
  }
  PublishAddrinfo(block, found, canon, port, flags, socktype, protocol);
  *res = &block->info;
  return 0;
}

void RdnsResolver::ProxyFreeaddrinfo(addrinfo* res) noexcept {
  while (res != nullptr) {
    addrinfo* next = res->ai_next;
    // info is the first member, so the addrinfo* is the AddrinfoBlock*.
    delete reinterpret_cast<AddrinfoBlock*>(res);
    res = next;
  }
}

int RdnsResolver::ProxyGetnameinfo(const sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen,
                                   char* serv, socklen_t servlen, int flags) noexcept {
  if (sa == nullptr || salen == 0) {
    return EAI_FAMILY;
  }
  if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) {
    return EAI_FAMILY;
  }
  const bool v6 = sa->sa_family == AF_INET6;
  const socklen_t need = v6 ? static_cast<socklen_t>(sizeof(sockaddr_in6))
                            : static_cast<socklen_t>(sizeof(sockaddr_in));
  if (salen < need) {
    return EAI_FAMILY;
  }

  uint16_t port_net = 0;
  uint8_t v4[4]{};
  uint8_t v6_bytes[16]{};
  bool present_v4 = !v6;
  uint32_t scope_id = 0;
  if (v6) {
    const auto* address = reinterpret_cast<const sockaddr_in6*>(sa);
    port_net = address->sin6_port;
    std::memcpy(v6_bytes, &address->sin6_addr, 16);
    if (IsMappedV6(v6_bytes)) {
      // Mapped addresses format as IPv4. A zone id belongs to the IPv6 form only.
      std::memcpy(v4, v6_bytes + 12, 4);
      present_v4 = true;
    } else if ((flags & NI_NUMERICSCOPE) != 0 && address->sin6_scope_id != 0) {
      scope_id = address->sin6_scope_id;
    }
  } else {
    const auto* address = reinterpret_cast<const sockaddr_in*>(sa);
    port_net = address->sin_port;
    std::memcpy(v4, &address->sin_addr, 4);
  }

  if (hostlen > 0) {
    if (host == nullptr) {
      return EAI_OVERFLOW;
    }
    bool wrote_name = false;
    if ((flags & NI_NUMERICHOST) == 0 && present_v4) {
      IpType4 ip{};
      std::memcpy(ip.octet, v4, 4);
      const std::optional<std::string> name = ResolveIpToHost(ip);
      if (name.has_value() && !name->empty()) {
        if (name->size() >= hostlen) {
          return EAI_OVERFLOW;
        }
        std::memcpy(host, name->data(), name->size() + 1);
        wrote_name = true;
      }
    }
    if (!wrote_name) {
      if ((flags & NI_NAMEREQD) != 0 && (flags & NI_NUMERICHOST) == 0) {
        return EAI_NONAME;
      }
      const void* source = present_v4 ? static_cast<const void*>(v4) : static_cast<const void*>(v6_bytes);
      const int af = present_v4 ? AF_INET : AF_INET6;
      if (::inet_ntop(af, source, host, hostlen) == nullptr) {
        return EAI_OVERFLOW;
      }
      if (scope_id != 0) {
        const std::size_t used = std::strlen(host);
        if (used >= hostlen) {
          return EAI_OVERFLOW;
        }
        const int wrote = std::snprintf(host + used, static_cast<std::size_t>(hostlen) - used, "%%%u", scope_id);
        if (wrote < 0 || static_cast<std::size_t>(wrote) >= static_cast<std::size_t>(hostlen) - used) {
          return EAI_OVERFLOW;
        }
      }
    }
  }
  if (servlen > 0) {
    if (!WriteDecimal(serv, servlen, ntohs(port_net))) {
      return EAI_OVERFLOW;
    }
  }
  return 0;
}

}  // namespace proxychains
