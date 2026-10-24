#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// Match the resolver's fallback when this glibc predates NI_NUMERICSCOPE.
#ifndef NI_NUMERICSCOPE
#define NI_NUMERICSCOPE 256
#endif

#include "daemon/udp_server.hpp"
#include "dns/dns_protocol.hpp"
#include "dns/fake_ip_table.hpp"
#include "dns/hosts_cache.hpp"
#include "dns/rdns_resolver.hpp"

namespace {

int g_checks = 0;
int g_failures = 0;

void Expect(bool condition, const char* expression, const char* file, int line) {
  ++g_checks;
  if (!condition) {
    std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expression);
    ++g_failures;
  }
}

#define EXPECT(cond) ::Expect(static_cast<bool>(cond), #cond, __FILE__, __LINE__)

class ServerThread {
 public:
  explicit ServerThread(proxychains::UdpServer& server) : server_(server) {
    thread_ = std::thread([this] {
      while (!server_.StopRequested()) {
        (void)server_.ServeOne();
      }
    });
  }
  ~ServerThread() {
    server_.RequestStop();
    if (thread_.joinable()) {
      thread_.join();
    }
  }
  ServerThread(const ServerThread&) = delete;
  ServerThread& operator=(const ServerThread&) = delete;

 private:
  proxychains::UdpServer& server_;
  std::thread thread_;
};

[[nodiscard]] bool BytesEqual(const void* left, const void* right, std::size_t size) {
  return std::memcmp(left, right, size) == 0;
}

void TestFakeIpEncoding() {
  const proxychains::IpType4 first = proxychains::FakeIpTable::MakeInternalIp(224, 0);
  EXPECT(first.octet[0] == 224);
  EXPECT(first.octet[1] == 0);
  EXPECT(first.octet[2] == 0);
  EXPECT(first.octet[3] == 1);
  EXPECT(proxychains::FakeIpTable::IndexFromInternalIp(first) == 0);

  const proxychains::IpType4 block = proxychains::FakeIpTable::MakeInternalIp(224, 255);
  EXPECT(block.octet[0] == 224);
  EXPECT(block.octet[1] == 0);
  EXPECT(block.octet[2] == 1);
  EXPECT(block.octet[3] == 0);
  EXPECT(proxychains::FakeIpTable::IndexFromInternalIp(block) == 255);

  const proxychains::IpType4 last = proxychains::FakeIpTable::MakeInternalIp(224, 0xFFFFFE);
  EXPECT(last.octet[0] == 224);
  EXPECT(last.octet[1] == 255);
  EXPECT(last.octet[2] == 255);
  EXPECT(last.octet[3] == 255);
  EXPECT(proxychains::FakeIpTable::IndexFromInternalIp(last) == 0xFFFFFE);

  const proxychains::IpType4 bad = proxychains::FakeIpTable::MakeInternalIp(224, 0xFFFFFF);
  EXPECT(bad.octet[0] == 255);
  EXPECT(bad.octet[1] == 255);
  EXPECT(bad.octet[2] == 255);
  EXPECT(bad.octet[3] == 255);
}

void TestFakeIpTableRoundTrip() {
  proxychains::FakeIpTable table(224);
  const auto first = table.GetOrAllocateIp("example.com");
  const auto again = table.GetOrAllocateIp("example.com");
  EXPECT(first.has_value());
  EXPECT(again.has_value());
  EXPECT(first->octet[0] == 224 && first->octet[1] == 0 && first->octet[2] == 0 && first->octet[3] == 1);
  EXPECT(again->as_int == first->as_int);

  const auto second = table.GetOrAllocateIp("other.test");
  EXPECT(second.has_value());
  EXPECT(second->octet[0] == 224 && second->octet[3] == 2);
  EXPECT(second->as_int != first->as_int);

  const auto host = table.GetHostnameForIp(*first);
  const auto other = table.GetHostnameForIp(*second);
  EXPECT(host.has_value() && *host == "example.com");
  EXPECT(other.has_value() && *other == "other.test");

  const std::string long_name(255, 'a');
  const std::string too_long(256, 'b');
  const auto accepted = table.GetOrAllocateIp(long_name);
  const auto rejected = table.GetOrAllocateIp(too_long);
  const auto empty = table.GetOrAllocateIp("");
  EXPECT(accepted.has_value());
  EXPECT(!rejected.has_value());
  EXPECT(rejected.error() == proxychains::make_error_code(proxychains::ErrorCode::kInvalidArgument));
  EXPECT(!empty.has_value());
  EXPECT(empty.error() == proxychains::make_error_code(proxychains::ErrorCode::kInvalidArgument));
  const auto round = table.GetHostnameForIp(*accepted);
  EXPECT(round.has_value() && *round == long_name);

  std::string embedded("a");
  embedded.push_back('\0');
  embedded.push_back('b');
  const auto nul = table.GetOrAllocateIp(embedded);
  EXPECT(!nul.has_value());

  table.SetRemoteSubnet(10);
  const auto moved = table.GetOrAllocateIp("example.com");
  EXPECT(moved.has_value());
  EXPECT(moved->octet[0] == 10 && moved->octet[3] == 1);
  EXPECT(table.GetHostnameForIp(*moved).value_or("") == "example.com");
  EXPECT(!table.GetHostnameForIp(*first).has_value());

  table.Clear();
  const auto restarted = table.GetOrAllocateIp("example.com");
  EXPECT(restarted.has_value());
  EXPECT(restarted->octet[0] == 10 && restarted->octet[3] == 1);
  EXPECT(table.GetRemoteSubnet() == 10);
}

void TestFakeIpConcurrent() {
  proxychains::FakeIpTable table(224);
  constexpr int kThreads = 8;
  constexpr int kNames = 32;
  std::vector<std::string> names;
  names.reserve(static_cast<std::size_t>(kNames));
  for (int i = 0; i < kNames; ++i) {
    names.push_back("conc-" + std::to_string(i));
  }
  std::vector<std::vector<proxychains::IpType4>> seen(static_cast<std::size_t>(kThreads),
                                                      std::vector<proxychains::IpType4>(static_cast<std::size_t>(kNames)));
  std::vector<std::vector<uint8_t>> ok(static_cast<std::size_t>(kThreads),
                                       std::vector<uint8_t>(static_cast<std::size_t>(kNames), 0));
  std::vector<std::thread> threads;
  threads.reserve(static_cast<std::size_t>(kThreads));
  for (int thread_index = 0; thread_index < kThreads; ++thread_index) {
    threads.emplace_back([&, thread_index] {
      for (int pass = 0; pass < 16; ++pass) {
        for (int name_index = 0; name_index < kNames; ++name_index) {
          const auto ip = table.GetOrAllocateIp(names[static_cast<std::size_t>(name_index)]);
          if (!ip.has_value()) {
            continue;
          }
          ok[static_cast<std::size_t>(thread_index)][static_cast<std::size_t>(name_index)] = 1;
          seen[static_cast<std::size_t>(thread_index)][static_cast<std::size_t>(name_index)] = *ip;
          const auto host = table.GetHostnameForIp(*ip);
          if (!host.has_value() || *host != names[static_cast<std::size_t>(name_index)]) {
            ok[static_cast<std::size_t>(thread_index)][static_cast<std::size_t>(name_index)] = 0;
          }
        }
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }

  std::vector<uint32_t> ids;
  ids.reserve(static_cast<std::size_t>(kNames));
  for (int name_index = 0; name_index < kNames; ++name_index) {
    const auto ip = table.GetOrAllocateIp(names[static_cast<std::size_t>(name_index)]);
    EXPECT(ip.has_value());
    if (!ip.has_value()) {
      continue;
    }
    EXPECT(ip->octet[0] == 224);
    const auto host = table.GetHostnameForIp(*ip);
    EXPECT(host.has_value() && *host == names[static_cast<std::size_t>(name_index)]);
    ids.push_back(ip->as_int);
    for (int thread_index = 0; thread_index < kThreads; ++thread_index) {
      EXPECT(ok[static_cast<std::size_t>(thread_index)][static_cast<std::size_t>(name_index)] == 1);
      EXPECT(seen[static_cast<std::size_t>(thread_index)][static_cast<std::size_t>(name_index)].as_int == ip->as_int);
    }
  }
  std::sort(ids.begin(), ids.end());
  EXPECT(std::adjacent_find(ids.begin(), ids.end()) == ids.end());
  EXPECT(static_cast<int>(ids.size()) == kNames);
}

void TestHostsFile() {
  char path[] = "/tmp/pc-hosts-XXXXXX";
  const int fd = ::mkstemp(path);
  EXPECT(fd >= 0);
  if (fd < 0) {
    return;
  }
  const char kFile[] =
      "# full line comment\n"
      "127.0.0.1 localhost myname # inline comment hides this\n"
      "::1 localhost ipv6-localhost\n"
      "\n"
      "192.0.2.10 alpha beta gamma\n"
      "2001:db8::1 v6host v6alias\n"
      "192.0.2.20\ttabhost\ttabalias\n"
      "not-an-ip shouldskip\n"
      "192.0.2.30 host#not-a-name\n";
  EXPECT(::write(fd, kFile, sizeof(kFile) - 1) == static_cast<ssize_t>(sizeof(kFile) - 1));
  EXPECT(::close(fd) == 0);

  const auto myname = proxychains::LookupEtcHosts("myname", path);
  const auto localhost = proxychains::LookupEtcHosts("localhost", path);
  const auto ipv6_localhost = proxychains::LookupEtcHosts("ipv6-localhost", path);
  const auto beta = proxychains::LookupEtcHosts("beta", path);
  const auto gamma = proxychains::LookupEtcHosts("gamma", path);
  const auto alias = proxychains::LookupEtcHosts("v6alias", path);
  const auto tab = proxychains::LookupEtcHosts("tabalias", path);
  const auto hidden = proxychains::LookupEtcHosts("hides", path);
  const auto skipped = proxychains::LookupEtcHosts("shouldskip", path);
  const auto commented = proxychains::LookupEtcHosts("not-a-name", path);
  const auto host = proxychains::LookupEtcHosts("host", path);
  const auto missing = proxychains::LookupEtcHosts("missing.example", path);
  const auto absent = proxychains::LookupEtcHosts("localhost", "/tmp/pc-hosts-does-not-exist");

  EXPECT(myname.has_value() && !myname->IsV6() && myname->ToString() == "127.0.0.1");
  EXPECT(localhost.has_value() && localhost->ToString() == "127.0.0.1");
  EXPECT(ipv6_localhost.has_value() && ipv6_localhost->IsV6() && ipv6_localhost->ToString() == "::1");
  EXPECT(beta.has_value() && beta->ToString() == "192.0.2.10");
  EXPECT(gamma.has_value() && gamma->ToString() == "192.0.2.10");
  EXPECT(alias.has_value() && alias->IsV6() && alias->ToString() == "2001:db8::1");
  EXPECT(tab.has_value() && tab->ToString() == "192.0.2.20");
  EXPECT(host.has_value() && host->ToString() == "192.0.2.30");
  EXPECT(!hidden.has_value());
  EXPECT(!skipped.has_value());
  EXPECT(!commented.has_value());
  EXPECT(!missing.has_value());
  EXPECT(!absent.has_value());
  EXPECT(::unlink(path) == 0);
}

void ExpectV4(const ::hostent* entry, unsigned char a, unsigned char b, unsigned char c,
              unsigned char d) {
  EXPECT(entry != nullptr);
  if (entry == nullptr || entry->h_addr_list == nullptr || entry->h_addr_list[0] == nullptr) {
    return;
  }
  const auto* bytes = reinterpret_cast<const unsigned char*>(entry->h_addr_list[0]);
  EXPECT(entry->h_addrtype == AF_INET);
  EXPECT(entry->h_length == 4);
  EXPECT(bytes[0] == a && bytes[1] == b && bytes[2] == c && bytes[3] == d);
  EXPECT(entry->h_addr_list[1] == nullptr);
  EXPECT(entry->h_aliases != nullptr && entry->h_aliases[0] == nullptr);
}

void TestThreadResolver() {
  proxychains::RdnsResolver resolver;
  resolver.Configure(proxychains::DnsMethod::kThread, 224);
  EXPECT(resolver.GetMethod() == proxychains::DnsMethod::kThread);
  EXPECT(std::strcmp(resolver.MethodName().data(), "thread") == 0);

  proxychains::GethostbynameData data{};
  ExpectV4(resolver.ProxyGethostbyname("localhost", &data), 127, 0, 0, 1);
  ExpectV4(resolver.ProxyGethostbyname("8.8.8.8", &data), 8, 8, 8, 8);

  const auto ip = resolver.ResolveHostToIp("unit.thread.invalid");
  EXPECT(ip.has_value());
  EXPECT(ip->octet[0] == 224 && ip->octet[1] == 0 && ip->octet[2] == 0 && ip->octet[3] == 1);
  const auto name = resolver.ResolveIpToHost(*ip);
  EXPECT(name.has_value() && *name == "unit.thread.invalid");

  ::hostent* entry = resolver.ProxyGethostbyname("unit.thread.invalid", &data);
  ExpectV4(entry, 224, 0, 0, 1);
  EXPECT(entry != nullptr && std::strcmp(entry->h_name, "unit.thread.invalid") == 0);

  ::hostent* mapped = resolver.ProxyGethostbyname2("unit.thread.invalid", AF_INET6, &data);
  EXPECT(mapped != nullptr);
  EXPECT(mapped->h_addrtype == AF_INET6);
  EXPECT(mapped->h_length == 16);
  const auto* v6 = reinterpret_cast<const unsigned char*>(mapped->h_addr_list[0]);
  EXPECT(v6[10] == 0xff && v6[11] == 0xff && v6[12] == 224 && v6[13] == 0 && v6[14] == 0 && v6[15] == 1);

  ::hostent ret{};
  ::hostent* result = nullptr;
  int herr = 0;
  char big[1024];
  int rc = resolver.ProxyGethostbynameR("unit.thread.invalid", &ret, big, sizeof(big), &result, &herr);
  EXPECT(rc == 0);
  EXPECT(result == &ret);
  EXPECT(herr == 0);
  EXPECT(result->h_addr_list != nullptr);
  in_addr_t got = 0;
  std::memcpy(&got, result->h_addr_list[0], 4);
  EXPECT(got == ip->as_int);

  char tiny[4];
  result = &ret;
  herr = 0;
  rc = resolver.ProxyGethostbynameR("unit.thread.invalid", &ret, tiny, sizeof(tiny), &result, &herr);
  EXPECT(rc == ERANGE);
  EXPECT(result == nullptr);

  rc = resolver.ProxyGethostbyname2R("unit.thread.invalid", AF_INET6, &ret, big, sizeof(big), &result, &herr);
  EXPECT(rc == 0);
  EXPECT(result != nullptr && result->h_addrtype == AF_INET6 && result->h_length == 16);

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* info = nullptr;
  rc = resolver.ProxyGetaddrinfo("unit.thread.invalid", "443", &hints, &info);
  EXPECT(rc == 0);
  EXPECT(info != nullptr && info->ai_family == AF_INET);
  const auto* sin = reinterpret_cast<sockaddr_in*>(info->ai_addr);
  EXPECT(sin != nullptr && ntohs(sin->sin_port) == 443 && sin->sin_addr.s_addr == ip->as_int);
  resolver.ProxyFreeaddrinfo(info);

  hints.ai_flags = AI_NUMERICHOST;
  info = nullptr;
  rc = resolver.ProxyGetaddrinfo("not-numeric.example", nullptr, &hints, &info);
  EXPECT(rc == EAI_NONAME);
  EXPECT(info == nullptr);

  hints.ai_flags = 0;
  hints.ai_family = AF_INET;
  info = nullptr;
  rc = resolver.ProxyGetaddrinfo("203.0.113.9", "80", &hints, &info);
  EXPECT(rc == 0);
  const auto* numeric = reinterpret_cast<sockaddr_in*>(info->ai_addr);
  unsigned char numeric_bytes[4];
  std::memcpy(numeric_bytes, &numeric->sin_addr, 4);
  EXPECT(numeric_bytes[0] == 203 && numeric_bytes[1] == 0 && numeric_bytes[2] == 113 && numeric_bytes[3] == 9);
  EXPECT(ntohs(numeric->sin_port) == 80);
  resolver.ProxyFreeaddrinfo(info);

  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(80);
  sa.sin_addr.s_addr = ip->as_int;
  char hbuf[NI_MAXHOST];
  char sbuf[NI_MAXSERV];
  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
                                 NI_NUMERICSERV);
  EXPECT(rc == 0);
  EXPECT(std::strcmp(hbuf, "unit.thread.invalid") == 0);
  EXPECT(std::strcmp(sbuf, "80") == 0);
  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
                                 NI_NUMERICHOST | NI_NUMERICSERV);
  EXPECT(rc == 0);
  EXPECT(std::strcmp(hbuf, "224.0.0.1") == 0);
  EXPECT(std::strcmp(sbuf, "80") == 0);

  proxychains::RdnsResolver off;
  off.Configure(proxychains::DnsMethod::kOff, 224);
  EXPECT(std::strcmp(off.MethodName().data(), "off") == 0);
  const auto denied = off.ResolveHostToIp("no.such.invalid");
  EXPECT(!denied.has_value());
  EXPECT(denied.error() == proxychains::make_error_code(proxychains::ErrorCode::kDnsFailure));
  EXPECT(off.ProxyGethostbyname("no.such.invalid", &data) == nullptr);
  ExpectV4(off.ProxyGethostbyname("8.8.4.4", &data), 8, 8, 4, 4);
}

void TestGetnameinfoEdges(proxychains::RdnsResolver& resolver) {
  sockaddr_in sa{};
  sa.sin_port = htons(80);
  unsigned char loopback[4] = {127, 0, 0, 1};
  std::memcpy(&sa.sin_addr, loopback, 4);
  char hbuf[NI_MAXHOST];
  char sbuf[NI_MAXSERV];

  int rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&sa), 0, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
                                     NI_NUMERICHOST | NI_NUMERICSERV);
  EXPECT(rc == EAI_FAMILY);

  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
                                 NI_NUMERICHOST | NI_NUMERICSERV);
  EXPECT(rc == EAI_FAMILY);

  sa.sin_family = AF_INET;
  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), hbuf, 1, sbuf, sizeof(sbuf),
                                 NI_NUMERICHOST | NI_NUMERICSERV);
  EXPECT(rc == EAI_OVERFLOW);

  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), hbuf, 0, sbuf, 1,
                                 NI_NUMERICHOST | NI_NUMERICSERV);
  EXPECT(rc == EAI_OVERFLOW);

  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa) - 1, hbuf, sizeof(hbuf), sbuf,
                                 sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV);
  EXPECT(rc == EAI_FAMILY);

  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), hbuf, 0, sbuf, sizeof(sbuf),
                                 NI_NUMERICHOST | NI_NUMERICSERV);
  EXPECT(rc == 0 && std::strcmp(sbuf, "80") == 0);

  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), hbuf, sizeof(hbuf), sbuf, 0,
                                 NI_NUMERICHOST | NI_NUMERICSERV);
  EXPECT(rc == 0 && std::strcmp(hbuf, "127.0.0.1") == 0);

  sockaddr_in6 mapped{};
  mapped.sin6_family = AF_INET6;
  mapped.sin6_port = htons(8080);
  mapped.sin6_scope_id = 3;
  const unsigned char mapped_bytes[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 2};
  std::memcpy(&mapped.sin6_addr, mapped_bytes, 16);
  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&mapped), sizeof(mapped), hbuf, sizeof(hbuf), sbuf,
                                 sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV | NI_NUMERICSCOPE);
  EXPECT(rc == 0);
  EXPECT(std::strcmp(hbuf, "192.168.1.2") == 0);
  EXPECT(std::strcmp(sbuf, "8080") == 0);

  unsigned char scoped[16] = {};
  scoped[0] = 0xfe;
  scoped[1] = 0x80;
  scoped[15] = 1;
  std::memcpy(&mapped.sin6_addr, scoped, 16);
  mapped.sin6_scope_id = 2;
  mapped.sin6_port = htons(1);
  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&mapped), sizeof(mapped), hbuf, sizeof(hbuf), sbuf,
                                 sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV | NI_NUMERICSCOPE);
  EXPECT(rc == 0);
  EXPECT(std::strcmp(hbuf, "fe80::1%2") == 0);
  EXPECT(std::strcmp(sbuf, "1") == 0);

  unsigned char loop6[16] = {};
  loop6[15] = 1;
  std::memcpy(&mapped.sin6_addr, loop6, 16);
  mapped.sin6_scope_id = 0;
  mapped.sin6_port = 0;
  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&mapped), sizeof(mapped), hbuf, sizeof(hbuf), nullptr, 0,
                                 NI_NUMERICHOST);
  EXPECT(rc == 0);
  EXPECT(std::strcmp(hbuf, "::1") == 0);
}

[[nodiscard]] int OpenClient() {
  const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }
  timeval timeout{};
  timeout.tv_sec = 1;
  if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

void TestDaemonWireAndResolver() {
  proxychains::UdpServer server(224);
  const auto listened = server.Listen("127.0.0.1", 0);
  EXPECT(listened.has_value());
  EXPECT(server.BoundPort() != 0);
  if (!listened.has_value() || server.BoundPort() == 0) {
    return;
  }
  ServerThread runner(server);

  const int fd = OpenClient();
  EXPECT(fd >= 0);
  if (fd < 0) {
    return;
  }
  proxychains::ScopedFd client{fd};
  sockaddr_in dest{};
  dest.sin_family = AF_INET;
  dest.sin_port = htons(server.BoundPort());
  dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  proxychains::AtMsg request{};
  const char kName[] = "wire.example";
  request.h.msgtype = static_cast<uint8_t>(proxychains::AtMsgType::kGetIp);
  std::memcpy(request.m.host, kName, sizeof(kName));
  request.h.datalen = htons(static_cast<uint16_t>(sizeof(kName)));
  const auto send_len = sizeof(proxychains::AtMsgHeader) + sizeof(kName);
  EXPECT(::sendto(client.Get(), &request, send_len, 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest)) ==
         static_cast<ssize_t>(send_len));
  proxychains::AtMsg response{};
  const ssize_t got = ::recvfrom(client.Get(), &response, sizeof(response), 0, nullptr, nullptr);
  EXPECT(got == static_cast<ssize_t>(sizeof(proxychains::AtMsgHeader) + 4));
  EXPECT(response.h.msgtype == static_cast<uint8_t>(proxychains::AtMsgType::kGetIp));
  EXPECT(ntohs(response.h.datalen) == 4);
  EXPECT(response.m.ip.octet[0] == 224);
  EXPECT(response.m.ip.octet[1] == 0);
  EXPECT(response.m.ip.octet[2] == 0);
  EXPECT(response.m.ip.octet[3] == 1);

  EXPECT(::sendto(client.Get(), &request, send_len, 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest)) ==
         static_cast<ssize_t>(send_len));
  proxychains::AtMsg second{};
  EXPECT(::recvfrom(client.Get(), &second, sizeof(second), 0, nullptr, nullptr) >= 8);
  EXPECT(BytesEqual(&second.m.ip, &response.m.ip, 4));

  proxychains::AtMsg name_req{};
  name_req.h.msgtype = static_cast<uint8_t>(proxychains::AtMsgType::kGetName);
  name_req.h.datalen = htons(4);
  name_req.m.ip = response.m.ip;
  EXPECT(::sendto(client.Get(), &name_req, sizeof(proxychains::AtMsgHeader) + 4, 0,
                  reinterpret_cast<sockaddr*>(&dest), sizeof(dest)) ==
         static_cast<ssize_t>(sizeof(proxychains::AtMsgHeader) + 4));
  proxychains::AtMsg name_res{};
  const ssize_t name_n = ::recvfrom(client.Get(), &name_res, sizeof(name_res), 0, nullptr, nullptr);
  EXPECT(name_n == static_cast<ssize_t>(sizeof(proxychains::AtMsgHeader) + sizeof(kName)));
  EXPECT(name_res.h.msgtype == static_cast<uint8_t>(proxychains::AtMsgType::kGetName));
  EXPECT(ntohs(name_res.h.datalen) == sizeof(kName));
  EXPECT(std::strcmp(name_res.m.host, "wire.example") == 0);

  proxychains::AtMsg bad{};
  bad.h.msgtype = 9;
  bad.h.datalen = htons(50);
  EXPECT(::sendto(client.Get(), &bad, sizeof(proxychains::AtMsgHeader), 0, reinterpret_cast<sockaddr*>(&dest),
                  sizeof(dest)) == static_cast<ssize_t>(sizeof(proxychains::AtMsgHeader)));
  proxychains::AtMsg bad_res{};
  EXPECT(::recvfrom(client.Get(), &bad_res, sizeof(bad_res), 0, nullptr, nullptr) >=
         static_cast<ssize_t>(sizeof(proxychains::AtMsgHeader)));
  EXPECT(bad_res.h.msgtype == static_cast<uint8_t>(proxychains::AtMsgType::kFail));
  EXPECT(ntohs(bad_res.h.datalen) == 0);

  proxychains::RdnsResolver resolver;
  resolver.Configure(proxychains::DnsMethod::kDaemon, 224, proxychains::IpAddress::LocalhostV4(), server.BoundPort());
  EXPECT(std::strcmp(resolver.MethodName().data(), "daemon") == 0);
  const auto ip = resolver.ResolveHostToIp("daemon.example.invalid");
  EXPECT(ip.has_value());
  EXPECT(ip->octet[0] == 224 && ip->octet[1] == 0 && ip->octet[2] == 0 && ip->octet[3] == 2);
  const auto again = resolver.ResolveHostToIp("daemon.example.invalid");
  EXPECT(again.has_value() && again->as_int == ip->as_int);
  const auto other = resolver.ResolveHostToIp("other.daemon.invalid");
  EXPECT(other.has_value() && other->octet[3] == 3);
  const auto host = resolver.ResolveIpToHost(*ip);
  EXPECT(host.has_value() && *host == "daemon.example.invalid");

  proxychains::GethostbynameData data{};
  ExpectV4(resolver.ProxyGethostbyname("daemon.example.invalid", &data), 224, 0, 0, 2);

  ::hostent ret{};
  ::hostent* result = nullptr;
  int herr = 0;
  char big[1024];
  int rc = resolver.ProxyGethostbynameR("daemon.example.invalid", &ret, big, sizeof(big), &result, &herr);
  EXPECT(rc == 0 && result == &ret && herr == 0);
  char tiny[8];
  result = &ret;
  rc = resolver.ProxyGethostbynameR("daemon.example.invalid", &ret, tiny, sizeof(tiny), &result, &herr);
  EXPECT(rc == ERANGE && result == nullptr);

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* info = nullptr;
  rc = resolver.ProxyGetaddrinfo("daemon.example.invalid", "443", &hints, &info);
  EXPECT(rc == 0 && info != nullptr && info->ai_family == AF_INET);
  const auto* sin = reinterpret_cast<sockaddr_in*>(info->ai_addr);
  EXPECT(ntohs(sin->sin_port) == 443 && sin->sin_addr.s_addr == ip->as_int);
  resolver.ProxyFreeaddrinfo(info);

  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(53);
  sa.sin_addr.s_addr = ip->as_int;
  char hbuf[NI_MAXHOST];
  char sbuf[NI_MAXSERV];
  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
                                 0);
  EXPECT(rc == 0);
  EXPECT(std::strcmp(hbuf, "daemon.example.invalid") == 0);
  EXPECT(std::strcmp(sbuf, "53") == 0);
  rc = resolver.ProxyGetnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
                                 NI_NUMERICHOST | NI_NUMERICSERV);
  EXPECT(rc == 0);
  EXPECT(std::strcmp(hbuf, "224.0.0.2") == 0);
  EXPECT(std::strcmp(sbuf, "53") == 0);

  const std::string too_long(256, 'x');
  const auto rejected = resolver.ResolveHostToIp(too_long);
  EXPECT(!rejected.has_value());
  EXPECT(rejected.error() == proxychains::make_error_code(proxychains::ErrorCode::kInvalidArgument));

  TestGetnameinfoEdges(resolver);
}

// Standard DNS wire query, built by hand so the daemon's c-ares writer is
// checked against an independent encoder.
[[nodiscard]] std::vector<uint8_t> EncodeDnsQuery(uint16_t id, std::string_view name, uint16_t qtype) {
  std::vector<uint8_t> out{static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id & 0xFFU), 0x01, 0x00,
                           0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  std::size_t start = 0;
  while (start < name.size()) {
    const std::size_t dot = name.find('.', start);
    const std::size_t end = dot == std::string_view::npos ? name.size() : dot;
    out.push_back(static_cast<uint8_t>(end - start));
    for (std::size_t i = start; i < end; ++i) {
      out.push_back(static_cast<uint8_t>(name[i]));
    }
    start = end + 1;
  }
  out.push_back(0);
  out.push_back(static_cast<uint8_t>(qtype >> 8));
  out.push_back(static_cast<uint8_t>(qtype & 0xFFU));
  out.push_back(0);
  out.push_back(1);
  return out;
}

[[nodiscard]] std::vector<uint8_t> ExchangeRaw(int fd, const sockaddr_in& dest, const std::vector<uint8_t>& query) {
  std::vector<uint8_t> reply;
  if (::sendto(fd, query.data(), query.size(), 0, reinterpret_cast<const sockaddr*>(&dest), sizeof(dest)) !=
      static_cast<ssize_t>(query.size())) {
    return reply;
  }
  reply.resize(2048);
  const ssize_t got = ::recvfrom(fd, reply.data(), reply.size(), 0, nullptr, nullptr);
  if (got < 0) {
    reply.clear();
    return reply;
  }
  reply.resize(static_cast<std::size_t>(got));
  return reply;
}

void TestDnsWireQueries() {
  proxychains::UdpServer server(224);
  const auto listened = server.Listen("127.0.0.1", 0);
  EXPECT(listened.has_value());
  if (!listened.has_value() || server.BoundPort() == 0) return;
  ServerThread runner(server);

  const int fd = OpenClient();
  EXPECT(fd >= 0);
  if (fd < 0) return;
  proxychains::ScopedFd client{fd};
  sockaddr_in dest{};
  dest.sin_family = AF_INET;
  dest.sin_port = htons(server.BoundPort());
  dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  constexpr uint16_t kTypeA = static_cast<uint16_t>(ARES_REC_TYPE_A);
  constexpr uint16_t kTypePtr = static_cast<uint16_t>(ARES_REC_TYPE_PTR);
  const std::vector<uint8_t> a_reply =
      ExchangeRaw(client.Get(), dest, EncodeDnsQuery(0x4242, "raw.cares.example", kTypeA));
  proxychains::DnsAnswer a_answer{};
  EXPECT(a_reply.size() >= 12 && a_reply[0] == 0x42 && a_reply[1] == 0x42);
  EXPECT(proxychains::ParseDnsAnswer(a_reply.data(), a_reply.size(), 0x4242, kTypeA, &a_answer));
  EXPECT(a_answer.address.octet[0] == 224 && a_answer.address.octet[3] == 1);

  proxychains::RdnsResolver resolver;
  resolver.Configure(proxychains::DnsMethod::kDaemon, 224, proxychains::IpAddress::LocalhostV4(),
                     server.BoundPort());
  const auto resolved = resolver.ResolveHostToIp("raw.cares.example");
  EXPECT(resolved.has_value() && resolved->octet[0] == 224 && resolved->octet[3] == 1);

  proxychains::IpType4 reversed{};
  EXPECT(proxychains::ParsePtrName("1.0.0.224.in-addr.arpa", &reversed));
  EXPECT(proxychains::MakePtrName(reversed) == "1.0.0.224.in-addr.arpa");
  const std::vector<uint8_t> ptr_reply =
      ExchangeRaw(client.Get(), dest, EncodeDnsQuery(0x4243, proxychains::MakePtrName(reversed), kTypePtr));
  proxychains::DnsAnswer ptr_answer{};
  EXPECT(proxychains::ParseDnsAnswer(ptr_reply.data(), ptr_reply.size(), 0x4243, kTypePtr, &ptr_answer));
  EXPECT(ptr_answer.name == "raw.cares.example");

  const auto named = resolver.ResolveIpToHost(resolved.value_or(proxychains::IPT4_INVALID));
  EXPECT(named.has_value() && *named == "raw.cares.example");

  const std::vector<uint8_t> missing =
      ExchangeRaw(client.Get(), dest, EncodeDnsQuery(0x4244, "99.0.0.224.in-addr.arpa", kTypePtr));
  proxychains::DnsAnswer absent{};
  EXPECT(missing.size() >= 12 && (missing[3] & 0x0FU) == 3);
  EXPECT(!proxychains::ParseDnsAnswer(missing.data(), missing.size(), 0x4244, kTypePtr, &absent));
}

[[nodiscard]] bool WaitChild(pid_t pid) {
  for (int attempt = 0; attempt < 50; ++attempt) {
    int status = 0;
    const pid_t waited = ::waitpid(pid, &status, WNOHANG);
    if (waited == pid) {
      return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    if (waited < 0) {
      return false;
    }
    ::usleep(100000U);
  }
  ::kill(pid, SIGKILL);
  int status = 0;
  ::waitpid(pid, &status, 0);
  return false;
}

void TestForkChildUsesTable() {
  proxychains::FakeIpTable table(224);
  std::atomic<bool> ready{false};
  std::atomic<bool> done{false};
  std::thread worker([&table, &ready, &done] {
    (void)table.GetOrAllocateIp("fork.a");
    (void)table.GetOrAllocateIp("fork.b");
    ready.store(true, std::memory_order_release);
    while (!done.load(std::memory_order_acquire)) {
    }
  });
  while (!ready.load(std::memory_order_acquire)) {
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    done.store(true, std::memory_order_release);
    worker.join();
    EXPECT(false);
    return;
  }
  if (pid == 0) {
    ::alarm(2U);
    const auto first = table.GetOrAllocateIp("fork.a");
    const auto second = table.GetOrAllocateIp("fork.b");
    const auto created = table.GetOrAllocateIp("fork.child");
    const auto first_name = first.has_value() ? table.GetHostnameForIp(*first) : std::nullopt;
    const auto second_name = second.has_value() ? table.GetHostnameForIp(*second) : std::nullopt;
    const auto created_name = created.has_value() ? table.GetHostnameForIp(*created) : std::nullopt;
    const bool ok = first.has_value() && first->octet[0] == 224 && first->octet[1] == 0 && first->octet[2] == 0 &&
                    first->octet[3] == 1 && proxychains::FakeIpTable::IndexFromInternalIp(*first) == 0 &&
                    second.has_value() && second->octet[3] == 2 &&
                    proxychains::FakeIpTable::IndexFromInternalIp(*second) == 1 && first_name.has_value() &&
                    *first_name == "fork.a" && second_name.has_value() && *second_name == "fork.b" &&
                    created.has_value() && created->octet[0] == 224 && created->octet[3] == 3 &&
                    proxychains::FakeIpTable::IndexFromInternalIp(*created) == 2 && created_name.has_value() &&
                    *created_name == "fork.child";
    _exit(ok ? 0 : 1);
  }

  done.store(true, std::memory_order_release);
  worker.join();
  EXPECT(WaitChild(pid));
  const auto parent_ip = table.GetOrAllocateIp("fork.a");
  const auto parent_name = parent_ip.has_value() ? table.GetHostnameForIp(*parent_ip) : std::nullopt;
  EXPECT(parent_ip.has_value() && parent_ip->octet[3] == 1 && parent_name.has_value() && *parent_name == "fork.a");
}

}  // namespace

int main() {
  static_assert(sizeof(proxychains::AtMsgHeader) == 4);
  static_assert(offsetof(proxychains::AtMsg, m) == sizeof(proxychains::AtMsgHeader));
  TestFakeIpEncoding();
  TestFakeIpTableRoundTrip();
  TestFakeIpConcurrent();
  TestForkChildUsesTable();
  TestHostsFile();
  TestThreadResolver();
  TestDnsWireQueries();
  TestDaemonWireAndResolver();
  if (g_failures != 0) {
    std::fprintf(stderr, "%d failure(s) in %d checks\n", g_failures, g_checks);
    return 1;
  }
  std::printf("ok (%d checks)\n", g_checks);
  return 0;
}
