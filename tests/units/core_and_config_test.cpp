#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>

#include <fmt/format.h>

#include "config/config.hpp"
#include "core/error.hpp"
#include "core/fd.hpp"
#include "core/log.hpp"
#include "core/types.hpp"

namespace {

using proxychains::ChainType;
using proxychains::CidrRule;
using proxychains::DnatRule;
using proxychains::DnsMethod;
using proxychains::ErrorCode;
using proxychains::IpAddress;
using proxychains::ProxychainsConfig;
using proxychains::ProxyType;
using proxychains::Result;

int g_checks = 0;
int g_failures = 0;

void ReportFailure(const char* file, int line, const std::string& message) {
  ++g_failures;
  std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, message.c_str());
}

#define CHECK(condition)                                                        \
  do {                                                                          \
    ++g_checks;                                                                 \
    if (!(condition)) {                                                         \
      ReportFailure(__FILE__, __LINE__, "check failed: " #condition);           \
    }                                                                           \
  } while (false)

void ExpectString(std::string_view actual, std::string_view expected,
                  const char* label, const char* file, int line) {
  ++g_checks;
  if (actual != expected) {
    ReportFailure(file, line,
                  fmt::format("{}: expected '{}', got '{}'", label, expected, actual));
  }
}

template <typename T>
void ExpectError(const Result<T>& result, ErrorCode expected, const char* label,
                 const char* file, int line) {
  ++g_checks;
  if (result.has_value()) {
    ReportFailure(file, line, fmt::format("{}: expected a failure", label));
    return;
  }
  if (result.error() != expected) {
    ReportFailure(file, line,
                  fmt::format("{}: expected '{}', got '{}'", label, expected,
                              result.error().message()));
  }
}

void ExpectYamlError(std::string_view yaml, ErrorCode expected, const char* label,
                     const char* file, int line) {
  ++g_checks;
  const auto config = proxychains::LoadConfigFromYamlString(yaml);
  if (config.has_value()) {
    ReportFailure(file, line, fmt::format("{}: expected a failure", label));
    return;
  }
  if (config.error() != expected) {
    ReportFailure(file, line,
                  fmt::format("{}: expected '{}', got '{}'", label, expected,
                              config.error().message()));
  }
}

#define EXPECT_YAML_ERROR(yaml, expected, label) \
  ExpectYamlError((yaml), (expected), (label), __FILE__, __LINE__)

IpAddress MustParseIp(std::string_view text) {
  const auto address = IpAddress::Parse(text);
  ++g_checks;
  if (!address) {
    ReportFailure(__FILE__, __LINE__, fmt::format("test setup: cannot parse '{}'", text));
    return IpAddress{};
  }
  return *address;
}

void ClearEnvironment() {
  unsetenv(proxychains::kConfFileEnvVar);
  unsetenv(proxychains::kQuietModeEnvVar);
  unsetenv(proxychains::kFakeUidEnvVar);
  unsetenv(proxychains::kFakeGidEnvVar);
  unsetenv(proxychains::kProxyUrlEnvVar);
}

void TestErrorCodes() {
  ExpectString(proxychains::ProxychainsErrorCategory().name(), "proxychains", "category name", __FILE__, __LINE__);
  CHECK(proxychains::make_error_code(ErrorCode::kTimeout) == ErrorCode::kTimeout);
  ExpectString(proxychains::make_error_code(ErrorCode::kInvalidArgument).message(),
               "invalid argument", "invalid argument message", __FILE__, __LINE__);
  ExpectString(fmt::format("{}", ErrorCode::kChainEmpty), "proxy chain is empty", "ErrorCode formatter", __FILE__, __LINE__);
}

void TestToStringViews() {
  const std::array<std::pair<ProxyType, std::string_view>, 4> proxy_types{{
      {ProxyType::kHttp, "http"},
      {ProxyType::kSocks4, "socks4"},
      {ProxyType::kSocks5, "socks5"},
      {ProxyType::kRaw, "raw"},
  }};
  for (const auto& [type, expected] : proxy_types) {
    ExpectString(proxychains::ToStringView(type), expected, "proxy type", __FILE__, __LINE__);
  }
  const std::array<std::pair<ChainType, std::string_view>, 4> chain_types{{
      {ChainType::kDynamic, "dynamic"},
      {ChainType::kStrict, "strict"},
      {ChainType::kRandom, "random"},
      {ChainType::kRoundRobin, "round_robin"},
  }};
  for (const auto& [type, expected] : chain_types) {
    ExpectString(proxychains::ToStringView(type), expected, "chain type", __FILE__, __LINE__);
  }
  const std::array<std::pair<proxychains::ProxyState, std::string_view>, 4> states{{
      {proxychains::ProxyState::kPlay, "play"},
      {proxychains::ProxyState::kDown, "down"},
      {proxychains::ProxyState::kBlocked, "blocked"},
      {proxychains::ProxyState::kBusy, "busy"},
  }};
  for (const auto& [state, expected] : states) {
    ExpectString(proxychains::ToStringView(state), expected, "proxy state", __FILE__, __LINE__);
  }
  const std::array<std::pair<DnsMethod, std::string_view>, 3> methods{{
      {DnsMethod::kOff, "off"},
      {DnsMethod::kThread, "thread"},
      {DnsMethod::kDaemon, "daemon"},
  }};
  for (const auto& [method, expected] : methods) {
    ExpectString(proxychains::ToStringView(method), expected, "dns method", __FILE__, __LINE__);
  }
}

void TestIpAddressV4() {
  const auto address = IpAddress::Parse("192.168.1.10");
  CHECK(address.has_value());
  if (!address) return;
  CHECK(!address->IsV6());
  CHECK(!address->IsV4MappedV6());
  ExpectString(address->ToString(), "192.168.1.10", "v4 text", __FILE__, __LINE__);
  CHECK(address->V4Bytes()[0] == 192);
  CHECK(address->V4Bytes()[1] == 168);
  CHECK(address->V4Bytes()[2] == 1);
  CHECK(address->V4Bytes()[3] == 10);
  CHECK(address->V4NetOrder() == htonl(0xC0A8010AU));
  const auto legacy = address->ToIpt4();
  CHECK(legacy.octet[0] == 192);
  CHECK(legacy.octet[3] == 10);
  CHECK(address->NormalizeV4Mapped() == *address);
  CHECK(!address->IsZeroV4());
  CHECK(address->IsFakeDnsIp(192));
  CHECK(!address->IsFakeDnsIp(224));
  const auto round_trip = IpAddress::FromV4NetOrder(htonl(0x01020304U));
  ExpectString(round_trip.ToString(), "1.2.3.4", "v4 net order", __FILE__, __LINE__);
  ExpectString(IpAddress::LocalhostV4().ToString(), "127.0.0.1", "localhost", __FILE__, __LINE__);
  CHECK(IpAddress::Parse("0.0.0.0")->IsZeroV4());
  CHECK(!IpAddress::Parse("0.0.0.1")->IsZeroV4());
  CHECK(MustParseIp("224.1.2.3").IsFakeDnsIp(224));
  CHECK(!MustParseIp("223.1.2.3").IsFakeDnsIp(224));
  ExpectError(IpAddress::Parse(""), ErrorCode::kInvalidArgument, "empty ip", __FILE__, __LINE__);
  ExpectError(IpAddress::Parse("999.1.1.1"), ErrorCode::kInvalidArgument, "ip octet", __FILE__, __LINE__);
  ExpectError(IpAddress::Parse("1.2.3"), ErrorCode::kInvalidArgument, "short ip", __FILE__, __LINE__);
  ExpectError(IpAddress::Parse("[::1]"), ErrorCode::kInvalidArgument, "bracketed ip", __FILE__, __LINE__);
  ExpectError(IpAddress::Parse(std::string_view("1.2.3.4\0evil", 12)),
              ErrorCode::kInvalidArgument, "embedded nul ip", __FILE__, __LINE__);
}

void TestIpAddressV6() {
  const auto loopback = IpAddress::Parse("::1");
  CHECK(loopback.has_value());
  if (!loopback) return;
  CHECK(loopback->IsV6());
  CHECK(!loopback->IsV4MappedV6());
  CHECK(!loopback->IsZeroV4());
  CHECK(loopback->V6Bytes()[15] == 1);
  CHECK(loopback->V4NetOrder() == 0);
  CHECK(loopback->ToIpt4().as_int == proxychains::IPT4_INVALID.as_int);
  const auto expanded = IpAddress::Parse("0:0:0:0:0:0:0:1");
  CHECK(expanded.has_value());
  if (expanded) CHECK(*expanded == *loopback);
  const auto mapped = IpAddress::Parse("::ffff:192.168.1.10");
  CHECK(mapped.has_value());
  if (mapped) {
    CHECK(mapped->IsV6());
    CHECK(mapped->IsV4MappedV6());
    CHECK(mapped->IsFakeDnsIp(192));
    CHECK(mapped->V4NetOrder() == htonl(0xC0A8010AU));
    CHECK(mapped->ToIpt4().octet[0] == 192);
    const auto normalized = mapped->NormalizeV4Mapped();
    CHECK(!normalized.IsV6());
    ExpectString(normalized.ToString(), "192.168.1.10", "normalized mapped", __FILE__, __LINE__);
    CHECK(mapped->NormalizeV4Mapped() != *mapped);
  }
  CHECK(IpAddress::Parse("::ffff:0.0.0.0")->IsZeroV4());
  CHECK(!IpAddress::Parse("::")->IsZeroV4());
  CHECK(!IpAddress::Parse("::")->IsFakeDnsIp(0));
  const auto documentation = IpAddress::Parse("2001:db8::1");
  CHECK(documentation.has_value());
  if (documentation) ExpectString(documentation->ToString(), "2001:db8::1", "v6 text", __FILE__, __LINE__);
  ExpectError(IpAddress::Parse("::gg"), ErrorCode::kInvalidArgument, "bad v6 group", __FILE__, __LINE__);
  ExpectError(IpAddress::Parse("2001:db8::1::2"), ErrorCode::kInvalidArgument, "double ::", __FILE__, __LINE__);
}

void TestCidrRules() {
  const auto rule = CidrRule::Parse("192.168.1.0/24");
  CHECK(rule.has_value());
  if (!rule) return;
  CHECK(rule->prefix_len == 24);
  CHECK(rule->port_host == 0);
  CHECK(rule->Matches(MustParseIp("192.168.1.200"), 1234));
  CHECK(!rule->Matches(MustParseIp("192.168.2.1"), 1234));
  CHECK(rule->Matches(MustParseIp("::ffff:192.168.1.5"), 1234));
  const auto dotted = CidrRule::Parse("192.168.1.0/255.255.255.0");
  CHECK(dotted.has_value());
  if (dotted) {
    CHECK(dotted->prefix_len == 24);
    CHECK(dotted->Matches(MustParseIp("192.168.1.1"), 0));
  }
  const auto host_rule = CidrRule::Parse("10.0.0.1:8080/32");
  CHECK(host_rule.has_value());
  if (host_rule) {
    CHECK(host_rule->port_host == 8080);
    CHECK(host_rule->Matches(MustParseIp("10.0.0.1"), 8080));
    CHECK(!host_rule->Matches(MustParseIp("10.0.0.1"), 8081));
    CHECK(!host_rule->Matches(MustParseIp("10.0.0.2"), 8080));
  }
  const auto v6_rule = CidrRule::Parse("[::1]/128");
  CHECK(v6_rule.has_value());
  if (v6_rule) {
    CHECK(v6_rule->Matches(MustParseIp("::1"), 0));
    CHECK(!v6_rule->Matches(MustParseIp("::2"), 0));
  }
  const auto link_local = CidrRule::Parse("[fe80::]:443/10");
  CHECK(link_local.has_value());
  if (link_local) {
    CHECK(link_local->port_host == 443);
    CHECK(link_local->Matches(MustParseIp("fe80::1"), 443));
    CHECK(!link_local->Matches(MustParseIp("fe80::1"), 444));
    CHECK(!link_local->Matches(MustParseIp("fec0::1"), 443));
  }
  const auto mapped_rule = CidrRule::Parse("[::ffff:192.168.1.0]/120");
  CHECK(mapped_rule.has_value());
  if (mapped_rule) {
    CHECK(mapped_rule->Matches(MustParseIp("192.168.1.5"), 0));
    CHECK(!mapped_rule->Matches(MustParseIp("192.168.2.5"), 0));
  }
  ExpectError(CidrRule::Parse("192.168.1.0"), ErrorCode::kInvalidArgument, "missing mask", __FILE__, __LINE__);
  ExpectError(CidrRule::Parse("192.168.1.0/33"), ErrorCode::kInvalidArgument, "v4 prefix", __FILE__, __LINE__);
  ExpectError(CidrRule::Parse("192.168.1.0/255.0.255.0"), ErrorCode::kInvalidArgument,
              "non-contiguous mask", __FILE__, __LINE__);
  ExpectError(CidrRule::Parse("[::1]/129"), ErrorCode::kInvalidArgument, "v6 prefix", __FILE__, __LINE__);
  ExpectError(CidrRule::Parse("1.2.3.4:0/32"), ErrorCode::kInvalidArgument, "zero port", __FILE__, __LINE__);
  ExpectError(CidrRule::Parse("[zz]/64"), ErrorCode::kInvalidArgument, "bad address", __FILE__, __LINE__);
}

void TestDnatRules() {
  const auto rule = DnatRule::Parse("1.1.1.1:1234", "1.1.1.2:443");
  CHECK(rule.has_value());
  if (!rule) return;
  ExpectString(rule->orig_ip.ToString(), "1.1.1.1", "dnat orig", __FILE__, __LINE__);
  ExpectString(rule->new_ip.ToString(), "1.1.1.2", "dnat new", __FILE__, __LINE__);
  CHECK(rule->orig_port_host == 1234);
  CHECK(rule->new_port_host == 443);
  CHECK(rule->Matches(MustParseIp("1.1.1.1"), 1234));
  CHECK(rule->Matches(MustParseIp("::ffff:1.1.1.1"), 1234));
  CHECK(!rule->Matches(MustParseIp("1.1.1.1"), 1235));
  CHECK(!rule->Matches(MustParseIp("1.1.1.2"), 1234));
  const auto v6_rule = DnatRule::Parse("[2001:db8::1]:80", "[2001:db8::2]:8080");
  CHECK(v6_rule.has_value());
  if (v6_rule) {
    ExpectString(v6_rule->orig_ip.ToString(), "2001:db8::1", "dnat v6 orig", __FILE__, __LINE__);
    CHECK(v6_rule->orig_port_host == 80);
    CHECK(v6_rule->new_port_host == 8080);
    CHECK(v6_rule->Matches(MustParseIp("2001:db8::1"), 80));
    CHECK(!v6_rule->Matches(MustParseIp("2001:db8::2"), 80));
  }
  const auto any_port = DnatRule::Parse("1.1.1.1", "1.1.1.2");
  CHECK(any_port.has_value());
  if (any_port) {
    CHECK(any_port->orig_port_host == 0);
    CHECK(any_port->new_port_host == 0);
    CHECK(any_port->Matches(MustParseIp("1.1.1.1"), 9999));
  }
  ExpectError(DnatRule::Parse("1.1.1.1:0", "1.1.1.2:443"), ErrorCode::kInvalidArgument, "dnat zero port", __FILE__, __LINE__);
  ExpectError(DnatRule::Parse("bad", "1.1.1.2:443"), ErrorCode::kInvalidArgument, "dnat bad orig", __FILE__, __LINE__);
  ExpectError(DnatRule::Parse("1.1.1.1:1", "[::1]:70000"), ErrorCode::kInvalidArgument, "dnat bad port", __FILE__, __LINE__);
}

void TestBlockingSocketGuard() {
  int fds[2] = {-1, -1};
  CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
  if (fds[0] < 0) return;
  CHECK(::fcntl(fds[0], F_SETFL, O_NONBLOCK | O_APPEND) == 0);
  const int before = ::fcntl(fds[0], F_GETFL, 0);
  CHECK((before & O_NONBLOCK) != 0);
  CHECK((before & O_APPEND) != 0);
  {
    proxychains::BlockingSocketGuard guard(fds[0]);
    const int during = ::fcntl(fds[0], F_GETFL, 0);
    CHECK((during & O_NONBLOCK) == 0);
    CHECK((during & O_APPEND) != 0);
    CHECK(during == (before & ~O_NONBLOCK));
  }
  CHECK(::fcntl(fds[0], F_GETFL, 0) == before);
  CHECK(::fcntl(fds[0], F_SETFL, O_APPEND) == 0);
  const int blocking = ::fcntl(fds[0], F_GETFL, 0);
  CHECK((blocking & O_NONBLOCK) == 0);
  {
    proxychains::BlockingSocketGuard guard(fds[0]);
    CHECK(::fcntl(fds[0], F_SETFL, blocking | O_NONBLOCK) == 0);
  }
  CHECK(::fcntl(fds[0], F_GETFL, 0) == blocking);
  CHECK(::close(fds[0]) == 0);
  CHECK(::close(fds[1]) == 0);
  int pipe_fds[2] = {-1, -1};
  CHECK(::pipe(pipe_fds) == 0);
  if (pipe_fds[0] >= 0) {
    proxychains::ScopedFd owned(pipe_fds[0]);
    CHECK(owned.Valid());
    CHECK(owned.Release() == pipe_fds[0]);
    CHECK(!owned.Valid());
    CHECK(::close(pipe_fds[0]) == 0);
    CHECK(::close(pipe_fds[1]) == 0);
  }
}

void TestParseProxyUrl() {
  const auto socks5 = proxychains::ParseProxyUrl("socks5://user:pass@127.0.0.1:40000");
  CHECK(socks5.has_value());
  if (socks5) {
    CHECK(socks5->type == ProxyType::kSocks5);
    CHECK(socks5->port_host == 40000);
    ExpectString(socks5->ip.ToString(), "127.0.0.1", "url ip", __FILE__, __LINE__);
    ExpectString(socks5->user, "user", "url user", __FILE__, __LINE__);
    ExpectString(socks5->pass, "pass", "url pass", __FILE__, __LINE__);
    CHECK(socks5->host.empty());
    CHECK(socks5->state == proxychains::ProxyState::kPlay);
  }
  const auto http = proxychains::ParseProxyUrl("http://127.0.0.1:8080");
  CHECK(http.has_value());
  if (http) {
    CHECK(http->type == ProxyType::kHttp);
    CHECK(http->port_host == 8080);
  }
  const auto socks4 = proxychains::ParseProxyUrl("socks4://127.0.0.1:9050");
  CHECK(socks4.has_value());
  if (socks4) CHECK(socks4->type == ProxyType::kSocks4);
  const auto raw = proxychains::ParseProxyUrl("raw://127.0.0.1:1080");
  CHECK(raw.has_value());
  if (raw) CHECK(raw->type == ProxyType::kRaw);
  const auto v6 = proxychains::ParseProxyUrl("socks5://[::1]:1080");
  CHECK(v6.has_value());
  if (v6) ExpectString(v6->ip.ToString(), "::1", "url v6 ip", __FILE__, __LINE__);
  const auto user_only = proxychains::ParseProxyUrl("socks5://bob@127.0.0.1:1080");
  CHECK(user_only.has_value());
  if (user_only) {
    ExpectString(user_only->user, "bob", "url user only", __FILE__, __LINE__);
    CHECK(user_only->pass.empty());
  }
  const auto domain = proxychains::ParseProxyUrl("socks5://proxy.example.com:1080");
  CHECK(domain.has_value());
  if (domain) ExpectString(domain->host, "proxy.example.com", "url domain", __FILE__, __LINE__);
  ExpectError(proxychains::ParseProxyUrl("socks5://127.0.0.1"), ErrorCode::kInvalidArgument,
              "url missing port", __FILE__, __LINE__);
  ExpectError(proxychains::ParseProxyUrl("socks5://127.0.0.1:0"), ErrorCode::kInvalidArgument,
              "url zero port", __FILE__, __LINE__);
  ExpectError(proxychains::ParseProxyUrl("socks5://127.0.0.1:70000"),
              ErrorCode::kInvalidArgument, "url large port", __FILE__, __LINE__);
  ExpectError(proxychains::ParseProxyUrl("socks5://127.0.0.1:abc"),
              ErrorCode::kInvalidArgument, "url text port", __FILE__, __LINE__);
  ExpectError(proxychains::ParseProxyUrl("ftp://127.0.0.1:1"), ErrorCode::kInvalidArgument, "url scheme", __FILE__, __LINE__);
  ExpectError(proxychains::ParseProxyUrl("://127.0.0.1:1"), ErrorCode::kInvalidArgument,
              "url empty scheme", __FILE__, __LINE__);
  ExpectError(proxychains::ParseProxyUrl(std::string_view("socks5://127.0.0.1:1080\0x", 25)),
              ErrorCode::kInvalidArgument, "url embedded nul", __FILE__, __LINE__);
}

void TestValidYaml() {
  const std::string yaml = R"yaml(
chain_type: strict
chain_len: 3
quiet_mode: true
dns:
  method: daemon
  daemon_addr: "127.0.0.1:1053"
  remote_subnet: 240
timeouts:
  tcp_read_ms: 1500
  tcp_connect_ms: 2500
fake_uid: 1000
fake_gid: 1001
localnet:
  - "192.168.1.0/24"
  - "[::1]/128"
  - "10.0.0.1:8080/32"
dnat:
  - orig: "1.1.1.1:1234"
    new: "1.1.1.2:443"
  - orig: "[2001:db8::1]:80"
    target: "[2001:db8::2]:8080"
proxies:
  - type: socks5
    host: "127.0.0.1"
    port: 40000
    user: "alice"
    pass: "secret"
  - type: http
    host: "10.0.0.2"
    port: 8080
  - type: raw
    host: "proxy.example.com"
    port: 1080
)yaml";
  const auto config = proxychains::LoadConfigFromYamlString(yaml);
  CHECK(config.has_value());
  if (!config) return;
  CHECK(config->chain_type == ChainType::kStrict);
  CHECK(config->max_chain == 3);
  CHECK(config->quiet_mode);
  CHECK(config->dns_method == DnsMethod::kDaemon);
  ExpectString(config->dns_daemon_ip.ToString(), "127.0.0.1", "daemon ip", __FILE__, __LINE__);
  CHECK(config->dns_daemon_port_host == 1053);
  CHECK(config->remote_dns_subnet == 240);
  CHECK(config->tcp_read_timeout_ms == 1500);
  CHECK(config->tcp_connect_timeout_ms == 2500);
  CHECK(config->fake_uid.has_value() && *config->fake_uid == 1000);
  CHECK(config->fake_gid.has_value() && *config->fake_gid == 1001);
  CHECK(config->localnet_rules.size() == 3);
  CHECK(config->dnat_rules.size() == 2);
  CHECK(config->proxies.size() == 3);
  if (config->proxies.size() == 3) {
    CHECK(config->proxies[0].type == ProxyType::kSocks5);
    CHECK(config->proxies[0].port_host == 40000);
    ExpectString(config->proxies[0].user, "alice", "proxy user", __FILE__, __LINE__);
    ExpectString(config->proxies[0].pass, "secret", "proxy pass", __FILE__, __LINE__);
    CHECK(config->proxies[1].type == ProxyType::kHttp);
    ExpectString(config->proxies[1].ip.ToString(), "10.0.0.2", "proxy ip", __FILE__, __LINE__);
    CHECK(config->proxies[2].type == ProxyType::kRaw);
    ExpectString(config->proxies[2].host, "proxy.example.com", "proxy domain", __FILE__, __LINE__);
    CHECK(config->proxies[2].ip.IsZeroV4());
  }
  if (!config->localnet_rules.empty()) {
    CHECK(config->localnet_rules[0].Matches(MustParseIp("192.168.1.4"), 0));
    CHECK(config->localnet_rules[2].Matches(MustParseIp("10.0.0.1"), 8080));
  }
  if (config->dnat_rules.size() == 2) {
    CHECK(config->dnat_rules[0].Matches(MustParseIp("1.1.1.1"), 1234));
    CHECK(config->dnat_rules[1].Matches(MustParseIp("2001:db8::1"), 80));
  }

  const std::string minimal = R"yaml(
proxies:
  - type: socks4
    host: "127.0.0.1"
    port: 9050
)yaml";
  const auto defaults = proxychains::LoadConfigFromYamlString(minimal);
  CHECK(defaults.has_value());
  if (defaults) {
    CHECK(defaults->chain_type == ChainType::kDynamic);
    CHECK(defaults->max_chain == 1);
    CHECK(!defaults->quiet_mode);
    CHECK(defaults->dns_method == DnsMethod::kThread);
    ExpectString(defaults->dns_daemon_ip.ToString(), "127.0.0.1", "default daemon", __FILE__, __LINE__);
    CHECK(defaults->tcp_read_timeout_ms == 4000);
    CHECK(defaults->tcp_connect_timeout_ms == 10000);
    CHECK(defaults->proxies.size() == 1);
  }

  const std::string comments = R"yaml(
# leading comment
chain_type: 'strict'   # trailing comment
quiet_mode: "false"
chain_len: 0
localnet: []
dnat: []
proxies:
  - type: "socks5"
    host: '10.0.0.9'
    port: "1080"
    user: 'alice'
)yaml";
  const auto parsed = proxychains::LoadConfigFromYamlString(comments);
  CHECK(parsed.has_value());
  if (parsed) {
    CHECK(parsed->chain_type == ChainType::kStrict);
    CHECK(!parsed->quiet_mode);
    CHECK(parsed->max_chain == 1);
    CHECK(parsed->dnat_rules.empty());
    CHECK(parsed->proxies.size() == 1);
    if (parsed->proxies.size() == 1) {
      ExpectString(parsed->proxies[0].user, "alice", "quoted user", __FILE__, __LINE__);
      CHECK(parsed->proxies[0].port_host == 1080);
    }
  }
}

void TestLegacyYamlAliases() {
  const std::string yaml = R"yaml(
max_chain: 2
proxy_dns: true
proxy_dns_daemon: "[::1]:5353"
remote_dns_subnet: 230
tcp_read_time_out: 1200
tcp_connect_time_out: 2200
proxy_list:
  - type: socks4
    host: "127.0.0.1"
    port: 9050
)yaml";
  const auto config = proxychains::LoadConfigFromYamlString(yaml);
  CHECK(config.has_value());
  if (config) {
    CHECK(config->max_chain == 2);
    CHECK(config->dns_method == DnsMethod::kDaemon);
    ExpectString(config->dns_daemon_ip.ToString(), "::1", "legacy daemon ip", __FILE__, __LINE__);
    CHECK(config->dns_daemon_port_host == 5353);
    CHECK(config->remote_dns_subnet == 230);
    CHECK(config->tcp_read_timeout_ms == 1200);
    CHECK(config->tcp_connect_timeout_ms == 2200);
    CHECK(config->proxies.size() == 1);
    if (config->proxies.size() == 1) CHECK(config->proxies[0].type == ProxyType::kSocks4);
  } else {
    CHECK(false);
  }

  const auto off = proxychains::LoadConfigFromYamlString(
      "proxy_dns: false\nproxy_list:\n  - type: http\n    host: \"127.0.0.1\"\n    port: 1\n");
  CHECK(off.has_value());
  if (off) CHECK(off->dns_method == DnsMethod::kOff);


  const auto daemon_only = proxychains::LoadConfigFromYamlString(
      "proxy_dns_daemon: \"127.0.0.1:1053\"\nproxy_list:\n  - type: http\n    host: \"127.0.0.1\"\n    port: 1\n");
  CHECK(daemon_only.has_value());
  if (daemon_only) CHECK(daemon_only->dns_method == DnsMethod::kDaemon);
}

void TestEmptyYaml() {
  const std::array<std::string_view, 4> empty_documents{{
      "", "   \n\r\n", "# comment\n  # more\n", "---\n# only comments\n...\n"}};
  for (const auto empty : empty_documents) {
    const auto config = proxychains::LoadConfigFromYamlString(empty);
    CHECK(config.has_value());
    if (config) {
      CHECK(config->proxies.empty());
      CHECK(config->chain_type == ChainType::kDynamic);
      CHECK(config->dns_method == DnsMethod::kThread);
    }
  }
}

void TestInvalidYaml() {
  const std::string proxy_prefix =
      "proxies:\n  - type: socks5\n    host: \"127.0.0.1\"\n    port: ";
  const std::string proxy_tail = proxy_prefix + "1080\n";
  const std::string http_proxy =
      "proxies:\n  - type: http\n    host: \"example.com\"\n    port: 1080\n";
  const std::string mixed_proxies =
      "proxies:\n  - type: http\n    host: \"10.0.0.1\"\n    port: 1080\n"
      "  - type: http\n    host: \"example.com\"\n    port: 1080\n";
  const std::string dnat_two_targets =
      "dnat:\n  - orig: \"1.1.1.1:1\"\n    new: \"1.1.1.2:2\"\n    target: \"1.1.1.3:3\"\n";
  const std::string socks_header = "proxies:\n  - type: socks5\n    host: \"127.0.0.1\"\n";
  const std::string bogus_header =
      "proxies:\n  - type: bogus\n    host: \"127.0.0.1\"\n    port: 1080\n";

  EXPECT_YAML_ERROR("unknown_key: 1\n" + proxy_tail, ErrorCode::kConfigParseError, "unknown key");
  EXPECT_YAML_ERROR("chain_type: bogus\n" + proxy_tail, ErrorCode::kInvalidArgument, "bad chain type");
  EXPECT_YAML_ERROR("chain_len: 513\n" + proxy_tail, ErrorCode::kInvalidArgument, "chain len cap");
  EXPECT_YAML_ERROR("chain_len: abc\n" + proxy_tail, ErrorCode::kInvalidArgument, "chain len text");
  EXPECT_YAML_ERROR("quiet_mode: maybe\n" + proxy_tail, ErrorCode::kInvalidArgument, "bad bool");
  EXPECT_YAML_ERROR("fake_uid: -1\n" + proxy_tail, ErrorCode::kInvalidArgument, "negative uid");
  EXPECT_YAML_ERROR("dns:\n  method: bogus\n" + proxy_tail, ErrorCode::kInvalidArgument, "bad dns method");
  EXPECT_YAML_ERROR("proxy_dns: bogus\n" + proxy_tail, ErrorCode::kInvalidArgument, "bad legacy dns");
  EXPECT_YAML_ERROR("dns:\n  remote_subnet: 300\n" + proxy_tail, ErrorCode::kInvalidArgument, "subnet high");
  EXPECT_YAML_ERROR("dns:\n  daemon_addr: \"127.0.0.1\"\n" + proxy_tail, ErrorCode::kInvalidArgument, "daemon no port");
  EXPECT_YAML_ERROR("dns:\n  daemon_addr: \"127.0.0.1:abc\"\n" + proxy_tail, ErrorCode::kInvalidArgument, "daemon text port");
  EXPECT_YAML_ERROR("timeouts:\n  tcp_read_ms: 0\n" + proxy_tail, ErrorCode::kInvalidArgument, "read timeout zero");
  EXPECT_YAML_ERROR("timeouts:\n  tcp_connect_ms: 0\n" + proxy_tail, ErrorCode::kInvalidArgument, "connect timeout zero");
  EXPECT_YAML_ERROR(socks_header, ErrorCode::kConfigParseError, "proxy missing port");
  EXPECT_YAML_ERROR("proxies:\n  - type: socks5\n    port: 1080\n", ErrorCode::kConfigParseError, "proxy missing host");
  EXPECT_YAML_ERROR("proxies:\n  - host: \"127.0.0.1\"\n    port: 1080\n", ErrorCode::kConfigParseError, "proxy missing type");
  EXPECT_YAML_ERROR(bogus_header, ErrorCode::kInvalidArgument, "proxy bad type");
  EXPECT_YAML_ERROR(proxy_prefix + "-1\n", ErrorCode::kInvalidArgument, "proxy port negative");
  EXPECT_YAML_ERROR(proxy_prefix + "70000\n", ErrorCode::kInvalidArgument, "proxy port large");
  EXPECT_YAML_ERROR(proxy_prefix + "0\n", ErrorCode::kInvalidArgument, "proxy port zero");
  EXPECT_YAML_ERROR(proxy_prefix + "abc\n", ErrorCode::kInvalidArgument, "proxy port text");
  const std::string both_lists =
      "proxies:\n  - type: http\n    host: \"127.0.0.1\"\n    port: 1\n"
      "proxy_list:\n  - type: http\n    host: \"127.0.0.2\"\n    port: 2\n";
  EXPECT_YAML_ERROR(both_lists, ErrorCode::kInvalidArgument, "both proxy lists");
  EXPECT_YAML_ERROR("chain_type: dynamic\n" + http_proxy, ErrorCode::kInvalidArgument, "domain dynamic");
  EXPECT_YAML_ERROR("chain_type: strict\ndns:\n  method: off\n" + mixed_proxies, ErrorCode::kInvalidArgument, "domain dns off");
  EXPECT_YAML_ERROR("chain_type: strict\ndns:\n  method: thread\n" + http_proxy, ErrorCode::kInvalidArgument, "domain first");
  EXPECT_YAML_ERROR("localnet:\n  - \"192.168.1.0\"\n" + proxy_tail, ErrorCode::kInvalidArgument, "localnet no mask");
  EXPECT_YAML_ERROR("dnat:\n  - orig: \"1.1.1.1:1\"\n" + proxy_tail, ErrorCode::kConfigParseError, "dnat missing new");
  EXPECT_YAML_ERROR(dnat_two_targets + proxy_tail, ErrorCode::kInvalidArgument, "dnat two targets");
  EXPECT_YAML_ERROR("proxies: []\n", ErrorCode::kChainEmpty, "empty proxies");
  EXPECT_YAML_ERROR("chain_type: strict\n", ErrorCode::kChainEmpty, "no proxies");
  EXPECT_YAML_ERROR("chain_type: \"strict\n", ErrorCode::kConfigParseError, "malformed yaml");

  std::string long_user =
      "proxies:\n  - type: socks5\n    host: \"127.0.0.1\"\n    port: 1080\n    user: \"";
  long_user.append(256, 'a');
  long_user += "\"\n";
  EXPECT_YAML_ERROR(long_user, ErrorCode::kInvalidArgument, "user too long");

  std::string many_localnet = "localnet:\n";
  for (int index = 0; index < 65; ++index) {
    many_localnet += "  - \"10.0.0." + std::to_string(index) + "/32\"\n";
  }
  many_localnet += proxy_tail;
  EXPECT_YAML_ERROR(many_localnet, ErrorCode::kInvalidArgument, "localnet cap");

  std::string many_dnat = "dnat:\n";
  for (int index = 1; index <= 65; ++index) {
    const std::string address = "1.1.1." + std::to_string(index);
    many_dnat += "  - orig: \"" + address + ":1\"\n    new: \"2.2.2.2:2\"\n";
  }
  many_dnat += proxy_tail;
  EXPECT_YAML_ERROR(many_dnat, ErrorCode::kInvalidArgument, "dnat cap");
}

void TestEnvironmentOverrides() {
  const std::string yaml = R"yaml(
proxies:
  - type: http
    host: "127.0.0.1"
    port: 8080
)yaml";
  setenv(proxychains::kQuietModeEnvVar, "1", 1);
  setenv(proxychains::kFakeUidEnvVar, "42", 1);
  setenv(proxychains::kFakeGidEnvVar, "43", 1);
  setenv(proxychains::kProxyUrlEnvVar, "socks5://bob:secret@127.0.0.1:1080", 1);
  const auto overridden = proxychains::LoadConfigFromYamlString(yaml);
  CHECK(overridden.has_value());
  if (overridden) {
    CHECK(overridden->quiet_mode);
    CHECK(overridden->fake_uid.has_value() && *overridden->fake_uid == 42);
    CHECK(overridden->fake_gid.has_value() && *overridden->fake_gid == 43);
    CHECK(overridden->proxies.size() == 1);
    if (overridden->proxies.size() == 1) {
      CHECK(overridden->proxies[0].type == ProxyType::kSocks5);
      CHECK(overridden->proxies[0].port_host == 1080);
      ExpectString(overridden->proxies[0].user, "bob", "env user", __FILE__, __LINE__);
      ExpectString(overridden->proxies[0].pass, "secret", "env pass", __FILE__, __LINE__);
    }
  }
  ClearEnvironment();

  setenv(proxychains::kProxyUrlEnvVar, "socks5://127.0.0.1:0", 1);
  EXPECT_YAML_ERROR(yaml, ErrorCode::kInvalidArgument, "env bad url");
  ClearEnvironment();

  setenv(proxychains::kProxyUrlEnvVar, "socks5://proxy.example.com:1080", 1);
  EXPECT_YAML_ERROR(yaml, ErrorCode::kInvalidArgument, "env domain url");
  ClearEnvironment();

  setenv(proxychains::kFakeUidEnvVar, "not-a-number", 1);
  EXPECT_YAML_ERROR(yaml, ErrorCode::kInvalidArgument, "env bad uid");
  ClearEnvironment();

  setenv(proxychains::kFakeUidEnvVar, "", 1);
  const auto empty_uid = proxychains::LoadConfigFromYamlString(yaml);
  CHECK(empty_uid.has_value());
  if (empty_uid) CHECK(!empty_uid->fake_uid.has_value());
  ClearEnvironment();

  setenv(proxychains::kProxyUrlEnvVar, "raw://127.0.0.1:1080", 1);
  const auto empty_with_env = proxychains::LoadConfigFromYamlString("");
  CHECK(empty_with_env.has_value());
  if (empty_with_env) {
    CHECK(empty_with_env->proxies.size() == 1);
    if (empty_with_env->proxies.size() == 1) {
      CHECK(empty_with_env->proxies[0].type == ProxyType::kRaw);
    }
  }
  ClearEnvironment();
}

void TestFileLoadingAndResolution() {
  char path_template[] = "/tmp/proxychains_core_config_XXXXXX";
  const int fd = ::mkstemp(path_template);
  CHECK(fd >= 0);
  if (fd < 0) return;
  const std::string content =
      "chain_type: strict\n"
      "proxies:\n"
      "  - type: socks4\n"
      "    host: \"127.0.0.1\"\n"
      "    port: 9050\n";
  CHECK(::write(fd, content.data(), content.size()) == static_cast<ssize_t>(content.size()));
  CHECK(::close(fd) == 0);

  const auto resolved = proxychains::ResolveConfigPath(path_template, "/nonexistent");
  CHECK(resolved.has_value());
  if (resolved) ExpectString(*resolved, path_template, "resolved explicit", __FILE__, __LINE__);
  const auto loaded = proxychains::LoadConfigFromFile(path_template);
  CHECK(loaded.has_value());
  if (loaded) {
    CHECK(loaded->proxies.size() == 1);
    CHECK(loaded->chain_type == ChainType::kStrict);
  }

  setenv(proxychains::kConfFileEnvVar, path_template, 1);
  const auto from_env = proxychains::ResolveConfigPath("", "/nonexistent");
  CHECK(from_env.has_value());
  if (from_env) ExpectString(*from_env, path_template, "resolved env", __FILE__, __LINE__);
  const auto fallback = proxychains::ResolveConfigPath("/definitely/not/a/config", "/nonexistent");
  CHECK(fallback.has_value());
  if (fallback) ExpectString(*fallback, path_template, "explicit fallback", __FILE__, __LINE__);
  ClearEnvironment();

  const auto missing = proxychains::LoadConfigFromFile("/tmp/definitely-not-a-proxychains-config");
  ExpectError(missing, ErrorCode::kConfigNotFound, "missing file", __FILE__, __LINE__);

  CHECK(::unlink(path_template) == 0);


  if (::access("configs/proxychains.yaml", R_OK) == 0) {
    const auto shipped = proxychains::LoadConfigFromFile("configs/proxychains.yaml");
    CHECK(shipped.has_value());
    if (shipped) {
      CHECK(shipped->chain_type == ChainType::kStrict);
      CHECK(shipped->proxies.size() == 1);
      CHECK(shipped->proxies[0].type == ProxyType::kSocks4);
      CHECK(shipped->proxies[0].port_host == 9050);
    }
  }
}

void TestLoggingApi() {
  proxychains::SetQuietMode(true);
  CHECK(proxychains::IsQuietMode());
  proxychains::LogInfo("quiet info suppressed");
  proxychains::LogChainProgress("quiet progress suppressed");
  proxychains::LogDebug("debug message");
  proxychains::SetQuietMode(false);
  CHECK(!proxychains::IsQuietMode());
  proxychains::LogError("fmtlog initialization check");
}

}  // namespace

int main() {
  ClearEnvironment();
  TestErrorCodes();
  TestToStringViews();
  TestIpAddressV4();
  TestIpAddressV6();
  TestCidrRules();
  TestDnatRules();
  TestBlockingSocketGuard();
  TestParseProxyUrl();
  TestValidYaml();
  TestLegacyYamlAliases();
  TestEmptyYaml();
  TestInvalidYaml();
  TestEnvironmentOverrides();
  TestFileLoadingAndResolution();
  TestLoggingApi();
  ClearEnvironment();
  proxychains::SetQuietMode(false);

  if (g_failures == 0) {
    std::printf("PASS: %d checks\n", g_checks);
    return 0;
  }
  std::fprintf(stderr, "FAILED: %d of %d checks\n", g_failures, g_checks);
  return 1;
}
