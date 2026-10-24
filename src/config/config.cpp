#include "config/config.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <glaze/yaml.hpp>

#include "core/fd.hpp"

namespace proxychains {
namespace config_detail {

struct RawDnsSection {
  std::optional<std::string> method{};
  std::optional<std::string> daemon_addr{};
  std::optional<std::string> remote_subnet{};
};

struct RawTimeoutsSection {
  std::optional<std::string> tcp_read_ms{};
  std::optional<std::string> tcp_connect_ms{};
};

struct RawDnatEntry {
  std::optional<std::string> orig{};
  std::optional<std::string> new_value{};
  std::optional<std::string> target{};
};

struct RawProxyItem {
  std::optional<std::string> type{};
  std::optional<std::string> host{};
  std::optional<std::string> port{};
  std::optional<std::string> user{};
  std::optional<std::string> pass{};
};

struct RawConfigDocument {
  std::optional<std::string> chain_type{};
  std::optional<std::string> chain_len{};
  std::optional<std::string> max_chain{};
  std::optional<std::string> quiet_mode{};
  std::optional<std::string> fake_uid{};
  std::optional<std::string> fake_gid{};
  RawDnsSection dns{};
  RawTimeoutsSection timeouts{};
  std::optional<std::string> proxy_dns{};
  std::optional<std::string> proxy_dns_daemon{};
  std::optional<std::string> remote_dns_subnet{};
  std::optional<std::string> tcp_read_time_out{};
  std::optional<std::string> tcp_connect_time_out{};
  std::vector<std::string> localnet{};
  std::vector<RawDnatEntry> dnat{};
  std::vector<RawProxyItem> proxies{};
  std::vector<RawProxyItem> proxy_list{};
};

}  // namespace config_detail
}  // namespace proxychains

namespace glz {

template <>
struct meta<proxychains::config_detail::RawDnsSection> {
  static constexpr auto value = glz::object(
      "method", &proxychains::config_detail::RawDnsSection::method,
      "daemon_addr", &proxychains::config_detail::RawDnsSection::daemon_addr,
      "remote_subnet", &proxychains::config_detail::RawDnsSection::remote_subnet);
};

template <>
struct meta<proxychains::config_detail::RawTimeoutsSection> {
  static constexpr auto value = glz::object(
      "tcp_read_ms", &proxychains::config_detail::RawTimeoutsSection::tcp_read_ms,
      "tcp_connect_ms", &proxychains::config_detail::RawTimeoutsSection::tcp_connect_ms);
};

template <>
struct meta<proxychains::config_detail::RawDnatEntry> {
  static constexpr auto value = glz::object(
      "orig", &proxychains::config_detail::RawDnatEntry::orig,
      "new", &proxychains::config_detail::RawDnatEntry::new_value,
      "target", &proxychains::config_detail::RawDnatEntry::target);
};

template <>
struct meta<proxychains::config_detail::RawProxyItem> {
  static constexpr auto value = glz::object(
      "type", &proxychains::config_detail::RawProxyItem::type,
      "host", &proxychains::config_detail::RawProxyItem::host,
      "port", &proxychains::config_detail::RawProxyItem::port,
      "user", &proxychains::config_detail::RawProxyItem::user,
      "pass", &proxychains::config_detail::RawProxyItem::pass);
};

template <>
struct meta<proxychains::config_detail::RawConfigDocument> {
  static constexpr auto value = glz::object(
      "chain_type", &proxychains::config_detail::RawConfigDocument::chain_type,
      "chain_len", &proxychains::config_detail::RawConfigDocument::chain_len,
      "max_chain", &proxychains::config_detail::RawConfigDocument::max_chain,
      "quiet_mode", &proxychains::config_detail::RawConfigDocument::quiet_mode,
      "fake_uid", &proxychains::config_detail::RawConfigDocument::fake_uid,
      "fake_gid", &proxychains::config_detail::RawConfigDocument::fake_gid,
      "dns", &proxychains::config_detail::RawConfigDocument::dns,
      "timeouts", &proxychains::config_detail::RawConfigDocument::timeouts,
      "proxy_dns", &proxychains::config_detail::RawConfigDocument::proxy_dns,
      "proxy_dns_daemon", &proxychains::config_detail::RawConfigDocument::proxy_dns_daemon,
      "remote_dns_subnet", &proxychains::config_detail::RawConfigDocument::remote_dns_subnet,
      "tcp_read_time_out", &proxychains::config_detail::RawConfigDocument::tcp_read_time_out,
      "tcp_connect_time_out",
      &proxychains::config_detail::RawConfigDocument::tcp_connect_time_out,
      "localnet", &proxychains::config_detail::RawConfigDocument::localnet,
      "dnat", &proxychains::config_detail::RawConfigDocument::dnat,
      "proxies", &proxychains::config_detail::RawConfigDocument::proxies,
      "proxy_list", &proxychains::config_detail::RawConfigDocument::proxy_list);
};

}  // namespace glz

namespace proxychains {
namespace {

constexpr std::size_t kMaxConfigBytes = 1U << 20U;
constexpr std::size_t kPathBufferSize = 4096;

std::error_code ParseError() noexcept {
  return make_error_code(ErrorCode::kConfigParseError);
}

std::error_code InvalidValue() noexcept {
  return make_error_code(ErrorCode::kInvalidArgument);
}

bool IsSpace(char c) noexcept { return c == ' ' || c == '\t' || c == '\r'; }

std::string_view TrimSpaces(std::string_view text) noexcept {
  while (!text.empty() && IsSpace(text.front())) text.remove_prefix(1);
  while (!text.empty() && IsSpace(text.back())) text.remove_suffix(1);
  return text;
}

std::string LowerAscii(std::string_view text) {
  std::string lowered;
  lowered.reserve(text.size());
  for (const char c : text) {
    lowered.push_back(c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c);
  }
  return lowered;
}

Result<int64_t> ParseInt64Text(std::string_view text) noexcept {
  const auto value = TrimSpaces(text);
  if (value.empty()) return std::unexpected(InvalidValue());
  int64_t parsed = 0;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
  if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
    return std::unexpected(InvalidValue());
  }
  return parsed;
}

Result<uint32_t> ParseUint32Text(std::string_view text) noexcept {
  const auto value = TrimSpaces(text);
  if (value.empty()) return std::unexpected(InvalidValue());
  uint32_t parsed = 0;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
  if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
    return std::unexpected(InvalidValue());
  }
  return parsed;
}

Result<bool> ParseBoolText(std::string_view text) {
  const auto lowered = LowerAscii(TrimSpaces(text));
  if (lowered == "true" || lowered == "yes" || lowered == "on" || lowered == "1") return true;
  if (lowered == "false" || lowered == "no" || lowered == "off" || lowered == "0") return false;
  return std::unexpected(InvalidValue());
}

Result<uint16_t> ParsePortText(std::string_view text) noexcept {
  const auto parsed = ParseUint32Text(text);
  if (!parsed || *parsed == 0 || *parsed > 65535) return std::unexpected(InvalidValue());
  return static_cast<uint16_t>(*parsed);
}

Result<ChainType> ParseChainTypeToken(std::string_view token) noexcept {
  if (token == "dynamic") return ChainType::kDynamic;
  if (token == "strict") return ChainType::kStrict;
  if (token == "random") return ChainType::kRandom;
  if (token == "round_robin") return ChainType::kRoundRobin;
  return std::unexpected(InvalidValue());
}

Result<ProxyType> ParseProxyTypeToken(std::string_view token) noexcept {
  if (token == "http") return ProxyType::kHttp;
  if (token == "socks4") return ProxyType::kSocks4;
  if (token == "socks5") return ProxyType::kSocks5;
  if (token == "raw") return ProxyType::kRaw;
  return std::unexpected(InvalidValue());
}

Result<DnsMethod> ParseDnsMethodToken(std::string_view token) noexcept {
  if (token == "off") return DnsMethod::kOff;
  if (token == "thread") return DnsMethod::kThread;
  if (token == "daemon") return DnsMethod::kDaemon;
  return std::unexpected(InvalidValue());
}

Result<DnsMethod> ParseLegacyDnsToken(std::string_view token, bool daemon_present) {
  const auto lowered = LowerAscii(TrimSpaces(token));
  if (lowered == "true" || lowered == "yes" || lowered == "on" || lowered == "1") {
    return daemon_present ? DnsMethod::kDaemon : DnsMethod::kThread;
  }
  if (lowered == "false" || lowered == "no" || lowered == "0") return DnsMethod::kOff;
  return ParseDnsMethodToken(lowered);
}

struct HostPort {
  std::string_view host;
  uint16_t port_host{0};
  bool has_port{false};
};

// Splits "addr", "addr:port", "[v6]" or "[v6]:port". A bare literal with
// multiple colons is treated as IPv6 without a port.
Result<HostPort> SplitHostPort(std::string_view spec) noexcept {
  spec = TrimSpaces(spec);
  if (spec.empty()) return std::unexpected(InvalidValue());
  HostPort result;
  if (spec.front() == '[') {
    const auto close = spec.find(']');
    if (close == std::string_view::npos || close <= 1) {
      return std::unexpected(InvalidValue());
    }
    result.host = spec.substr(1, close - 1);
    const auto rest = spec.substr(close + 1);
    if (!rest.empty()) {
      if (rest.front() != ':') return std::unexpected(InvalidValue());
      const auto port = ParsePortText(rest.substr(1));
      if (!port) return std::unexpected(port.error());
      result.port_host = *port;
      result.has_port = true;
    }
    return result;
  }
  const auto first_colon = spec.find(':');
  if (first_colon == std::string_view::npos) {
    result.host = spec;
    return result;
  }
  const auto last_colon = spec.rfind(':');
  if (first_colon == last_colon) {
    if (first_colon == 0) return std::unexpected(InvalidValue());
    result.host = spec.substr(0, first_colon);
    const auto port = ParsePortText(spec.substr(first_colon + 1));
    if (!port) return std::unexpected(port.error());
    result.port_host = *port;
    result.has_port = true;
    return result;
  }
  result.host = spec;
  return result;
}

bool IsValidHostname(std::string_view host) noexcept {
  if (host.empty() || host.size() > kMaxHostLen) return false;
  for (const char c : host) {
    const bool valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                       (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
    if (!valid) return false;
  }
  return true;
}

bool HasEffectiveContent(std::string_view yaml) noexcept {
  std::size_t begin = 0;
  while (begin <= yaml.size()) {
    const auto newline = yaml.find('\n', begin);
    const auto end = newline == std::string_view::npos ? yaml.size() : newline;
    const auto line = TrimSpaces(yaml.substr(begin, end - begin));
    begin = end + 1;
    if (line.empty() || line.front() == '#' || line == "---" || line == "...") continue;
    return true;
  }
  return false;
}

Result<void> ApplyDocument(const config_detail::RawConfigDocument& doc,
                           ProxychainsConfig* config) {
  if (doc.chain_type) {
    const auto type = ParseChainTypeToken(*doc.chain_type);
    if (!type) return std::unexpected(type.error());
    config->chain_type = *type;
  }

  const std::optional<std::string>* chain_text = nullptr;
  if (doc.chain_len && doc.max_chain) {
    const auto chain_len = ParseInt64Text(*doc.chain_len);
    const auto max_chain = ParseInt64Text(*doc.max_chain);
    if (!chain_len || !max_chain || *chain_len != *max_chain) {
      return std::unexpected(InvalidValue());
    }
    chain_text = &doc.max_chain;
  } else if (doc.max_chain) {
    chain_text = &doc.max_chain;
  } else if (doc.chain_len) {
    chain_text = &doc.chain_len;
  }
  if (chain_text != nullptr) {
    const auto parsed = ParseInt64Text(**chain_text);
    if (!parsed || *parsed < 0) return std::unexpected(InvalidValue());
    if (*parsed == 0) {
      config->max_chain = 1;
    } else if (static_cast<uint64_t>(*parsed) > kMaxChain) {
      return std::unexpected(InvalidValue());
    } else {
      config->max_chain = static_cast<uint32_t>(*parsed);
    }
  }

  if (doc.quiet_mode) {
    const auto parsed = ParseBoolText(*doc.quiet_mode);
    if (!parsed) return std::unexpected(parsed.error());
    config->quiet_mode = *parsed;
  }

  if (doc.fake_uid) {
    const auto parsed = ParseInt64Text(*doc.fake_uid);
    if (!parsed || *parsed < 0 ||
        static_cast<uint64_t>(*parsed) > std::numeric_limits<uint32_t>::max()) {
      return std::unexpected(InvalidValue());
    }
    config->fake_uid = static_cast<uint32_t>(*parsed);
  }
  if (doc.fake_gid) {
    const auto parsed = ParseInt64Text(*doc.fake_gid);
    if (!parsed || *parsed < 0 ||
        static_cast<uint64_t>(*parsed) > std::numeric_limits<uint32_t>::max()) {
      return std::unexpected(InvalidValue());
    }
    config->fake_gid = static_cast<uint32_t>(*parsed);
  }

  const std::optional<std::string>* daemon_text = nullptr;
  if (doc.dns.daemon_addr) {
    daemon_text = &doc.dns.daemon_addr;
  } else if (doc.proxy_dns_daemon) {
    daemon_text = &doc.proxy_dns_daemon;
  }
  if (doc.dns.method) {
    const auto method = ParseDnsMethodToken(*doc.dns.method);
    if (!method) return std::unexpected(method.error());
    config->dns_method = *method;
  } else if (doc.proxy_dns) {
    const auto method = ParseLegacyDnsToken(*doc.proxy_dns, daemon_text != nullptr);
    if (!method) return std::unexpected(method.error());
    config->dns_method = *method;
  } else if (daemon_text != nullptr) {
    config->dns_method = DnsMethod::kDaemon;
  }
  if (daemon_text != nullptr) {
    const auto parsed = SplitHostPort(**daemon_text);
    if (!parsed || !parsed->has_port) return std::unexpected(InvalidValue());
    const auto ip = IpAddress::Parse(parsed->host);
    if (!ip) return std::unexpected(ip.error());
    config->dns_daemon_ip = *ip;
    config->dns_daemon_port_host = parsed->port_host;
  }

  const std::optional<std::string>* subnet_text = nullptr;
  if (doc.dns.remote_subnet) {
    subnet_text = &doc.dns.remote_subnet;
  } else if (doc.remote_dns_subnet) {
    subnet_text = &doc.remote_dns_subnet;
  }
  if (subnet_text != nullptr) {
    const auto parsed = ParseInt64Text(**subnet_text);
    if (!parsed || *parsed < 0 || *parsed > 255) return std::unexpected(InvalidValue());
    config->remote_dns_subnet = static_cast<uint8_t>(*parsed);
  }

  const std::optional<std::string>* read_text = nullptr;
  if (doc.timeouts.tcp_read_ms) {
    read_text = &doc.timeouts.tcp_read_ms;
  } else if (doc.tcp_read_time_out) {
    read_text = &doc.tcp_read_time_out;
  }
  if (read_text != nullptr) {
    const auto parsed = ParseInt64Text(**read_text);
    if (!parsed || *parsed <= 0 || *parsed > std::numeric_limits<int>::max()) {
      return std::unexpected(InvalidValue());
    }
    config->tcp_read_timeout_ms = static_cast<int>(*parsed);
  }
  const std::optional<std::string>* connect_text = nullptr;
  if (doc.timeouts.tcp_connect_ms) {
    connect_text = &doc.timeouts.tcp_connect_ms;
  } else if (doc.tcp_connect_time_out) {
    connect_text = &doc.tcp_connect_time_out;
  }
  if (connect_text != nullptr) {
    const auto parsed = ParseInt64Text(**connect_text);
    if (!parsed || *parsed <= 0 || *parsed > std::numeric_limits<int>::max()) {
      return std::unexpected(InvalidValue());
    }
    config->tcp_connect_timeout_ms = static_cast<int>(*parsed);
  }

  if (doc.localnet.size() > kMaxLocalnet) return std::unexpected(InvalidValue());
  for (const auto& spec : doc.localnet) {
    auto rule = CidrRule::Parse(spec);
    if (!rule) return std::unexpected(rule.error());
    config->localnet_rules.push_back(std::move(*rule));
  }

  if (doc.dnat.size() > kMaxDnat) return std::unexpected(InvalidValue());
  for (const auto& entry : doc.dnat) {
    if (!entry.orig) return std::unexpected(ParseError());
    if (entry.new_value && entry.target) return std::unexpected(InvalidValue());
    const auto* replacement = entry.new_value ? &entry.new_value : &entry.target;
    if (!*replacement) return std::unexpected(ParseError());
    auto rule = DnatRule::Parse(*entry.orig, **replacement);
    if (!rule) return std::unexpected(rule.error());
    config->dnat_rules.push_back(std::move(*rule));
  }

  if (!doc.proxies.empty() && !doc.proxy_list.empty()) {
    return std::unexpected(InvalidValue());
  }
  const auto& list = doc.proxies.empty() ? doc.proxy_list : doc.proxies;
  if (list.size() > kMaxChain) return std::unexpected(InvalidValue());
  for (std::size_t index = 0; index < list.size(); ++index) {
    const auto& raw = list[index];
    if (!raw.type || !raw.host || !raw.port) return std::unexpected(ParseError());
    const auto type = ParseProxyTypeToken(*raw.type);
    if (!type) return std::unexpected(type.error());
    const auto port = ParsePortText(*raw.port);
    if (!port) return std::unexpected(port.error());
    if ((raw.user && raw.user->size() > kMaxHostLen) ||
        (raw.pass && raw.pass->size() > kMaxHostLen)) {
      return std::unexpected(InvalidValue());
    }
    ProxyEndpoint endpoint;
    endpoint.type = *type;
    endpoint.port_host = *port;
    endpoint.user = raw.user.value_or("");
    endpoint.pass = raw.pass.value_or("");
    std::string_view host = *raw.host;
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
      host = host.substr(1, host.size() - 2);
    }
    const auto ip = IpAddress::Parse(host);
    if (ip) {
      endpoint.ip = *ip;
    } else {
      if (config->chain_type != ChainType::kStrict ||
          config->dns_method == DnsMethod::kOff || index == 0 ||
          !IsValidHostname(*raw.host)) {
        return std::unexpected(InvalidValue());
      }
      endpoint.host = *raw.host;
    }
    config->proxies.push_back(std::move(endpoint));
  }
  return {};
}

Result<void> ApplyEnvironmentOverrides(ProxychainsConfig* config) noexcept {
  if (const char* quiet = std::getenv(kQuietModeEnvVar);
      quiet != nullptr && quiet[0] == '1') {
    config->quiet_mode = true;
  }
  if (const char* uid = std::getenv(kFakeUidEnvVar);
      uid != nullptr && uid[0] != '\0') {
    const auto parsed = ParseUint32Text(uid);
    if (!parsed) return std::unexpected(parsed.error());
    config->fake_uid = *parsed;
  }
  if (const char* gid = std::getenv(kFakeGidEnvVar);
      gid != nullptr && gid[0] != '\0') {
    const auto parsed = ParseUint32Text(gid);
    if (!parsed) return std::unexpected(parsed.error());
    config->fake_gid = *parsed;
  }
  if (const char* url = std::getenv(kProxyUrlEnvVar);
      url != nullptr && url[0] != '\0') {
    auto endpoint = ParseProxyUrl(url);
    if (!endpoint) return std::unexpected(endpoint.error());
    if (!endpoint->host.empty()) return std::unexpected(InvalidValue());
    config->proxies.clear();
    config->proxies.push_back(std::move(*endpoint));
  }
  return {};
}

bool IsReadable(const std::string& path) noexcept {
  return !path.empty() && ::access(path.c_str(), R_OK) == 0;
}

}  // namespace

Result<std::string> ResolveConfigPath(std::string_view explicit_path,
                                      std::string_view sysconfdir) noexcept {
  if (!explicit_path.empty()) {
    const std::string candidate(explicit_path);
    if (IsReadable(candidate)) return candidate;
  }
  if (const char* configured = std::getenv(kConfFileEnvVar);
      configured != nullptr && configured[0] != '\0') {
    const std::string candidate(configured);
    if (IsReadable(candidate)) return candidate;
  }
  std::array<char, kPathBufferSize> cwd{};
  if (::getcwd(cwd.data(), cwd.size()) != nullptr) {
    const std::string candidate =
        std::string(cwd.data()) + "/" + std::string(kDefaultConfFileName);
    if (IsReadable(candidate)) return candidate;
  }
  if (const char* home = std::getenv("HOME"); home != nullptr && home[0] != '\0') {
    std::string candidate =
        std::string(home) + "/.proxychains/" + std::string(kDefaultConfFileName);
    if (IsReadable(candidate)) return candidate;
    candidate =
        std::string(home) + "/config/settings/" + std::string(kDefaultConfFileName);
    if (IsReadable(candidate)) return candidate;
  }
  if (!sysconfdir.empty()) {
    const std::string candidate =
        std::string(sysconfdir) + "/" + std::string(kDefaultConfFileName);
    if (IsReadable(candidate)) return candidate;
  }
  const std::string system_candidate = "/etc/" + std::string(kDefaultConfFileName);
  if (IsReadable(system_candidate)) return system_candidate;
  return std::unexpected(make_error_code(ErrorCode::kConfigNotFound));
}

Result<ProxyEndpoint> ParseProxyUrl(std::string_view url) noexcept {
  if (url.find('\0') != std::string_view::npos) {
    return std::unexpected(InvalidValue());
  }
  const auto scheme_end = url.find("://");
  if (scheme_end == std::string_view::npos || scheme_end == 0) {
    return std::unexpected(InvalidValue());
  }
  ProxyType type;
  const auto scheme = url.substr(0, scheme_end);
  if (scheme == "http") {
    type = ProxyType::kHttp;
  } else if (scheme == "socks4") {
    type = ProxyType::kSocks4;
  } else if (scheme == "socks5") {
    type = ProxyType::kSocks5;
  } else if (scheme == "raw") {
    type = ProxyType::kRaw;
  } else {
    return std::unexpected(InvalidValue());
  }
  std::string_view rest = url.substr(scheme_end + 3);
  std::string user;
  std::string pass;
  std::string_view authority = rest;
  const auto at = rest.rfind('@');
  if (at != std::string_view::npos) {
    const auto userinfo = rest.substr(0, at);
    authority = rest.substr(at + 1);
    const auto colon = userinfo.find(':');
    if (colon == std::string_view::npos) {
      user = std::string(userinfo);
    } else {
      user = std::string(userinfo.substr(0, colon));
      pass = std::string(userinfo.substr(colon + 1));
    }
    if (user.size() > kMaxHostLen || pass.size() > kMaxHostLen) {
      return std::unexpected(InvalidValue());
    }
  }
  const auto host_port = SplitHostPort(authority);
  if (!host_port || !host_port->has_port) return std::unexpected(InvalidValue());
  ProxyEndpoint endpoint;
  endpoint.type = type;
  endpoint.port_host = host_port->port_host;
  endpoint.user = std::move(user);
  endpoint.pass = std::move(pass);
  const auto ip = IpAddress::Parse(host_port->host);
  if (ip) {
    endpoint.ip = *ip;
    return endpoint;
  }
  if (!IsValidHostname(host_port->host)) return std::unexpected(InvalidValue());
  endpoint.host = std::string(host_port->host);
  return endpoint;
}

Result<ProxychainsConfig> LoadConfigFromYamlString(
    std::string_view yaml_content) noexcept {
  ProxychainsConfig config;
  const bool has_content = HasEffectiveContent(yaml_content);
  if (has_content) {
    config_detail::RawConfigDocument document;
    const auto error = glz::read<glz::yaml::yaml_opts{.error_on_unknown_keys = true}>(
        document, yaml_content);
    if (error) return std::unexpected(ParseError());
    auto status = ApplyDocument(document, &config);
    if (!status) return std::unexpected(status.error());
  }
  auto status = ApplyEnvironmentOverrides(&config);
  if (!status) return std::unexpected(status.error());
  if (has_content && config.proxies.empty()) {
    return std::unexpected(make_error_code(ErrorCode::kChainEmpty));
  }
  return config;
}

Result<ProxychainsConfig> LoadConfigFromFile(std::string_view path) noexcept {
  if (path.empty()) {
    return std::unexpected(make_error_code(ErrorCode::kConfigNotFound));
  }
  const std::string file_path(path);
  ScopedFd fd(::open(file_path.c_str(), O_RDONLY | O_CLOEXEC));
  if (!fd.Valid()) {
    return std::unexpected(make_error_code(ErrorCode::kConfigNotFound));
  }
  struct stat info {};
  if (::fstat(fd.Get(), &info) != 0 || !S_ISREG(info.st_mode)) {
    return std::unexpected(ParseError());
  }
  if (info.st_size < 0 ||
      static_cast<uint64_t>(info.st_size) > kMaxConfigBytes) {
    return std::unexpected(ParseError());
  }
  std::string content(static_cast<std::size_t>(info.st_size), '\0');
  std::size_t offset = 0;
  while (offset < content.size()) {
    const ssize_t read_size =
        ::read(fd.Get(), content.data() + offset, content.size() - offset);
    if (read_size < 0) {
      if (errno == EINTR) continue;
      return std::unexpected(make_error_code(ErrorCode::kSystemError));
    }
    if (read_size == 0) break;
    offset += static_cast<std::size_t>(read_size);
  }
  content.resize(offset);
  return LoadConfigFromYamlString(content);
}

}  // namespace proxychains
