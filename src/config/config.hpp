#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/error.hpp"
#include "core/types.hpp"

namespace proxychains {

/** @file
 *  @brief Zero-exception loader for the proxychains.yaml subset.
 */

inline constexpr const char* kConfFileEnvVar = "PROXYCHAINS_CONF_FILE";
inline constexpr const char* kQuietModeEnvVar = "PROXYCHAINS_QUIET_MODE";
inline constexpr const char* kFakeUidEnvVar = "PROXYCHAINS_FAKE_UID";
inline constexpr const char* kFakeGidEnvVar = "PROXYCHAINS_FAKE_GID";
inline constexpr const char* kProxyUrlEnvVar = "PROXYCHAINS_PROXY_URL";
inline constexpr std::string_view kDefaultConfFileName = "proxychains.yaml";

/** @brief Fully validated runtime configuration. */
struct ProxychainsConfig {
  ChainType chain_type{ChainType::kDynamic};
  uint32_t max_chain{1};
  bool quiet_mode{false};
  DnsMethod dns_method{DnsMethod::kThread};
  IpAddress dns_daemon_ip{IpAddress::LocalhostV4()};
  uint16_t dns_daemon_port_host{1053};
  uint8_t remote_dns_subnet{224};
  int tcp_read_timeout_ms{4000};
  int tcp_connect_timeout_ms{10000};
  std::optional<uint32_t> fake_uid{};
  std::optional<uint32_t> fake_gid{};
  std::vector<CidrRule> localnet_rules{};
  std::vector<DnatRule> dnat_rules{};
  std::vector<ProxyEndpoint> proxies{};
};

/**
 * @brief Finds a readable configuration file.
 *
 * Search order: explicit_path, PROXYCHAINS_CONF_FILE, ./proxychains.yaml,
 * $HOME/.proxychains/proxychains.yaml, $HOME/config/settings/proxychains.yaml,
 * <sysconfdir>/proxychains.yaml, /etc/proxychains.yaml.
 */
[[nodiscard]] Result<std::string> ResolveConfigPath(
    std::string_view explicit_path = {},
    std::string_view sysconfdir = "/usr/local/etc") noexcept;

/**
 * @brief Parses scheme://[user[:pass]@]host:port.
 *
 * A numeric host fills ProxyEndpoint::ip; a hostname fills
 * ProxyEndpoint::host and must be admitted by the caller's chain policy.
 */
[[nodiscard]] Result<ProxyEndpoint> ParseProxyUrl(std::string_view url) noexcept;

/**
 * @brief Parses and validates a YAML document with glaze.
 *
 * Environment overrides are applied after the document is parsed:
 * PROXYCHAINS_QUIET_MODE, PROXYCHAINS_FAKE_UID, PROXYCHAINS_FAKE_GID and
 * PROXYCHAINS_PROXY_URL. Both the structured keys and the legacy aliases
 * (proxy_dns, proxy_dns_daemon, remote_dns_subnet, tcp_read_time_out,
 * tcp_connect_time_out, max_chain, proxy_list) are accepted; unknown keys are
 * rejected. Empty or comment-only input yields a default configuration.
 */
[[nodiscard]] Result<ProxychainsConfig> LoadConfigFromYamlString(
    std::string_view yaml_content) noexcept;

/** @brief Reads a file and parses it with LoadConfigFromYamlString. */
[[nodiscard]] Result<ProxychainsConfig> LoadConfigFromFile(
    std::string_view path) noexcept;

}  // namespace proxychains
