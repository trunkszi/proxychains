#pragma once

#include <cstdint>
#include <expected>
#include <string_view>
#include <system_error>

#include <fmt/core.h>
#include <fmt/format.h>

namespace proxychains {

/** @file
 *  @brief Domain error codes shared by every proxychains layer.
 */

/** @brief Recoverable failure classes reported by proxychains modules. */
enum class ErrorCode : uint8_t {
  kSuccess = 0,
  kInvalidArgument,
  kConfigNotFound,
  kConfigParseError,
  kMemoryExhausted,
  kSocketError,
  kTimeout,
  kChainDown,
  kChainEmpty,
  kProxyBlocked,
  kDnsFailure,
  kProtocolError,
  kSystemError,
};

/** @brief Returns the singleton category used by every ErrorCode. */
[[nodiscard]] const std::error_category& ProxychainsErrorCategory() noexcept;

/** @brief Builds an std::error_code from a domain error code. */
[[nodiscard]] std::error_code make_error_code(ErrorCode code) noexcept;

/** @brief Result type used across the library. */
template <typename T>
using Result = std::expected<T, std::error_code>;

}  // namespace proxychains

namespace std {
template <>
struct is_error_code_enum<proxychains::ErrorCode> : true_type {};
}  // namespace std

template <>
struct fmt::formatter<proxychains::ErrorCode> : fmt::formatter<std::string_view> {
  auto format(proxychains::ErrorCode code, fmt::format_context& ctx) const {
    return fmt::formatter<std::string_view>::format(
        proxychains::make_error_code(code).message(), ctx);
  }
};
