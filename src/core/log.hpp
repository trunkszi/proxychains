#pragma once

#include <string_view>

namespace proxychains {

/** @file
 *  @brief Thread-safe stderr logging backed by fmtlog.
 */

inline constexpr std::string_view kLogPrefix = "[proxychains] ";

/** @brief Enables or disables informational output. */
void SetQuietMode(bool quiet) noexcept;
[[nodiscard]] bool IsQuietMode() noexcept;

/** @brief Reports an informational message; suppressed in quiet mode. */
void LogInfo(std::string_view message) noexcept;
/** @brief Reports chain progress; suppressed in quiet mode. */
void LogChainProgress(std::string_view text) noexcept;
/** @brief Reports an error; never suppressed. */
void LogError(std::string_view message) noexcept;
/** @brief Reports an errno description; never suppressed. */
void LogErrno(std::string_view context, int errnum) noexcept;
/** @brief Reports a getaddrinfo error description; never suppressed. */
void LogGaiError(std::string_view context, int gai_err) noexcept;
/** @brief Reports a diagnostic message. */
void LogDebug(std::string_view message) noexcept;

}  // namespace proxychains
