#pragma once

/// @file socket_io.hpp
/// @brief Deadline-bounded socket primitives used by every proxy handshake.
///
/// All functions take a total millisecond budget measured from the call and
/// enforce it with a monotonic absolute deadline, so a slow peer cannot extend
/// an operation by restarting the timeout on every partial read or write.

#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "core/error.hpp"
#include "core/types.hpp"

namespace proxychains {

/// Connect syscall injected by callers/tests; production passes `::connect`.
using ConnectSyscallFn = int (*)(int, const struct sockaddr*, socklen_t);

/// Connects `sock_fd` to `ip:port_host` within `timeout_ms`.
///
/// The call uses a non-blocking connect followed by `poll(POLLOUT)`, and
/// restores the descriptor's original status flags on every path.
///
/// @return Success, kTimeout when the budget expires, or kSocketError.
[[nodiscard]] Result<void> TimedConnect(int sock_fd,
                                        const IpAddress& ip,
                                        uint16_t port_host,
                                        int timeout_ms,
                                        ConnectSyscallFn connect_fn) noexcept;

/// Writes every byte of `data` within one total `timeout_ms` budget.
///
/// @return Success, kTimeout, or kSocketError.
[[nodiscard]] Result<void> PollWriteAll(int sock_fd,
                                        std::span<const uint8_t> data,
                                        int timeout_ms) noexcept;

/// Reads exactly `buffer.size()` bytes within one total `timeout_ms` budget.
///
/// @return Success, kTimeout, or kSocketError (including premature EOF).
[[nodiscard]] Result<void> PollReadExact(int sock_fd,
                                         std::span<uint8_t> buffer,
                                         int timeout_ms) noexcept;

/// Reads through the first `CRLFCRLF` into `buffer`.
///
/// @return Bytes consumed including the terminator, kTimeout, kSocketError, or
///         kProtocolError when the terminator does not fit in `buffer`.
[[nodiscard]] Result<std::size_t> PollReadHttpHeaders(int sock_fd,
                                                      std::span<uint8_t> buffer,
                                                      int timeout_ms) noexcept;

/// Encodes `input` as standard Base64 with padding.
[[nodiscard]] std::string EncodeBase64(std::string_view input) noexcept;

}  // namespace proxychains
