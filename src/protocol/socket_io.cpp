#include "protocol/socket_io.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>

#include <cerrno>
#include <cstring>
#include <string>


namespace proxychains {
namespace {

constexpr int64_t kNanosPerMilli = 1'000'000;
constexpr int64_t kNanosPerSecond = 1'000'000'000;
constexpr int kMaxPollBudgetMs = 60'000;

int64_t NowMonotonicNanos() noexcept {
  timespec now{};
  if (::clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    return 0;
  }
  return static_cast<int64_t>(now.tv_sec) * kNanosPerSecond + static_cast<int64_t>(now.tv_nsec);
}

int RemainingMillis(int64_t deadline_ns) noexcept {
  const int64_t remaining = deadline_ns - NowMonotonicNanos();
  if (remaining <= 0) {
    return 0;
  }
  const int64_t millis = (remaining + kNanosPerMilli - 1) / kNanosPerMilli;
  return static_cast<int>(millis > kMaxPollBudgetMs ? kMaxPollBudgetMs : millis);
}

// Returns 1 when ready, 0 on deadline expiry, -1 on poll failure.
int WaitForReady(int sock_fd, short events, int64_t deadline_ns) noexcept {
  for (;;) {
    const int remaining = RemainingMillis(deadline_ns);
    if (remaining == 0) {
      return 0;
    }
    pollfd entry{sock_fd, events, 0};
    const int ready = ::poll(&entry, 1, remaining);
    if (ready > 0) {
      if ((entry.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        return 1;
      }
      if ((entry.revents & events) != 0) {
        return 1;
      }
      continue;
    }
    if (ready == 0) {
      // A poll slice may be shorter than the remaining budget; re-check the
      // absolute deadline instead of treating the slice as expiry.
      continue;
    }
    if (errno != EINTR) {
      return -1;
    }
  }
}

std::size_t FindHeaderEnd(std::span<const uint8_t> bytes) noexcept {
  if (bytes.size() < 4) {
    return std::string::npos;
  }
  for (std::size_t i = 0; i + 3 < bytes.size(); ++i) {
    if (bytes[i] == '\r' && bytes[i + 1] == '\n' && bytes[i + 2] == '\r' && bytes[i + 3] == '\n') {
      return i + 4;
    }
  }
  return std::string::npos;
}

}  // namespace

Result<void> TimedConnect(int sock_fd,
                          const IpAddress& ip,
                          uint16_t port_host,
                          int timeout_ms,
                          ConnectSyscallFn connect_fn) noexcept {
  if (sock_fd < 0 || connect_fn == nullptr || timeout_ms <= 0) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }
  const int64_t deadline_ns = NowMonotonicNanos() + static_cast<int64_t>(timeout_ms) * kNanosPerMilli;

  // Save the exact original status flags and restore them on every return
  // path; the legacy code cleared every flag with `!O_NONBLOCK`.
  const int orig_flags = ::fcntl(sock_fd, F_GETFL, 0);
  if (orig_flags < 0) {
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  struct FlagRestorer {
    int fd;
    int flags;
    bool active;
    ~FlagRestorer() noexcept {
      if (active && fd >= 0 && flags >= 0) {
        (void)::fcntl(fd, F_SETFL, flags);
      }
    }
  } restorer{sock_fd, orig_flags, false};
  if ((orig_flags & O_NONBLOCK) == 0) {
    if (::fcntl(sock_fd, F_SETFL, orig_flags | O_NONBLOCK) != 0) {
      return std::unexpected(make_error_code(ErrorCode::kSocketError));
    }
    restorer.active = true;
  }

  const IpAddress target = ip.NormalizeV4Mapped();
  sockaddr_storage storage{};
  socklen_t storage_len = 0;
  if (target.IsV6()) {
    auto* address = reinterpret_cast<sockaddr_in6*>(&storage);
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(port_host);
    std::memcpy(address->sin6_addr.s6_addr, target.V6Bytes().data(), target.V6Bytes().size());
    storage_len = sizeof(sockaddr_in6);
  } else {
    auto* address = reinterpret_cast<sockaddr_in*>(&storage);
    address->sin_family = AF_INET;
    address->sin_port = htons(port_host);
    std::memcpy(&address->sin_addr, target.V4Bytes().data(), target.V4Bytes().size());
    storage_len = sizeof(sockaddr_in);
  }

  const int rc = connect_fn(sock_fd, reinterpret_cast<const sockaddr*>(&storage), storage_len);
  if (rc == 0) {
    return {};
  }
  if (errno != EINPROGRESS && errno != EALREADY) {
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  const int ready = WaitForReady(sock_fd, POLLOUT, deadline_ns);
  if (ready == 0) {
    return std::unexpected(make_error_code(ErrorCode::kTimeout));
  }
  if (ready < 0) {
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  int socket_error = 0;
  socklen_t error_len = sizeof(socket_error);
  if (::getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) != 0) {
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  if (socket_error != 0) {
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  return {};
}

Result<void> PollWriteAll(int sock_fd,
                          std::span<const uint8_t> data,
                          int timeout_ms) noexcept {
  if (sock_fd < 0 || timeout_ms <= 0) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }
  const int64_t deadline_ns = NowMonotonicNanos() + static_cast<int64_t>(timeout_ms) * kNanosPerMilli;
  std::size_t offset = 0;
  while (offset < data.size()) {
    const ssize_t written = ::send(sock_fd, data.data() + offset, data.size() - offset,
                        MSG_NOSIGNAL | MSG_DONTWAIT);
    if (written > 0) {
      offset += static_cast<std::size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      const int ready = WaitForReady(sock_fd, POLLOUT, deadline_ns);
      if (ready == 0) {
        return std::unexpected(make_error_code(ErrorCode::kTimeout));
      }
      if (ready < 0) {
        return std::unexpected(make_error_code(ErrorCode::kSocketError));
      }
      continue;
    }
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  return {};
}

namespace {

Result<void> ReadExactBefore(int sock_fd, std::span<uint8_t> buffer,
                             int64_t deadline_ns) noexcept {
  std::size_t offset = 0;
  while (offset < buffer.size()) {
    const ssize_t received = ::recv(sock_fd, buffer.data() + offset, buffer.size() - offset, MSG_DONTWAIT);
    if (received > 0) {
      offset += static_cast<std::size_t>(received);
      continue;
    }
    if (received == 0) {
      return std::unexpected(make_error_code(ErrorCode::kSocketError));
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      const int ready = WaitForReady(sock_fd, POLLIN, deadline_ns);
      if (ready == 0) {
        return std::unexpected(make_error_code(ErrorCode::kTimeout));
      }
      if (ready < 0) {
        return std::unexpected(make_error_code(ErrorCode::kSocketError));
      }
      continue;
    }
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  return {};
}

}  // namespace

Result<void> PollReadExact(int sock_fd, std::span<uint8_t> buffer, int timeout_ms) noexcept {
  if (sock_fd < 0 || timeout_ms <= 0) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }
  const int64_t deadline_ns = NowMonotonicNanos() + static_cast<int64_t>(timeout_ms) * kNanosPerMilli;
  return ReadExactBefore(sock_fd, buffer, deadline_ns);
}

Result<std::size_t> PollReadHttpHeaders(int sock_fd, std::span<uint8_t> buffer,
                                        int timeout_ms) noexcept {
  if (sock_fd < 0 || timeout_ms <= 0 || buffer.empty()) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }
  const int64_t deadline_ns = NowMonotonicNanos() + static_cast<int64_t>(timeout_ms) * kNanosPerMilli;
  std::size_t consumed = 0;
  for (;;) {
    const std::span<uint8_t> remaining = buffer.subspan(consumed);
    const ssize_t peeked = ::recv(sock_fd, remaining.data(), remaining.size(), MSG_PEEK | MSG_DONTWAIT);
    if (peeked > 0) {
      const std::size_t chunk_len = static_cast<std::size_t>(peeked);
      const std::size_t total = consumed + chunk_len;
      const std::size_t head_end = FindHeaderEnd(buffer.first(total));
      if (head_end != std::string::npos) {
        // Consume only up to the end of the header; any post-header payload
        // stays queued in the kernel for the protocol that takes over.
        const std::size_t to_read = head_end - consumed;
        const auto ok = ReadExactBefore(sock_fd, remaining.first(to_read), deadline_ns);
        if (!ok.has_value()) {
          return std::unexpected(ok.error());
        }
        return head_end;
      }
      if (total == buffer.size()) {
        return std::unexpected(make_error_code(ErrorCode::kProtocolError));
      }
      const auto drained = ReadExactBefore(sock_fd, remaining.first(chunk_len), deadline_ns);
      if (!drained.has_value()) {
        return std::unexpected(drained.error());
      }
      consumed = total;
      continue;
    } else if (peeked == 0) {
      return std::unexpected(make_error_code(ErrorCode::kSocketError));
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      return std::unexpected(make_error_code(ErrorCode::kSocketError));
    }
    const int ready = WaitForReady(sock_fd, POLLIN, deadline_ns);
    if (ready == 0) {
      return std::unexpected(make_error_code(ErrorCode::kTimeout));
    }
    if (ready < 0) {
      return std::unexpected(make_error_code(ErrorCode::kSocketError));
    }
  }
}

std::string EncodeBase64(std::string_view input) noexcept {
  constexpr std::string_view kAlphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string encoded;
  encoded.reserve(((input.size() + 2) / 3) * 4);
  std::size_t offset = 0;
  while (offset + 3 <= input.size()) {
    const uint32_t chunk = (static_cast<uint32_t>(static_cast<uint8_t>(input[offset])) << 16) |
                           (static_cast<uint32_t>(static_cast<uint8_t>(input[offset + 1])) << 8) |
                           static_cast<uint32_t>(static_cast<uint8_t>(input[offset + 2]));
    encoded.push_back(kAlphabet[(chunk >> 18) & 0x3f]);
    encoded.push_back(kAlphabet[(chunk >> 12) & 0x3f]);
    encoded.push_back(kAlphabet[(chunk >> 6) & 0x3f]);
    encoded.push_back(kAlphabet[chunk & 0x3f]);
    offset += 3;
  }
  const std::size_t remaining = input.size() - offset;
  if (remaining == 1) {
    const uint32_t chunk = static_cast<uint32_t>(static_cast<uint8_t>(input[offset])) << 16;
    encoded.push_back(kAlphabet[(chunk >> 18) & 0x3f]);
    encoded.push_back(kAlphabet[(chunk >> 12) & 0x3f]);
    encoded.push_back('=');
    encoded.push_back('=');
  } else if (remaining == 2) {
    const uint32_t chunk = (static_cast<uint32_t>(static_cast<uint8_t>(input[offset])) << 16) |
                           (static_cast<uint32_t>(static_cast<uint8_t>(input[offset + 1])) << 8);
    encoded.push_back(kAlphabet[(chunk >> 18) & 0x3f]);
    encoded.push_back(kAlphabet[(chunk >> 12) & 0x3f]);
    encoded.push_back(kAlphabet[(chunk >> 6) & 0x3f]);
    encoded.push_back('=');
  }
  return encoded;
}

}  // namespace proxychains
