#pragma once

#include <fcntl.h>
#include <unistd.h>
#include <utility>

namespace proxychains {

/** @file
 *  @brief File descriptor and socket flag RAII helpers.
 */

/** @brief Owns a file descriptor and closes it with a caller-selected closer. */
class ScopedFd {
 public:
  using CloseFn = int (*)(int);
  constexpr ScopedFd() noexcept = default;
  explicit ScopedFd(int fd, CloseFn close_fn = ::close) noexcept
      : fd_(fd), close_fn_(close_fn) {}
  ~ScopedFd() noexcept { Reset(); }

  ScopedFd(const ScopedFd&) = delete;
  ScopedFd& operator=(const ScopedFd&) = delete;

  ScopedFd(ScopedFd&& other) noexcept
      : fd_(std::exchange(other.fd_, -1)), close_fn_(other.close_fn_) {}
  ScopedFd& operator=(ScopedFd&& other) noexcept {
    if (this != &other) {
      Reset();
      fd_ = std::exchange(other.fd_, -1);
      close_fn_ = other.close_fn_;
    }
    return *this;
  }

  [[nodiscard]] int Get() const noexcept { return fd_; }
  [[nodiscard]] bool Valid() const noexcept { return fd_ >= 0; }
  int Release() noexcept { return std::exchange(fd_, -1); }
  void Reset(int new_fd = -1) noexcept {
    if (fd_ >= 0 && close_fn_ != nullptr) {
      close_fn_(fd_);
    }
    fd_ = new_fd;
  }

 private:
  int fd_{-1};
  CloseFn close_fn_{::close};
};

/**
 * @brief Clears O_NONBLOCK for a scope and restores the original flags.
 *
 * Only O_NONBLOCK is cleared on construction. Destruction restores the whole
 * original flag word even when the caller changed the descriptor meanwhile.
 */
class BlockingSocketGuard {
 public:
  explicit BlockingSocketGuard(int fd) noexcept : fd_(fd) {
    if (fd_ >= 0) {
      orig_flags_ = ::fcntl(fd_, F_GETFL, 0);
      if (orig_flags_ >= 0 && (orig_flags_ & O_NONBLOCK) != 0) {
        (void)::fcntl(fd_, F_SETFL, orig_flags_ & ~O_NONBLOCK);
      }
    }
  }
  ~BlockingSocketGuard() noexcept {
    if (fd_ >= 0 && orig_flags_ >= 0) {
      (void)::fcntl(fd_, F_SETFL, orig_flags_);
    }
  }
  BlockingSocketGuard(const BlockingSocketGuard&) = delete;
  BlockingSocketGuard& operator=(const BlockingSocketGuard&) = delete;

 private:
  int fd_{-1};
  int orig_flags_{-1};
};

}  // namespace proxychains
