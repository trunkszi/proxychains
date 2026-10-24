#include "core/log.hpp"

#include <netdb.h>
#include <pthread.h>

#include <atomic>
#include <mutex>
#include <system_error>

#ifndef FMTLOG_HEADER_ONLY
#define FMTLOG_HEADER_ONLY
#endif
#include <fmtlog/fmtlog.h>

template <>
fmtlog fmtlogWrapper<0>::impl __attribute__((init_priority(101))){};

template <>
fmtlogDetailT<0> fmtlogDetailWrapper<0>::impl __attribute__((init_priority(101))){};

namespace proxychains {
namespace {

std::atomic<bool>& QuietFlag() noexcept {
  static std::atomic<bool> quiet{false};
  return quiet;
}

struct LogState {
  std::mutex mutex;
  bool initialized{false};
};

LogState& RawState() noexcept {
  static LogState state;
  return state;
}

void ForkPrepare() noexcept { RawState().mutex.lock(); }

void ForkParent() noexcept { RawState().mutex.unlock(); }

void ForkChild() noexcept { RawState().mutex.unlock(); }

LogState& State() noexcept {
  static const int registered = ::pthread_atfork(&ForkPrepare, &ForkParent, &ForkChild);
  (void)registered;
  return RawState();
}

// The host process may fork after the preload constructor. fmtlog is used only
// synchronously here: no polling thread is started, so no thread state is
// inherited by a child process.
void InitializeLocked(LogState& state) noexcept {
  if (!state.initialized) {
    fmtlog::setLogFile(stderr, false);
    fmtlog::setHeaderPattern("[proxychains] ");
    fmtlog::setLogLevel(fmtlog::INF);
    state.initialized = true;
  }
}

void PollLocked() noexcept { fmtlog::poll(true); }

}  // namespace

void SetQuietMode(bool quiet) noexcept { QuietFlag().store(quiet); }

bool IsQuietMode() noexcept { return QuietFlag().load(); }

void LogInfo(std::string_view message) noexcept {
  if (IsQuietMode()) {
    return;
  }
  LogState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  InitializeLocked(state);
  logi("{}", message);
  PollLocked();
}

void LogChainProgress(std::string_view text) noexcept { LogInfo(text); }

void LogError(std::string_view message) noexcept {
  LogState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  InitializeLocked(state);
  loge("{}", message);
  PollLocked();
}

void LogErrno(std::string_view context, int errnum) noexcept {
  LogState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  InitializeLocked(state);
  loge("{}: {}", context, std::error_code(errnum, std::generic_category()).message());
  PollLocked();
}

void LogGaiError(std::string_view context, int gai_err) noexcept {
  const char* description = ::gai_strerror(gai_err);
  LogState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  InitializeLocked(state);
  loge("{}: {}", context,
       description != nullptr ? description : "unknown getaddrinfo error");
  PollLocked();
}

void LogDebug(std::string_view message) noexcept {
  LogState& state = State();
  const std::lock_guard<std::mutex> lock(state.mutex);
  InitializeLocked(state);
  logd("{}", message);
  PollLocked();
}

}  // namespace proxychains
