#include "dns/hosts_cache.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include <optional>
#include <string>

#include "core/fd.hpp"

namespace proxychains {
namespace {

constexpr std::size_t kMaxHostsFileBytes = 4U * 1024U * 1024U;

[[nodiscard]] bool IsSpace(char ch) noexcept {
  return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\f' || ch == '\v';
}

[[nodiscard]] std::string_view TrimLeft(std::string_view text) noexcept {
  while (!text.empty() && IsSpace(text.front())) {
    text.remove_prefix(1);
  }
  return text;
}

[[nodiscard]] std::optional<std::string_view> NextToken(std::string_view* line) noexcept {
  *line = TrimLeft(*line);
  if (line->empty()) {
    return std::nullopt;
  }
  std::size_t length = 0;
  while (length < line->size() && !IsSpace((*line)[length])) {
    ++length;
  }
  const std::string_view token = line->substr(0, length);
  line->remove_prefix(length);
  return token;
}

[[nodiscard]] std::optional<std::string> ReadFile(std::string_view path) noexcept {
  if (path.empty() || path.find('\0') != std::string_view::npos) {
    return std::nullopt;
  }
  const std::string owned{path};
  ScopedFd fd{::open(owned.c_str(), O_RDONLY | O_CLOEXEC)};
  if (!fd.Valid()) {
    return std::nullopt;
  }

  std::string data;
  char buf[4096];
  while (data.size() < kMaxHostsFileBytes) {
    const ssize_t n = ::read(fd.Get(), buf, sizeof(buf));
    if (n == 0) {
      return data;
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return std::nullopt;
    }
    const auto take = static_cast<std::size_t>(n);
    if (take > kMaxHostsFileBytes - data.size()) {
      return std::nullopt;
    }
    data.append(buf, take);
  }
  return std::nullopt;
}

}  // namespace

std::optional<IpAddress> LookupEtcHosts(std::string_view hostname,
                                        std::string_view hosts_path) noexcept {
  if (hostname.empty() || hostname.find('\0') != std::string_view::npos) {
    return std::nullopt;
  }
  const std::optional<std::string> file = ReadFile(hosts_path);
  if (!file.has_value()) {
    return std::nullopt;
  }

  std::string_view rest{*file};
  while (!rest.empty()) {
    const auto newline = rest.find('\n');
    std::string_view line = rest.substr(0, newline == std::string_view::npos ? rest.size() : newline);
    if (newline == std::string_view::npos) {
      rest = {};
    } else {
      rest.remove_prefix(newline + 1);
    }
    const auto comment = line.find('#');
    if (comment != std::string_view::npos) {
      line = line.substr(0, comment);
    }

    const std::optional<std::string_view> address_text = NextToken(&line);
    if (!address_text.has_value()) {
      continue;
    }
    const Result<IpAddress> address = IpAddress::Parse(*address_text);
    if (!address.has_value()) {
      continue;
    }
    while (const std::optional<std::string_view> name = NextToken(&line)) {
      if (*name == hostname) {
        return *address;
      }
    }
  }
  return std::nullopt;
}

}  // namespace proxychains
