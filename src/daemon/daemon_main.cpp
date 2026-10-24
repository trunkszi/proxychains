#ifndef CXXOPTS_NO_EXCEPTIONS
#define CXXOPTS_NO_EXCEPTIONS
#endif
#include <cxxopts.hpp>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <string>
#include <string_view>

#include <fmt/format.h>

#include "core/error.hpp"
#include "core/log.hpp"
#include "daemon/udp_server.hpp"

namespace {

[[nodiscard]] int Usage(const char* argv0) {
  std::fprintf(stderr,
               "Proxychains-NG remote dns daemon\n"
               "--------------------------------\n"
               "usage: %s [-i listenip] [-p port] [-r remotesubnet]\n"
               "all arguments are optional.\n"
               "by default listenip is 127.0.0.1, port 1053 and remotesubnet 224.\n\n",
               argv0 != nullptr ? argv0 : "proxychains-daemon");
  return 1;
}

[[nodiscard]] bool ValidateDaemonArgs(int argc, char** argv) noexcept {
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg{argv[i] != nullptr ? argv[i] : ""};
    if (arg == "-h" || arg == "--help") {
      continue;
    }
    if (arg == "-i" || arg == "--ip" || arg == "-p" || arg == "--port" || arg == "-r" ||
        arg == "--remote-subnet") {
      if (i + 1 >= argc || argv[i + 1] == nullptr || argv[i + 1][0] == '\0') {
        return false;
      }
      ++i;
      continue;
    }
    return false;
  }
  return true;
}

[[nodiscard]] bool ParseBounded(const std::string& text, unsigned max_value, unsigned* out) {
  if (text.empty() || out == nullptr) {
    return false;
  }
  char* end = nullptr;
  errno = 0;
  const unsigned long value = std::strtoul(text.c_str(), &end, 10);
  if (end == text.c_str() || *end != '\0' || errno != 0 || value > max_value) {
    return false;
  }
  *out = static_cast<unsigned>(value);
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  if (!ValidateDaemonArgs(argc, argv)) {
    return Usage(argc > 0 ? argv[0] : nullptr);
  }

  cxxopts::Options options(argv != nullptr && argc > 0 && argv[0] != nullptr ? argv[0]
                                                                             : "proxychains-daemon",
                           "Proxychains-NG remote dns daemon");
  options.add_options()("i,ip", "Listen IP address",
                        cxxopts::value<std::string>()->default_value("127.0.0.1"))(
      "p,port", "Listen UDP port", cxxopts::value<std::string>()->default_value("1053"))(
      "r,remote-subnet", "Remote fake-IP subnet prefix",
      cxxopts::value<std::string>()->default_value("224"))("h,help", "Show help",
                                                           cxxopts::value<bool>());

  const auto parsed = options.parse(argc, argv);
  if (parsed.count("help") > 0) {
    return Usage(argc > 0 ? argv[0] : nullptr);
  }

  const std::string listen_ip = parsed["ip"].as<std::string>();
  unsigned port = 1053;
  unsigned subnet = 224;
  if (listen_ip.empty() || !ParseBounded(parsed["port"].as<std::string>(), 65535U, &port) ||
      !ParseBounded(parsed["remote-subnet"].as<std::string>(), 255U, &subnet)) {
    return Usage(argc > 0 ? argv[0] : nullptr);
  }

  std::signal(SIGPIPE, SIG_IGN);
  proxychains::UdpServer server{static_cast<uint8_t>(subnet)};
  const proxychains::Result<void> listened = server.Listen(listen_ip, static_cast<uint16_t>(port));
  if (!listened.has_value()) {
    proxychains::LogError(fmt::format("failed to bind {}:{}", listen_ip, port));
    return 1;
  }

  while (!server.StopRequested()) {
    const proxychains::Result<void> served = server.ServeOne();
    if (!served.has_value() &&
        served.error() != proxychains::make_error_code(proxychains::ErrorCode::kTimeout)) {
      proxychains::LogError(served.error().message());
    }
  }
  return 0;
}
