#ifndef CXXOPTS_NO_EXCEPTIONS
#define CXXOPTS_NO_EXCEPTIONS
#endif
#include <cxxopts.hpp>

#include <dlfcn.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>

#include "config/config.hpp"
#include "core/log.hpp"

#ifndef DLL_NAME
#define DLL_NAME "libproxychains.so"
#endif
#ifndef LIB_DIR
#define LIB_DIR "/usr/local/lib"
#endif
#ifndef SYSCONFDIR
#define SYSCONFDIR "/usr/local/etc"
#endif
#ifndef LD_PRELOAD_ENV
#define LD_PRELOAD_ENV "LD_PRELOAD"
#endif
#ifndef LD_PRELOAD_SEP
#define LD_PRELOAD_SEP " "
#endif

extern "C" const char* proxychains_get_version(void);

namespace proxychains {
namespace {

enum class EarlyExit : std::uint8_t { kNone, kHelp, kVersion };

struct OptionSplit {
  int option_argc{0};
  int command_index{0};
  EarlyExit early{EarlyExit::kNone};
  bool ok{false};
};

// Returns how many argv slots this proxychains option consumes, or -1 when the
// token is not a known option or is missing its value. Illegal input must be
// rejected here: cxxopts calls exit(1) for those cases when exceptions are off.
int ConsumeLauncherOption(char* const* argv, int argc, int index, EarlyExit* early) noexcept {
  const std::string_view arg{argv[index]};
  if (arg.size() < 2 || arg.front() != '-') {
    return -1;
  }
  if (arg[1] != '-') {
    for (std::size_t pos = 1; pos < arg.size(); ++pos) {
      const char flag = arg[pos];
      if (flag == 'q') {
        continue;
      }
      if (flag == 'h') {
        if (*early == EarlyExit::kNone) {
          *early = EarlyExit::kHelp;
        }
        continue;
      }
      if (flag == 'v') {
        if (*early == EarlyExit::kNone) {
          *early = EarlyExit::kVersion;
        }
        continue;
      }
      if (flag != 'f' && flag != 'p' && flag != 'u' && flag != 'g') {
        return -1;
      }
      if (pos + 1 < arg.size()) {
        return 1;
      }
      if (index + 1 >= argc) {
        return -1;
      }
      return 2;
    }
    return 1;
  }

  const auto equals = arg.find('=');
  const std::string_view name = equals == std::string_view::npos ? arg.substr(2) : arg.substr(2, equals - 2);
  const bool has_value = equals != std::string_view::npos;
  if (name == "help" || name == "version" || name == "quiet") {
    if (has_value) {
      return -1;
    }
    if (name == "help" && *early == EarlyExit::kNone) {
      *early = EarlyExit::kHelp;
    }
    if (name == "version" && *early == EarlyExit::kNone) {
      *early = EarlyExit::kVersion;
    }
    return 1;
  }
  if (name != "file" && name != "proxy" && name != "uid" && name != "gid") {
    return -1;
  }
  if (has_value) {
    return arg.substr(equals + 1).empty() ? -1 : 1;
  }
  if (index + 1 >= argc) {
    return -1;
  }
  return 2;
}

OptionSplit SplitLauncherArguments(int argc, char* const* argv) noexcept {
  OptionSplit split;
  int index = 1;
  while (index < argc) {
    const std::string_view arg{argv[index]};
    if (arg == "--") {
      split.option_argc = index;
      split.command_index = index + 1;
      split.ok = true;
      return split;
    }
    if (arg.empty() || arg == "-" || arg.front() != '-') {
      split.option_argc = index;
      split.command_index = index;
      split.ok = true;
      return split;
    }
    const int consumed = ConsumeLauncherOption(argv, argc, index, &split.early);
    if (consumed < 0) {
      return split;
    }
    index += consumed;
  }
  split.option_argc = argc;
  split.command_index = argc;
  split.ok = true;
  return split;
}

}  // namespace

enum class LaunchStatus : std::uint8_t {
  kOk = 0,
  kError = 1,
  kHelp = 2,
  kVersion = 3,
};

LaunchStatus ParseLaunchArguments(int argc, char* const* argv, bool* quiet, std::string* config_path,
                                  std::string* proxy_url, std::string* fake_uid, std::string* fake_gid,
                                  std::vector<std::string>* command) noexcept {
  if (quiet == nullptr || config_path == nullptr || proxy_url == nullptr || fake_uid == nullptr ||
      fake_gid == nullptr || command == nullptr || argv == nullptr || argc < 1) {
    return LaunchStatus::kError;
  }
  *quiet = false;
  config_path->clear();
  proxy_url->clear();
  fake_uid->clear();
  fake_gid->clear();
  command->clear();

  // Options stop at the first target command or at "--". The tail belongs to
  // the launched program, including flags such as curl's -v.
  const OptionSplit split = SplitLauncherArguments(argc, argv);
  if (!split.ok) {
    return LaunchStatus::kError;
  }

  cxxopts::Options options{argv[0] != nullptr ? argv[0] : "proxychains", "Proxy chains launcher"};
  options.add_options()("q,quiet", "Quiet mode", cxxopts::value<bool>())(
      "f,file", "Configuration file path", cxxopts::value<std::string>())(
      "p,proxy", "Direct proxy URL (socks5://, socks4://, http://, raw://)", cxxopts::value<std::string>())(
      "u,uid", "Fake UID", cxxopts::value<std::string>())("g,gid", "Fake GID", cxxopts::value<std::string>())(
      "v,version", "Show version", cxxopts::value<bool>())("h,help", "Show help", cxxopts::value<bool>());

  std::vector<const char*> option_argv;
  option_argv.reserve(static_cast<std::size_t>(split.option_argc));
  for (int index = 0; index < split.option_argc; ++index) {
    option_argv.push_back(argv[index]);
  }
  const cxxopts::ParseResult parsed = options.parse(split.option_argc, option_argv.data());

  if (parsed.count("proxy") > 0) {
    const std::string& url = parsed["proxy"].as<std::string>();
    if (!ParseProxyUrl(url)) {
      return LaunchStatus::kError;
    }
    *proxy_url = url;
  }
  if (split.early == EarlyExit::kHelp || parsed.count("help") > 0) {
    return LaunchStatus::kHelp;
  }
  if (split.early == EarlyExit::kVersion || parsed.count("version") > 0) {
    return LaunchStatus::kVersion;
  }
  if (split.command_index >= argc) {
    return LaunchStatus::kError;
  }
  *quiet = parsed.count("quiet") > 0;
  if (parsed.count("file") > 0) {
    *config_path = parsed["file"].as<std::string>();
  }
  if (parsed.count("uid") > 0) {
    *fake_uid = parsed["uid"].as<std::string>();
  }
  if (parsed.count("gid") > 0) {
    *fake_gid = parsed["gid"].as<std::string>();
  }
  for (int index = split.command_index; index < argc; ++index) {
    command->emplace_back(argv[index] != nullptr ? argv[index] : "");
  }
  return LaunchStatus::kOk;
}

std::string DirectoryOfExecutablePath(std::string_view executable_path) noexcept {
  const auto slash = executable_path.rfind('/');
  if (slash == std::string_view::npos) {
    return ".";
  }
  if (slash == 0) {
    return "/";
  }
  return std::string{executable_path.substr(0, slash)};
}

std::string DirectoryOfLoadedImage(const void* symbol_address) noexcept {
  if (symbol_address == nullptr) {
    return ".";
  }
  Dl_info info{};
  if (dladdr(symbol_address, &info) == 0 || info.dli_fname == nullptr) {
    return ".";
  }
  char resolved[4096];
  if (::realpath(info.dli_fname, resolved) != nullptr) {
    return DirectoryOfExecutablePath(resolved);
  }
  if (std::strchr(info.dli_fname, '/') == nullptr) {
    const ssize_t len = ::readlink("/proc/self/exe", resolved, sizeof(resolved) - 1);
    if (len > 0) {
      resolved[len] = '\0';
      return DirectoryOfExecutablePath(resolved);
    }
  }
  return DirectoryOfExecutablePath(info.dli_fname);
}

std::string FormatLdPreloadValue(std::string_view library_path, const char* existing_value) noexcept {
  std::string value{library_path};
  if (existing_value != nullptr && existing_value[0] != '\0') {
    value.append(LD_PRELOAD_SEP);
    value.append(existing_value);
  }
  return value;
}

namespace {

void PrintUsage(const char* argv0) noexcept {
  std::fprintf(stdout,
               "\nUsage:\t%s [-q] [-f config_file] [-p proxy_url|--proxy proxy_url] [-u uid] [-g gid] "
               "program_name [arguments]\n"
               "\t-q makes proxychains quiet - this overrides the config setting\n"
               "\t-f allows one to manually specify a configfile to use\n"
               "\t-p, --proxy proxy URL (for example socks5://127.0.0.1:40000 or --proxy=<url>).\n"
               "\t\tWith a proxy URL and no -f, a missing default config file is ignored.\n"
               "\t-u fake uid returned by getuid/geteuid/getresuid\n"
               "\t-g fake gid returned by getgid/getegid/getresgid (defaults to uid if not set)\n"
               "\t-h, --help show this help\n"
               "\t-v, --version show the version\n"
               "\tfor example : proxychains telnet somehost.com\n"
               "More help in README file\n\n",
               argv0 != nullptr ? argv0 : "proxychains");
}

void PrintPrefixed(const char* text) noexcept { LogError(text); }

std::string FindLibrary(const std::string& own_dir) noexcept {
  std::vector<std::string> directories;
#ifndef SUPER_SECURE
  directories.emplace_back(".");
#endif
  directories.push_back(own_dir);
  directories.emplace_back(LIB_DIR);
  directories.emplace_back("/lib");
  directories.emplace_back("/usr/lib");
  directories.emplace_back("/usr/local/lib");
  directories.emplace_back("/lib64");
  for (const auto& directory : directories) {
    std::string candidate = directory;
    if (candidate.empty() || candidate.back() != '/') {
      candidate.push_back('/');
    }
    candidate.append(DLL_NAME);
    if (access(candidate.c_str(), R_OK) == 0) {
      return candidate;
    }
  }
  return {};
}

}  // namespace

int RunLauncher(int argc, char** argv) noexcept {
  bool quiet = false;
  std::string config_path;
  std::string proxy_url;
  std::string fake_uid;
  std::string fake_gid;
  std::vector<std::string> command;
  const LaunchStatus status =
      ParseLaunchArguments(argc, argv, &quiet, &config_path, &proxy_url, &fake_uid, &fake_gid, &command);
  if (status == LaunchStatus::kHelp) {
    PrintUsage(argc > 0 ? argv[0] : "proxychains");
    return EXIT_FAILURE;
  }
  if (status == LaunchStatus::kVersion) {
    std::fprintf(stdout, "proxychains %s\n", proxychains_get_version());
    return EXIT_SUCCESS;
  }
  if (status != LaunchStatus::kOk) {
    PrintUsage(argc > 0 ? argv[0] : "proxychains");
    return EXIT_FAILURE;
  }

  SetQuietMode(quiet);
  if (!proxy_url.empty()) {
    if (setenv(kProxyUrlEnvVar, proxy_url.c_str(), 1) != 0) {
      PrintPrefixed("failed to publish PROXYCHAINS_PROXY_URL");
      return EXIT_FAILURE;
    }
    LogInfo(fmt::format("proxy url: {}", proxy_url));
  }
  const char* active_proxy = std::getenv(kProxyUrlEnvVar);
  const bool proxy_available = active_proxy != nullptr && active_proxy[0] != '\0';
  auto resolved = ResolveConfigPath(config_path, SYSCONFDIR);
  if (!resolved) {
    // -p/--proxy and a pre-set PROXYCHAINS_PROXY_URL can start with no config file.
    // An explicit -f still fails closed when that path cannot be resolved.
    if (!config_path.empty() || !proxy_available) {
      PrintPrefixed("configuration file not found");
      return EXIT_FAILURE;
    }
  } else {
    if (setenv(kConfFileEnvVar, resolved->c_str(), 1) != 0) {
      PrintPrefixed("failed to publish PROXYCHAINS_CONF_FILE");
      return EXIT_FAILURE;
    }
    if (!proxy_available) {
      LogInfo(fmt::format("config file found: {}", *resolved));
    }
  }
  if (quiet && setenv(kQuietModeEnvVar, "1", 1) != 0) {
    PrintPrefixed("failed to publish PROXYCHAINS_QUIET_MODE");
    return EXIT_FAILURE;
  }
  if (!fake_uid.empty() && setenv(kFakeUidEnvVar, fake_uid.c_str(), 1) != 0) {
    PrintPrefixed("failed to publish PROXYCHAINS_FAKE_UID");
    return EXIT_FAILURE;
  }
  if (!fake_gid.empty() && setenv(kFakeGidEnvVar, fake_gid.c_str(), 1) != 0) {
    PrintPrefixed("failed to publish PROXYCHAINS_FAKE_GID");
    return EXIT_FAILURE;
  }

  // dladdr needs a function in this executable. ISO C++ forbids &main, and a
  // data symbol does not identify the loaded image.
  const std::string own_dir = DirectoryOfLoadedImage(reinterpret_cast<const void*>(&RunLauncher));
  const std::string library = FindLibrary(own_dir);
  if (library.empty()) {
    LogError(fmt::format(
        "could not find {}.\nLooked in the launcher directory, {}, /lib, /usr/lib, /usr/local/lib, and /lib64.",
        DLL_NAME, LIB_DIR));
    return EXIT_FAILURE;
  }
  const char* existing = std::getenv(LD_PRELOAD_ENV);
  const std::string preload = FormatLdPreloadValue(library, existing);
  if (setenv(LD_PRELOAD_ENV, preload.c_str(), 1) != 0) {
    PrintPrefixed("failed to publish LD_PRELOAD");
    return EXIT_FAILURE;
  }

  std::vector<char*> exec_argv;
  exec_argv.reserve(command.size() + 1);
  for (auto& argument : command) {
    exec_argv.push_back(argument.data());
  }
  exec_argv.push_back(nullptr);
  execvp(exec_argv[0], exec_argv.data());
  LogErrno(fmt::format("could not start process '{}'", command[0]), errno);
  return EXIT_FAILURE;
}

}  // namespace proxychains

__attribute__((weak)) int main(int argc, char** argv) { return proxychains::RunLauncher(argc, argv); }
