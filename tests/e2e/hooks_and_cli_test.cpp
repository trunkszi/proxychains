#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace proxychains {

enum class LaunchStatus : std::uint8_t {
  kOk = 0,
  kError = 1,
  kHelp = 2,
  kVersion = 3,
};

LaunchStatus ParseLaunchArguments(int argc, char* const* argv, bool* quiet, std::string* config_path,
                                  std::string* proxy_url, std::string* fake_uid, std::string* fake_gid,
                                  std::vector<std::string>* command) noexcept;

std::string DirectoryOfExecutablePath(std::string_view executable_path) noexcept;
std::string DirectoryOfLoadedImage(const void* symbol_address) noexcept;
std::string FormatLdPreloadValue(std::string_view library_path, const char* existing_value) noexcept;
int RunLauncher(int argc, char** argv) noexcept;

}  // namespace proxychains

namespace {

int g_failures = 0;

void Check(bool condition, const char* expression, const char* file, int line) {
  if (!condition) {
    std::fprintf(stderr, "FAIL %s:%d %s\n", file, line, expression);
    ++g_failures;
  }
}

#define CHECK(condition) Check(static_cast<bool>(condition), #condition, __FILE__, __LINE__)

std::string SelfExecutablePath() {
  char buffer[4096];
  const ssize_t length = ::readlink("/proc/self/exe", buffer, sizeof buffer - 1);
  if (length <= 0) {
    return {};
  }
  buffer[length] = '\0';
  return buffer;
}

void TestDirectoryExtraction() {
  CHECK(proxychains::DirectoryOfExecutablePath("/usr/local/bin/proxychains") == "/usr/local/bin");
  CHECK(proxychains::DirectoryOfExecutablePath("ab/c") == "ab");
  CHECK(proxychains::DirectoryOfExecutablePath("/ab/c") == "/ab");
  CHECK(proxychains::DirectoryOfExecutablePath("a/bc") == "a");
  CHECK(proxychains::DirectoryOfExecutablePath("proxychains") == ".");
  CHECK(proxychains::DirectoryOfExecutablePath("/proxychains") == "/");

  const std::string long_dir(300, 'd');
  CHECK(proxychains::DirectoryOfExecutablePath(long_dir + "/proxychains") == long_dir);

  const std::string self = SelfExecutablePath();
  const auto slash = self.rfind('/');
  CHECK(slash != std::string::npos);
  const std::string expected = self.substr(0, slash);
  const std::string loaded =
      proxychains::DirectoryOfLoadedImage(reinterpret_cast<const void*>(&proxychains::DirectoryOfLoadedImage));
  CHECK(loaded == expected);
}

void TestPreloadValueKeepsLongPath() {
  const std::string library(400, 'x');
  const std::string full = library + "/libproxychains.so";
  const std::string value = proxychains::FormatLdPreloadValue(full, "/lib/libother.so");
  CHECK(value == full + " /lib/libother.so");
  CHECK(value.size() > 256);
  CHECK(proxychains::FormatLdPreloadValue("/lib/libproxychains.so", nullptr) == "/lib/libproxychains.so");
  CHECK(proxychains::FormatLdPreloadValue("/lib/libproxychains.so", "") == "/lib/libproxychains.so");
}

struct ParsedLaunch {
  proxychains::LaunchStatus status{proxychains::LaunchStatus::kError};
  bool quiet{false};
  std::string config_path;
  std::string proxy_url;
  std::string fake_uid;
  std::string fake_gid;
  std::vector<std::string> command;
};

ParsedLaunch Parse(const std::vector<std::string>& args) {
  std::vector<std::string> storage = args;
  std::vector<char*> argv;
  argv.reserve(storage.size() + 1);
  for (auto& arg : storage) {
    argv.push_back(arg.data());
  }
  argv.push_back(nullptr);
  ParsedLaunch parsed;
  parsed.status = proxychains::ParseLaunchArguments(static_cast<int>(storage.size()), argv.data(), &parsed.quiet,
                                                    &parsed.config_path, &parsed.proxy_url, &parsed.fake_uid,
                                                    &parsed.fake_gid, &parsed.command);
  return parsed;
}

void TestLaunchArguments() {
  const auto proxied = Parse({"proxychains", "-q", "-p", "socks5://127.0.0.1:40000", "-u", "0", "-g", "1", "curl",
                              "https://example.com"});
  CHECK(proxied.status == proxychains::LaunchStatus::kOk);
  CHECK(proxied.quiet);
  CHECK(proxied.proxy_url == "socks5://127.0.0.1:40000");
  CHECK(proxied.fake_uid == "0");
  CHECK(proxied.fake_gid == "1");
  CHECK(proxied.command.size() == 2);
  CHECK(proxied.command[0] == "curl");
  CHECK(proxied.command[1] == "https://example.com");

  const auto config = Parse({"proxychains", "-f", "/tmp/pc.yaml", "curl"});
  CHECK(config.status == proxychains::LaunchStatus::kOk);
  CHECK(!config.quiet);
  CHECK(config.config_path == "/tmp/pc.yaml");
  CHECK(config.proxy_url.empty());
  CHECK(config.command.size() == 1);
  CHECK(config.command[0] == "curl");

  CHECK(Parse({"proxychains", "-p", "not-a-proxy", "curl"}).status == proxychains::LaunchStatus::kError);
  CHECK(Parse({"proxychains", "-p", "socks5://127.0.0.1:0", "curl"}).status == proxychains::LaunchStatus::kError);
  CHECK(Parse({"proxychains", "-q"}).status == proxychains::LaunchStatus::kError);
  CHECK(Parse({"proxychains", "-f"}).status == proxychains::LaunchStatus::kError);
  CHECK(Parse({"proxychains", "--help"}).status == proxychains::LaunchStatus::kHelp);
  CHECK(Parse({"proxychains", "-h"}).status == proxychains::LaunchStatus::kHelp);
  CHECK(Parse({"proxychains", "-v"}).status == proxychains::LaunchStatus::kVersion);
  CHECK(Parse({"proxychains", "--version"}).status == proxychains::LaunchStatus::kVersion);

  const auto long_proxy = Parse({"proxychains", "--proxy", "socks5://127.0.0.1:40000", "curl"});
  CHECK(long_proxy.status == proxychains::LaunchStatus::kOk);
  CHECK(long_proxy.proxy_url == "socks5://127.0.0.1:40000");
  CHECK(long_proxy.config_path.empty());
  CHECK(long_proxy.command.size() == 1);
  CHECK(long_proxy.command[0] == "curl");

  const auto assigned = Parse({"proxychains", "--proxy=socks5://127.0.0.1:40000", "curl", "https://example.com"});
  CHECK(assigned.status == proxychains::LaunchStatus::kOk);
  CHECK(assigned.proxy_url == "socks5://127.0.0.1:40000");
  CHECK(assigned.command.size() == 2);
  CHECK(assigned.command[0] == "curl");
  CHECK(assigned.command[1] == "https://example.com");

  CHECK(Parse({"proxychains", "--proxy"}).status == proxychains::LaunchStatus::kError);
  CHECK(Parse({"proxychains", "--proxy="}).status == proxychains::LaunchStatus::kError);
  CHECK(Parse({"proxychains", "--proxy=not-a-proxy", "curl"}).status == proxychains::LaunchStatus::kError);
  CHECK(Parse({"proxychains", "--proxy", "socks5://127.0.0.1:0", "curl"}).status == proxychains::LaunchStatus::kError);

  const auto target_flags = Parse({"proxychains", "curl", "-v", "https://example.com"});
  CHECK(target_flags.status == proxychains::LaunchStatus::kOk);
  CHECK(target_flags.command.size() == 3);
  CHECK(target_flags.command[0] == "curl");
  CHECK(target_flags.command[1] == "-v");
  CHECK(target_flags.command[2] == "https://example.com");

  const auto clustered = Parse({"proxychains", "-qf", "/tmp/pc.yaml", "curl", "-v"});
  CHECK(clustered.status == proxychains::LaunchStatus::kOk);
  CHECK(clustered.quiet);
  CHECK(clustered.config_path == "/tmp/pc.yaml");
  CHECK(clustered.command.size() == 2);
  CHECK(clustered.command[0] == "curl");
  CHECK(clustered.command[1] == "-v");

  const auto longs = Parse({"proxychains", "--quiet", "--file", "/tmp/pc.yaml", "--uid", "4", "--gid", "5", "curl"});
  CHECK(longs.status == proxychains::LaunchStatus::kOk);
  CHECK(longs.quiet);
  CHECK(longs.config_path == "/tmp/pc.yaml");
  CHECK(longs.fake_uid == "4");
  CHECK(longs.fake_gid == "5");
  CHECK(longs.command.size() == 1);
  CHECK(longs.command[0] == "curl");

  const auto assigned_ids = Parse({"proxychains", "--file=/etc/proxychains.conf", "--uid=8", "--gid=9", "curl"});
  CHECK(assigned_ids.status == proxychains::LaunchStatus::kOk);
  CHECK(assigned_ids.config_path == "/etc/proxychains.conf");
  CHECK(assigned_ids.fake_uid == "8");
  CHECK(assigned_ids.fake_gid == "9");

  const auto separated = Parse({"proxychains", "-q", "--", "curl", "-v", "https://example.com"});
  CHECK(separated.status == proxychains::LaunchStatus::kOk);
  CHECK(separated.quiet);
  CHECK(separated.command.size() == 3);
  CHECK(separated.command[0] == "curl");
  CHECK(separated.command[1] == "-v");
  CHECK(separated.command[2] == "https://example.com");

  CHECK(Parse({"proxychains", "--not-an-option", "curl"}).status == proxychains::LaunchStatus::kError);
  CHECK(Parse({"proxychains", "-x", "curl"}).status == proxychains::LaunchStatus::kError);
  CHECK(Parse({"proxychains", "--uid"}).status == proxychains::LaunchStatus::kError);
  CHECK(Parse({"proxychains", "--file="}).status == proxychains::LaunchStatus::kError);
}

int CaptureLauncher(const char* home, bool publish_proxy, std::string* error) {
  int pipes[2] = {-1, -1};
  if (pipe(pipes) != 0) {
    return -1;
  }
  const pid_t pid = fork();
  if (pid < 0) {
    close(pipes[0]);
    close(pipes[1]);
    return -1;
  }
  if (pid == 0) {
    close(pipes[0]);
    if (dup2(pipes[1], STDERR_FILENO) < 0) {
      _exit(96);
    }
    close(pipes[1]);
    if (chdir(home) != 0 || setenv("HOME", home, 1) != 0) {
      _exit(98);
    }
    unsetenv("PROXYCHAINS_CONF_FILE");
    if (publish_proxy) {
      if (setenv("PROXYCHAINS_PROXY_URL", "socks5://127.0.0.1:40000", 1) != 0) {
        _exit(99);
      }
    } else if (unsetenv("PROXYCHAINS_PROXY_URL") != 0) {
      _exit(99);
    }
    char arg0[] = "proxychains";
    char arg1[] = "/bin/true";
    char* argv[] = {arg0, arg1, nullptr};
    _exit(proxychains::RunLauncher(2, argv));
  }
  close(pipes[1]);
  error->clear();
  char buffer[512];
  while (true) {
    const ssize_t count = read(pipes[0], buffer, sizeof buffer);
    if (count < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (count == 0) {
      break;
    }
    error->append(buffer, static_cast<std::size_t>(count));
  }
  close(pipes[0]);
  int status = 0;
  if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
    return -1;
  }
  return WEXITSTATUS(status);
}

void TestLaunchWithProxyUrlAndNoConfigFile() {
  char name[] = "/tmp/pc-launch-XXXXXX";
  char* const home = mkdtemp(name);
  CHECK(home != nullptr);
  if (home == nullptr) {
    return;
  }

  std::string error;
  const int missing = CaptureLauncher(home, false, &error);
  CHECK(missing == EXIT_FAILURE);
  CHECK(error.find("configuration file not found") != std::string::npos);

  const int launched = CaptureLauncher(home, true, &error);
  CHECK(error.find("configuration file not found") == std::string::npos);
  CHECK(launched == EXIT_SUCCESS || error.find("could not find") != std::string::npos ||
        error.find("could not start") != std::string::npos);
  rmdir(home);
}

void TestIdentityHooks() {
  CHECK(unsetenv("PROXYCHAINS_FAKE_UID") == 0);
  CHECK(unsetenv("PROXYCHAINS_FAKE_GID") == 0);
  CHECK(getuid() == static_cast<uid_t>(syscall(SYS_getuid)));
  CHECK(geteuid() == static_cast<uid_t>(syscall(SYS_geteuid)));
  CHECK(getgid() == static_cast<gid_t>(syscall(SYS_getgid)));
  CHECK(getegid() == static_cast<gid_t>(syscall(SYS_getegid)));

  uid_t real_ruid = 1;
  uid_t real_euid = 1;
  uid_t real_suid = 1;
  CHECK(getresuid(&real_ruid, &real_euid, &real_suid) == 0);
  uid_t sys_ruid = 0;
  uid_t sys_euid = 0;
  uid_t sys_suid = 0;
  CHECK(syscall(SYS_getresuid, &sys_ruid, &sys_euid, &sys_suid) == 0);
  CHECK(real_ruid == sys_ruid);
  CHECK(real_euid == sys_euid);
  CHECK(real_suid == sys_suid);

  CHECK(setenv("PROXYCHAINS_FAKE_UID", "42", 1) == 0);
  CHECK(unsetenv("PROXYCHAINS_FAKE_GID") == 0);
  CHECK(getuid() == 42);
  CHECK(geteuid() == 42);
  CHECK(getgid() == 42);
  CHECK(getegid() == 42);
  uid_t ruid = 0;
  uid_t euid = 0;
  uid_t suid = 0;
  CHECK(getresuid(&ruid, &euid, &suid) == 0);
  CHECK(ruid == 42 && euid == 42 && suid == 42);
  gid_t rgid = 0;
  gid_t egid = 0;
  gid_t sgid = 0;
  CHECK(getresgid(&rgid, &egid, &sgid) == 0);
  CHECK(rgid == 42 && egid == 42 && sgid == 42);

  CHECK(setenv("PROXYCHAINS_FAKE_GID", "99", 1) == 0);
  CHECK(getuid() == 42);
  CHECK(getgid() == 99);
  CHECK(getegid() == 99);
  CHECK(getresgid(&rgid, &egid, &sgid) == 0);
  CHECK(rgid == 99 && egid == 99 && sgid == 99);
  CHECK(getresuid(&ruid, &euid, &suid) == 0);
  CHECK(ruid == 42 && euid == 42 && suid == 42);

  CHECK(unsetenv("PROXYCHAINS_FAKE_UID") == 0);
  CHECK(unsetenv("PROXYCHAINS_FAKE_GID") == 0);
}

void TestConcurrentNameLookup() {
  std::string seen[2];
  std::atomic<int> finished{0};
  std::thread workers[2];
  const char* names[2] = {"alpha.example", "bravo.example"};
  for (int index = 0; index < 2; ++index) {
    workers[index] = std::thread([&, index] {
      hostent* ent = gethostbyname(names[index]);
      finished.fetch_add(1, std::memory_order_acq_rel);
      while (finished.load(std::memory_order_acquire) < 2) {
        std::this_thread::yield();
      }
      if (ent != nullptr && ent->h_name != nullptr && ent->h_addr_list != nullptr && ent->h_addr_list[0] != nullptr) {
        seen[index] = ent->h_name;
        CHECK(ent->h_addrtype == AF_INET);
        CHECK(ent->h_length == 4);
      }
    });
  }
  for (auto& worker : workers) {
    worker.join();
  }
  CHECK(seen[0] == "alpha.example");
  CHECK(seen[1] == "bravo.example");
}

void TestConcurrentReentrantNameLookup() {
  std::string seen[2];
  std::atomic<int> finished{0};
  std::thread workers[2];
  const char* names[2] = {"gamma.example", "delta.example"};
  for (int index = 0; index < 2; ++index) {
    workers[index] = std::thread([&, index] {
      alignas(64) char buffer[1024];
      hostent ret{};
      hostent* result = nullptr;
      int error = 0;
      const int rc = gethostbyname_r(names[index], &ret, buffer, sizeof buffer, &result, &error);
      finished.fetch_add(1, std::memory_order_acq_rel);
      while (finished.load(std::memory_order_acquire) < 2) {
        std::this_thread::yield();
      }
      if (rc == 0 && result != nullptr && result->h_name != nullptr) {
        seen[index] = result->h_name;
      }
    });
  }
  for (auto& worker : workers) {
    worker.join();
  }
  CHECK(seen[0] == "gamma.example");
  CHECK(seen[1] == "delta.example");
}

void TestAddressReverseFormatting() {
  in_addr v4{};
  CHECK(inet_pton(AF_INET, "9.9.9.9", &v4) == 1);
  hostent* ent = gethostbyaddr(&v4, sizeof v4, AF_INET);
  v4.s_addr = 0;
  CHECK(ent != nullptr);
  CHECK(ent->h_name != nullptr);
  CHECK(std::strcmp(ent->h_name, "9.9.9.9") == 0);
  CHECK(ent->h_addrtype == AF_INET);
  CHECK(ent->h_length == 4);
  CHECK(ent->h_addr_list != nullptr && ent->h_addr_list[0] != nullptr);
  CHECK(std::memcmp(ent->h_addr_list[0], "\x09\x09\x09\x09", 4) == 0);

  in6_addr v6{};
  CHECK(inet_pton(AF_INET6, "2001:db8::1", &v6) == 1);
  ent = gethostbyaddr(&v6, sizeof v6, AF_INET6);
  CHECK(ent != nullptr);
  CHECK(std::strcmp(ent->h_name, "2001:db8::1") == 0);
  CHECK(ent->h_addrtype == AF_INET6);
  CHECK(ent->h_length == 16);

  std::string seen[2];
  std::atomic<int> finished{0};
  const char* ips[2] = {"1.2.3.4", "8.8.4.4"};
  std::thread workers[2];
  for (int index = 0; index < 2; ++index) {
    workers[index] = std::thread([&, index] {
      in_addr addr{};
      inet_pton(AF_INET, ips[index], &addr);
      hostent* local = gethostbyaddr(&addr, sizeof addr, AF_INET);
      finished.fetch_add(1, std::memory_order_acq_rel);
      while (finished.load(std::memory_order_acquire) < 2) {
        std::this_thread::yield();
      }
      if (local != nullptr && local->h_name != nullptr) {
        seen[index] = local->h_name;
      }
    });
  }
  for (auto& worker : workers) {
    worker.join();
  }
  CHECK(seen[0] == "1.2.3.4");
  CHECK(seen[1] == "8.8.4.4");

  alignas(64) char buffer[256];
  hostent ret{};
  hostent* result = nullptr;
  int error = 0;
  in_addr again{};
  CHECK(inet_pton(AF_INET, "1.1.1.1", &again) == 1);
  CHECK(gethostbyaddr_r(&again, sizeof again, AF_INET, &ret, buffer, sizeof buffer, &result, &error) == 0);
  CHECK(result == &ret);
  CHECK(std::strcmp(ret.h_name, "1.1.1.1") == 0);
}

int TcpSocket() { return socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0); }

void TestUnspecifiedAddressRefused() {
  const int fd = TcpSocket();
  CHECK(fd >= 0);
  sockaddr_in zero{};
  zero.sin_family = AF_INET;
  zero.sin_port = htons(1);
  zero.sin_addr.s_addr = htonl(0);
  CHECK(connect(fd, reinterpret_cast<sockaddr*>(&zero), sizeof zero) == -1);
  CHECK(errno == ECONNREFUSED);
  close(fd);

  const int v6fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
  CHECK(v6fd >= 0);
  sockaddr_in6 mapped{};
  mapped.sin6_family = AF_INET6;
  mapped.sin6_port = htons(1);
  CHECK(inet_pton(AF_INET6, "::ffff:0.0.0.0", &mapped.sin6_addr) == 1);
  CHECK(connect(v6fd, reinterpret_cast<sockaddr*>(&mapped), sizeof mapped) == -1);
  CHECK(errno == ECONNREFUSED);
  close(v6fd);

  const int fast = TcpSocket();
  CHECK(fast >= 0);
  const ssize_t sent = sendto(fast, "x", 1, MSG_FASTOPEN, reinterpret_cast<sockaddr*>(&zero), sizeof zero);
  CHECK(sent == -1);
  CHECK(errno == ECONNREFUSED);
  close(fast);
}

__attribute__((constructor(101))) void SeedTestProxyBeforeHooksConstructor() {
  if (std::getenv("PROXYCHAINS_PROXY_URL") == nullptr) {
    ::setenv("PROXYCHAINS_PROXY_URL", "socks5://127.0.0.1:1080", 1);
    ::setenv("PROXYCHAINS_QUIET_MODE", "1", 1);
  }
}

}  // namespace

int main(int argc, char** argv) {
  (void)argc;
  if (std::getenv("PROXYCHAINS_PROXY_URL") == nullptr) {
    ::setenv("PROXYCHAINS_PROXY_URL", "socks5://127.0.0.1:1080", 1);
    ::setenv("PROXYCHAINS_QUIET_MODE", "1", 1);
    ::execv("/proc/self/exe", argv);
    std::fprintf(stderr, "PROXYCHAINS_PROXY_URL must be set before process start\n");
    return 2;
  }
  TestDirectoryExtraction();
  TestPreloadValueKeepsLongPath();
  TestLaunchArguments();
  TestLaunchWithProxyUrlAndNoConfigFile();
  TestIdentityHooks();
  TestConcurrentNameLookup();
  TestConcurrentReentrantNameLookup();
  TestAddressReverseFormatting();
  TestUnspecifiedAddressRefused();
  if (g_failures != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", g_failures);
    return 1;
  }
  std::printf("hooks_and_cli_test: all checks passed\n");
  return 0;
}
