/// @file protocol_and_chain_test.cpp
/// @brief Unit and loopback integration tests for Shard 2.
/// Dependency-free harness: failed assertions accumulate and exit non-zero, so
/// the file builds under -fno-exceptions and ASan/UBSan without a framework.
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include "chain/chain_scheduler.hpp"
#include "core/fd.hpp"
#include "protocol/socket_io.hpp"
#include "protocol/tunnel_fsm.hpp"
namespace {
using namespace proxychains;
int g_failures = 0;
void Check(bool condition, const char* expression, const char* file, int line) {
  if (!condition) {
    std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expression);
    ++g_failures;
  }
}
#define CHECK(condition) Check((condition), #condition, __FILE__, __LINE__)
struct SocketPair {
  ScopedFd first{};
  ScopedFd second{};
  SocketPair() noexcept {
    int fds[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0) {
      first.Reset(fds[0]);
      second.Reset(fds[1]);
    }
  }
};
struct Listener {
  ScopedFd fd{};
  uint16_t port{0};
  bool Start() noexcept {
    fd.Reset(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (!fd.Valid()) {
      return false;
    }
    int reuse = 1;
    (void)::setsockopt(fd.Get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(fd.Get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
      return false;
    }
    if (::listen(fd.Get(), 8) != 0) {
      return false;
    }
    socklen_t length = sizeof(address);
    if (::getsockname(fd.Get(), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
      return false;
    }
    port = ntohs(address.sin_port);
    return true;
  }
  int Accept(int timeout_ms = 1000) const noexcept {
    if (timeout_ms > 0) {
      timeval timeout{};
      timeout.tv_sec = timeout_ms / 1000;
      timeout.tv_usec = (timeout_ms % 1000) * 1000;
      (void)::setsockopt(fd.Get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    }
    return ::accept(fd.Get(), nullptr, nullptr);
  }
};
void SetReceiveTimeout(int fd, int timeout_ms) noexcept {
  timeval timeout{};
  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
  (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}
ScopedFd ConnectTo(uint16_t port) noexcept {
  ScopedFd client;
  client.Reset(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!client.Valid()) {
    return client;
  }
  const auto address = IpAddress::Parse("127.0.0.1");
  if (!address.has_value()) {
    return client;
  }
  const auto connected = TimedConnect(client.Get(), address.value(), port, 1000, ::connect);
  if (!connected.has_value()) {
    client.Reset();
  }
  return client;
}
std::string ReadUntil(int fd, std::string_view delimiter) noexcept {
  std::string data;
  char buffer[512];
  while (data.find(delimiter) == std::string::npos) {
    const ssize_t count = ::recv(fd, buffer, sizeof(buffer), 0);
    if (count <= 0) {
      break;
    }
    data.append(buffer, static_cast<std::size_t>(count));
    if (data.size() > 65536) {
      break;
    }
  }
  return data;
}
bool ReadExactRaw(int fd, uint8_t* buffer, std::size_t length) noexcept {
  std::size_t offset = 0;
  while (offset < length) {
    const ssize_t count = ::recv(fd, buffer + offset, length - offset, 0);
    if (count <= 0) {
      return false;
    }
    offset += static_cast<std::size_t>(count);
  }
  return true;
}
void WriteRaw(int fd, std::string_view bytes) noexcept {
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t count = ::send(fd, bytes.data() + offset, bytes.size() - offset, MSG_NOSIGNAL);
    if (count <= 0) {
      return;
    }
    offset += static_cast<std::size_t>(count);
  }
}
ProxyEndpoint MakeProxy(uint16_t port, ProxyType type) noexcept {
  ProxyEndpoint proxy{};
  const auto address = IpAddress::Parse("127.0.0.1");
  if (address.has_value()) {
    proxy.ip = address.value();
  }
  proxy.port_host = port;
  proxy.type = type;
  return proxy;
}
void TestEncodeBase64() {
  CHECK(EncodeBase64("").empty());
  CHECK(EncodeBase64("f") == "Zg==");
  CHECK(EncodeBase64("fo") == "Zm8=");
  CHECK(EncodeBase64("foo") == "Zm9v");
  CHECK(EncodeBase64("foob") == "Zm9vYg==");
  CHECK(EncodeBase64("fooba") == "Zm9vYmE=");
  CHECK(EncodeBase64("foobar") == "Zm9vYmFy");
  CHECK(EncodeBase64(std::string_view("\x00\x01\x02", 3)) == "AAEC");
  CHECK(EncodeBase64("user:pass") == "dXNlcjpwYXNz");
}
void TestPollWriteAllAndReadExact() {
  SocketPair pair;
  std::vector<uint8_t> payload(64 * 1024);
  for (std::size_t i = 0; i < payload.size(); ++i) {
    payload[i] = static_cast<uint8_t>(i % 251);
  }
  CHECK(PollWriteAll(pair.first.Get(), payload, 1000).has_value());
  std::vector<uint8_t> received(payload.size());
  CHECK(PollReadExact(pair.second.Get(), received, 1000).has_value());
  CHECK(received == payload);
}
void TestPollReadExactTimesOutWithinBudget() {
  SocketPair pair;
  std::vector<uint8_t> buffer(16);
  const auto start = std::chrono::steady_clock::now();
  const auto result = PollReadExact(pair.second.Get(), buffer, 60);
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::steady_clock::now() - start)
                           .count();
  CHECK(!result.has_value());
  CHECK(result.error() == make_error_code(ErrorCode::kTimeout));
  CHECK(elapsed >= 40);
  CHECK(elapsed < 1000);
}
void TestPollReadExactReportsPrematureEof() {
  SocketPair pair;
  std::vector<uint8_t> buffer(16);
  pair.first.Reset();
  const auto result = PollReadExact(pair.second.Get(), buffer, 1000);
  CHECK(!result.has_value());
  CHECK(result.error() == make_error_code(ErrorCode::kSocketError));
}
void TestPollReadHttpHeadersHandlesFragmentation() {
  SocketPair pair;
  const std::string first = "HTTP/1.1 200 Connection established\r\n";
  const std::string second = "Proxy-Agent: mock\r\n\r\n";
  std::thread writer([&pair, first, second] {
    WriteRaw(pair.first.Get(), first);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    WriteRaw(pair.first.Get(), second);
  });
  std::vector<uint8_t> buffer(512);
  const auto count = PollReadHttpHeaders(pair.second.Get(), buffer, 1000);
  writer.join();
  CHECK(count.has_value());
  CHECK(count.value() == first.size() + second.size());
  CHECK(std::string(reinterpret_cast<const char*>(buffer.data()), count.value_or(0)) == first + second);
}
void TestPollReadHttpHeadersRejectsOversizedHead() {
  SocketPair pair;
  const std::string head = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  WriteRaw(pair.first.Get(), head);
  std::vector<uint8_t> buffer(8);
  const auto count = PollReadHttpHeaders(pair.second.Get(), buffer, 1000);
  CHECK(!count.has_value());
  CHECK(count.error() == make_error_code(ErrorCode::kProtocolError));
}
void TestTimedConnectSucceedsAndPreservesFlags() {
  Listener listener;
  CHECK(listener.Start());
  ScopedFd client;
  client.Reset(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
  CHECK(client.Valid());
  const int before = ::fcntl(client.Get(), F_GETFL, 0);
  CHECK((before & O_NONBLOCK) != 0);
  const auto address = IpAddress::Parse("127.0.0.1");
  CHECK(address.has_value());
  const auto result = TimedConnect(client.Get(), address.value(), listener.port, 1000, ::connect);
  CHECK(result.has_value());
  const int after = ::fcntl(client.Get(), F_GETFL, 0);
  CHECK(after == before);
  const int accepted = listener.Accept();
  CHECK(accepted >= 0);
  if (accepted >= 0) {
    (void)::close(accepted);
  }
}
void TestTimedConnectRefusesClosedPort() {
  uint16_t dead_port = 0;
  {
    Listener listener;
    CHECK(listener.Start());
    dead_port = listener.port;
  }
  ScopedFd client;
  client.Reset(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
  CHECK(client.Valid());
  const auto address = IpAddress::Parse("127.0.0.1");
  CHECK(address.has_value());
  const auto result = TimedConnect(client.Get(), address.value(), dead_port, 500, ::connect);
  CHECK(!result.has_value());
  CHECK(result.error() == make_error_code(ErrorCode::kSocketError));
}
Result<void> RunHttpTunnel(const ProxyEndpoint& proxy, const IpAddress& target, uint16_t port,
                           std::string_view domain, int read_timeout_ms) noexcept {
  ScopedFd client = ConnectTo(proxy.port_host);
  if (!client.Valid()) {
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  return EstablishProxyTunnel(client.Get(), proxy, target, port, domain, read_timeout_ms);
}
struct HttpCase { std::string request; Result<void> result; };
HttpCase RunHttpCase(ProxyEndpoint proxy, const IpAddress& target, uint16_t target_port,
                     std::string_view response, std::string_view domain = {}) {
  Listener listener;
  HttpCase outcome{{}, std::unexpected(make_error_code(ErrorCode::kSocketError))};
  if (!listener.Start()) return outcome;
  proxy.port_host = listener.port;
  std::thread server([&listener, &outcome, response] {
    const int fd = listener.Accept(2000);
    if (fd < 0) return;
    SetReceiveTimeout(fd, 2000);
    outcome.request = ReadUntil(fd, "\r\n\r\n");
    WriteRaw(fd, response);
    (void)::close(fd);
  });
  ScopedFd client = ConnectTo(listener.port);
  if (client.Valid()) {
    outcome.result = EstablishProxyTunnel(client.Get(), proxy, target, target_port, domain, 1000);
  }
  server.join();
  return outcome;
}
void TestHttpConnectIpv4AndBasicAuth() {
  ProxyEndpoint proxy = MakeProxy(0, ProxyType::kHttp);
  proxy.user = "user";
  proxy.pass = "pass";
  const HttpCase outcome = RunHttpCase(proxy, IpAddress::LocalhostV4(), 443, "HTTP/1.1 200 Connection established\r\n\r\n");
  CHECK(outcome.result.has_value());
  CHECK(outcome.request.find("CONNECT 127.0.0.1:443 HTTP/1.1\r\n") == 0);
  CHECK(outcome.request.find("Host: 127.0.0.1:443\r\n") != std::string::npos);
  CHECK(outcome.request.find("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") != std::string::npos);
}
void TestHttpConnectBracketsIpv6() {
  const auto address = IpAddress::Parse("::1");
  CHECK(address.has_value());
  const HttpCase outcome = RunHttpCase(MakeProxy(0, ProxyType::kHttp), address.value(), 443, "HTTP/1.1 200 OK\r\n\r\n");
  CHECK(outcome.result.has_value());
  CHECK(outcome.request.find("CONNECT [::1]:443 HTTP/1.1\r\n") == 0);
  CHECK(outcome.request.find("Host: [::1]:443\r\n") != std::string::npos);
}
void TestHttpStatusVariants() {
  const HttpCase blocked = RunHttpCase(MakeProxy(0, ProxyType::kHttp), IpAddress::LocalhostV4(), 80, "HTTP/1.1 403 Forbidden\r\n\r\n");
  CHECK(!blocked.result.has_value());
  CHECK(blocked.result.error() == make_error_code(ErrorCode::kProxyBlocked));
  const HttpCase no_content = RunHttpCase(MakeProxy(0, ProxyType::kHttp), IpAddress::LocalhostV4(), 80, "HTTP/1.1 204 No Content\r\n\r\n");
  CHECK(no_content.result.has_value());
  const HttpCase malformed = RunHttpCase(MakeProxy(0, ProxyType::kHttp), IpAddress::LocalhostV4(), 80, "HTTP/1.1 2000 Weird\r\n\r\n");
  CHECK(!malformed.result.has_value());
  CHECK(malformed.result.error() == make_error_code(ErrorCode::kProtocolError));
  const HttpCase extra_space = RunHttpCase(MakeProxy(0, ProxyType::kHttp), IpAddress::LocalhostV4(), 80, "HTTP/1.1   200 OK\r\n\r\n");
  CHECK(extra_space.result.has_value());
  const HttpCase truncated = RunHttpCase(MakeProxy(0, ProxyType::kHttp), IpAddress::LocalhostV4(), 80, "HTTP/1.1 2");
  CHECK(!truncated.result.has_value());
}
void TestHttpConnectPreservesTrailingPayload() {
  Listener listener;
  CHECK(listener.Start());
  std::thread server([&listener] {
    const int fd = listener.Accept(2000);
    if (fd < 0) return;
    SetReceiveTimeout(fd, 2000);
    (void)ReadUntil(fd, "\r\n\r\n");
    WriteRaw(fd, "HTTP/1.1 200 OK\r\n\r\nBANNER");
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    (void)::close(fd);
  });
  ScopedFd client = ConnectTo(listener.port);
  CHECK(client.Valid());
  const auto tunnel = EstablishProxyTunnel(client.Get(), MakeProxy(listener.port, ProxyType::kHttp), IpAddress::LocalhostV4(), 80, "", 1000);
  CHECK(tunnel.has_value());
  std::vector<uint8_t> banner(6);
  CHECK(PollReadExact(client.Get(), banner, 500).has_value());
  CHECK(std::string(reinterpret_cast<const char*>(banner.data()), banner.size()) == "BANNER");
  server.join();
}
void TestSocks4AndSocks4a() {
  Listener listener;
  CHECK(listener.Start());
  std::string request;
  std::thread server([&listener, &request] {
    const int fd = listener.Accept();
    if (fd < 0) {
      return;
    }
    SetReceiveTimeout(fd, 2000);
    uint8_t octets[9] = {};
    if (!ReadExactRaw(fd, octets, sizeof(octets))) {
      (void)::close(fd);
      return;
    }
    request.assign(reinterpret_cast<const char*>(octets), sizeof(octets));
    const uint8_t response[8] = {0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    (void)::send(fd, response, sizeof(response), MSG_NOSIGNAL);
    (void)::close(fd);
  });
  const ProxyEndpoint proxy = MakeProxy(listener.port, ProxyType::kSocks4);
  const auto address = IpAddress::Parse("127.0.0.1");
  CHECK(address.has_value());
  const auto result = RunHttpTunnel(proxy, address.value(), 80, "", 1000);
  server.join();
  CHECK(result.has_value());
  CHECK(request.size() >= 9);
  CHECK(static_cast<uint8_t>(request[0]) == 0x04);
  CHECK(static_cast<uint8_t>(request[1]) == 0x01);
  Listener domain_listener;
  CHECK(domain_listener.Start());
  std::string domain_request;
  std::thread domain_server([&domain_listener, &domain_request] {
    const int fd = domain_listener.Accept();
    if (fd < 0) {
      return;
    }
    SetReceiveTimeout(fd, 2000);
    domain_request = ReadUntil(fd, "example.test");
    const uint8_t response[8] = {0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    (void)::send(fd, response, sizeof(response), MSG_NOSIGNAL);
    (void)::close(fd);
  });
  const ProxyEndpoint domain_proxy = MakeProxy(domain_listener.port, ProxyType::kSocks4);
  const auto domain_result = RunHttpTunnel(domain_proxy, address.value(), 80, "example.test", 1000);
  domain_server.join();
  CHECK(domain_result.has_value());
  CHECK(domain_request.find("example.test") != std::string::npos);
}
void TestSocks4RejectsIpv6AndBlocked() {
  SocketPair pair;
  ProxyEndpoint proxy{};
  proxy.type = ProxyType::kSocks4;
  const auto v6 = IpAddress::Parse("::1");
  CHECK(v6.has_value());
  const auto rejected = EstablishProxyTunnel(pair.first.Get(), proxy, v6.value(), 80, "", 1000);
  CHECK(!rejected.has_value());
  CHECK(rejected.error() == make_error_code(ErrorCode::kProtocolError));
  Listener listener;
  CHECK(listener.Start());
  std::thread server([&listener] {
    const int fd = listener.Accept();
    if (fd < 0) {
      return;
    }
    SetReceiveTimeout(fd, 2000);
    uint8_t octets[9] = {};
    (void)ReadExactRaw(fd, octets, sizeof(octets));
    const uint8_t response[8] = {0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    (void)::send(fd, response, sizeof(response), MSG_NOSIGNAL);
    (void)::close(fd);
  });
  const auto v4 = IpAddress::Parse("127.0.0.1");
  CHECK(v4.has_value());
  const auto blocked = RunHttpTunnel(MakeProxy(listener.port, ProxyType::kSocks4), v4.value(), 80, "", 1000);
  server.join();
  CHECK(!blocked.has_value());
  CHECK(blocked.error() == make_error_code(ErrorCode::kProxyBlocked));
}
void TestSocks5NoAuthIpv4() {
  Listener listener;
  CHECK(listener.Start());
  std::vector<uint8_t> greeting;
  std::vector<uint8_t> request;
  std::thread server([&listener, &greeting, &request] {
    const int fd = listener.Accept();
    if (fd < 0) {
      return;
    }
    SetReceiveTimeout(fd, 2000);
    uint8_t head[2] = {0, 0};
    if (!ReadExactRaw(fd, head, 2)) {
      (void)::close(fd);
      return;
    }
    greeting.assign(head, head + 2);
    std::vector<uint8_t> methods(head[1]);
    if (!methods.empty()) {
      (void)ReadExactRaw(fd, methods.data(), methods.size());
      greeting.insert(greeting.end(), methods.begin(), methods.end());
    }
    const uint8_t selection[2] = {0x05, 0x00};
    (void)::send(fd, selection, sizeof(selection), MSG_NOSIGNAL);
    uint8_t request_head[4] = {0, 0, 0, 0};
    if (!ReadExactRaw(fd, request_head, 4)) {
      (void)::close(fd);
      return;
    }
    request.assign(request_head, request_head + 4);
    std::vector<uint8_t> address(4 + 2);
    if (!ReadExactRaw(fd, address.data(), address.size())) {
      (void)::close(fd);
      return;
    }
    request.insert(request.end(), address.begin(), address.end());
    const uint8_t reply[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    (void)::send(fd, reply, sizeof(reply), MSG_NOSIGNAL);
    (void)::close(fd);
  });
  const auto target = IpAddress::Parse("127.0.0.1");
  CHECK(target.has_value());
  const auto result = RunHttpTunnel(MakeProxy(listener.port, ProxyType::kSocks5), target.value(), 80, "", 1000);
  server.join();
  CHECK(result.has_value());
  CHECK(greeting.size() == 3);
  CHECK(greeting[0] == 0x05 && greeting[1] == 0x01 && greeting[2] == 0x00);
  CHECK(request.size() == 10);
  CHECK(request[3] == 0x01);
}
void TestSocks5UserPassAndDomainReply() {
  Listener listener;
  CHECK(listener.Start());
  std::vector<uint8_t> auth;
  std::thread server([&listener, &auth] {
    const int fd = listener.Accept();
    if (fd < 0) {
      return;
    }
    SetReceiveTimeout(fd, 2000);
    uint8_t head[2] = {0, 0};
    if (!ReadExactRaw(fd, head, 2)) {
      (void)::close(fd);
      return;
    }
    std::vector<uint8_t> methods(head[1]);
    if (!methods.empty()) { (void)ReadExactRaw(fd, methods.data(), methods.size()); }
    const uint8_t selection[2] = {0x05, 0x02};
    (void)::send(fd, selection, sizeof(selection), MSG_NOSIGNAL);
    uint8_t auth_head[2] = {0, 0};
    if (!ReadExactRaw(fd, auth_head, 2)) {
      (void)::close(fd);
      return;
    }
    auth.assign(auth_head, auth_head + 2);
    std::vector<uint8_t> credentials(auth_head[1]);
    if (!credentials.empty()) {
      (void)ReadExactRaw(fd, credentials.data(), credentials.size());
      auth.insert(auth.end(), credentials.begin(), credentials.end());
    }
    uint8_t pass_length = 0;
    if (!ReadExactRaw(fd, &pass_length, 1)) {
      (void)::close(fd);
      return;
    }
    auth.push_back(pass_length);
    std::vector<uint8_t> password(pass_length);
    if (!password.empty()) {
      (void)ReadExactRaw(fd, password.data(), password.size());
      auth.insert(auth.end(), password.begin(), password.end());
    }
    const uint8_t auth_reply[2] = {0x01, 0x00};
    (void)::send(fd, auth_reply, sizeof(auth_reply), MSG_NOSIGNAL);
    uint8_t request_head[5] = {0, 0, 0, 0, 0};
    if (!ReadExactRaw(fd, request_head, 5)) {
      (void)::close(fd);
      return;
    }
    std::size_t tail_length = 5;
    if (request_head[3] == 0x03) {
      tail_length = static_cast<std::size_t>(request_head[4]) + 2;
    } else if (request_head[3] == 0x04) {
      tail_length = 17;
    }
    std::vector<uint8_t> tail(tail_length);
    if (!ReadExactRaw(fd, tail.data(), tail.size())) {
      (void)::close(fd);
      return;
    }
    std::vector<uint8_t> reply = {0x05, 0x00, 0x00, 0x03, 200};
    reply.resize(reply.size() + 200 + 2, 0x61);
    (void)::send(fd, reply.data(), reply.size(), MSG_NOSIGNAL);
    (void)::close(fd);
  });
  ProxyEndpoint proxy = MakeProxy(listener.port, ProxyType::kSocks5);
  proxy.user = "alice";
  proxy.pass = "s3cret";
  const auto target = IpAddress::Parse("127.0.0.1");
  CHECK(target.has_value());
  const auto result = RunHttpTunnel(proxy, target.value(), 80, "", 1000);
  server.join();
  CHECK(result.has_value());
  CHECK(auth.size() == 2 + 5 + 1 + 6);
  CHECK(auth[0] == 0x01 && auth[1] == 5 && auth[7] == 6);
}
void TestSocks5Ipv6AndDomainTargets() {
  auto address_type_for = [](const IpAddress& target, std::string_view domain) {
    Listener listener;
    if (!listener.Start()) {
      return uint8_t{0};
    }
    std::atomic<uint8_t> observed{0};
    std::thread server([&listener, &observed] {
      const int fd = listener.Accept(2000);
      if (fd < 0) {
        return;
      }
      SetReceiveTimeout(fd, 2000);
      uint8_t head[2] = {0, 0};
      if (!ReadExactRaw(fd, head, 2)) {
        (void)::close(fd);
        return;
      }
      std::vector<uint8_t> methods(head[1]);
      if (!methods.empty()) { (void)ReadExactRaw(fd, methods.data(), methods.size()); }
      const uint8_t selection[2] = {0x05, 0x00};
      (void)::send(fd, selection, sizeof(selection), MSG_NOSIGNAL);
      uint8_t request_head[5] = {0, 0, 0, 0, 0};
      if (!ReadExactRaw(fd, request_head, 5)) {
        (void)::close(fd);
        return;
      }
      observed.store(request_head[3]);
      std::size_t tail_length = request_head[3] == 0x04
                                    ? 17
                                    : static_cast<std::size_t>(request_head[4]) + 2;
      std::vector<uint8_t> tail(tail_length);
      (void)ReadExactRaw(fd, tail.data(), tail.size());
      const uint8_t reply[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
      (void)::send(fd, reply, sizeof(reply), MSG_NOSIGNAL);
      (void)::close(fd);
    });
    const auto result = RunHttpTunnel(MakeProxy(listener.port, ProxyType::kSocks5), target, 80, domain, 1000);
    server.join();
    CHECK(result.has_value());
    return observed.load();
  };
  const auto v6 = IpAddress::Parse("::1");
  CHECK(v6.has_value());
  CHECK(address_type_for(v6.value(), "") == 0x04);
  const auto v4 = IpAddress::Parse("127.0.0.1");
  CHECK(v4.has_value());
  CHECK(address_type_for(v4.value(), "example.test") == 0x03);
}
void TestChainEmptyAndDynamicFailover() {
  ChainScheduler scheduler;
  ProxychainsConfig empty_config{};
  scheduler.Configure(empty_config);
  ScopedFd app_socket;
  app_socket.Reset(::socket(AF_INET, SOCK_STREAM, 0));
  const auto target = IpAddress::Parse("127.0.0.1");
  CHECK(target.has_value());
  const auto empty = scheduler.ConnectThroughChain(app_socket.Get(), target.value(), 80, ::connect, nullptr);
  CHECK(!empty.has_value());
  CHECK(empty.error() == make_error_code(ErrorCode::kChainEmpty));
  uint16_t dead_port = 0;
  {
    Listener dead;
    CHECK(dead.Start());
    dead_port = dead.port;
  }
  Listener live;
  CHECK(live.Start());
  std::atomic<int> accepted{0};
  std::thread server([&live, &accepted] {
    const int fd = live.Accept(2000);
    if (fd < 0) {
      return;
    }
    accepted.fetch_add(1);
    SetReceiveTimeout(fd, 2000);
    char byte = 0;
    (void)::recv(fd, &byte, 1, 0);
    (void)::close(fd);
  });
  ProxychainsConfig config{};
  config.chain_type = ChainType::kDynamic;
  config.max_chain = 2;
  config.proxies.push_back(MakeProxy(dead_port, ProxyType::kRaw));
  config.proxies.push_back(MakeProxy(live.port, ProxyType::kRaw));
  scheduler.Configure(config);
  ScopedFd dynamic_socket;
  dynamic_socket.Reset(::socket(AF_INET, SOCK_STREAM, 0));
  const auto dynamic = scheduler.ConnectThroughChain(dynamic_socket.Get(), target.value(), 80, ::connect, nullptr);
  CHECK(dynamic.has_value());
  const char ping = 'P';
  CHECK(::send(dynamic_socket.Get(), &ping, 1, MSG_NOSIGNAL) == 1);
  server.join();
  CHECK(accepted.load() == 1);
  const auto snapshot = scheduler.SnapshotProxies();
  CHECK(snapshot.size() == 2);
  CHECK(snapshot[0].state == ProxyState::kBlocked);
}
void TestChainStrictDoesNotFailOver() {
  uint16_t dead_port = 0;
  {
    Listener dead;
    CHECK(dead.Start());
    dead_port = dead.port;
  }
  Listener live;
  CHECK(live.Start());
  std::atomic<int> accepted{0};
  std::thread server([&live, &accepted] {
    const int fd = live.Accept(500);
    if (fd >= 0) {
      accepted.fetch_add(1);
      (void)::close(fd);
    }
  });
  ProxychainsConfig config{};
  config.chain_type = ChainType::kStrict;
  config.max_chain = 2;
  config.proxies.push_back(MakeProxy(dead_port, ProxyType::kRaw));
  config.proxies.push_back(MakeProxy(live.port, ProxyType::kRaw));
  ChainScheduler scheduler;
  scheduler.Configure(config);
  ScopedFd app_socket;
  app_socket.Reset(::socket(AF_INET, SOCK_STREAM, 0));
  const auto target = IpAddress::Parse("127.0.0.1");
  CHECK(target.has_value());
  const auto result = scheduler.ConnectThroughChain(app_socket.Get(), target.value(), 80, ::connect, nullptr);
  server.join();
  CHECK(!result.has_value());
  CHECK(accepted.load() == 0);
}
void TestChainRandomAndRoundRobin() {
  Listener first;
  Listener second;
  CHECK(first.Start());
  CHECK(second.Start());
  std::atomic<int> first_accepts{0};
  std::atomic<int> second_accepts{0};
  auto serve = [](const Listener& listener, std::atomic<int>& counter) {
    return std::thread([&listener, &counter] {
      for (int i = 0; i < 2; ++i) {
        const int fd = listener.Accept(500);
        if (fd < 0) {
          return;
        }
        counter.fetch_add(1);
        SetReceiveTimeout(fd, 500);
        char byte = 0;
        (void)::recv(fd, &byte, 1, 0);
        (void)::close(fd);
      }
    });
  };
  std::thread first_server = serve(first, first_accepts);
  std::thread second_server = serve(second, second_accepts);
  ProxychainsConfig random_config{};
  random_config.chain_type = ChainType::kRandom;
  random_config.max_chain = 2;
  random_config.proxies.push_back(MakeProxy(first.port, ProxyType::kRaw));
  random_config.proxies.push_back(MakeProxy(second.port, ProxyType::kRaw));
  ChainScheduler random_scheduler;
  random_scheduler.Configure(random_config);
  ScopedFd random_socket;
  random_socket.Reset(::socket(AF_INET, SOCK_STREAM, 0));
  const auto target = IpAddress::Parse("127.0.0.1");
  CHECK(target.has_value());
  const auto random_result = random_scheduler.ConnectThroughChain(random_socket.Get(), target.value(), 80, ::connect, nullptr);
  CHECK(random_result.has_value());
  const char ping = 'R';
  CHECK(::send(random_socket.Get(), &ping, 1, MSG_NOSIGNAL) == 1);
  random_socket.Reset();
  ChainScheduler round_robin;
  ProxychainsConfig rr_config{};
  rr_config.chain_type = ChainType::kRoundRobin;
  rr_config.max_chain = 2;
  rr_config.proxies.push_back(MakeProxy(first.port, ProxyType::kRaw));
  rr_config.proxies.push_back(MakeProxy(second.port, ProxyType::kRaw));
  round_robin.Configure(rr_config);
  ScopedFd rr_socket_one;
  rr_socket_one.Reset(::socket(AF_INET, SOCK_STREAM, 0));
  CHECK(round_robin
            .ConnectThroughChain(rr_socket_one.Get(), target.value(), 80, ::connect, nullptr)
            .has_value());
  (void)::send(rr_socket_one.Get(), &ping, 1, MSG_NOSIGNAL);
  ScopedFd rr_socket_two;
  rr_socket_two.Reset(::socket(AF_INET, SOCK_STREAM, 0));
  CHECK(round_robin
            .ConnectThroughChain(rr_socket_two.Get(), target.value(), 80, ::connect, nullptr)
            .has_value());
  (void)::send(rr_socket_two.Get(), &ping, 1, MSG_NOSIGNAL);
  first_server.join();
  second_server.join();
  CHECK(first_accepts.load() >= 1);
  CHECK(second_accepts.load() >= 1);
  CHECK(first_accepts.load() + second_accepts.load() >= 3);
}
void TestTwoHopChain() {
  Listener inner;
  Listener outer;
  CHECK(inner.Start());
  CHECK(outer.Start());
  std::string first_connect;
  std::string second_connect;
  std::thread outer_server([&outer, &first_connect, &second_connect] {
    const int fd = outer.Accept(2000);
    if (fd < 0) return;
    SetReceiveTimeout(fd, 2000);
    first_connect = ReadUntil(fd, "\r\n\r\n");
    WriteRaw(fd, "HTTP/1.1 200 OK\r\n\r\n");
    second_connect = ReadUntil(fd, "\r\n\r\n");
    WriteRaw(fd, "HTTP/1.1 200 OK\r\n\r\n");
    char byte = 0;
    (void)::recv(fd, &byte, 1, 0);
    (void)::close(fd);
  });
  ProxychainsConfig config{};
  config.chain_type = ChainType::kDynamic;
  config.proxies.push_back(MakeProxy(outer.port, ProxyType::kHttp));
  config.proxies.push_back(MakeProxy(inner.port, ProxyType::kHttp));
  ChainScheduler scheduler;
  scheduler.Configure(config);
  ScopedFd app_socket;
  app_socket.Reset(::socket(AF_INET, SOCK_STREAM, 0));
  CHECK(scheduler.ConnectThroughChain(app_socket.Get(), IpAddress::LocalhostV4(), 8080, ::connect, nullptr)
            .has_value());
  const char probe = 'H';
  CHECK(::send(app_socket.Get(), &probe, 1, MSG_NOSIGNAL) == 1);
  outer_server.join();
  const std::string expected_hop = "CONNECT 127.0.0.1:" + std::to_string(inner.port);
  CHECK(first_connect.find(expected_hop) == 0);
  CHECK(second_connect.find("CONNECT 127.0.0.1:8080") == 0);
}
}  // namespace
int main() {
  TestEncodeBase64();
  TestPollWriteAllAndReadExact();
  TestPollReadExactTimesOutWithinBudget();
  TestPollReadExactReportsPrematureEof();
  TestPollReadHttpHeadersHandlesFragmentation();
  TestPollReadHttpHeadersRejectsOversizedHead();
  TestTimedConnectSucceedsAndPreservesFlags();
  TestTimedConnectRefusesClosedPort();
  TestHttpConnectIpv4AndBasicAuth();
  TestHttpConnectBracketsIpv6();
  TestHttpStatusVariants();
  TestHttpConnectPreservesTrailingPayload();
  TestSocks4AndSocks4a();
  TestSocks4RejectsIpv6AndBlocked();
  TestSocks5NoAuthIpv4();
  TestSocks5UserPassAndDomainReply();
  TestSocks5Ipv6AndDomainTargets();
  TestChainEmptyAndDynamicFailover();
  TestChainStrictDoesNotFailOver();
  TestChainRandomAndRoundRobin();
  TestTwoHopChain();
  if (g_failures != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", g_failures);
    return 1;
  }
  std::printf("protocol_and_chain_test: all checks passed\n");
  return 0;
}
