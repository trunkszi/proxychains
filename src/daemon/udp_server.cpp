#include "daemon/udp_server.hpp"

#include <ares.h>
#include <ares_dns_record.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "dns/dns_protocol.hpp"

namespace proxychains {
namespace {

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

constexpr int kRecvTimeoutMs = 200;
constexpr std::size_t kAtMsgPayloadMax = sizeof(AtMsg::m);

struct AddrinfoFree {
  addrinfo* ptr{nullptr};
  explicit AddrinfoFree(addrinfo* resolved) noexcept : ptr(resolved) {}
  ~AddrinfoFree() {
    if (ptr != nullptr) {
      ::freeaddrinfo(ptr);
    }
  }
  AddrinfoFree(const AddrinfoFree&) = delete;
  AddrinfoFree& operator=(const AddrinfoFree&) = delete;
};

enum class AtMsgOutcome { kNotAtMsg, kAnswered };

[[nodiscard]] bool Reply(int fd, const sockaddr* to, socklen_t to_len, AtMsg* out,
                         uint16_t payload_len, bool failed) noexcept {
  if (failed) {
    out->h.msgtype = static_cast<uint8_t>(AtMsgType::kFail);
    payload_len = 0;
  }
  out->h.datalen = htons(payload_len);
  if (to == nullptr || to_len == 0) {
    return false;
  }
  const auto bytes = sizeof(AtMsgHeader) + static_cast<std::size_t>(payload_len);
  const ssize_t sent = ::sendto(fd, out, bytes, 0, to, to_len);
  return sent == static_cast<ssize_t>(bytes);
}

/// Answers a legacy AtMsg datagram. Returns kNotAtMsg when the bytes are not a
/// valid AtMsg request, so the caller can try the standard DNS wire format.
[[nodiscard]] AtMsgOutcome HandleAtMsg(FakeIpTable& table, const uint8_t* data,
                                       std::size_t length, AtMsg* response,
                                       uint16_t* payload_len, bool* failed) noexcept {
  if (length < sizeof(AtMsgHeader)) {
    return AtMsgOutcome::kNotAtMsg;
  }
  AtMsgHeader header{};
  std::memcpy(&header, data, sizeof(header));
  const uint16_t data_len = ntohs(header.datalen);
  const bool shaped = header.msgtype <= static_cast<uint8_t>(AtMsgType::kExit) &&
                      header.reserved == 0 &&
                      length == sizeof(AtMsgHeader) + data_len && data_len <= kAtMsgPayloadMax;
  if (!shaped) {
    return AtMsgOutcome::kNotAtMsg;
  }

  response->h.msgtype = header.msgtype;
  *failed = true;
  if (header.msgtype == static_cast<uint8_t>(AtMsgType::kGetIp)) {
    if (data_len < 2) {
      return AtMsgOutcome::kNotAtMsg;
    }
    char host[sizeof(AtMsg::m.host)]{};
    std::memcpy(host, data + sizeof(AtMsgHeader), data_len);
    const bool terminated = std::memchr(host, '\0', data_len) != nullptr;
    if (!terminated) {
      return AtMsgOutcome::kNotAtMsg;
    }
    const std::size_t name_len = std::strlen(host);
    if (name_len == 0 || name_len + 1 != data_len) {
      return AtMsgOutcome::kNotAtMsg;
    }
    for (std::size_t i = 0; i < name_len; ++i) {
      const unsigned char ch = static_cast<unsigned char>(host[i]);
      if (ch < 0x21 || ch > 0x7e) {
        return AtMsgOutcome::kNotAtMsg;
      }
    }
    const Result<IpType4> ip = table.GetOrAllocateIp(std::string_view{host, name_len});
    if (ip.has_value() && (*ip).as_int != IPT4_INVALID.as_int) {
      response->m.ip = *ip;
      *payload_len = 4;
      *failed = false;
    }
  } else if (header.msgtype == static_cast<uint8_t>(AtMsgType::kGetName)) {
    if (data_len != sizeof(IpType4)) {
      return AtMsgOutcome::kNotAtMsg;
    }
    IpType4 address{};
    std::memcpy(address.octet, data + sizeof(AtMsgHeader), sizeof(IpType4));
    const std::optional<std::string> host = table.GetHostnameForIp(address);
    if (host.has_value() && !host->empty() && host->size() <= kMaxHostLen) {
      std::memcpy(response->m.host, host->data(), host->size());
      response->m.host[host->size()] = '\0';
      *payload_len = static_cast<uint16_t>(host->size() + 1);
      *failed = false;
    }
  } else if (data_len != 0) {
    return AtMsgOutcome::kNotAtMsg;
  }
  return AtMsgOutcome::kAnswered;
}

/// Answers a standard DNS query from the fake-IP table (A and PTR only).
[[nodiscard]] Result<void> AnswerDns(FakeIpTable& table, int fd, const uint8_t* data,
                                     std::size_t length, const sockaddr* to,
                                     socklen_t to_len) noexcept {
  uint16_t query_id = 0;
  uint16_t qtype = 0;
  std::string question;
  if (!ParseDnsQuestion(data, length, &query_id, &question, &qtype)) {
    return std::unexpected(make_error_code(ErrorCode::kProtocolError));
  }

  DnsAnswer answer{};
  if (qtype == static_cast<uint16_t>(ARES_REC_TYPE_A)) {
    const Result<IpType4> ip = table.GetOrAllocateIp(question);
    if (ip.has_value() && (*ip).as_int != IPT4_INVALID.as_int) {
      answer.address = *ip;
      answer.found = true;
    }
  } else {
    IpType4 reverse{};
    if (ParsePtrName(question, &reverse)) {
      const std::optional<std::string> host = table.GetHostnameForIp(reverse);
      if (host.has_value() && !host->empty() && host->size() <= kMaxHostLen) {
        answer.name = *host;
        answer.found = true;
      }
    }
  }

  const std::vector<uint8_t> wire =
      BuildDnsResponse(query_id, question, qtype, answer,
                       answer.found ? ARES_RCODE_NOERROR : ARES_RCODE_NXDOMAIN);
  if (wire.empty()) {
    return std::unexpected(make_error_code(ErrorCode::kProtocolError));
  }
  const ssize_t sent = ::sendto(fd, wire.data(), wire.size(), 0, to, to_len);
  if (sent != static_cast<ssize_t>(wire.size())) {
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  return {};
}

}  // namespace

UdpServer::UdpServer(uint8_t remote_subnet) noexcept : table_(remote_subnet) {}

Result<void> UdpServer::Listen(std::string_view listen_ip, uint16_t port) noexcept {
  fd_.Reset();
  bound_port_ = 0;
  stop_.store(false, std::memory_order_release);
  if (listen_ip.empty() || listen_ip.find('\0') != std::string_view::npos) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }

  const std::string host{listen_ip};
  char port_text[8];
  if (std::snprintf(port_text, sizeof(port_text), "%u", static_cast<unsigned>(port)) < 0) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* resolved = nullptr;
  if (::getaddrinfo(host.c_str(), port_text, &hints, &resolved) != 0) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }
  AddrinfoFree guard{resolved};

  for (addrinfo* candidate = resolved; candidate != nullptr; candidate = candidate->ai_next) {
    const int raw = ::socket(candidate->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (raw < 0) {
      continue;
    }
    ScopedFd listen_fd{raw};
    const int yes = 1;
    (void)::setsockopt(listen_fd.Get(), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    if (::bind(listen_fd.Get(), candidate->ai_addr, candidate->ai_addrlen) != 0) {
      continue;
    }

    timeval timeout{};
    timeout.tv_sec = kRecvTimeoutMs / 1000;
    timeout.tv_usec = (kRecvTimeoutMs % 1000) * 1000;
    if (::setsockopt(listen_fd.Get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
      continue;
    }

    sockaddr_storage bound{};
    socklen_t bound_len = sizeof(bound);
    if (::getsockname(listen_fd.Get(), reinterpret_cast<sockaddr*>(&bound), &bound_len) != 0) {
      continue;
    }
    if (bound.ss_family == AF_INET) {
      bound_port_ = ntohs(reinterpret_cast<sockaddr_in*>(&bound)->sin_port);
    } else if (bound.ss_family == AF_INET6) {
      bound_port_ = ntohs(reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port);
    } else {
      continue;
    }

    fd_ = std::move(listen_fd);
    return {};
  }
  return std::unexpected(make_error_code(ErrorCode::kSocketError));
}

uint16_t UdpServer::BoundPort() const noexcept { return bound_port_; }

bool UdpServer::StopRequested() const noexcept {
  return stop_.load(std::memory_order_acquire);
}

void UdpServer::RequestStop() noexcept { stop_.store(true, std::memory_order_release); }

Result<void> UdpServer::ServeOne() noexcept {
  if (StopRequested()) {
    return std::unexpected(make_error_code(ErrorCode::kTimeout));
  }
  if (!fd_.Valid()) {
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }

  uint8_t datagram[kMaxDnsDatagram];
  sockaddr_storage from{};
  socklen_t from_len = sizeof(from);
  const ssize_t received = ::recvfrom(fd_.Get(), datagram, sizeof(datagram), 0,
                                      reinterpret_cast<sockaddr*>(&from), &from_len);
  if (received < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
      return std::unexpected(make_error_code(ErrorCode::kTimeout));
    }
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  const std::size_t length = static_cast<std::size_t>(received);

  uint16_t query_id = 0;
  uint16_t qtype = 0;
  std::string question;
  if (length >= 12 && ParseDnsQuestion(datagram, length, &query_id, &question, &qtype)) {
    return AnswerDns(table_, fd_.Get(), datagram, length,
                     reinterpret_cast<sockaddr*>(&from), from_len);
  }

  AtMsg response{};
  uint16_t payload_len = 0;
  bool failed = true;
  if (HandleAtMsg(table_, datagram, length, &response, &payload_len, &failed) ==
      AtMsgOutcome::kAnswered) {
    if (!Reply(fd_.Get(), reinterpret_cast<sockaddr*>(&from), from_len, &response, payload_len,
               failed)) {
      return std::unexpected(make_error_code(ErrorCode::kSocketError));
    }
    return {};
  }

  // Datagrams that are neither AtMsg nor DNS keep the historical failure reply.
  if (!Reply(fd_.Get(), reinterpret_cast<sockaddr*>(&from), from_len, &response, 0, true)) {
    return std::unexpected(make_error_code(ErrorCode::kSocketError));
  }
  return {};
}

}  // namespace proxychains
