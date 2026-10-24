#pragma once

/// @file dns_protocol.hpp
/// @brief Legacy AtMsg framing plus c-ares DNS wire helpers and blocking lookups.
///
/// The daemon accepts both the historical 4-byte-header AtMsg datagrams and
/// standard DNS messages. Query construction, parsing, and the finite blocking
/// driver for c-ares live here so the daemon and the resolver share one wire
/// implementation.

#include <ares.h>
#include <ares_dns_record.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/types.hpp"

namespace proxychains {

enum class AtMsgType : uint8_t {
  kGetIp = 0,
  kGetName = 1,
  kFail = 2,
  kExit = 3,
};

struct AtMsgHeader {
  uint8_t msgtype{0};
  uint8_t reserved{0};
  uint16_t datalen{0};  // network byte order on UDP wire
};

struct AtMsg {
  AtMsgHeader h{};
  union {
    char host[260];
    IpType4 ip;
  } m{};
};

inline constexpr uint32_t kDnsAnswerTtl = 60;
inline constexpr int kCaresTimeoutMs = 3000;
inline constexpr std::size_t kMaxDnsDatagram = 2048;

struct DnsAnswer {
  IpType4 address{};
  std::string name{};
  bool found{false};
};

/// Builds a recursive DNS query for one question.
inline std::vector<uint8_t> BuildDnsQuery(uint16_t id, std::string_view name,
                                          uint16_t qtype) noexcept {
  std::vector<uint8_t> wire;
  ares_dns_record_t* record = nullptr;
  if (ares_dns_record_create(&record, id, static_cast<unsigned short>(ARES_FLAG_RD),
                             ARES_OPCODE_QUERY, ARES_RCODE_NOERROR) != ARES_SUCCESS) {
    return wire;
  }
  const std::string owned(name);
  if (ares_dns_record_query_add(record, owned.c_str(),
                                static_cast<ares_dns_rec_type_t>(qtype),
                                ARES_CLASS_IN) == ARES_SUCCESS) {
    unsigned char* buffer = nullptr;
    std::size_t length = 0;
    if (ares_dns_write(record, &buffer, &length) == ARES_SUCCESS && buffer != nullptr) {
      wire.assign(buffer, buffer + length);
      ares_free_string(buffer);
    }
  }
  ares_dns_record_destroy(record);
  return wire;
}

/// Extracts the single query question from a standard DNS query message.
inline bool ParseDnsQuestion(const uint8_t* data, std::size_t length, uint16_t* id,
                             std::string* name, uint16_t* qtype) noexcept {
  ares_dns_record_t* record = nullptr;
  if (data == nullptr || id == nullptr || name == nullptr || qtype == nullptr) {
    return false;
  }
  if (ares_dns_parse(data, length, 0, &record) != ARES_SUCCESS || record == nullptr) {
    return false;
  }
  bool parsed = false;
  if ((ares_dns_record_get_flags(record) & ARES_FLAG_QR) == 0 &&
      ares_dns_record_query_cnt(record) == 1) {
    const char* question = nullptr;
    ares_dns_rec_type_t type = ARES_REC_TYPE_A;
    ares_dns_class_t klass = ARES_CLASS_IN;
    if (ares_dns_record_query_get(record, 0, &question, &type, &klass) == ARES_SUCCESS &&
        question != nullptr && klass == ARES_CLASS_IN &&
        (type == ARES_REC_TYPE_A || type == ARES_REC_TYPE_PTR)) {
      *id = ares_dns_record_get_id(record);
      *name = question;
      *qtype = static_cast<uint16_t>(type);
      parsed = true;
    }
  }
  ares_dns_record_destroy(record);
  return parsed;
}

/// Builds a DNS response that echoes the question and optionally one answer.
inline std::vector<uint8_t> BuildDnsResponse(uint16_t id, std::string_view question_name,
                                             uint16_t qtype, const DnsAnswer& answer,
                                             ares_dns_rcode_t rcode) noexcept {
  std::vector<uint8_t> wire;
  ares_dns_record_t* record = nullptr;
  if (ares_dns_record_create(&record, id,
                             static_cast<unsigned short>(ARES_FLAG_QR | ARES_FLAG_RD | ARES_FLAG_RA),
                             ARES_OPCODE_QUERY, rcode) != ARES_SUCCESS) {
    return wire;
  }
  const std::string name(question_name);
  const auto type = static_cast<ares_dns_rec_type_t>(qtype);
  bool built = ares_dns_record_query_add(record, name.c_str(), type, ARES_CLASS_IN) == ARES_SUCCESS;
  if (built && answer.found) {
    ares_dns_rr_t* rr = nullptr;
    built = ares_dns_record_rr_add(&rr, record, ARES_SECTION_ANSWER, name.c_str(), type,
                                   ARES_CLASS_IN, kDnsAnswerTtl) == ARES_SUCCESS &&
            rr != nullptr;
    if (built && type == ARES_REC_TYPE_A) {
      in_addr address{};
      std::memcpy(&address, answer.address.octet, 4);
      built = ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &address) == ARES_SUCCESS;
    } else if (built && type == ARES_REC_TYPE_PTR) {
      built = ares_dns_rr_set_str(rr, ARES_RR_PTR_DNAME, answer.name.c_str()) == ARES_SUCCESS;
    }
  }
  if (built) {
    unsigned char* buffer = nullptr;
    std::size_t length = 0;
    if (ares_dns_write(record, &buffer, &length) == ARES_SUCCESS && buffer != nullptr) {
      wire.assign(buffer, buffer + length);
      ares_free_string(buffer);
    }
  }
  ares_dns_record_destroy(record);
  return wire;
}

/// Extracts the first A or PTR answer matching `qtype` and the query id.
inline bool ParseDnsAnswer(const uint8_t* data, std::size_t length, uint16_t expected_id,
                           uint16_t qtype, DnsAnswer* out) noexcept {
  if (data == nullptr || out == nullptr) {
    return false;
  }
  ares_dns_record_t* record = nullptr;
  if (ares_dns_parse(data, length, 0, &record) != ARES_SUCCESS || record == nullptr) {
    return false;
  }
  bool found = false;
  const auto type = static_cast<ares_dns_rec_type_t>(qtype);
  if (ares_dns_record_get_id(record) == expected_id &&
      (ares_dns_record_get_flags(record) & ARES_FLAG_QR) != 0 &&
      ares_dns_record_get_rcode(record) == ARES_RCODE_NOERROR) {
    const std::size_t count = ares_dns_record_rr_cnt(record, ARES_SECTION_ANSWER);
    for (std::size_t i = 0; i < count && !found; ++i) {
      ares_dns_rr_t* rr = ares_dns_record_rr_get(record, ARES_SECTION_ANSWER, i);
      if (rr == nullptr || ares_dns_rr_get_type(rr) != type) {
        continue;
      }
      if (type == ARES_REC_TYPE_A) {
        const in_addr* address = ares_dns_rr_get_addr(rr, ARES_RR_A_ADDR);
        if (address != nullptr) {
          std::memcpy(out->address.octet, address, 4);
          out->found = true;
          found = true;
        }
      } else if (type == ARES_REC_TYPE_PTR) {
        const char* name = ares_dns_rr_get_str(rr, ARES_RR_PTR_DNAME);
        if (name != nullptr) {
          out->name = name;
          out->found = true;
          found = true;
        }
      }
    }
  }
  ares_dns_record_destroy(record);
  return found;
}

/// Builds the `d.c.b.a.in-addr.arpa` name for an IPv4 address.
inline std::string MakePtrName(IpType4 ip) noexcept {
  std::string name;
  name.reserve(24);
  for (int i = 3; i >= 0; --i) {
    name += std::to_string(static_cast<unsigned>(ip.octet[i]));
    name.push_back('.');
  }
  name += "in-addr.arpa";
  return name;
}

/// Parses `d.c.b.a.in-addr.arpa` into the corresponding IPv4 address.
inline bool ParsePtrName(std::string_view name, IpType4* out) noexcept {
  if (name.size() < 13 || out == nullptr) {
    return false;
  }
  uint8_t octets[4]{};
  std::size_t cursor = 0;
  for (int label = 0; label < 4; ++label) {
    const std::size_t dot = name.find('.', cursor);
    if (dot == std::string_view::npos || dot == cursor || dot - cursor > 3) {
      return false;
    }
    unsigned value = 0;
    for (std::size_t i = cursor; i < dot; ++i) {
      if (name[i] < '0' || name[i] > '9') {
        return false;
      }
      value = value * 10 + static_cast<unsigned>(name[i] - '0');
    }
    if (value > 255) {
      return false;
    }
    octets[3 - label] = static_cast<uint8_t>(value);
    cursor = dot + 1;
  }
  if (name.substr(cursor) != "in-addr.arpa") {
    return false;
  }
  std::memcpy(out->octet, octets, 4);
  return true;
}

// --- Blocking c-ares driver -------------------------------------------------
// c-ares only exposes asynchronous queries. The hook API is synchronous, so a
// single query is driven to completion on the caller's thread with its own
// socket-state callback; no c-ares socket is installed into a global loop.

inline void EnsureCaresInitialized() noexcept {
  static const int kInit = ares_library_init(ARES_LIB_INIT_ALL);
  (void)kInit;
}

struct CaresSocketState {
  ares_socket_t fds[16]{};
  int read_flags[16]{};
  int write_flags[16]{};
  int count{0};
};

inline void CaresSocketCallback(void* data, ares_socket_t fd, int readable,
                                int writable) noexcept {
  auto* state = static_cast<CaresSocketState*>(data);
  if (state == nullptr) {
    return;
  }
  int index = 0;
  while (index < state->count && state->fds[index] != fd) {
    ++index;
  }
  if (readable == 0 && writable == 0) {
    if (index < state->count) {
      --state->count;
      state->fds[index] = state->fds[state->count];
      state->read_flags[index] = state->read_flags[state->count];
      state->write_flags[index] = state->write_flags[state->count];
    }
    return;
  }
  if (index == state->count) {
    if (state->count >= 16) {
      return;
    }
    ++state->count;
  }
  state->fds[index] = fd;
  state->read_flags[index] = readable;
  state->write_flags[index] = writable;
}

/// Polls c-ares sockets until the callback sets `done` or the budget expires.
inline bool DriveCares(ares_channel_t* channel, CaresSocketState* state,
                       bool* done) noexcept {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(kCaresTimeoutMs);
  while (!*done) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      return false;
    }
    pollfd poll_fds[16]{};
    int poll_count = 0;
    for (int i = 0; i < state->count; ++i) {
      short events = 0;
      if (state->read_flags[i] != 0) events = static_cast<short>(events | POLLIN);
      if (state->write_flags[i] != 0) events = static_cast<short>(events | POLLOUT);
      poll_fds[poll_count++] = pollfd{state->fds[i], events, 0};
    }
    const int ready = ::poll(poll_count > 0 ? poll_fds : nullptr,
                             static_cast<nfds_t>(poll_count), 50);
    ares_fd_events_t events[16]{};
    std::size_t event_count = 0;
    if (ready > 0) {
      for (int i = 0; i < poll_count; ++i) {
        unsigned int mask = 0;
        if ((poll_fds[i].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
          mask |= ARES_FD_EVENT_READ;
        }
        if ((poll_fds[i].revents & (POLLOUT | POLLERR)) != 0) {
          mask |= ARES_FD_EVENT_WRITE;
        }
        if (mask != 0) {
          events[event_count++] = ares_fd_events_t{poll_fds[i].fd, mask};
        }
      }
    }
    (void)ares_process_fds(channel, events, event_count, ARES_PROCESS_FLAG_NONE);
  }
  return true;
}

struct CaresAddressResult {
  bool done{false};
  int status{ARES_ENODATA};
  IpType4 address{};
  bool found{false};
};

inline void CaresAddressCallback(void* data, int status, int timeouts,
                                 ares_addrinfo* info) noexcept {
  (void)timeouts;
  auto* result = static_cast<CaresAddressResult*>(data);
  if (result == nullptr) {
    if (info != nullptr) ares_freeaddrinfo(info);
    return;
  }
  result->done = true;
  result->status = status;
  for (ares_addrinfo_node* node = info != nullptr ? info->nodes : nullptr; node != nullptr;
       node = node->ai_next) {
    if (node->ai_family != AF_INET || node->ai_addr == nullptr ||
        node->ai_addrlen < static_cast<ares_socklen_t>(sizeof(sockaddr_in))) {
      continue;
    }
    const auto* address = reinterpret_cast<const sockaddr_in*>(node->ai_addr);
    std::memcpy(result->address.octet, &address->sin_addr, 4);
    result->found = true;
    break;
  }
  if (info != nullptr) {
    ares_freeaddrinfo(info);
  }
}

struct CaresNameResult {
  bool done{false};
  int status{ARES_ENODATA};
  std::string name{};
};

inline void CaresNameCallback(void* data, int status, int timeouts, char* node,
                              char* service) noexcept {
  (void)timeouts;
  (void)service;
  auto* result = static_cast<CaresNameResult*>(data);
  if (result == nullptr) {
    return;
  }
  result->done = true;
  result->status = status;
  if (status == ARES_SUCCESS && node != nullptr) {
    result->name = node;
  }
}

/// Creates one channel with a bounded timeout and the local socket tracker.
inline ares_channel_t* CreateCaresChannel(CaresSocketState* state) noexcept {
  EnsureCaresInitialized();
  ares_options options{};
  options.timeout = kCaresTimeoutMs;
  options.sock_state_cb = &CaresSocketCallback;
  options.sock_state_cb_data = state;
  ares_channel_t* channel = nullptr;
  if (ares_init_options(&channel, &options,
                        ARES_OPT_TIMEOUTMS | ARES_OPT_SOCK_STATE_CB) != ARES_SUCCESS) {
    return nullptr;
  }
  return channel;
}

/// Creates a c-ares channel targeting a specific UDP DNS daemon endpoint.
inline ares_channel_t* CreateCaresDaemonChannel(const IpAddress& daemon_ip, uint16_t port,
                                                CaresSocketState* state) noexcept {
  if (daemon_ip.IsV6() || port == 0) {
    return nullptr;
  }
  EnsureCaresInitialized();
  char lookups[] = "b";
  ares_options options{};
  options.flags = ARES_FLAG_STAYOPEN | ARES_FLAG_NOSEARCH | ARES_FLAG_NOALIASES;
  options.timeout = kCaresTimeoutMs;
  options.tries = 1;
  options.ndots = 0;
  options.lookups = lookups;
  options.sock_state_cb = &CaresSocketCallback;
  options.sock_state_cb_data = state;
  ares_channel_t* channel = nullptr;
  if (ares_init_options(&channel, &options,
                        ARES_OPT_FLAGS | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_NDOTS |
                            ARES_OPT_LOOKUPS | ARES_OPT_SOCK_STATE_CB |
                            ARES_OPT_NOROTATE) != ARES_SUCCESS) {
    return nullptr;
  }
  const std::string server_csv =
      daemon_ip.ToString() + ":" + std::to_string(static_cast<unsigned>(port));
  if (ares_set_servers_ports_csv(channel, server_csv.c_str()) != ARES_SUCCESS) {
    ares_destroy(channel);
    return nullptr;
  }
  return channel;
}

struct CaresDnsrecResult {
  bool done{false};
  ares_status_t status{ARES_ENODATA};
  uint16_t expected_qtype{0};
  DnsAnswer answer{};
};

inline void CaresDnsrecCallback(void* arg, ares_status_t status, std::size_t timeouts,
                                const ares_dns_record_t* dnsrec) noexcept {
  (void)timeouts;
  auto* result = static_cast<CaresDnsrecResult*>(arg);
  if (result == nullptr) {
    return;
  }
  result->done = true;
  result->status = status;
  if (status != ARES_SUCCESS || dnsrec == nullptr) {
    return;
  }
  const auto want_type = static_cast<ares_dns_rec_type_t>(result->expected_qtype);
  if (ares_dns_record_get_rcode(dnsrec) != ARES_RCODE_NOERROR) {
    return;
  }
  const std::size_t count = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
  for (std::size_t i = 0; i < count; ++i) {
    const ares_dns_rr_t* rr =
        ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, i);
    if (rr == nullptr || ares_dns_rr_get_type(rr) != want_type) {
      continue;
    }
    if (want_type == ARES_REC_TYPE_A) {
      const in_addr* address = ares_dns_rr_get_addr(rr, ARES_RR_A_ADDR);
      if (address != nullptr) {
        std::memcpy(result->answer.address.octet, address, 4);
        result->answer.found = true;
        break;
      }
    } else if (want_type == ARES_REC_TYPE_PTR) {
      const char* name = ares_dns_rr_get_str(rr, ARES_RR_PTR_DNAME);
      if (name != nullptr) {
        result->answer.name = name;
        result->answer.found = true;
        break;
      }
    }
  }
}

/// Resolves `hostname` through the system resolver (c-ares, method `off`).
inline Result<IpType4> ResolveAddressWithCares(std::string_view hostname) noexcept {
  if (hostname.empty() || hostname.size() > kMaxHostLen ||
      hostname.find('\0') != std::string_view::npos) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }
  CaresSocketState state{};
  ares_channel_t* channel = CreateCaresChannel(&state);
  if (channel == nullptr) {
    return std::unexpected(make_error_code(ErrorCode::kDnsFailure));
  }
  CaresAddressResult result{};
  ares_addrinfo_hints hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  const std::string owned(hostname);
  ares_getaddrinfo(channel, owned.c_str(), nullptr, &hints, &CaresAddressCallback, &result);
  const bool completed = DriveCares(channel, &state, &result.done);
  ares_destroy(channel);
  if (!completed) {
    return std::unexpected(make_error_code(ErrorCode::kDnsFailure));
  }
  if (result.status != ARES_SUCCESS || !result.found) {
    return std::unexpected(make_error_code(ErrorCode::kDnsFailure));
  }
  return result.address;
}

/// Reverse-resolves an IPv4 address through the system resolver (c-ares).
inline std::optional<std::string> ResolveNameWithCares(IpType4 address) noexcept {
  CaresSocketState state{};
  ares_channel_t* channel = CreateCaresChannel(&state);
  if (channel == nullptr) {
    return std::nullopt;
  }
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  std::memcpy(&sa.sin_addr, address.octet, 4);
  CaresNameResult result{};
  ares_getnameinfo(channel, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa),
                   ARES_NI_NAMEREQD, &CaresNameCallback, &result);
  const bool completed = DriveCares(channel, &state, &result.done);
  ares_destroy(channel);
  if (!completed || result.status != ARES_SUCCESS || result.name.empty()) {
    return std::nullopt;
  }
  return result.name;
}

}  // namespace proxychains
