#include "protocol/tunnel_fsm.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "protocol/socket_io.hpp"

namespace proxychains {
namespace {

enum class HandshakeState : uint8_t {
  kRaw,
  kHttpSend,
  kHttpRead,
  kHttpValidate,
  kSocks4Send,
  kSocks4Read,
  kSocks5GreetingSend,
  kSocks5GreetingRead,
  kSocks5AuthSend,
  kSocks5AuthRead,
  kSocks5RequestSend,
  kSocks5ReplyHead,
  kSocks5ReplyAddress,
  kDone,
  kFailed,
};

constexpr std::size_t kHttpHeaderCapacity = 8192;
constexpr uint8_t kSocks5Version = 0x05;
constexpr uint8_t kSocks5NoAuth = 0x00;
constexpr uint8_t kSocks5UserPass = 0x02;
constexpr uint8_t kSocks4Version = 0x04;
constexpr uint8_t kSocks4Granted = 0x5a;
constexpr uint8_t kSocks4Rejected = 0x5b;
constexpr uint8_t kSocks5AtypV4 = 0x01;
constexpr uint8_t kSocks5AtypDomain = 0x03;
constexpr uint8_t kSocks5AtypV6 = 0x04;

std::string FormatAuthority(std::string_view domain, const IpAddress& ip,
                            uint16_t port_host) noexcept {
  if (!domain.empty()) {
    return std::string(domain) + ":" + std::to_string(port_host);
  }
  std::string host = ip.ToString();
  if (ip.IsV6()) {
    host = "[" + host + "]";
  }
  return host + ":" + std::to_string(port_host);
}

void AppendByte(std::vector<uint8_t>& out, uint8_t value) noexcept { out.push_back(value); }

void AppendPort(std::vector<uint8_t>& out, uint16_t port_host) noexcept {
  out.push_back(static_cast<uint8_t>((port_host >> 8) & 0xff));
  out.push_back(static_cast<uint8_t>(port_host & 0xff));
}

void AppendBoundedString(std::vector<uint8_t>& out, std::string_view text,
                         std::size_t max_len) noexcept {
  const std::size_t length = text.size() < max_len ? text.size() : max_len;
  out.insert(out.end(), text.begin(), text.begin() + static_cast<std::ptrdiff_t>(length));
}

bool IsHttpSpace(char c) noexcept { return c == ' ' || c == '\t'; }

bool ValidateHttpStatus(std::span<const uint8_t> head, int& status_code) noexcept {
  const std::string_view text(reinterpret_cast<const char*>(head.data()), head.size());
  const std::size_t line_end = text.find("\r\n");
  if (line_end == std::string_view::npos) {
    return false;
  }
  const std::string_view line = text.substr(0, line_end);
  if (line.size() < 12 || line.compare(0, 7, "HTTP/1.") != 0) {
    return false;
  }
  std::size_t pos = 7;
  const std::size_t minor_start = pos;
  while (pos < line.size() && line[pos] >= '0' && line[pos] <= '9') {
    ++pos;
  }
  if (pos == minor_start || pos >= line.size() || !IsHttpSpace(line[pos])) {
    return false;
  }
  while (pos < line.size() && IsHttpSpace(line[pos])) {
    ++pos;
  }
  if (pos + 3 > line.size()) {
    return false;
  }
  int parsed = 0;
  for (std::size_t i = 0; i < 3; ++i) {
    const char digit = line[pos + i];
    if (digit < '0' || digit > '9') {
      return false;
    }
    parsed = parsed * 10 + (digit - '0');
  }
  pos += 3;
  if (pos < line.size() && !IsHttpSpace(line[pos])) {
    return false;
  }
  status_code = parsed;
  return true;
}

}  // namespace

Result<void> EstablishProxyTunnel(int sock_fd,
                                  const ProxyEndpoint& proxy,
                                  const IpAddress& target_ip,
                                  uint16_t target_port_host,
                                  std::string_view target_domain,
                                  int read_timeout_ms) noexcept {
  if (sock_fd < 0 || read_timeout_ms <= 0) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }

  HandshakeState state = HandshakeState::kFailed;
  switch (proxy.type) {
    case ProxyType::kRaw:
      state = HandshakeState::kRaw;
      break;
    case ProxyType::kHttp:
      state = HandshakeState::kHttpSend;
      break;
    case ProxyType::kSocks4:
      state = HandshakeState::kSocks4Send;
      break;
    case ProxyType::kSocks5:
      state = HandshakeState::kSocks5GreetingSend;
      break;
  }

  std::error_code failure = make_error_code(ErrorCode::kProtocolError);
  std::vector<uint8_t> request;
  std::vector<uint8_t> response;
  std::size_t reply_address_length = 0;
  bool user_pass_offered = false;

  while (state != HandshakeState::kDone && state != HandshakeState::kFailed) {
    switch (state) {
      case HandshakeState::kRaw:
        state = HandshakeState::kDone;
        break;

      case HandshakeState::kHttpSend: {
        request.clear();
        const std::string target = FormatAuthority(target_domain, target_ip, target_port_host);
        std::string head = "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n";
        if (!proxy.user.empty() || !proxy.pass.empty()) {
          head += "Proxy-Authorization: Basic " +
                  EncodeBase64(proxy.user + ":" + proxy.pass) + "\r\n";
        }
        head += "\r\n";
        request.assign(head.begin(), head.end());
        const auto written = PollWriteAll(sock_fd, request, read_timeout_ms);
        if (!written.has_value()) {
          failure = written.error();
          state = HandshakeState::kFailed;
          break;
        }
        state = HandshakeState::kHttpRead;
        break;
      }

      case HandshakeState::kHttpRead: {
        response.assign(kHttpHeaderCapacity, 0);
        const auto count = PollReadHttpHeaders(sock_fd, response, read_timeout_ms);
        if (!count.has_value()) {
          failure = count.error();
          state = HandshakeState::kFailed;
          break;
        }
        response.resize(count.value());
        state = HandshakeState::kHttpValidate;
        break;
      }

      case HandshakeState::kHttpValidate: {
        int status_code = 0;
        if (!ValidateHttpStatus(response, status_code)) {
          failure = make_error_code(ErrorCode::kProtocolError);
          state = HandshakeState::kFailed;
          break;
        }
        if (status_code >= 200 && status_code <= 299) {
          state = HandshakeState::kDone;
        } else {
          failure = make_error_code(ErrorCode::kProxyBlocked);
          state = HandshakeState::kFailed;
        }
        break;
      }

      case HandshakeState::kSocks4Send: {
        if (target_ip.IsV6()) {
          failure = make_error_code(ErrorCode::kProtocolError);
          state = HandshakeState::kFailed;
          break;
        }
        request.clear();
        AppendByte(request, kSocks4Version);
        AppendByte(request, 0x01);
        AppendPort(request, target_port_host);
        if (!target_domain.empty()) {
          AppendByte(request, 0x00);
          AppendByte(request, 0x00);
          AppendByte(request, 0x00);
          AppendByte(request, 0x01);
          AppendBoundedString(request, proxy.user, kMaxHostLen);
          AppendByte(request, 0x00);
          AppendBoundedString(request, target_domain, kMaxHostLen);
          AppendByte(request, 0x00);
        } else {
          const auto& octets = target_ip.V4Bytes();
          request.insert(request.end(), octets.begin(), octets.end());
          AppendBoundedString(request, proxy.user, kMaxHostLen);
          AppendByte(request, 0x00);
        }
        const auto written = PollWriteAll(sock_fd, request, read_timeout_ms);
        if (!written.has_value()) {
          failure = written.error();
          state = HandshakeState::kFailed;
          break;
        }
        state = HandshakeState::kSocks4Read;
        break;
      }

      case HandshakeState::kSocks4Read: {
        response.assign(8, 0);
        const auto read = PollReadExact(sock_fd, response, read_timeout_ms);
        if (!read.has_value()) {
          failure = read.error();
          state = HandshakeState::kFailed;
          break;
        }
        if (response[0] != 0x00) {
          failure = make_error_code(ErrorCode::kProtocolError);
          state = HandshakeState::kFailed;
          break;
        }
        if (response[1] == kSocks4Granted) {
          state = HandshakeState::kDone;
        } else if (response[1] == kSocks4Rejected) {
          failure = make_error_code(ErrorCode::kProxyBlocked);
          state = HandshakeState::kFailed;
        } else {
          failure = make_error_code(ErrorCode::kProtocolError);
          state = HandshakeState::kFailed;
        }
        break;
      }

      case HandshakeState::kSocks5GreetingSend: {
        request.clear();
        AppendByte(request, kSocks5Version);
        user_pass_offered = !proxy.user.empty() || !proxy.pass.empty();
        if (user_pass_offered) {
          AppendByte(request, 0x02);
          AppendByte(request, kSocks5NoAuth);
          AppendByte(request, kSocks5UserPass);
        } else {
          AppendByte(request, 0x01);
          AppendByte(request, kSocks5NoAuth);
        }
        const auto written = PollWriteAll(sock_fd, request, read_timeout_ms);
        if (!written.has_value()) {
          failure = written.error();
          state = HandshakeState::kFailed;
          break;
        }
        state = HandshakeState::kSocks5GreetingRead;
        break;
      }

      case HandshakeState::kSocks5GreetingRead: {
        response.assign(2, 0);
        const auto read = PollReadExact(sock_fd, response, read_timeout_ms);
        if (!read.has_value()) {
          failure = read.error();
          state = HandshakeState::kFailed;
          break;
        }
        if (response[0] != kSocks5Version) {
          failure = make_error_code(ErrorCode::kProtocolError);
          state = HandshakeState::kFailed;
        } else if (response[1] == kSocks5NoAuth) {
          state = HandshakeState::kSocks5RequestSend;
        } else if (response[1] == kSocks5UserPass && user_pass_offered) {
          state = HandshakeState::kSocks5AuthSend;
        } else if (response[1] == 0xff) {
          failure = make_error_code(ErrorCode::kProxyBlocked);
          state = HandshakeState::kFailed;
        } else {
          failure = make_error_code(ErrorCode::kProtocolError);
          state = HandshakeState::kFailed;
        }
        break;
      }

      case HandshakeState::kSocks5AuthSend: {
        request.clear();
        AppendByte(request, 0x01);
        const std::size_t user_length =
            proxy.user.size() < kMaxHostLen ? proxy.user.size() : kMaxHostLen;
        AppendByte(request, static_cast<uint8_t>(user_length));
        AppendBoundedString(request, proxy.user, kMaxHostLen);
        const std::size_t pass_length =
            proxy.pass.size() < kMaxHostLen ? proxy.pass.size() : kMaxHostLen;
        AppendByte(request, static_cast<uint8_t>(pass_length));
        AppendBoundedString(request, proxy.pass, kMaxHostLen);
        const auto written = PollWriteAll(sock_fd, request, read_timeout_ms);
        if (!written.has_value()) {
          failure = written.error();
          state = HandshakeState::kFailed;
          break;
        }
        state = HandshakeState::kSocks5AuthRead;
        break;
      }

      case HandshakeState::kSocks5AuthRead: {
        response.assign(2, 0);
        const auto read = PollReadExact(sock_fd, response, read_timeout_ms);
        if (!read.has_value()) {
          failure = read.error();
          state = HandshakeState::kFailed;
          break;
        }
        if (response[1] == 0x00) {
          state = HandshakeState::kSocks5RequestSend;
        } else {
          failure = make_error_code(ErrorCode::kProxyBlocked);
          state = HandshakeState::kFailed;
        }
        break;
      }

      case HandshakeState::kSocks5RequestSend: {
        request.clear();
        AppendByte(request, kSocks5Version);
        AppendByte(request, 0x01);
        AppendByte(request, 0x00);
        const std::size_t domain_length =
            target_domain.size() < kMaxHostLen ? target_domain.size() : kMaxHostLen;
        if (domain_length > 0) {
          AppendByte(request, kSocks5AtypDomain);
          AppendByte(request, static_cast<uint8_t>(domain_length));
          AppendBoundedString(request, target_domain, kMaxHostLen);
        } else if (target_ip.IsV6()) {
          AppendByte(request, kSocks5AtypV6);
          const auto& bytes = target_ip.V6Bytes();
          request.insert(request.end(), bytes.begin(), bytes.end());
        } else {
          AppendByte(request, kSocks5AtypV4);
          const auto& bytes = target_ip.V4Bytes();
          request.insert(request.end(), bytes.begin(), bytes.end());
        }
        AppendPort(request, target_port_host);
        const auto written = PollWriteAll(sock_fd, request, read_timeout_ms);
        if (!written.has_value()) {
          failure = written.error();
          state = HandshakeState::kFailed;
          break;
        }
        state = HandshakeState::kSocks5ReplyHead;
        break;
      }

      case HandshakeState::kSocks5ReplyHead: {
        response.assign(4, 0);
        const auto read = PollReadExact(sock_fd, response, read_timeout_ms);
        if (!read.has_value()) {
          failure = read.error();
          state = HandshakeState::kFailed;
          break;
        }
        if (response[0] != kSocks5Version) {
          failure = make_error_code(ErrorCode::kProtocolError);
          state = HandshakeState::kFailed;
          break;
        }
        if (response[1] != 0x00) {
          failure = make_error_code(ErrorCode::kProxyBlocked);
          state = HandshakeState::kFailed;
          break;
        }
        switch (response[3]) {
          case kSocks5AtypV4:
            reply_address_length = 4 + 2;
            break;
          case kSocks5AtypV6:
            reply_address_length = 16 + 2;
            break;
          case kSocks5AtypDomain: {
            uint8_t domain_length = 0;
            const auto length_read = PollReadExact(
                sock_fd, std::span<uint8_t>(&domain_length, 1), read_timeout_ms);
            if (!length_read.has_value()) {
              failure = length_read.error();
              state = HandshakeState::kFailed;
              break;
            }
            reply_address_length = static_cast<std::size_t>(domain_length) + 2;
            break;
          }
          default:
            failure = make_error_code(ErrorCode::kProtocolError);
            state = HandshakeState::kFailed;
            break;
        }
        if (state == HandshakeState::kFailed) {
          break;
        }
        state = HandshakeState::kSocks5ReplyAddress;
        break;
      }

      case HandshakeState::kSocks5ReplyAddress: {
        response.assign(reply_address_length, 0);
        const auto read = PollReadExact(sock_fd, response, read_timeout_ms);
        if (!read.has_value()) {
          failure = read.error();
          state = HandshakeState::kFailed;
          break;
        }
        state = HandshakeState::kDone;
        break;
      }

      case HandshakeState::kDone:
      case HandshakeState::kFailed:
        break;
    }
  }

  if (state == HandshakeState::kFailed) {
    return std::unexpected(failure);
  }
  return {};
}

}  // namespace proxychains
