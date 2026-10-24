#include "core/error.hpp"

#include <string>

namespace proxychains {
namespace {

class ProxychainsErrorCategoryImpl final : public std::error_category {
 public:
  [[nodiscard]] const char* name() const noexcept override { return "proxychains"; }

  [[nodiscard]] std::string message(int value) const override {
    switch (static_cast<ErrorCode>(value)) {
      case ErrorCode::kSuccess:
        return "success";
      case ErrorCode::kInvalidArgument:
        return "invalid argument";
      case ErrorCode::kConfigNotFound:
        return "configuration file not found";
      case ErrorCode::kConfigParseError:
        return "configuration parse error";
      case ErrorCode::kMemoryExhausted:
        return "memory exhausted";
      case ErrorCode::kSocketError:
        return "socket error";
      case ErrorCode::kTimeout:
        return "operation timed out";
      case ErrorCode::kChainDown:
        return "proxy chain is down";
      case ErrorCode::kChainEmpty:
        return "proxy chain is empty";
      case ErrorCode::kProxyBlocked:
        return "proxy is blocked";
      case ErrorCode::kDnsFailure:
        return "DNS resolution failed";
      case ErrorCode::kProtocolError:
        return "protocol error";
      case ErrorCode::kSystemError:
        return "system error";
    }
    return "unknown proxychains error";
  }
};

}  // namespace

const std::error_category& ProxychainsErrorCategory() noexcept {
  static const ProxychainsErrorCategoryImpl category{};
  return category;
}

std::error_code make_error_code(ErrorCode code) noexcept {
  return std::error_code(static_cast<int>(code), ProxychainsErrorCategory());
}

}  // namespace proxychains
