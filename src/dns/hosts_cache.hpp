#pragma once

#include <optional>
#include <string_view>

#include "core/types.hpp"

namespace proxychains {

[[nodiscard]] std::optional<IpAddress> LookupEtcHosts(
    std::string_view hostname,
    std::string_view hosts_path = "/etc/hosts") noexcept;

}  // namespace proxychains
