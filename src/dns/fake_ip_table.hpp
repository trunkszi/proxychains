#pragma once

#include <cstdint>
#include <optional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "core/error.hpp"
#include "core/types.hpp"

namespace proxychains {

class FakeIpTable {
 public:
  explicit FakeIpTable(uint8_t remote_subnet = 224) noexcept;
  ~FakeIpTable();

  FakeIpTable(const FakeIpTable&) = delete;
  FakeIpTable& operator=(const FakeIpTable&) = delete;
  FakeIpTable(FakeIpTable&&) = delete;
  FakeIpTable& operator=(FakeIpTable&&) = delete;

  void SetRemoteSubnet(uint8_t remote_subnet) noexcept;
  [[nodiscard]] uint8_t GetRemoteSubnet() const noexcept;

  [[nodiscard]] Result<IpType4> GetOrAllocateIp(std::string_view hostname) noexcept;
  [[nodiscard]] std::optional<std::string> GetHostnameForIp(IpType4 fake_ip) const noexcept;
  void Clear() noexcept;

  // Exclusive lock for the forking thread. prepare takes it; parent and child
  // release it. A thread must not wait for fork while holding this lock.
  void AcquireForkLock() noexcept;
  void ReleaseForkLock() noexcept;

  [[nodiscard]] static uint32_t IndexFromInternalIp(IpType4 internal_ip) noexcept;
  [[nodiscard]] static IpType4 MakeInternalIp(uint8_t subnet, uint32_t index) noexcept;

 private:
  static void PrepareProcessFork() noexcept;
  static void ParentProcessFork() noexcept;
  static void ChildProcessFork() noexcept;

  // Plain mutex: a rwlock records the writer tid, which the child cannot unlock.
  mutable std::mutex mutex_{};
  uint8_t remote_subnet_{224};
  std::vector<std::string> index_to_host_{};
  std::unordered_map<std::string, uint32_t> host_to_index_{};
};

}  // namespace proxychains
