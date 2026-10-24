#include "dns/fake_ip_table.hpp"

#include <pthread.h>

#include <mutex>
#include <utility>
#include <vector>

namespace proxychains {
namespace {

// ip_index lives in the low 24 bits and starts at 1, so  x.0.0.0 is never issued.
constexpr uint32_t kMaxIpIndex = 0x00FFFFFFu;

// The child keeps only the thread that called fork. Every live table is locked
// in that thread before the syscall and unlocked again on both sides.
struct ForkState {
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  std::vector<FakeIpTable*> tables;
  bool installed{false};
};

ForkState& State() noexcept {
  static ForkState state;
  return state;
}

}  // namespace

FakeIpTable::FakeIpTable(uint8_t remote_subnet) noexcept : remote_subnet_(remote_subnet) {
  ForkState& state = State();
  pthread_mutex_lock(&state.mutex);
  if (!state.installed) {
    state.installed = ::pthread_atfork(&FakeIpTable::PrepareProcessFork, &FakeIpTable::ParentProcessFork,
                                       &FakeIpTable::ChildProcessFork) == 0;
  }
  state.tables.push_back(this);
  pthread_mutex_unlock(&state.mutex);
}

FakeIpTable::~FakeIpTable() {
  ForkState& state = State();
  pthread_mutex_lock(&state.mutex);
  std::erase(state.tables, this);
  pthread_mutex_unlock(&state.mutex);
}

void FakeIpTable::AcquireForkLock() noexcept { mutex_.lock(); }

void FakeIpTable::ReleaseForkLock() noexcept { mutex_.unlock(); }

void FakeIpTable::PrepareProcessFork() noexcept {
  ForkState& state = State();
  pthread_mutex_lock(&state.mutex);
  for (FakeIpTable* table : state.tables) {
    table->mutex_.lock();
  }
}

void FakeIpTable::ParentProcessFork() noexcept {
  ForkState& state = State();
  for (FakeIpTable* table : state.tables) {
    table->mutex_.unlock();
  }
  pthread_mutex_unlock(&state.mutex);
}

void FakeIpTable::ChildProcessFork() noexcept {
  ForkState& state = State();
  for (FakeIpTable* table : state.tables) {
    table->mutex_.unlock();
  }
  pthread_mutex_unlock(&state.mutex);
}

void FakeIpTable::SetRemoteSubnet(uint8_t remote_subnet) noexcept {
  std::unique_lock lock(mutex_);
  remote_subnet_ = remote_subnet;
}

uint8_t FakeIpTable::GetRemoteSubnet() const noexcept {
  std::unique_lock lock(mutex_);
  return remote_subnet_;
}

Result<IpType4> FakeIpTable::GetOrAllocateIp(std::string_view hostname) noexcept {
  // The daemon wire image is a single C string, so an embedded NUL would truncate.
  if (hostname.empty() || hostname.size() > kMaxHostLen ||
      hostname.find('\0') != std::string_view::npos) {
    return std::unexpected(make_error_code(ErrorCode::kInvalidArgument));
  }

  const std::string key{hostname};
  {
    std::unique_lock lock(mutex_);
    const auto found = host_to_index_.find(key);
    if (found != host_to_index_.end()) {
      return MakeInternalIp(remote_subnet_, found->second);
    }
  }

  std::unique_lock lock(mutex_);
  const auto found = host_to_index_.find(key);
  if (found != host_to_index_.end()) {
    return MakeInternalIp(remote_subnet_, found->second);
  }
  if (index_to_host_.size() >= kMaxIpIndex) {
    return std::unexpected(make_error_code(ErrorCode::kMemoryExhausted));
  }

  const auto index = static_cast<uint32_t>(index_to_host_.size());
  index_to_host_.push_back(key);
  host_to_index_.emplace(index_to_host_.back(), index);
  return MakeInternalIp(remote_subnet_, index);
}

std::optional<std::string> FakeIpTable::GetHostnameForIp(IpType4 fake_ip) const noexcept {
  std::unique_lock lock(mutex_);
  if (fake_ip.octet[0] != remote_subnet_) {
    return std::nullopt;
  }
  const uint32_t index = IndexFromInternalIp(fake_ip);
  if (index >= index_to_host_.size()) {
    return std::nullopt;
  }
  return index_to_host_[index];
}

void FakeIpTable::Clear() noexcept {
  std::unique_lock lock(mutex_);
  index_to_host_.clear();
  host_to_index_.clear();
}

uint32_t FakeIpTable::IndexFromInternalIp(IpType4 internal_ip) noexcept {
  const uint32_t ip_index = (static_cast<uint32_t>(internal_ip.octet[1]) << 16) |
                            (static_cast<uint32_t>(internal_ip.octet[2]) << 8) |
                            static_cast<uint32_t>(internal_ip.octet[3]);
  return ip_index - 1U;
}

IpType4 FakeIpTable::MakeInternalIp(uint8_t subnet, uint32_t index) noexcept {
  if (index >= kMaxIpIndex) {
    return IPT4_INVALID;
  }
  const uint32_t ip_index = index + 1U;
  IpType4 ip{};
  ip.octet[0] = subnet;
  ip.octet[1] = static_cast<unsigned char>((ip_index >> 16) & 0xFFu);
  ip.octet[2] = static_cast<unsigned char>((ip_index >> 8) & 0xFFu);
  ip.octet[3] = static_cast<unsigned char>(ip_index & 0xFFu);
  return ip;
}

}  // namespace proxychains
