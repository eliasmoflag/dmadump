#pragma once
#include <type_traits>
#include <functional>
#include <vmmdll.h>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace dmadump {
template <typename T> struct DefaultDeleter;

template <> struct DefaultDeleter<VMM_HANDLE> {
  static inline void cleanup(VMM_HANDLE h) {
    if (h) {
      VMMDLL_Close(h);
    }
  }
};

template <> struct DefaultDeleter<HANDLE> {
  static inline void cleanup(HANDLE h) {
    if (h) {
      CloseHandle(h);
    }
  }
};

template <typename HandleType> class Handle {
public:
  using DeleterType = std::function<void(HandleType)>;

  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;

  inline Handle() : handle{}, deleter{} {}

  inline Handle(HandleType handle,
                std::function<void(HandleType handle)> deleter =
                    DefaultDeleter<HandleType>::cleanup)
      : handle(handle), deleter(std::move(deleter)) {}

  inline Handle(Handle &&other) noexcept
      : handle(other.handle), deleter(std::move(other.deleter)) {}

  inline Handle &operator=(Handle &&other) noexcept {
    if (handle && deleter) {
      deleter(handle);
    }
    handle = other.handle;
    deleter = std::move(other.deleter);
    other.handle = {};
    return *this;
  }

  inline ~Handle() {
    if (handle && deleter) {
      deleter(handle);
    }
  }

  inline operator HandleType() const { return handle; }
  inline HandleType get() const { return handle; }

private:
  HandleType handle;
  std::function<void(HandleType handle)> deleter;
};

using VmmHandle = Handle<VMM_HANDLE>;

#ifdef _WIN32
using Win32Handle = Handle<HANDLE>;
#endif

template <typename HandleType>
inline Handle<HandleType> makeBorrowedHandle(HandleType handle) {
  return Handle<HandleType>(handle, [](HandleType) {});
}
} // namespace dmadump
