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
  static void cleanup(VMM_HANDLE h) {
    if (h) {
      VMMDLL_Close(h);
    }
  }
};

#ifdef _WIN32
template <> struct DefaultDeleter<HANDLE> {
  static void cleanup(HANDLE h) {
    if (h) {
      CloseHandle(h);
    }
  }
};
#endif

template <typename HandleType> class Handle {
public:
  using DeleterType = std::function<void(HandleType)>;

  Handle(const Handle &) = delete;
  Handle &operator=(const Handle &) = delete;

  Handle() : handle{}, deleter{} {}
  Handle(std::nullopt_t) : handle{}, deleter{} {}
  Handle(std::nullptr_t) : handle{}, deleter{} {}

  Handle(HandleType handle,
                std::function<void(HandleType handle)> deleter =
                    DefaultDeleter<HandleType>::cleanup)
      : handle(handle), deleter(std::move(deleter)) {}

  Handle(Handle &&other) noexcept
      : handle(std::exchange(other.handle, Handle())), deleter(std::move(other.deleter)) {}

  Handle &operator=(Handle &&other) noexcept {
    if (handle && deleter) {
      deleter(handle);
    }
    handle = other.handle;
    deleter = std::move(other.deleter);
    other.handle = {};
    return *this;
  }

  ~Handle() {
    if (handle && deleter) {
      deleter(handle);
    }
  }

  operator HandleType() const { return handle; }
  HandleType get() const { return handle; }

private:
  HandleType handle;
  std::function<void(HandleType handle)> deleter;
};

using VmmHandle = Handle<VMM_HANDLE>;

#ifdef _WIN32
using Win32Handle = Handle<HANDLE>;
#endif

template <typename HandleType>
Handle<HandleType> makeBorrowedHandle(HandleType handle) {
  return Handle<HandleType>(handle, [](HandleType) {});
}
} // namespace dmadump
