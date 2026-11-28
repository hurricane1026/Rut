#pragma once

namespace core {

template <typename T>
struct RemoveRef {
    using type = T;
};
template <typename T>
struct RemoveRef<T&> {
    using type = T;
};
template <typename T>
struct RemoveRef<T&&> {
    using type = T;
};
template <typename T>
using RemoveRef_t = typename RemoveRef<T>::type;

// Preserve the caller's value category without a C++ standard library header.
template <typename T>
[[nodiscard]] constexpr T&& forward(RemoveRef_t<T>& value) noexcept {
    return static_cast<T&&>(value);
}

template <typename T>
    requires(!__is_same(T, RemoveRef_t<T>&))
[[nodiscard]] constexpr T&& forward(RemoveRef_t<T>&& value) noexcept {
    return core::forward<T>(value);
}

template <typename T>
    requires(__is_same(T, RemoveRef_t<T>&))
[[nodiscard]] T&& forward(RemoveRef_t<T>&&) = delete;

}  // namespace core
