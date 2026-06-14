/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

// Expected<T, E> — C++23 std::expected equivalent, no stdlib dependency.
//
// Usage:
//   Expected<int, ErrorCode> parse(const char* s);
//   auto result = parse("42");
//   if (result) use(result.value());
//   else handle(result.error());
//
// Monadic:
//   parse("42").and_then(validate).or_else(log_error);

// Placement new — declaration only; definition lives in a single TU.
// Guarded so mixed inclusion with <new> or arena.h won't conflict.
#ifndef RUE_PLACEMENT_NEW_DECLARED
#define RUE_PLACEMENT_NEW_DECLARED
void* operator new(decltype(sizeof(0)), void* p) noexcept;
#endif

namespace core {

// ── Type traits (no <type_traits>) ──────────────────────────────────

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

template <typename T>
struct RemoveCv {
    using type = T;
};
template <typename T>
struct RemoveCv<const T> {
    using type = T;
};
template <typename T>
struct RemoveCv<volatile T> {
    using type = T;
};
template <typename T>
struct RemoveCv<const volatile T> {
    using type = T;
};

template <typename T>
using RemoveCvRef_t = typename RemoveCv<RemoveRef_t<T>>::type;

// Default-constructibility detection
template <typename T, typename = void>
struct IsDefaultConstructible {
    static constexpr bool value = false;
};
template <typename T>
struct IsDefaultConstructible<T, decltype(void(T{}))> {
    static constexpr bool value = true;
};

// ── Unexpected wrapper (tags the error value) ────────────────────────

template <typename E>
struct Unexpected {
    E val;

    constexpr explicit Unexpected(const E& e) : val(e) {}
    constexpr explicit Unexpected(E&& e) : val(static_cast<E&&>(e)) {}

    constexpr const E& value() const& { return val; }
    constexpr E& value() & { return val; }
    constexpr E&& value() && { return static_cast<E&&>(val); }
};

template <typename E>
Unexpected(E) -> Unexpected<E>;

// ── Forward declaration ──────────────────────────────────────────────

template <typename T, typename E>
class Expected;

// ── Storage: discriminated union via placement + aligned_storage ─────

namespace detail {

// alignof / sizeof max helper
template <typename A, typename B>
struct MaxAlign {
    static constexpr auto value = alignof(A) > alignof(B) ? alignof(A) : alignof(B);
};

template <typename A, typename B>
struct MaxSize {
    static constexpr auto value = sizeof(A) > sizeof(B) ? sizeof(A) : sizeof(B);
};

// __builtin_launder: required after destroy + reconstruct in the same storage
// to ensure the compiler sees the new object, not a stale cached value.
template <typename T>
constexpr T* launder(T* p) noexcept {
    return __builtin_launder(p);
}

template <typename T, typename E>
struct Storage {
    alignas(MaxAlign<T, E>::value) char buf[MaxSize<T, E>::value];
    bool has_val;

    // Construct value
    template <typename... Args>
    constexpr void construct_val(Args&&... args) {
        ::new (static_cast<void*>(buf)) T(static_cast<Args&&>(args)...);
        has_val = true;
    }

    // Construct error
    template <typename... Args>
    constexpr void construct_err(Args&&... args) {
        ::new (static_cast<void*>(buf)) E(static_cast<Args&&>(args)...);
        has_val = false;
    }

    constexpr T& val() { return *launder(reinterpret_cast<T*>(buf)); }
    constexpr const T& val() const { return *launder(reinterpret_cast<const T*>(buf)); }
    constexpr E& err() { return *launder(reinterpret_cast<E*>(buf)); }
    constexpr const E& err() const { return *launder(reinterpret_cast<const E*>(buf)); }

    constexpr void destroy() {
        if (has_val)
            val().~T();
        else
            err().~E();
    }
};

// Void specialization — no value storage, only error
template <typename E>
struct Storage<void, E> {
    alignas(alignof(E)) char buf[sizeof(E)];
    bool has_val;

    constexpr void construct_val() { has_val = true; }

    template <typename... Args>
    constexpr void construct_err(Args&&... args) {
        ::new (static_cast<void*>(buf)) E(static_cast<Args&&>(args)...);
        has_val = false;
    }

    constexpr E& err() { return *launder(reinterpret_cast<E*>(buf)); }
    constexpr const E& err() const { return *launder(reinterpret_cast<const E*>(buf)); }

    constexpr void destroy() {
        if (!has_val) err().~E();
    }
};

}  // namespace detail

// ── Expected<T, E> ──────────────────────────────────────────────────

template <typename T, typename E>
class Expected {
    detail::Storage<T, E> stor_;

public:
    using value_type = T;
    using error_type = E;

    // ── Constructors ────────────────────────────────────────────────

    // Default: value-initialize T (only when T is default-constructible)
    constexpr Expected()
        requires(IsDefaultConstructible<T>::value)
    {
        stor_.construct_val();
    }

    // Implicit from T (value)
    constexpr Expected(const T& v) { stor_.construct_val(v); }
    constexpr Expected(T&& v) { stor_.construct_val(static_cast<T&&>(v)); }

    // From Unexpected<E> (error)
    constexpr Expected(const Unexpected<E>& u) { stor_.construct_err(u.value()); }
    constexpr Expected(Unexpected<E>&& u) { stor_.construct_err(static_cast<E&&>(u.value())); }

    // Copy
    constexpr Expected(const Expected& o) {
        if (o.stor_.has_val)
            stor_.construct_val(o.stor_.val());
        else
            stor_.construct_err(o.stor_.err());
    }

    // Move
    constexpr Expected(Expected&& o) {
        if (o.stor_.has_val)
            stor_.construct_val(static_cast<T&&>(o.stor_.val()));
        else
            stor_.construct_err(static_cast<E&&>(o.stor_.err()));
    }

    ~Expected() { stor_.destroy(); }

    // ── Assignment ──────────────────────────────────────────────────

    constexpr Expected& operator=(const Expected& o) {
        if (this != &o) {
            stor_.destroy();
            if (o.stor_.has_val)
                stor_.construct_val(o.stor_.val());
            else
                stor_.construct_err(o.stor_.err());
        }
        return *this;
    }

    constexpr Expected& operator=(Expected&& o) {
        if (this != &o) {
            stor_.destroy();
            if (o.stor_.has_val)
                stor_.construct_val(static_cast<T&&>(o.stor_.val()));
            else
                stor_.construct_err(static_cast<E&&>(o.stor_.err()));
        }
        return *this;
    }

    // ── Observers ───────────────────────────────────────────────────

    constexpr bool has_value() const { return stor_.has_val; }
    constexpr explicit operator bool() const { return stor_.has_val; }

    constexpr T& value() & { return stor_.val(); }
    constexpr const T& value() const& { return stor_.val(); }
    constexpr T&& value() && { return static_cast<T&&>(stor_.val()); }

    constexpr T& operator*() & { return stor_.val(); }
    constexpr const T& operator*() const& { return stor_.val(); }
    constexpr T* operator->() { return &stor_.val(); }
    constexpr const T* operator->() const { return &stor_.val(); }

    constexpr E& error() & { return stor_.err(); }
    constexpr const E& error() const& { return stor_.err(); }
    constexpr E&& error() && { return static_cast<E&&>(stor_.err()); }

    // ── value_or ────────────────────────────────────────────────────

    template <typename U>
    constexpr T value_or(U&& fallback) const& {
        return has_value() ? value() : static_cast<T>(static_cast<U&&>(fallback));
    }

    template <typename U>
    constexpr T value_or(U&& fallback) && {
        return has_value() ? static_cast<T&&>(stor_.val())
                           : static_cast<T>(static_cast<U&&>(fallback));
    }

    // ── Monadic operations ──────────────────────────────────────────

    // and_then: F(T) -> Expected<U, E>
    // Chains operations that can fail. Short-circuits on error.
    template <typename F>
    constexpr auto and_then(F&& f) & {
        using R = decltype(static_cast<F&&>(f)(stor_.val()));
        if (has_value()) return static_cast<F&&>(f)(stor_.val());
        return R(Unexpected<E>(stor_.err()));
    }

    template <typename F>
    constexpr auto and_then(F&& f) const& {
        using R = decltype(static_cast<F&&>(f)(stor_.val()));
        if (has_value()) return static_cast<F&&>(f)(stor_.val());
        return R(Unexpected<E>(stor_.err()));
    }

    template <typename F>
    constexpr auto and_then(F&& f) && {
        using R = decltype(static_cast<F&&>(f)(static_cast<T&&>(stor_.val())));
        if (has_value()) return static_cast<F&&>(f)(static_cast<T&&>(stor_.val()));
        return R(Unexpected<E>(static_cast<E&&>(stor_.err())));
    }

    // or_else: F(E) -> R, where R = decltype(f(error)) and R is constructible from T.
    // Handles/recovers from errors. If *this has a value, returns R(value()).
    template <typename F>
    constexpr auto or_else(F&& f) & {
        using R = decltype(static_cast<F&&>(f)(stor_.err()));
        if (has_value()) return R(stor_.val());
        return static_cast<F&&>(f)(stor_.err());
    }

    template <typename F>
    constexpr auto or_else(F&& f) const& {
        using R = decltype(static_cast<F&&>(f)(stor_.err()));
        if (has_value()) return R(stor_.val());
        return static_cast<F&&>(f)(stor_.err());
    }

    template <typename F>
    constexpr auto or_else(F&& f) && {
        using R = decltype(static_cast<F&&>(f)(static_cast<E&&>(stor_.err())));
        if (has_value()) return R(static_cast<T&&>(stor_.val()));
        return static_cast<F&&>(f)(static_cast<E&&>(stor_.err()));
    }

    // transform: F(T) -> U (plain value, not Expected)
    // Maps the value. Wraps result in Expected<U, E>.
    template <typename F>
    constexpr auto transform(F&& f) & {
        using U = decltype(static_cast<F&&>(f)(stor_.val()));
        if (has_value()) return Expected<U, E>(static_cast<F&&>(f)(stor_.val()));
        return Expected<U, E>(Unexpected<E>(stor_.err()));
    }

    template <typename F>
    constexpr auto transform(F&& f) const& {
        using U = decltype(static_cast<F&&>(f)(stor_.val()));
        if (has_value()) return Expected<U, E>(static_cast<F&&>(f)(stor_.val()));
        return Expected<U, E>(Unexpected<E>(stor_.err()));
    }

    template <typename F>
    constexpr auto transform(F&& f) && {
        using U = decltype(static_cast<F&&>(f)(static_cast<T&&>(stor_.val())));
        if (has_value()) return Expected<U, E>(static_cast<F&&>(f)(static_cast<T&&>(stor_.val())));
        return Expected<U, E>(Unexpected<E>(static_cast<E&&>(stor_.err())));
    }
};

// ── Expected<void, E> specialization ────────────────────────────────

template <typename E>
class Expected<void, E> {
    detail::Storage<void, E> stor_;

public:
    using value_type = void;
    using error_type = E;

    // Success
    constexpr Expected() { stor_.construct_val(); }

    // Error
    constexpr Expected(const Unexpected<E>& u) { stor_.construct_err(u.value()); }
    constexpr Expected(Unexpected<E>&& u) { stor_.construct_err(static_cast<E&&>(u.value())); }

    // Copy / Move
    constexpr Expected(const Expected& o) {
        if (o.stor_.has_val)
            stor_.construct_val();
        else
            stor_.construct_err(o.stor_.err());
    }

    constexpr Expected(Expected&& o) {
        if (o.stor_.has_val)
            stor_.construct_val();
        else
            stor_.construct_err(static_cast<E&&>(o.stor_.err()));
    }

    ~Expected() { stor_.destroy(); }

    constexpr Expected& operator=(const Expected& o) {
        if (this != &o) {
            stor_.destroy();
            if (o.stor_.has_val)
                stor_.construct_val();
            else
                stor_.construct_err(o.stor_.err());
        }
        return *this;
    }

    constexpr Expected& operator=(Expected&& o) {
        if (this != &o) {
            stor_.destroy();
            if (o.stor_.has_val)
                stor_.construct_val();
            else
                stor_.construct_err(static_cast<E&&>(o.stor_.err()));
        }
        return *this;
    }

    constexpr bool has_value() const { return stor_.has_val; }
    constexpr explicit operator bool() const { return stor_.has_val; }

    constexpr E& error() & { return stor_.err(); }
    constexpr const E& error() const& { return stor_.err(); }
    constexpr E&& error() && { return static_cast<E&&>(stor_.err()); }
};

// ── Helper: construct Unexpected ────────────────────────────────────

template <typename E>
constexpr Unexpected<RemoveCvRef_t<E>> make_unexpected(E&& e) {
    return Unexpected<RemoveCvRef_t<E>>(static_cast<E&&>(e));
}

}  // namespace core

// ── TRY macro — Rust-style ? operator ───────────────────────────────
//
// Usage:
//   Expected<int, Err> foo() {
//       auto val = TRY(bar());   // early-return Unexpected on error
//       return val + 1;
//   }
//
// Uses GCC/Clang statement expression extension ({}).
// __COUNTER__ ensures unique variable names when TRY/TRY_VOID are used
// multiple times on the same line (e.g. TRY(a) + TRY(b)).

#define TRY_CONCAT_(a, b) a##b
#define TRY_CONCAT(a, b) TRY_CONCAT_(a, b)

// Internal helpers that take a unique suffix generated by __COUNTER__.
#define TRY_IMPL(expr, uniq)                                                                       \
    __extension__({                                                                                \
        auto&& TRY_CONCAT(_try_r_, uniq) = (expr);                                                 \
        if (!TRY_CONCAT(_try_r_, uniq))                                                            \
            return ::core::make_unexpected(                                                        \
                static_cast<decltype(TRY_CONCAT(_try_r_, uniq))&&>(TRY_CONCAT(_try_r_, uniq))      \
                    .error());                                                                     \
        auto TRY_CONCAT(_try_v_, uniq) =                                                           \
            static_cast<decltype(TRY_CONCAT(_try_r_, uniq))&&>(TRY_CONCAT(_try_r_, uniq)).value(); \
        TRY_CONCAT(_try_v_, uniq);                                                                 \
    })

#define TRY_VOID_IMPL(expr, uniq)                                                             \
    do {                                                                                      \
        auto&& TRY_CONCAT(_try_r_, uniq) = (expr);                                            \
        if (!TRY_CONCAT(_try_r_, uniq))                                                       \
            return ::core::make_unexpected(                                                   \
                static_cast<decltype(TRY_CONCAT(_try_r_, uniq))&&>(TRY_CONCAT(_try_r_, uniq)) \
                    .error());                                                                \
    } while (0)

// TRY: unwrap Expected<T, E> -> T, early-return on error
#define TRY(expr) TRY_IMPL(expr, __COUNTER__)

// TRY_VOID: unwrap Expected<void, E>, early-return on error, no value
#define TRY_VOID(expr) TRY_VOID_IMPL(expr, __COUNTER__)
