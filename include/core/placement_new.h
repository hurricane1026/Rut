#pragma once

#ifdef __APPLE__
// A template overload supplies placement construction without declaring
// libc++'s ABI-tagged non-template overload. If libc++ is also included, its
// non-template overload wins overload resolution without a redeclaration.
template <typename = void>
inline void* operator new(decltype(sizeof(0)), void* p) noexcept {
    return p;
}
#else
#ifndef RUE_PLACEMENT_NEW_DECLARED
#define RUE_PLACEMENT_NEW_DECLARED
void* operator new(decltype(sizeof(0)), void* p) noexcept;
#endif
#endif
