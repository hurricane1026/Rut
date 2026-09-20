#pragma once

#ifdef __APPLE__
// libc++ (already used by atomics and BoringSSL) annotates placement new with
// ABI tags. A hand-written forward declaration conflicts with that definition.
#include <new>
#else
#ifndef RUE_PLACEMENT_NEW_DECLARED
#define RUE_PLACEMENT_NEW_DECLARED
void* operator new(decltype(sizeof(0)), void* p) noexcept;
#endif
#endif
