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

#include "epoll_tls_test_hooks.h"

#include <atomic>

namespace rut {

namespace {

std::atomic<const EpollTlsHooks*> g_test_tls_hooks = nullptr;

}  // namespace

const EpollTlsHooks* get_epoll_tls_hooks_for_test() {
    return g_test_tls_hooks.load(std::memory_order_acquire);
}

void set_epoll_tls_hooks_for_test(const EpollTlsHooks* hooks) {
    g_test_tls_hooks.store(hooks, std::memory_order_release);
}

void reset_epoll_tls_hooks_for_test() {
    g_test_tls_hooks.store(nullptr, std::memory_order_release);
}

}  // namespace rut
