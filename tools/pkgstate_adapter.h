// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <libpkgaudit/inventory.h>
#include <libpkgstate/snapshot.h>

namespace pkgchk {

[[nodiscard]] pkgaudit::inventory
make_inventory(const pkgstate::snapshot& state);

} // namespace pkgchk
