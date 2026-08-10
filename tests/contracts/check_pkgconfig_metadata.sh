#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

build=$1
expected_version=$2
pc=$build/meson-private/libpkgaudit.pc
fail()
{
  echo "pkgconfig-metadata-contract: $*" >&2
  [ ! -f "$pc" ] || cat "$pc" >&2
  exit 1
}

[ -s "$pc" ] || fail 'generated libpkgaudit.pc is missing'
version=$(sed -n 's/^Version:[[:space:]]*//p' "$pc")
[ "$version" = "$expected_version" ] ||
  fail "version is '$version', expected '$expected_version'"

grep -F 'Cflags: -I${includedir}' "$pc" >/dev/null ||
  fail 'pkg-config include root does not support <libpkgaudit/...> headers'
if grep -E '^Requires(\.private)?:' "$pc" >/dev/null; then
  fail 'dependency metadata escaped into the dependency-free library'
fi

printf '%s\n' 'pkgconfig-metadata-contract: ok'
