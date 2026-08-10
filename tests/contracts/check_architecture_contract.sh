#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

root=$1
fail()
{
  echo "architecture-contract: $*" >&2
  exit 1
}

if find "$root/include" "$root/src" -type f \
    \( -name '*.h' -o -name '*.cpp' \) -exec \
    grep -nE '#[[:space:]]*include[[:space:]]*<libpkg(state|image|core|apply|plan|transaction)/' {} + \
    | grep . >/dev/null; then
  fail 'library imports package-state or neighboring package authority headers'
fi

if grep -RIn 'libpkgstate_dep' "$root/src" "$root/include" >/dev/null; then
  fail 'library build surface acquired the frontend package-state dependency'
fi

grep -F "gnu_symbol_visibility: 'hidden'" "$root/src/meson.build" >/dev/null ||
  fail 'shared-library hidden visibility is not enforced'
grep -F 'libpkgaudit.exports' "$root/meson.build" >/dev/null ||
  fail 'reviewed export surface is not wired into the build'

grep -F "if get_option('tools').enabled()" "$root/meson.build" >/dev/null ||
  fail 'optional frontend dependency boundary is absent'
grep -F "'libpkgstate'" "$root/meson.build" >/dev/null ||
  fail 'reference frontend no longer declares its semantic state dependency'
grep -F "'libpkgstate-posix'" "$root/meson.build" >/dev/null ||
  fail 'reference frontend no longer declares its native state provider'
if grep -RIn 'legacy_text_store' "$root/tools" >/dev/null; then
  fail 'reference frontend reacquired the historical state mechanism'
fi

printf '%s\n' 'architecture-contract: ok'
