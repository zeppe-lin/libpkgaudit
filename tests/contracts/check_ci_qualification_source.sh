#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

root=$1
workflow=$root/.github/workflows/build.yml
fail()
{
  echo "ci-qualification-source-contract: $*" >&2
  exit 1
}

[ -s "$workflow" ] || fail 'build workflow is missing'
for needle in \
  'glibc-gcc' \
  'glibc-clang' \
  'musl-gcc' \
  'link_mode: [shared, static]' \
  'library-only:' \
  'sanitizers:' \
  'documentation:' \
  'meson test -C build --print-errorlogs' \
  'PKG_CONFIG_SYSROOT_DIR' \
  'Checkout libpkgstate-posix' \
  '--force-fallback-for=libpkgstate,libpkgstate-posix'
 do
  grep -F -- "$needle" "$workflow" >/dev/null ||
    fail "workflow does not qualify: $needle"
 done

printf '%s\n' 'ci-qualification-source-contract: ok'
