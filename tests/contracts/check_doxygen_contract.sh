#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

root=$1
file=$root/Doxyfile
fail()
{
  echo "doxygen-contract: $*" >&2
  exit 1
}

[ -s "$file" ] || fail 'Doxyfile is missing'
grep -E '^PROJECT_NAME[[:space:]]*=[[:space:]]*libpkgaudit$' "$file" >/dev/null ||
  fail 'Doxygen project name drifted'
grep -E '^INPUT[[:space:]]*=[[:space:]]*include/libpkgaudit$' "$file" >/dev/null ||
  fail 'Doxygen input no longer names the public API'
grep -E '^WARN_AS_ERROR[[:space:]]*=[[:space:]]*FAIL_ON_WARNINGS$' "$file" >/dev/null ||
  fail 'Doxygen warnings are not fatal'

for header in "$root"/include/libpkgaudit/*.h
 do
  grep -F '\file' "$header" >/dev/null || fail "public header lacks file documentation: $header"
 done

printf '%s\n' 'doxygen-contract: ok'
