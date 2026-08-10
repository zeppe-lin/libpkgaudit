#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

root=$1
fail()
{
  echo "repository-contract: $*" >&2
  exit 1
}

for required in \
  .clang-format \
  abi/libpkgaudit.exports \
  scripts/generate-elf-export-script.sh \
  include/libpkgaudit/libpkgaudit.h \
  include/libpkgaudit/visibility.h \
  src/audit.cpp \
  src/posix_filesystem.cpp \
  tests/meson.build
 do
  [ -s "$root/$required" ] || fail "missing or empty $required"
 done

for directory in unit integration mechanism property cli header fixtures support contracts
 do
  [ -d "$root/tests/$directory" ] || fail "missing tests/$directory"
 done

printf '%s\n' 'repository-contract: ok'
