#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

root=$1
fail()
{
  echo "documentation-source-contract: $*" >&2
  exit 1
}

for document in README.md DESIGN.md TESTING.md MIGRATION.md HISTORY.md
 do
  [ -s "$root/$document" ] || fail "missing or empty $document"
  case $(sed -n '1p' "$root/$document") in
    '# '*) ;;
    *) fail "$document does not start with an ATX level-one heading" ;;
  esac
 done

if grep -RInE '^[-=]{3,}$' "$root"/*.md >/dev/null; then
  fail 'Setext Markdown heading remains in root documentation'
fi

for document in README.md DESIGN.md man/libpkgaudit.3.scdoc
 do
  grep -F 'libpkgstate' "$root/$document" >/dev/null ||
    fail "$document does not state the package-state boundary"
 done

grep -F 'descriptor-relative' "$root/DESIGN.md" >/dev/null ||
  fail 'design does not describe descriptor-relative observation'
grep -F '::fstatat' "$root/src/posix_filesystem.cpp" >/dev/null ||
  fail 'descriptor-relative fstatat mechanism disappeared'
grep -F '::readlinkat' "$root/src/posix_filesystem.cpp" >/dev/null ||
  fail 'descriptor-relative readlinkat mechanism disappeared'

grep -F 'backend_contract_violation' "$root/DESIGN.md" >/dev/null ||
  fail 'backend response quarantine is undocumented'
grep -F 'report::complete()' "$root/README.md" >/dev/null ||
  fail 'incomplete-audit semantics are undocumented'

grep -F 'canonical generation store' "$root/README.md" >/dev/null ||
  fail 'reference frontend native state provider is undocumented'
grep -F 'frontend never initializes a state' "$root/DESIGN.md" >/dev/null ||
  fail 'reference frontend read-only state authority is undocumented'
grep -F '*--canonical-store*' "$root/man/pkgchk.1.scdoc" >/dev/null ||
  fail 'pkgchk manual does not require explicit canonical state'

printf '%s\n' 'documentation-source-contract: ok'
