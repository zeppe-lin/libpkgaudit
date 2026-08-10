#!/bin/sh
# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

root=$1
fail()
{
  echo "style-contract: $*" >&2
  exit 1
}

[ -s "$root/.clang-format" ] || fail '.clang-format is missing'

tab=$(printf '\t')
if find "$root/include" "$root/src" "$root/tools" "$root/tests" -type f \
    \( -name '*.h' -o -name '*.hpp' -o -name '*.cpp' -o -name '*.py' -o -name '*.sh' -o -name 'meson.build' \) \
    -exec grep -n "$tab" {} + | grep . >/dev/null; then
  fail 'tab remains in code, test, or build source'
fi

if find "$root/include" "$root/src" "$root/tools" "$root/tests" -type f \
    \( -name '*.h' -o -name '*.hpp' -o -name '*.cpp' -o -name '*.py' -o -name '*.sh' -o -name 'meson.build' \) \
    -exec grep -nE '[[:blank:]]+$' {} + | grep . >/dev/null; then
  fail 'trailing whitespace remains in code, test, or build source'
fi

printf '%s\n' 'style-contract: ok'
