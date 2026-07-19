# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

scdoc = find_program('scdoc', required: get_option('man_pages'))
if scdoc.found()
  custom_target(
    'libpkgaudit.3',
    input: 'libpkgaudit.3.scdoc',
    output: 'libpkgaudit.3',
    command: [scdoc],
    feed: true,
    capture: true,
    install: true,
    install_dir: get_option('mandir') / 'man3',
  )

  custom_target(
    'pkgchk.1',
    input: 'pkgchk.1.scdoc',
    output: 'pkgchk.1',
    command: [scdoc],
    feed: true,
    capture: true,
    install: get_option('install_tools'),
    install_dir: get_option('mandir') / 'man1',
  )
endif
