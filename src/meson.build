# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

public_inc = include_directories('../include')

libpkgaudit_sources = files(
  'audit.cpp',
  'error.cpp',
  'inventory.cpp',
  'path.cpp',
  'posix_filesystem.cpp',
  'report.cpp',
  'request.cpp',
)

libpkgaudit = library(
  'pkgaudit',
  libpkgaudit_sources,
  include_directories: public_inc,
  install: true,
  version: meson.project_version(),
  soversion: '0',
  gnu_symbol_visibility: 'hidden',
  cpp_args: visibility_cpp_args,
  link_args: ['-Wl,--version-script=' + elf_export_script_path],
  link_depends: [elf_export_script],
)

libpkgaudit_dep = declare_dependency(
  link_with: libpkgaudit,
  include_directories: public_inc,
)

meson.override_dependency('libpkgaudit', libpkgaudit_dep)

install_headers(
  '../include/libpkgaudit/audit.h',
  '../include/libpkgaudit/error.h',
  '../include/libpkgaudit/filesystem.h',
  '../include/libpkgaudit/inventory.h',
  '../include/libpkgaudit/libpkgaudit.h',
  '../include/libpkgaudit/observation.h',
  '../include/libpkgaudit/path.h',
  '../include/libpkgaudit/report.h',
  '../include/libpkgaudit/visibility.h',
  subdir: 'libpkgaudit',
)

pkgconf.generate(
  libpkgaudit,
  name: 'libpkgaudit',
  filebase: 'libpkgaudit',
  description: 'Backend-neutral package integrity audit library',
  subdirs: '.',
)
