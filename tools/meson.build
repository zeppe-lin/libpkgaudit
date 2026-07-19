# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

pkgchk_configuration = configuration_data()
pkgchk_configuration.set_quoted('LIBPKGAUDIT_VERSION', meson.project_version())
pkgchk_config = configure_file(
  output: 'pkgchk-config.h',
  configuration: pkgchk_configuration,
)

pkgchk_executable = executable(
  'pkgchk',
  [
    'pkgchk.cpp',
    'pkgstate_adapter.cpp',
    pkgchk_config,
  ],
  include_directories: include_directories('.'),
  dependencies: [libpkgaudit_dep, libpkgstate_dep],
  install: get_option('install_tools'),
)
