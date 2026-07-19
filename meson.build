# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

project(
  'libpkgaudit',
  'cpp',
  version: '0.1.0',
  license: 'GPL-3.0-or-later',
  meson_version: '>=1.6.0',
  default_options: [
    'cpp_std=c++17',
    'warning_level=3',
    'b_ndebug=if-release',
  ],
)

if get_option('default_library') == 'both'
  error('libpkgaudit requires separate shared and static builds')
endif

want_static = get_option('link_mode') == 'static'
if want_static and get_option('default_library') != 'static'
  error('link_mode=static requires default_library=static')
endif

pkgconf = import('pkgconfig')

subdir('src')

if get_option('tools').enabled()
  libpkgstate_dep = dependency(
    'libpkgstate',
    required: true,
    static: want_static,
    fallback: ['libpkgstate', 'libpkgstate_dep'],
  )
  subdir('tools')
endif

if get_option('tests').enabled()
  subdir('tests')
endif

subdir('man')
