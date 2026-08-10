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
    'default_library=shared',
    'b_ndebug=if-release',
  ],
)

if get_option('default_library') == 'both'
  error('libpkgaudit requires separate shared and static builds')
endif

library_kind = get_option('default_library')
want_static = get_option('link_mode') == 'static'
if (library_kind == 'static') != want_static
  error('default_library and link_mode must both select shared or static')
endif

cpp = meson.get_compiler('cpp')
visibility_cpp_args = []
if cpp.has_argument('-fvisibility-inlines-hidden')
  visibility_cpp_args += ['-fvisibility-inlines-hidden']
endif

pkgconf = import('pkgconfig')

elf_export_generator = find_program(
  meson.project_source_root() / 'scripts/generate-elf-export-script.sh',
)
elf_export_script_name = 'libpkgaudit.exports.map'
elf_export_script_path = meson.current_build_dir() / elf_export_script_name
elf_export_script = configure_file(
  input: 'abi/libpkgaudit.exports',
  output: elf_export_script_name,
  command: [elf_export_generator, '@INPUT@'],
  capture: true,
)

subdir('src')

if get_option('tools').enabled()
  libpkgstate_dep = dependency(
    'libpkgstate',
    version: '>=3.0.0',
    required: true,
    static: want_static,
    fallback: ['libpkgstate', 'libpkgstate_dep'],
  )
  libpkgstate_posix_dep = dependency(
    'libpkgstate-posix',
    version: '>=3.0.0',
    required: true,
    static: want_static,
    fallback: ['libpkgstate-posix', 'libpkgstate_posix_dep'],
  )
  subdir('tools')
endif

if get_option('tests').enabled()
  subdir('tests')
endif

subdir('man')
