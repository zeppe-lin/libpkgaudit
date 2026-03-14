public_inc = include_directories('../include')

libpkgaudit = library(
  'pkgaudit',
  [
    'ownership_index.cpp',
    'auditor.cpp',
    'serial_probe_engine.cpp',
  ],
  include_directories: [public_inc],
  dependencies: [libpkgcore_dep],
  install: true,
  version: meson.project_version(),
  soversion: '1',
)

install_headers(
  '../include/libpkgaudit/types.h',
  '../include/libpkgaudit/probe.h',
  '../include/libpkgaudit/ownership_index.h',
  '../include/libpkgaudit/auditor.h',
  subdir: 'libpkgaudit',
)

pkgconf.generate(
  libpkgaudit,
  name: 'libpkgaudit',
  filebase: 'libpkgaudit',
  description: 'Package integrity audit library',
  subdirs: 'pkgaudit',
  requires_private: ['libpkgcore'],
)
