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

libpkgaudit_dep = declare_dependency(
  link_with: libpkgaudit,
  include_directories: public_inc,
  dependencies: [libpkgcore_dep],
)

meson.override_dependency('libpkgaudit', libpkgaudit_dep)

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
  subdirs: 'libpkgaudit',
  requires_private: ['libpkgcore'],
)
