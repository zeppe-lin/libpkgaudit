public_inc = include_directories('../include')

libpkgaudit_sources = files(
  'error.cpp',
  'inventory.cpp',
  'path.cpp',
)

libpkgaudit = library(
  'pkgaudit',
  libpkgaudit_sources,
  include_directories: public_inc,
  install: true,
  version: meson.project_version(),
  soversion: '0',
)

libpkgaudit_dep = declare_dependency(
  link_with: libpkgaudit,
  include_directories: public_inc,
)

meson.override_dependency('libpkgaudit', libpkgaudit_dep)

install_headers(
  '../include/libpkgaudit/error.h',
  '../include/libpkgaudit/inventory.h',
  '../include/libpkgaudit/libpkgaudit.h',
  '../include/libpkgaudit/path.h',
  subdir: 'libpkgaudit',
)

pkgconf.generate(
  libpkgaudit,
  name: 'libpkgaudit',
  filebase: 'libpkgaudit',
  description: 'Backend-neutral package integrity audit library',
  subdirs: 'libpkgaudit',
)
