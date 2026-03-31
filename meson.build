project(
  'libpkgaudit',
  'cpp',
  version: '1.0',
  default_options: [
    'cpp_std=c++17',
    'warning_level=3',
    'default_library=both',
    'b_ndebug=if-release',
  ],
)

libpkgcore_dep = dependency(
  'libpkgcore',
  required: true,
  fallback: ['libpkgcore', 'libpkgcore_dep'],
)

pkgconf = import('pkgconfig')

subdir('src')
