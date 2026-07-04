project(
  'libpkgaudit',
  'cpp',
  version: '1.0',
  default_options: [
    'cpp_std=c++17',
    'warning_level=3',
    'default_library=shared',
    'b_ndebug=if-release',
  ],
)

want_static = get_option('link_mode') == 'static'

if want_static and get_option('default_library') == 'both'
  error('''
Invalid configuration: link_mode=static requires default_library=static.
See project README: Link Mode.
''')
endif

libpkgcore_dep = dependency(
  'libpkgcore',
  required: true,
  fallback: ['libpkgcore', 'libpkgcore_dep'],
  static: want_static,
)

pkgconf = import('pkgconfig')

subdir('src')
subdir('man')
