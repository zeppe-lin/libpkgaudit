# SPDX-FileCopyrightText: 2026 Alexandr Savca
# SPDX-License-Identifier: GPL-3.0-or-later

sh = find_program('sh')
test_inc = include_directories('.')

unit_tests = [
  ['model', 'unit/model_test.cpp'],
  ['request', 'unit/request_test.cpp'],
]
foreach spec : unit_tests
  target = executable(
    spec[0] + '-test',
    spec[1],
    include_directories: test_inc,
    dependencies: libpkgaudit_dep,
    install: false,
  )
  test(spec[0], target, suite: 'unit')
endforeach

integration_test = executable(
  'audit-test',
  'integration/audit_test.cpp',
  include_directories: test_inc,
  dependencies: libpkgaudit_dep,
  install: false,
)
test('audit', integration_test, suite: 'integration')

mechanism_test = executable(
  'posix-filesystem-test',
  'mechanism/posix_filesystem_test.cpp',
  include_directories: test_inc,
  dependencies: libpkgaudit_dep,
  install: false,
)
test('posix-filesystem', mechanism_test, suite: 'mechanism')

property_test = executable(
  'audit-properties-test',
  'property/audit_properties_test.cpp',
  include_directories: test_inc,
  dependencies: libpkgaudit_dep,
  install: false,
)
test('audit-properties', property_test, suite: 'property')

if get_option('tools').enabled()
  adapter_test = executable(
    'pkgstate-adapter-test',
    [
      'integration/pkgstate_adapter_test.cpp',
      '../tools/pkgstate_adapter.cpp',
    ],
    include_directories: [test_inc, include_directories('../tools')],
    dependencies: [libpkgaudit_dep, libpkgstate_dep],
    install: false,
  )
  test('pkgstate-adapter', adapter_test, suite: 'integration')

  pkgchk_fixture = executable(
    'pkgchk-fixture',
    'support/pkgchk_fixture.cpp',
    include_directories: test_inc,
    dependencies: libpkgstate_posix_dep,
    install: false,
  )

  python = find_program('python3')
  test(
    'pkgchk-cli',
    python,
    args: [files('cli/pkgchk_test.py'), pkgchk_executable, pkgchk_fixture],
    timeout: 60,
    suite: 'cli',
  )
endif

foreach header : [
  'libpkgaudit/audit.h',
  'libpkgaudit/error.h',
  'libpkgaudit/filesystem.h',
  'libpkgaudit/inventory.h',
  'libpkgaudit/libpkgaudit.h',
  'libpkgaudit/observation.h',
  'libpkgaudit/path.h',
  'libpkgaudit/report.h',
  'libpkgaudit/visibility.h',
]
  header_configuration = configuration_data()
  header_configuration.set('HEADER', header)
  header_source = configure_file(
    input: 'header/public_header.cpp.in',
    output: 'public-header-' + header.split('/')[1] + '.cpp',
    configuration: header_configuration,
  )
  header_test = executable(
    'public-header-' + header.split('/')[1],
    header_source,
    dependencies: libpkgaudit_dep,
    install: false,
  )
  test('public-header-' + header.split('/')[1], header_test, suite: 'header')
endforeach

if library_kind == 'shared'
  nm = find_program('nm')
  test(
    'abi-surface',
    sh,
    args: [
      meson.current_source_dir() / 'contracts/check_abi_surface.sh',
      nm.full_path(),
      libpkgaudit.full_path(),
      meson.project_source_root() / 'abi/libpkgaudit.exports',
    ],
    suite: 'contract',
  )
endif

foreach contract : [
  'architecture_contract',
  'ci_qualification_source',
  'documentation_source',
  'doxygen_contract',
  'repository_contract',
  'style_contract',
  'test_layout',
]
  test(
    contract.replace('_', '-'),
    sh,
    args: [
      meson.current_source_dir() / ('contracts/check_' + contract + '.sh'),
      meson.project_source_root(),
    ],
    suite: 'contract',
  )
endforeach

test(
  'pkgconfig-metadata',
  sh,
  args: [
    meson.current_source_dir() / 'contracts/check_pkgconfig_metadata.sh',
    meson.project_build_root(),
    meson.project_version(),
  ],
  suite: 'contract',
)
