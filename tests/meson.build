foreach name, source: {
  'model': 'test_model.cpp',
  'contract': 'test_contract.cpp',
  'audit': 'test_audit.cpp',
  'posix': 'test_posix.cpp',
  'properties': 'test_properties.cpp',
}
  executable_test = executable(
    'test-' + name,
    source,
    dependencies: libpkgaudit_dep,
  )
  test(name, executable_test)
endforeach

if get_option('tools').enabled()
  adapter_test = executable(
    'test-pkgstate-adapter',
    [
      'test_pkgstate_adapter.cpp',
      '../tools/pkgstate_adapter.cpp',
    ],
    include_directories: include_directories('../tools'),
    dependencies: [libpkgaudit_dep, libpkgstate_dep],
  )
  test('pkgstate-adapter', adapter_test)

  python = find_program('python3')
  test(
    'pkgchk-cli',
    python,
    args: [files('test_pkgchk.py'), pkgchk_executable],
    timeout: 60,
  )
endif

foreach header: [
  'libpkgaudit/audit.h',
  'libpkgaudit/error.h',
  'libpkgaudit/filesystem.h',
  'libpkgaudit/inventory.h',
  'libpkgaudit/libpkgaudit.h',
  'libpkgaudit/observation.h',
  'libpkgaudit/path.h',
  'libpkgaudit/report.h',
]
  header_configuration = configuration_data()
  header_configuration.set('HEADER', header)
  header_source = configure_file(
    input: 'public_header.cpp.in',
    output: 'public-header-' + header.split('/')[1] + '.cpp',
    configuration: header_configuration,
  )
  header_test = executable(
    'public-header-' + header.split('/')[1],
    header_source,
    dependencies: libpkgaudit_dep,
  )
  test('public-header-' + header.split('/')[1], header_test)
endforeach
