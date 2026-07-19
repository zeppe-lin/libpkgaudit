foreach name, source: {
  'model': 'test_model.cpp',
  'contract': 'test_contract.cpp',
  'audit': 'test_audit.cpp',
  'posix': 'test_posix.cpp',
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
