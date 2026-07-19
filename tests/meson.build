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
