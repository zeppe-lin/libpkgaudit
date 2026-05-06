if get_option('build_man')
  scdoc = find_program('scdoc')

  foreach section, pages: {
    '3': [
      'libpkgaudit',
      'pkgaudit_auditor',
      'pkgaudit_ownership_index',
      'pkgaudit_probe',
      'pkgaudit_types',
    ]
  }
    foreach page: pages
      custom_target(
        page + '.' + section,
        input: page + '.' + section + '.scdoc',
        output: page + '.' + section,
        command: [scdoc],
        feed: true,
        capture: true,
        install: true,
        install_dir: get_option('mandir') / ('man' + section),
        install_tag: 'man',
      )
    endforeach
  endforeach
endif
