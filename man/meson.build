manpages = get_option('manpages')
if not manpages.disabled()
  scdoc = find_program('scdoc', required: manpages)
  if scdoc.found()
    foreach section, pages: {
      '1': ['pkgchk'],
      '3': ['libpkgaudit'],
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
endif
