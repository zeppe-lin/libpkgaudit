libpkgaudit testing
===================

Doctrine
--------

The suite tests contracts, not implementation anecdotes.  Every boundary that
may later become concurrent or gain another backend is exercised without
assuming response order, syscall strategy, or external storage.

A clean run is:

```sh
meson test -C build --print-errorlogs
```

Suite inventory
---------------

`model`
: canonical path parsing, rejection rules, package validation, deterministic
  ordering, duplicate rejection, exact lookup, and shared ownership.

`contract`
: explicit check sets, package selections, report completeness, and typed
  failure retention.

`audit`
: missing objects, durable class mismatch, shared-path deduplication,
  package-scoped findings, all ownership relations, dangling links, explicit
  probe failures, missing/duplicate/unknown/mismatched backend responses, and
  absent selected packages.

`posix`
: regular files, directories, links, FIFOs, missing objects, relative and
  absolute links inside alternate roots, dangling links, loops, root escapes,
  unrepresentable targets, invalid roots, and resolution limits.

`properties`
: all package-order permutations for a representative inventory, all 24
  completion orders for four observations, 2,000 randomized object-state
  audits checked against an independent count oracle, and 1,000 normalization
  stability cases.

`public-header-*`
: every installed header is compiled independently rather than relying on
  inclusion order or the umbrella header.

`pkgstate-adapter`
: durable directory identity, non-directory identity, package names, and shared
  ownership survive the private tool adaptation without exposing state types
  from the library.

`pkgchk-cli`
: alternate-root state loading, clean audits, missing objects, class mismatch,
  foreign ownership presentation, verbosity, dangling links, absent packages,
  help, version, conflicting modes, and exit-status policy.

CI matrix
---------

The supported matrix contains:

* GCC and Clang;
* glibc and musl;
* separate shared and static builds;
* library-only dependency-closure builds;
* AddressSanitizer plus UndefinedBehaviorSanitizer; and
* staged installation with pkg-config verification.

Tests must run in every ordinary build.  Sanitizer jobs disable no semantic or
filesystem tests.  A new backend is not accepted without running the common
auditor contract suite against reordered, missing, duplicate, and malformed
responses.

Adding tests
------------

A bug fix starts with a failing regression.  Model changes require construction
and rejection tests.  New findings require both a scripted-backend semantic
test and a real-filesystem test when the POSIX backend is involved.  New CLI
policy belongs in the black-box command test, not in library tests.
