# libpkgaudit testing

## Doctrine

The suite tests contracts, not implementation anecdotes. Every boundary that
may later become concurrent or gain another backend is exercised without
assuming response order, syscall strategy, or external storage.

A clean run is:

```sh
meson test -C build --print-errorlogs
```

The directory and Meson suite names state which boundary owns each test. A
regression belongs at the lowest public seam that can express the failure; a
CLI test is not a substitute for a missing semantic or mechanism contract.

## Suite inventory

`unit`
: canonical path parsing and rejection, immutable package facts, inventory
  indexing, explicit check sets, package selection, and report completeness.

`integration`
: the auditor composed with a scripted backend, including missing objects,
  durable class mismatch, shared-path deduplication, package-scoped findings,
  ownership relations, dangling links, explicit probe failures, absent selected
  packages, and malformed backend-response quarantine. When tools are enabled,
  the private `libpkgstate` adapter is also qualified here because it is a
  producer/consumer seam rather than a library unit.

`mechanism`
: the real POSIX backend against temporary roots: regular files, directories,
  links, FIFOs, missing objects, relative and absolute links inside alternate
  roots, dangling links, loops, root escapes, unrepresentable targets, invalid
  roots, and resolution limits.

`property`
: package-order permutations, all completion orders for a representative
  observation batch, 2,000 randomized object-state audits checked against an
  independent count oracle, and 1,000 normalization stability cases.

`cli`
: a real canonical native state store, exact target-binding handoff, alternate
  audit roots, clean audits, missing objects, class mismatch, foreign ownership
  presentation, verbosity, dangling links, absent packages, read-only refusal to
  initialize missing state, help, version, conflicting modes, and exit-status
  policy.

`header`
: every installed public header is compiled independently. This catches hidden
  include-order dependencies and keeps the umbrella header honest.

`contract`
: architecture/dependency direction, the exact shared-library ELF surface,
  generated pkg-config metadata, repository/test topology, documentation and
  Doxygen source, style, and the CI qualification promises themselves.

## Installed-interface qualification

Source-tree success is insufficient. The shared build compares its dynamic
symbol set with `abi/libpkgaudit.exports`, and the CI install step compiles a
fresh consumer using the staged `libpkgaudit.pc` with `PKG_CONFIG_SYSROOT_DIR`.
This is intended to catch exported implementation symbols, bad installed include
roots, dependency leakage, and version drift before a release is tagged.

The library itself remains dependency-free. `libpkgstate` and
`libpkgstate-posix` enter only through the optional reference-tool build and its
private adapter/provider composition; the library-only CI job proves that
closure separately.

## CI matrix

The supported matrix contains:

* GCC and Clang;
* glibc and musl;
* separate shared and static builds;
* library-only dependency-closure builds;
* AddressSanitizer plus UndefinedBehaviorSanitizer;
* staged installation plus a pkg-config consumer; and
* Doxygen and manual-page source qualification.

Tests run in every ordinary build. Sanitizer jobs disable no semantic or
filesystem tests. A new backend is not accepted without running the common
auditor contract surface against reordered, missing, duplicate, and malformed
responses.

## Adding tests

A bug fix starts with a failing regression. Model changes require construction
and rejection tests. New findings require a scripted-backend semantic test and
a real-filesystem test when the POSIX backend is involved. New CLI policy
belongs in the black-box command test, not in library tests.
