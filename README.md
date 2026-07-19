libpkgaudit
===========

`libpkgaudit` is a C++17 library for comparing an immutable package-object
inventory with typed filesystem observations.

It provides:

* canonical root-relative audit paths;
* immutable package facts with shared-ownership queries;
* backend-neutral observation requests and responses;
* deterministic object-state and symlink audit semantics;
* typed integrity findings, ownership relations, and incomplete-audit failures;
* a root-bound Linux/POSIX filesystem backend; and
* an optional `pkgchk(1)` reference frontend.

The library has no package-database dependency.  It does not include or expose
`libpkgstate`, inspect package archives, parse package filenames, assign
severity, format diagnostics, or select an exit status.  A consumer supplies
facts; `libpkgaudit` returns facts.

The implementation is original Zeppe-Lin code.  It is not derived from CRUX
`pkgutils`, the historical `pkgchk(1)`, or the former CRUX-derived
`libpkgcore` implementation.

Model
-----

The supported composition is:

```text
state or another authority
          |
          | consumer-owned adapter
          v
 pkgaudit::inventory
          |
          +--------------------+
          |                    |
          v                    v
    audit_request       filesystem_backend
          |                    |
          +---------+----------+
                    v
             pkgaudit::report
          findings / relations / failures
```

`inventory` is a complete immutable fact universe for one audit.  The library
does not make lazy ownership callbacks into an external database.  Shared
objects are observed once and may produce package-scoped findings for every
selected owner.

Filesystem backends may return responses in any order.  Every request has a
stable identifier; missing, duplicate, unknown, or path-mismatched responses
become explicit backend-contract failures.  Probe failures are not converted
into clean observations.

`report::complete()` is true only when no probe or backend-contract failure was
recorded.  Severity and presentation remain consumer policy.

Requirements
------------

Build-time requirements:

* Linux;
* a C++17 compiler;
* Meson 1.6.0 or later;
* Ninja; and
* pkg-config.

The optional `pkgchk` tool additionally requires `libpkgstate`.  Python 3 is
required for its black-box command tests.  `scdoc` and Doxygen are optional
documentation dependencies.

Building
--------

Shared library and reference tool:

```sh
meson setup build
meson compile -C build
meson test -C build --print-errorlogs
```

Static library and static dependencies:

```sh
meson setup build-static \
  -Ddefault_library=static \
  -Dlink_mode=static
meson compile -C build-static
meson test -C build-static --print-errorlogs
```

Library-only build:

```sh
meson setup build-library -Dtools=disabled
```

Reference tools are built by default and are not installed by default.  They
may be disabled or installed explicitly:

```sh
meson setup build-no-tools -Dtools=disabled
meson setup build-install-tools -Dinstall_tools=true
```

The project rejects `default_library=both`; shared and static artifacts are
separate builds.

Reference tool
--------------

`tools/pkgchk` is the composition root for the current Zeppe-Lin installed
state:

```text
libpkgstate::snapshot
          |
          | private tools/pkgstate_adapter
          v
 pkgaudit::inventory -> libpkgaudit -> terminal policy
```

The adapter is private to the executable and is not installed.  `libpkgaudit`
does not link against `libpkgstate`, and `libpkgaudit.pc` does not advertise it.

During migration the executable remains uninstalled unless
`-Dinstall_tools=true` is selected.  It preserves the useful historical mode
spellings without preserving the inherited implementation.

API documentation
-----------------

Public interfaces are documented under `include/libpkgaudit`.  Generate the
HTML reference with:

```sh
doxygen Doxyfile
```

The output is written to `build/docs/html`.

Compiler and linker flags are available through pkg-config:

```sh
pkg-config --cflags --libs libpkgaudit
pkg-config --static --libs libpkgaudit
```

Documentation
-------------

* `DESIGN.md` — architectural boundaries and invariants;
* `TESTING.md` — test doctrine and suite inventory;
* `MIGRATION.md` — behavioral changes from inherited `pkgchk`;
* `HISTORY.md` — project lineage;
* `libpkgaudit(3)` — library contract; and
* `pkgchk(1)` — reference frontend.

Layout
------

* `include/libpkgaudit/` — public API;
* `src/` — audit semantics and POSIX backend;
* `tools/` — optional `pkgchk` and private `libpkgstate` adapter;
* `tests/` — model, contract, property, filesystem, adapter, and CLI tests;
* `man/` — scdoc manual sources; and
* `.github/workflows/` — compiler, shared/static, and sanitizer CI.

License
-------

`libpkgaudit` is licensed under the GNU General Public License version 3 or
later.  See `COPYING` for license terms and `COPYRIGHT` for notices.
