# libpkgaudit

`libpkgaudit` is a small C++17 library for package integrity audits.

It extracts audit logic out of `pkgchk(1)` (see [pkgutils][1]) and
turns it into a reusable component with a clear boundary:

- audit semantics
- filesystem probing
- ownership lookup
- issue reporting

The goal is to let `pkgchk(1)` stay a thin CLI while the audit engine
can evolve independently.

## Why

The old `pkgchk(1)` implementation mixed several concerns in one file:

- command-line parsing
- package database traversal
- filesystem probing
- ownership resolution
- output formatting

That made performance work unnecessarily hard.  Any attempt to add
parallel probing or `io_uring(7)` risked rewriting audit semantics at
the same time.

`libpkgaudit` fixes that by introducing a membrane between:

- **what** is being audited
- **how** filesystem state is probed
- **how** results are presented

## Scope

`libpkgaudit` is responsible for package audit logic such as:

- broken symlink detection
- symlink ownership awareness
- disappeared file detection
- ownership indexing

It is **not** responsible for:

- package installation or removal
- package database storage primitives
- archive extraction
- CLI argument parsing
- final output formatting

Those remain outside the library.

## Relationship to libpkgcore

`libpkgaudit` depends on [libpkgcore][2].

`libpkgcore` provides core package-management primitives such as
package database access and helper utilities.

`libpkgaudit` builds audit policy on top of that.

Roughly:

- `libpkgcore` = package core
- `libpkgaudit` = audit engine
- `pkgchk(1)` = CLI frontend

## Design

The library is built around three layers:

### 1. Audit model

Typed issues and audit options:

- severity
- issue kind
- package
- path
- target
- owner sets

This keeps semantics explicit and testable.

### 2. Ownership index

A reverse index maps paths to package owners.

This avoids rescanning the whole package database for every lookup.

### 3. Probe engine

Filesystem access lives behind a probe interface.

This lets the execution engine change without changing audit semantics.

Possible engines:

- serial syscall loop
- bounded thread pool
- `io_uring(7)`

The first implementation is intentionally simple and serial.
The important part is the contract.

## Current checks

The initial library extracts the existing `pkgchk(1)` checks:

- symlink integrity
- disappeared files

Future checks can be added without growing the CLI into another
monolith.

## Build requirements

- C++17 compiler
- Meson
- Ninja
- `pkg-config(1)`
- [libpkgcore][2]

`libpkgaudit` uses `libpkgcore` headers and links against
`libpkgcore`.

## Build

```sh
# Configure
meson setup build

# Compile
meson compile -C build

# Install
meson install -C build
```

## pkg-config

The build installs `libpkgaudit.pc`.

Typical usage:

```sh
pkg-config --cflags libpkgaudit
pkg-config --libs libpkgaudit
```

For static linkage:

```sh
pkg-config --static --libs libpkgaudit
```

## Public API direction

The intended public surface is small:

* issue and option types
* ownership index
* audit entry points
* probe-engine interface
* factory for the default serial probe engine

The library returns typed issues.
Formatting belongs to the caller.

That means the same audit engine can later serve:

* `pkgchk(1)`
* JSON output
* test harnesses
* batch auditing tools

## Status

This library starts as an extraction from `pkgchk(1)`.

The first milestone is correctness and API clarity, not maximum
throughput.

Once the semantics are pinned behind a stable contract, alternate
probe engines can be added.

In other words:

first membrane, then concurrency.

## License

`libpkgaudit` is licensed under the
[GNU General Public License v3 or later][3].

See `COPYING` for license terms and `COPYRIGHT` for notices.

[1]: https://github.com/zeppe-lin/pkgutils
[2]: https://github.com/zeppe-lin/libpkgcore
[3]: https://gnu.org/licenses/gpl.html
