Migration from inherited pkgchk
===============================

This project is a clean replacement.  The CRUX-derived implementation is a
behavioral reference only; no source is carried forward.

Preserved interface
-------------------

The reference frontend retains the useful command spellings:

```text
pkgchk [-Vh] [-r root-dir] {-l | -d | -a} [package ...]
```

With no package arguments, every installed package is selected.

Redefined behavior
------------------

`-d`
: checks both disappearance and durable directory/non-directory class.  A
  directory replaced by a regular file is no longer silently considered
  present and healthy.

`-l`
: resolves symlinks inside the selected root and reports ownership as a typed
  relation.  Absolute targets under an alternate root do not resolve against
  the host root.

Probe failures
: permission, I/O, stale-object, and backend-contract failures make the audit
  incomplete.  They are never silently skipped.

Ordering
: output derives from canonical report order and does not depend on database,
  manifest, or backend completion order.

Exit status
: 0 means a complete audit with no integrity findings; 1 means integrity
  findings were reported; 2 means usage, state, or incomplete-audit failure.

Removed accidental behavior
---------------------------

The replacement removes:

* `pkgutil` and `libpkgcore` from the audit library;
* regex-based ownership lookup;
* string concatenation and prefix stripping for alternate roots;
* positional coupling between probe requests and responses;
* severity, verbosity, and preformatted messages in library results;
* silent `lstat(2)` and `readlink(2)` failures; and
* success exit status after per-package operational failures.

Newly specified behavior
------------------------

The replacement specifies:

* immutable materialized audit inventories;
* exact shared ownership;
* stable observation identifiers;
* backend-contract validation;
* explicit incomplete reports;
* bounded root-contained symlink resolution;
* private `libpkgstate` adaptation in `tools/`; and
* independent library and frontend dependency closures.
