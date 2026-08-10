# libpkgaudit design

## Purpose

`libpkgaudit` compares supplied durable expectations with supplied filesystem
observations.  It owns the semantic transformation from those inputs to typed
facts.  It does not own the authority that produced the inventory or the policy
used to present the report.

## Architectural boundary

```text
consumer
  |-- constructs immutable inventory from its authority
  |-- selects packages and checks
  |-- provides a filesystem backend
  |-- assigns severity, formatting, and exit status
  `-- may verify that its authority did not change during the audit

libpkgaudit
  |-- validates and indexes supplied package facts
  |-- deduplicates physical observations
  |-- validates backend response identity
  |-- derives findings and ownership relations
  `-- reports every inability to establish a fact
```

The library deliberately has no `libpkgstate` dependency.  Replacing that link
with an abstract database or ownership-provider callback would preserve the
same contamination.  Instead, a consumer materializes one complete inventory
before the audit begins.

## Inventory model

An `object_path` is canonical and root-relative.  Empty paths, absolute paths,
`..`, NUL, carriage return, and newline are rejected.  Paths carry no directory
suffix convention.

A `package_facts` value contains an opaque, line-safe package identifier and a
canonical sorted set of expected objects.  The expected type is intentionally
limited to `directory` and `non_directory`, matching the durable distinction
available from the current installed-state format.  The audit engine does not
invent an expected regular-file, symlink, FIFO, or device type.

An `inventory` owns all package facts and an exact-path reverse index.  Package
and owner order is lexical and deterministic.  Shared ownership is retained.

## Observation protocol

Each `observation_request` has a stable identifier, a logical path, and an
explicit symlink-resolution requirement.  Backends may complete requests in
any order.

The auditor validates that responses:

* use only requested identifiers;
* contain exactly one response per identifier;
* retain the requested logical path;
* provide exactly one of a failed observation or an observed type; and
* provide only the symlink fields required by the request and observed type.

Violations become `backend_contract_violation` failures.  They are not ignored
and do not become integrity findings.

A missing object is a successful observation.  Permission, I/O, stale-object,
resolution-limit, and representation errors are failed observations.  This
distinction prevents an unreadable object from being reported as absent or
healthy.

## Audit semantics

Object-state checks produce:

* `missing_object`; and
* `object_class_mismatch` between durable directory/non-directory identity and
  the observed `lstat(2)` class.

Symlink-resolution checks produce:

* `dangling_symlink`;
* `symlink_loop`; and
* `symlink_target_outside_root`.

Symlink-ownership checks produce neutral relations:

* `source_package_owns_target`;
* `other_package_owns_target`; and
* `target_is_unowned`.

Calling another package's ownership a warning is frontend policy, not a library
fact.

Shared paths are observed once.  Findings remain package-scoped because the
same missing object violates every selected owner's expectation.  Report order
is independent of package input order, manifest order, and backend completion
order.

## POSIX backend

The default backend opens the selected root once and uses descriptor-relative
`fstatat(2)` and `readlinkat(2)` operations.  Owned objects are inspected with
`lstat(2)` semantics.  Absolute symlink targets are interpreted inside the
selected root rather than against the host root.

Symlink chains are resolved component by component beneath the root descriptor.
The backend bounds the number of followed links, detects missing components,
rejects relative traversal above the selected root, and verifies that a
symlink did not change across reading its target.

The backend returns logical paths.  Alternate-root host paths never leak into
the semantic report.

## Report model

A report contains three independent streams:

* integrity findings — established mismatches;
* ownership relations — established topology; and
* audit failures — facts that could not be established.

A report is complete only when the failure stream is empty.  It contains no
severity, verbosity, preformatted message, ANSI sequence, or process exit
status.

## Reference frontend

`pkgchk(1)` is an optional reference client.  It owns:

* command-line parsing;
* opening one existing native `libpkgstate-posix` canonical store against an
  exact caller-supplied state target binding;
* adapting one immutable snapshot into `pkgaudit::inventory`;
* constructing the audit POSIX backend for the separately selected target root;
* diagnostic wording and verbosity;
* warning policy for ownership relations; and
* exit-status selection.

The state adapter is a private tool source file.  It is not a library API and
does not appear in pkg-config metadata.  The frontend never initializes a state
store, imports a historical database, repairs a generation, or infers the
managed target from a pathname.

The shared object exports only the reviewed public C++ surface recorded in
`abi/libpkgaudit.exports`.  The reference frontend and its state adapter are not
part of that ABI.
