# libpkgaudit history

The first repository version extracted audit code from the Zeppe-Lin fork of
CRUX `pkgutils`.  It still accepted `pkgutil`, linked `libpkgcore`, constructed
ownership state internally, concatenated alternate-root paths, and returned
severity and presentation strings.

That extraction established the project name but not the final boundary.

The current implementation is an original rewrite.  Package-state access moved
out of the library entirely.  Consumers now provide immutable normalized facts,
filesystem observations use a validated request/response protocol, and the
library returns findings, relations, and failures without presentation policy.

`tools/pkgchk` is the current Zeppe-Lin composition root.  It opens an existing
native `libpkgstate-posix` canonical generation store against explicit target
binding authority, then uses a private adapter from `libpkgstate::snapshot`; the
library itself remains independent of both state libraries.

Before the first release, the POSIX backend was hardened so root containment is
mechanical rather than lexical: requested paths and symlink targets are walked
one component at a time beneath the selected root descriptor.  This removed a
case where `AT_SYMLINK_NOFOLLOW` protected only the final component while an
intermediate symlink could still be followed by the host VFS.
