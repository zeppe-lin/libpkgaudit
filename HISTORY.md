libpkgaudit history
===================

The first repository version extracted audit code from the Zeppe-Lin fork of
CRUX `pkgutils`.  It still accepted `pkgutil`, linked `libpkgcore`, constructed
ownership state internally, concatenated alternate-root paths, and returned
severity and presentation strings.

That extraction established the project name but not the final boundary.

The current implementation is an original rewrite.  Package-state access moved
out of the library entirely.  Consumers now provide immutable normalized facts,
filesystem observations use a validated request/response protocol, and the
library returns findings, relations, and failures without presentation policy.

`tools/pkgchk` is the current Zeppe-Lin composition root.  It uses a private
adapter from `libpkgstate::snapshot`; the library itself remains independent of
that storage model.
