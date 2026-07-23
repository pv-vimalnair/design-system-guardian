# Trusted execution boundary

Design System Guardian 0.2.0 is a cross-agent pilot candidate. Its local
HMAC seals detect accidental corruption and cross-run replay, but they are not a
production authority against code running as the same operating-system account.
An agent process that can read the local sealing key must never be allowed to
turn local evidence into a production approval.

## Required production boundary

A production gate must run the pinned Guardian release in a protected host or CI
identity that the product-building agent cannot modify or impersonate. That host
must provide all of the following as one reviewed integration:

- a canonical absolute, integrity-pinned Guardian interpreter or signed
  standalone executable;
- the exact trusted Dart SDK artifact and governed Flutter/framework package
  closure declared by the authority-bound company profile;
- independently protected analysis and finalization attestations;
- a rollback-resistant catalog approval high-water checkpoint;
- the already-required external/WORM release-head provider; and
- a host-attested UX/accessibility evaluator.

No environment variable, project-local executable, caller-supplied path, local
JSON file, in-process object, or plugin-cache file may stand in for that host.
The provider must be fixed by reviewed code and must fail closed when it is
unavailable.

## Private-pilot behavior

This release does not integrate the protected production authority or trusted
UX evaluator. Therefore it cannot issue a production pass. Local audit output is
diagnostic development evidence only and remains `productionReady=false` with
exit code `4` when a protected lane is unavailable.

The convenience launchers `scripts/guardian` and `scripts/guardian.cmd`
deliberately exit `4`; they never discover Python from `PATH`. A protected host
invokes `scripts/guardian.py` through its authority-bound absolute runtime.
For private-pilot diagnostics and repository tests, a host-supplied absolute
Python executable may invoke `scripts/guardian.py` after its absolute path and
SHA-256 are recorded. That diagnostic route is not a production authority and
cannot change the compile-time fail-closed result.
