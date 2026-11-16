# Validation record and outstanding acceptance

Version: HashBrown 0.2.0. The repository has 65 automated unittest cases: the 52
package/preflight cases plus 13 repository-only A2 acceptance-helper cases.

Executed in the Windows development environment:

- Original-image hash and preserved-copy equality; source remains unchanged.
- Server transfer interruption and checkpoint resume without resubmitting a flow.
- Tampered checkpoint, corrupt download, altered source upload and altered final image rejection.
- Uncheckpointed trailing-write truncation and crash-after-rename recovery.
- Wrong client, hostname, organization, flow parameters and upload path rejection.
- Missing ledger, missing partial bytes, mismatched custody receipt and raw-metadata tamper detection.
- Explicit disk selection, positive budget and synthetic-file requirements.
- Short capture, flow error and missing completed descriptor remain partial.
- Memory address extent validation, including holes and overlapping ranges.
- Immutable HashBrown bindings; independent `HB-...` namespace.
- Escaped offline report and freeform reference notes.
- Deterministic FAT12 and memory-transfer fixture generation and overwrite refusal.
- Owned artifact export and an end-to-end inert CLI demo with two verified images.
- Preflight uses observed explicit-file size, saved descriptors or clearly unverified declarations.
- Advisory analyst-volume capacity, remaining checkpoint bytes and insufficient-space failures.
- Missing prerequisites, invalid budgets/declarations, missing cases/roots and pending transactions.
- No case/root mutation on passing or failing preflight; no locks, journal repair, API or executable invocation.
- No image/tool/config-content opens and no credential contents in JSON, text or error output.
- Device/FIFO rejection and linked-ancestor rejection before leaf inspection.
- Source/output hardlink identity, Windows short-path aliases and partial/final collisions.
- Shared collection parameter validation and preflight-only options cannot redirect an actual sync.
- A2 helper snapshots of explicit generated image files without case mutation.
- Exact-target checks before an API client, bounded controlled checkpoints, and same-flow completion using API doubles.
- Preserved runtime/reference/reader-output fingerprints; modified retained evidence is rejected.
- Operator assertions and fixture hashes cannot grant native-capture or independent-readability qualification.

Run from this repository or an independently installed source checkout:

```powershell
python -m unittest discover -s tests -v
hashbrown --root .\acceptance-cases demo
python scripts/installed_smoke.py
```

The 0.2.0 development suite passes all 52 tests on Windows, including the Windows
short-path check. That one platform-specific test is skipped on Linux. Tests use
inert files and controlled capacity/API doubles; no physical capture is exercised.
The installed smoke script now checks JSON/text preflight, invalid budgets and a
missing root, and compares case hashes and modification times before/after planning.
The release coordinator built the 0.2.0 wheel and installed it into a separate fresh
Windows/Python 3.14.7 environment. All 52 tests passed against the installed package
using Python isolated mode. The extended installed smoke passed outside the checkout:
two inert images verified, JSON/text plans and failure paths exercised, and case
contents/modification times unchanged by preflight. The package resolved from the
new environment's `site-packages`; neither sibling tool was installed. Hosted CI
records the platform checks for each published revision.

The subsequent repository-only A2 preparation adds `scripts/a2_lab.py` and the
[designated-VM runbook](a2-lab-acceptance.md), without a package behavior/version change.
All 65 development tests pass on Windows. No designated VM or exact live target was
available during preparation, so the helper's remote checkpoint tests used API
doubles only. This preparation does not change the outstanding physical capture,
driver or independent-reader qualifications below. Any generated local fixture
snapshot must retain `fixture-transfer` scope and `native_capture: not_executed`.

The publishing coordinator independently built and installed the 0.2.0 wheel in a
new HashBrown-only Windows environment using Python 3.14.7. All **65 tests passed
with Python isolated mode**, and the installed smoke verified two inert images and
unchanged evidence through preflight success/failure paths. The helper is tested
from the repository against the installed package. No API or physical capture was
used in these release checks.

For the earlier **0.1.0** release, on 2026-11-16 the release coordinator built the wheel and installed it into a fresh
HashBrown-only virtual environment. All 30 tests passed there. The installed demo
ran in Python isolated mode outside the checkout and verified both generated images.
No sibling project or third-party Python runtime dependency was installed.

The installed HashBrown wheel also installed all three `Custom.HashBrown.*` artifacts
on a temporary local Velociraptor 0.77.3 server. Its enrolled Windows client uploaded
both inert files, and HashBrown downloaded and verified them using its own case store.
An injected disconnect at 1,048,576 bytes preserved the prefix checkpoint; resuming
used the same flow and matched the full source SHA-256. Exactly two collections
were submitted for the two images, and the final report had no acquisition gaps.
This exercised the renamed file artifact and native API/filestore transfer path.
The disk/memory device artifacts were installed but their physical capture paths
were not executed. No driver was loaded and no physical device was read.

The unit tests use a deterministic API double; the native fixture check above is
separate evidence. Repeat the client/server fixture procedure in
[acquisition.md](acquisition.md) to validate your deployment.

Still outstanding:

- Actual WinPmem kernel-driver RAM capture on a designated compatible Windows VM.
- Actual physical-device capture and forensic-tool readability checks.
- Driver/Windows security compatibility matrix and behavior on read errors.
- Large images, multi-terabyte workloads and throughput measurement.
- Independent signatures, immutable external custody storage and multiuser controls.

No real host RAM or disk devices were read during this package's build tests.
No driver was loaded and no server was provisioned by the inert demo. A verified
transfer hash establishes byte integrity relative to the reported source, not a
complete, consistent or incident-time snapshot.
