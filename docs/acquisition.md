# Acquisition and recovery

HashBrown owns its cases and the three `Custom.HashBrown.AcquireFile`,
`Custom.HashBrown.AcquireDisk` and `Custom.HashBrown.AcquireMemory` artifacts.
It uses an existing Velociraptor server/client deployment; it does not provision
or change client enrollment, security settings or driver policy.

## Install the artifacts

With an administrator-provisioned API identity authorized to write artifacts:

```powershell
hashbrown install --velociraptor C:\IR\velociraptor.exe --api-config C:\IR\artifact-writer.yaml --org root
```

Alternatively export the packaged definitions for manual import in the server:

```powershell
hashbrown artifacts --output .\hashbrown-artifacts
```

Export refuses to overwrite different files. API query arguments are passed as
process arguments, without a shell; query variables carry paths and parameters.
API credential files remain external to cases. The executable SHA-256 is recorded
for remote capture. The metadata API identity must be able to inspect the client,
schedule collections and read that collection's results/uploads in the selected
organization. Artifact installation requires its separate artifact-writer access.
Binary `fs_sparse` reads require **SERVER_ADMIN** in that organization. Use
`--download-api-config` on `sync` to separate export access, or omit it when the
main API identity has both roles. An alternative is native Velociraptor export
followed by a local import with the independently recorded source hash.

## Create a case and bind the actual endpoint

```powershell
hashbrown --root D:\HashBrownCases case create --label INCIDENT --operator 'Analyst J'
hashbrown --root D:\HashBrownCases case bind HB-2026-REPLACE `
  --client-id C.0123456789abcdef --hostname exact.server-reported-fqdn --org root
```

Use the returned case ID and actual enrolled client values. Names are compared
case-insensitively with a trailing dot normalized. A fresh remote collection,
including an explicitly synthetic file collection, checks the server's current
client/FQDN against this binding. Flow recovery also checks organization, client,
artifact, request ID and parameters. Bindings cannot be reassigned in place.
The inert offline demo's synthetic binding is for generated fixtures only.

## Read-only preflight

Version 0.2 adds `--preflight` to the existing import, collect and sync operations.
Use their normal source, operator, binding, format, budget and timeout arguments.
The same pure parameter validators serve planning and actual acquisition.
The case must already exist and be bound; a missing case/root produces a failed
plan without creating directories. Pending metadata transactions are reported,
not repaired. No case lock, report, ledger, journal or evidence file is written.

```powershell
hashbrown --root D:\HashBrownCases acquisition import HB-2026-REPLACE `
  --client-id C.0123456789abcdef --kind disk --file D:\Evidence\disk.raw `
  --operator 'Analyst J' --max-bytes 137438953472 --preflight --plan-format text

hashbrown --root D:\HashBrownCases acquisition collect HB-2026-REPLACE `
  --client-id C.0123456789abcdef --kind memory --operator 'Analyst J' `
  --max-bytes 34359738368 --declared-bytes 17179869184 --preflight `
  --velociraptor C:\IR\velociraptor.exe --api-config C:\IR\api.yaml
```

The second command describes a hypothetical collection; it executes no collector
and contacts no server. `--declared-bytes` is an unverified size estimate **only
accepted with `--preflight`**. It does not carry into a later capture or impose an
expected length. Without a declaration or saved descriptor, source extent remains
unknown and the plan uses `--max-bytes` as a capacity ceiling. An observed local
file or declared size above the budget fails preflight. A declaration inconsistent
with observed file metadata or a saved descriptor also fails. A supplied SHA-256
is syntax-checked only; no image is hashed by preflight.

JSON is the default; `--plan-format text` renders the same checks and unknowns.
The machine-readable schema contains `schema`, `tool`, `version`, `read_only`,
`inspected_at`, `operation`, `case_id`, overall `status`, `checks`, `unknowns` and
`plan`. Each check has `name`, `status`, `message` and `details`. Known plan fields
include endpoint binding, mode, source host/size/basis, budget, output location and
analyst filesystem capacity. Overall status is the most severe check:

| Status / exit | Meaning |
| --- | --- |
| `pass` / `0` | No blocking local observation or actionable warning; explicit unknowns still apply |
| `warning` / `2` | Unknown source extent/prerequisites or a condition requiring review |
| `fail` / `1` | Invalid parameters, missing prerequisites/case, conflicting outputs, or insufficient planned capacity |

Argument syntax errors retain normal CLI usage output and exit `2`. Supplying
planning-only options without `--preflight` is rejected before case mutation.

Local source and prerequisite checks inspect **regular-file metadata only**;
neither image bytes nor API credential contents are opened. Config presence is
not proof of valid credentials, organization or roles. The executable is not
invoked or authenticated. Obvious device/network namespaces, Windows mapped
network drives, device/FIFO inputs, and observed symlink/junction/reparse entries
or ancestors are rejected before descending through them. Supply direct local
paths without `..`; Windows 8.3 names are resolved to canonical paths after checks.
Use a local filesystem: non-Windows network mount backends are not certified.
These are filesystem observations, not a race-free guarantee against concurrent
path replacement. No lock or write probe is taken.

For a saved local import, explicitly identify the original source to permit its
metadata/identity checks and comparison with the saved source and output files:

```powershell
hashbrown --root D:\HashBrownCases acquisition sync HB-2026-REPLACE `
  --job ACQ-REPLACE --file D:\Evidence\disk.raw --preflight --plan-format text
```

`--file` on sync is preflight-only and cannot redirect a saved job. The plan checks
canonical paths and file identity, detecting a source/output alias or hardlink
before normal resume could truncate a partial output. Without explicit `--file`,
source availability, unchanged metadata and same-file collisions remain a warning.
It checks partial/final output types and lengths, including a missing checkpoint
or simultaneous `.part`/`.bin` files. It does not validate the saved prefix hash;
normal sync still performs its full checks. Already committed outputs require
rehashing during sync and are not described as newly verified by the plan.

New acquisitions have no allocated acquisition ID yet; the plan displays
`<new-acquisition-id>` and checks the output parent directories. It cannot certify
the future filename or reserve it. Matching unfinished remote requests are shown
as reused jobs, consistent with `collect`'s existing no-duplicate behavior.

Capacity is a snapshot of the **analyst case output filesystem**, not the enrolled
endpoint or server. It uses remaining image bytes after the saved offset, plus the
normal 16 MiB reserve; existing final images need no additional image allocation.
An insufficient observed/declaration-based estimate is a planning failure. When
extent is unknown, a budget-ceiling shortfall is a warning. No space is reserved,
and permissions, concurrent writers or sparse-file behavior may change the result.
Endpoint RAM staging space, remote upload storage, device extent, driver readiness,
network connectivity, API privileges and capture completeness stay unknown.
Neither this plan nor a successful fixture/hash check qualifies physical capture.

## Existing image on the enrolled endpoint

```powershell
hashbrown --root D:\HashBrownCases acquisition collect HB-2026-REPLACE `
  --client-id C.0123456789abcdef --kind memory --source C:\Evidence\memory.raw `
  --operator 'Analyst J' --velociraptor C:\IR\velociraptor.exe --api-config C:\IR\api.yaml
```

This copies an existing file. It does not take a fresh memory snapshot. The
artifact returns source metadata, capture window, upload hash and byte count.

## Physical capture on a designated Windows VM

Live capture remains an uncompleted acceptance exercise. Use an enrolled Windows
x64 test VM and independently verify the resulting image with your forensic tools.
The client needs access to physical disk devices and permission to load the
memory driver. Memory capture calls Velociraptor's built-in WinPmem function;
driver compatibility depends on the VM's Windows build/security configuration.
HashBrown does not alter Defender, Secure Boot, VBS or driver policy.

RAM capture first writes an uncompressed file in the client's configured temporary
directory and then uploads it. The temporary file is cleaned up on normal artifact
scope completion. Memory address holes may make the image larger than installed
RAM. Provision client staging, server upload and analyst case storage. The budget
bounds upload/download, but **WinPmem staging may grow before its output is checked**.

```powershell
hashbrown --root D:\HashBrownCases acquisition collect HB-2026-REPLACE `
  --client-id C.0123456789abcdef --kind memory --operator 'Analyst J' `
  --max-bytes 34359738368 --timeout 86400 `
  --velociraptor C:\IR\velociraptor.exe --api-config C:\IR\api.yaml
```

For disk capture, determine the intended `Win32_DiskDrive` index on the chosen VM
using your normal read-only inventory. An explicit disk number is mandatory:

```powershell
hashbrown --root D:\HashBrownCases acquisition collect HB-2026-REPLACE `
  --client-id C.0123456789abcdef --kind disk --disk-number 1 --operator 'Analyst J' `
  --max-bytes 137438953472 --timeout 86400 `
  --velociraptor C:\IR\velociraptor.exe --api-config C:\IR\api.yaml
```

The artifact records WMI device path, model, serial number, sector size and
expected length, and streams raw sectors through `raw_file`. HashBrown does not
silently pad read failures. Raw disk reads may preserve encrypted sectors. Live
disk writes and RAM acquisition activity can make the image internally inconsistent;
neither is an atomic snapshot. Physical capture produces raw images only.
`--simulation` is rejected unless `--source` explicitly names an existing fixture.

The default budget is **274877906944 bytes (256 GiB)** and the default collection
timeout is **86400 seconds (24 hours)**. Allowed timeout: 60–172800 seconds. Free
space checks leave a 16 MiB reserve but do not reserve space against other writers.

## Sync and recover

`collect` saves an `ACQ-...` ID and ordinarily exits `2` while the collection is
pending. It does not wait for physical capture to finish. Use the same job ID:

```powershell
hashbrown --root D:\HashBrownCases acquisition status HB-2026-REPLACE
hashbrown --root D:\HashBrownCases acquisition sync HB-2026-REPLACE --job ACQ-REPLACE `
  --velociraptor C:\IR\velociraptor.exe --api-config C:\IR\api.yaml `
  --download-api-config C:\IR\export-api.yaml
```

Repeat `sync` after a transfer interruption. HashBrown validates the persisted
prefix hash and resumes 1 MiB chunks from `image.part`; an uncheckpointed trailing
write is discarded. This resumes **server-to-case transfer from an existing
upload**, not an interrupted live capture. Local imports resume with the same
command without API flags while the original file remains unchanged/available.

If the submission response was lost, the request becomes `submission_unknown`.
HashBrown does not silently schedule a second collection. Find the original flow
in the server and supply `--flow-id F.REPLACE` to `sync`. The full saved request
identity is checked before attaching it. An unfinished conflicting acquisition of
the same evidence kind on that endpoint is rejected.

A full hash match promotes `.part` to `image.bin`. Wrong hashes retain the bytes
as `integrity_failed` without promotion. Start a separate acquisition to retry
that state. A flow error, unexpected length or invalid WinPmem memory ranges
retains `partial` even when the received bytes verify. No completed descriptor
means no complete image claim; inspect the native collection logs and any server
partial uploads. Start a new job for another physical capture attempt.

## Inert client/server fixture exercise

Generate the two fixtures without reading any host devices:

```powershell
hashbrown fixtures --output .\fixtures
```

Copy `disk.img`, `memory.raw` and `fixture-manifest.json` to `C:\IRLab` on your
already enrolled lab VM by your normal lab process. Create a fresh HashBrown case,
bind its actual client ID/FQDN/org, install the three artifacts, and submit:

```powershell
hashbrown --root D:\HashBrownCases acquisition collect HB-2026-REPLACE `
  --client-id C.0123456789abcdef --kind memory --source C:\IRLab\memory.raw `
  --simulation --operator 'Lab analyst' `
  --velociraptor C:\IR\velociraptor.exe --api-config C:\IR\api.yaml
```

Sync the saved ID, then repeat for `--kind disk --source C:\IRLab\disk.img`.
Compare preserved SHA-256/length against the fixture manifest and run `verify`.
This exercises native file upload and binary preservation only. The memory fixture
is transfer bytes, not an analyzable RAM image. It never validates WinPmem or raw
physical-device capture. Do not treat a fixture result as live acceptance.

## Evidence layout

Each case resides under `STORE/LABEL/HB-.../`:

| File | Purpose |
| --- | --- |
| `case.json` | HashBrown version, case identity, operator, immutable endpoint bindings |
| `acquisitions.json` | Requests, job state, source/flow IDs, hashes, checkpoints and custody chain |
| `evidence_manifest.json` | SHA-256-indexed original metadata registry |
| `raw/acquisition_metadata/*.json` | Original flow/result/upload JSON bytes |
| `images/ACQ-.../image.part` | In-progress or failed transfer bytes |
| `images/ACQ-.../image.bin` | Complete received bytes verified against source SHA-256 |
| `report.html` | Regenerable offline overview and custody record |
| `hashbrown.log` | Local endpoint-binding activity; not a signed audit log |

The CLI takes a case lock during reads/mutations/verification. Library callers
must use `with case.lock():` and verify raw metadata before acquisition actions.
Keep the whole case when handing off. Verify again after copying, and retain an
independent integrity anchor. Notes can record original acquisition history and
external references; no other tool's store is read or written automatically.
