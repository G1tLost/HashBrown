# A2: designated-VM disk and RAM acceptance

This is a repeatable acceptance procedure, **not a passed qualification**. The
repository helper collects reviewable records around HashBrown's existing
preflight/collect/sync workflow. It never submits a collection or provisions a
server. Only its explicitly invoked `sync-checkpoint` command contacts an existing
server to resume a saved job. No target is inferred from the analyst workstation,
historical fixture cases, client caches or old server configurations.

Until an owner supplies the designated VM and exact source/destination, actual
disk/RAM capture remains **not executed**. An inert fixture transfer and matching
SHA-256 establish neither driver compatibility nor physical image readability.

## Required resources

Obtain these for one disposable, explicitly designated Windows x64 lab VM:

1. VM/access reference, actual enrolled client ID, server-reported FQDN, organization,
   operator and authorization reference. Keep access credentials outside this repository.
2. Intended `Win32_DiskDrive` index, device path, model/serial and size. Identify the
   test disk unambiguously; do not default to disk zero or the analyst's device.
3. RAM inventory, intended memory byte budget and expected physical address extent
   if known. Installed RAM is not necessarily raw image length because of address holes.
4. Client temporary staging, server filestore and analyst case destinations, with
   timestamped free-space observations for each host. Memory staging can grow before
   the artifact checks its upload budget. Confirm the source is disposable and size bounded.
5. Exact analyst and enrolled-client Velociraptor executable versions/SHA-256, the
   actual WinPmem driver SHA-256, and provenance showing which binaries actually
   ran/loaded. Hashing a downloaded driver copy alone is insufficient. If the actual
   driver cannot be identified, leave this gate incomplete; do not invent a hash.
6. Harmless, known reference content and its recorded identity/hash before capture:
   a file on the intended test disk and a known running process/content reference
   for memory. Have the VM owner prepare these within the authorized lab scope.
7. Protected metadata/export API config paths. Binary retrieval requires SERVER_ADMIN
   in the bound org. Install HashBrown's three artifacts through the normal authorized
   administration workflow before the exercise; this helper does not install them.
8. An independently chosen disk reader and memory reader, their exact versions and
   executable/package hashes, the commands used, retained stdout/logs, recovered
   reference evidence and limitations. A byte hash or a search for a marker alone
   is not a filesystem/physical-memory readability assessment.

On the **designated VM**, its owner can record read-only inventory such as
`Get-CimInstance Win32_DiskDrive`, `Get-CimInstance Win32_OperatingSystem`, and
`Get-CimInstance Win32_ComputerSystem`. Use `Get-FileHash -LiteralPath ... -Algorithm
SHA256` for the actual selected binaries/known files. Record real paths supplied
by the owner; the procedure does not guess installed client or loaded-driver paths.
Do not weaken Defender, Secure Boot, VBS or driver policy to make acceptance pass.

## Prepare a private evidence bundle

Use the independently installed HashBrown environment and this repository's helper.
The package/CLI remains 0.2.0; the helper is repository-only validation support.
Create a new, private output directory explicitly, outside the public checkout:

```powershell
$Python = 'C:\IR\HashBrownEnv\Scripts\python.exe'
$Helper = 'C:\IR\HashBrown\scripts\a2_lab.py'
$Run = 'D:\A2\RUN-REPLACE'
New-Item -ItemType Directory -Path $Run
& $Python $Helper template --output "$Run\run.json"
```

Populate `run.json` with the authorized target and relative evidence-receipt paths.
Null fields mean missing evidence. The helper never overwrites an existing output;
use a new filename for every attempt, error, checkpoint and assessment. Keep the
bundle private: it contains endpoint identities and forensic evidence references.
Snapshot/checkpoint outputs inside the supplied case root are rejected before any
image hashing or API connection; acceptance records belong in this separate bundle.

Copy the selected runtime/driver binaries, native provenance output, known-reference
records, reader outputs and storage observations into this private bundle. The
fingerprint command reads only an explicitly named regular local file, rejects
device/special paths and observed linked ancestors, and defaults to a 512 MiB bound:

```powershell
& $Python $Helper fingerprint --file "$Run\analyst-velociraptor.exe" `
  --role analyst-runtime --output "$Run\analyst-runtime.json"
& $Python $Helper fingerprint --file "$Run\endpoint-velociraptor.exe" `
  --role endpoint-runtime-copy --output "$Run\endpoint-runtime.json"
& $Python $Helper fingerprint --file "$Run\actual-driver.sys" `
  --role driver-copy --output "$Run\driver.json"
& $Python $Helper fingerprint --file "$Run\runtime-provenance.txt" `
  --role runtime-provenance --output "$Run\runtime-provenance.json"
```

These commands hash retained local copies. Their records explicitly do not prove
which binary ran on the VM. Retained provenance must identify the source host,
paths, versions, driver identity, timestamps and native output needed for review.
Do not copy API credential contents into the bundle. Fingerprint reference and
storage records using roles `known-reference` and `storage-observation` respectively.
Retain both the files and their JSON receipts: assessment rehashes each retained file.

## Create, preflight and capture through the existing CLI

Set the following variables only from the designated resources above: `$Store`,
`$ClientId`, `$Hostname`, `$Org`, `$Operator`, `$Vr`, `$Api`, `$ExportApi`,
`$DiskNumber`, `$DiskBytes`, `$DiskBudget`, `$MemoryBudget` and `$CaseId`.
The API config paths stay outside the bundle. Record exact command lines without
credential contents. Create a fresh case and bind the actual target:

```powershell
& $Python -m hashbrown_ir --root $Store case create --label A2 --operator $Operator
# Assign the returned case_id to $CaseId, then bind:
& $Python -m hashbrown_ir --root $Store case bind $CaseId `
  --client-id $ClientId --hostname $Hostname --org $Org

& $Python -m hashbrown_ir --root $Store acquisition collect $CaseId `
  --client-id $ClientId --kind memory --operator $Operator --max-bytes $MemoryBudget `
  --timeout 3600 --velociraptor $Vr --api-config $Api --preflight
& $Python -m hashbrown_ir --root $Store acquisition collect $CaseId `
  --client-id $ClientId --kind disk --disk-number $DiskNumber --operator $Operator `
  --max-bytes $DiskBudget --declared-bytes $DiskBytes --timeout 3600 `
  --velociraptor $Vr --api-config $Api --preflight
```

Save each JSON plan as its own record. Resolve failures and review warnings.
The plans observe only the analyst filesystem and local prerequisites; they do not
check the VM, server capacity, roles or driver readiness. Confirm those separately.
The one-hour collection timeout is a bounded example for a small lab; select an
explicit, justified timeout within HashBrown's allowed range if needed.

Only after target authorization and resource review, issue the actual memory
collection, using the same arguments **without `--preflight`**. Record the returned
ACQ/flow IDs and process exit code. Do the selected disk in a separate collection
afterward, removing the planning-only `--declared-bytes` as well. Physical collection
must have no `--source` and no `--simulation`. Do not substitute fixture results
when a driver/device capture fails. Preserve its error and mark the gate incomplete.

`collect` normally exits 2 while pending. Inspect the actual native flow and its
logs. Avoid an unbounded polling loop. One `acquisition status` inspects local saved
state; it is not proof the remote capture finished. Use bounded attempts and retain
each result. A timed-out or failed capture must remain failed/partial evidence.

## Exercise interrupted server-to-case transfer

Choose one completed upload larger than 1 MiB that has not already been downloaded.
Supply its saved `$Job` and repeat the **exact designated target**. The helper rejects
a target mismatch before constructing an API client:

```powershell
& $Python $Helper sync-checkpoint --root $Store --case-id $CaseId --job $Job `
  --client-id $ClientId --hostname $Hostname --org $Org `
  --velociraptor $Vr --api-config $Api --download-api-config $ExportApi `
  --transfer-bytes 1048576 --seconds 120 --output "$Run\checkpoint-01.json"
```

The helper uses normal `acquisition.resume`, permits at most 1 MiB of binary reads
in this call, then deliberately stops before the next chunk. It permits no new
collection. API calls share a 120-second budget, checked between calls; local
filesystem stalls are not a hard real-time deadline. The allowed limits are
1–64 MiB per invocation and 15–900 seconds. A normal controlled stop exits 2 and
retains the saved prefix checkpoint and custody interruption record. A pending
flow or an image shorter than the limit is **not** an observed interruption; inspect
`interrupted_transfer_observed`, `before_offset`, `after_offset`, `same_flow` and error.

Resume the **same** `$Job` with the normal CLI once, retaining timing, exit status
and JSON output. Do not collect again:

```powershell
$Timer = [Diagnostics.Stopwatch]::StartNew()
& $Python -m hashbrown_ir --root $Store acquisition sync $CaseId --job $Job `
  --velociraptor $Vr --api-config $Api --download-api-config $ExportApi
$SyncExit = $LASTEXITCODE
$Timer.Stop()
# Retain $Timer.Elapsed.TotalSeconds and $SyncExit with that command's output.
& $Python -m hashbrown_ir --root $Store verify $CaseId
```

The final transfer is bounded by the saved acquisition byte budget, with per-API
timeouts; the standard CLI has no hard overall transfer deadline. Record actual
elapsed time and retain any interruption instead of masking it with a retry loop.
The controlled checkpoint tests persistence and same-flow recovery, not network
fault injection or resumption of a physical disk/RAM capture.

## Record bytes and independent readability

For each disk/memory job, explicitly name its committed `image.bin` path:

```powershell
& $Python $Helper snapshot --root $Store --case-id $CaseId --job $DiskJob `
  --image $DiskImage --scope designated-vm --max-bytes $DiskBudget `
  --output "$Run\disk-snapshot.json"
& $Python $Helper snapshot --root $Store --case-id $CaseId --job $MemoryJob `
  --image $MemoryImage --scope designated-vm --max-bytes $MemoryBudget `
  --output "$Run\memory-snapshot.json"
```

Snapshot reads and hashes the explicit image without modifying the case. It records
size, full SHA, saved expected hash, source device/memory-range metadata, capture
window/elapsed time, errors, original-metadata hashes, hash elapsed time and current
analyst free space. A partial image can be snapshotted too, but cannot be called a
complete verified acquisition. `fixture-transfer` scope is required for fixture-only
exercises; changing a scope label cannot turn a synthetic/local import into native capture.
It exits 0 for a complete hash-matching snapshot, 2 for recorded partial/mismatched
bytes, and 1 for an operational error. The record is retained even when bytes do not verify.

Use the independently selected readers **read-only** against the preserved images.
Record exact reader hashes/versions and commands; retain their raw output/logs.
For disk, show recognized partitions/filesystems as appropriate and recovered known
file content/hash from the intended device. For memory, show recognized OS structures
and the known process/content reference, with symbol/configuration failures and other
limits retained. Do not claim independent readability from HashBrown's own SHA check.
Do not repair, mount read-write, or alter the preserved image to make a reader succeed.

```powershell
& $Python $Helper fingerprint --file "$Run\disk-reader.exe" --role reader-tool `
  --output "$Run\disk-reader.json"
& $Python $Helper fingerprint --file "$Run\disk-reader-output.txt" --role reader-output `
  --output "$Run\disk-reader-output.json"
# Repeat with the memory reader and its retained output; fingerprint known-reference records.
```

Reader output must identify the actual image/hash and what was recovered. A
fingerprinted text file saying "passed" is an operator assertion, not independent
qualification. Fill `run.json` with relative paths to these receipts, both snapshots,
checkpoint, runtime/provenance, references and all three storage observations.

```powershell
& $Python $Helper assess --record "$Run\run.json" --output "$Run\assessment-01.json"
```

Assessment exits 2 intentionally. Missing gates produce `incomplete`; a complete
set of retained records produces `review_required`. `qualification` is always
`not_granted`: a human must examine native source/runtime provenance and independent
reader results. The report distinguishes byte integrity, a physical-capture
descriptor, interruption receipts and reader-output presence. It never promotes
operator assertions, fixture hashes or even a valid native descriptor into proven
physical completeness/readability. Records are local, unsigned evidence, not attestations.
Assessment labels integrity as `snapshot_reports_verified` when the retained
snapshot reports a match; it does not silently reread the entire image on every
assessment. Runtime/reference/reader files retained in the bundle are rehashed.

## Current result

The helper's automated tests use generated bytes and API doubles only. A separate
fixture-only snapshot can validate helper plumbing and local image integrity, but
**A2 actual physical disk/RAM capture, driver compatibility and independent native
image readability remain not executed until the designated VM is supplied and this
procedure is completed**. Preserve that limitation in release notes and acceptance records.
