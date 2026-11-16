# HashBrown

**HashBrown 0.2.0 is a standalone disk/RAM acquisition and evidence-tracking tool.**
It creates its own cases, imports existing image files, schedules Windows capture
through an existing Velociraptor server, downloads preserved uploads in resumable
chunks, checks SHA-256, and records a hash-chained custody history.

Distribution: `hashbrown-ir`. Python package: `hashbrown_ir`. Command: `hashbrown`.
It has no runtime Python dependencies and no shared engine, installer, case store,
or automatic linkage with other incident-response tools. Velociraptor is an
external prerequisite only for remote acquisition. No binary is bundled or downloaded.

## Install and run the inert demo

Python 3.12 or newer:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\hashbrown.exe --version
.\.venv\Scripts\hashbrown.exe --root .\demo-cases demo
```

On Linux/macOS, use `.venv/bin/python` and `.venv/bin/hashbrown` instead. The same
CLI is available with `python -m hashbrown_ir` from the installed interpreter.

The demo prints JSON with a new `HB-...` case ID, case path, **two verified images**,
no acquisition gaps, and the path to `report.html`. Open that report in a browser.
Each demo run creates a new case. It generates a 1,474,560-byte FAT12 disk image and
a 3,149,824-byte memory-transfer fixture. The latter is **not a Windows RAM dump**
and cannot validate memory analysis. It reads no host disks or physical RAM,
loads no driver, executes no malware, and contacts no server.

## Import an existing image

```powershell
hashbrown --root D:\HashBrownCases case create --label INCIDENT --operator 'Analyst J'
# Use the case_id returned above.
hashbrown --root D:\HashBrownCases case bind HB-2026-REPLACE `
  --client-id C.0123456789abcdef --hostname host.example.test --org root
hashbrown --root D:\HashBrownCases acquisition import HB-2026-REPLACE `
  --client-id C.0123456789abcdef --kind disk --file D:\Evidence\disk.raw `
  --operator 'Analyst J' --sha256 ORIGINAL_SHA256
hashbrown --root D:\HashBrownCases verify HB-2026-REPLACE
```

Replace the sample case ID, client ID, hostname, source path and hash. Bind the
source endpoint's actual Velociraptor ID/FQDN/organization; bindings are immutable.
Existing files can be imported offline after binding. Omit `--sha256` if no
independent acquisition hash is available; HashBrown still hashes the original
and its copy, but that does not establish the original's earlier history.

Images are copied without conversion to `images/ACQ-.../image.bin`. The source is
preserved. `--kind memory` accepts an existing memory image. `--format raw|vhdx|vmdk|other`
is a label for one file, not a format validator or a segmented-image merger.
HashBrown does not collect VMDK dependencies. Use `--simulation` only for synthetic
fixture files. The default maximum image size is 256 GiB; set `--max-bytes` when needed.

## Read-only preflight

Add `--preflight` to the same `acquisition import`, `collect`, or `sync` command
before running it. The plan checks parameters, case/binding metadata, explicitly
named local file metadata, output collisions and advisory free space on the
**analyst's case output filesystem**. It never submits a collection, executes
Velociraptor, loads a driver, opens image/credential contents, or writes evidence,
reports, checkpoints or case locks.

```powershell
hashbrown --root D:\HashBrownCases acquisition import HB-2026-REPLACE `
  --client-id C.0123456789abcdef --kind disk --file D:\Evidence\disk.raw `
  --operator 'Analyst J' --preflight
# Use --plan-format text for a readable plan instead of JSON.
```

The JSON includes `status`, individual `checks`, a `plan` and explicit `unknowns`.
Preflight exits `0` for locally passing checks, `2` for warnings/unknown prerequisites,
and `1` for blocking failures. Passing checks do not certify capture readiness or
completeness. Usage errors still follow argparse's normal exit code `2`.

Remote size is unknown unless a saved upload descriptor or optional
`--declared-bytes N` supplies a planning estimate. A declaration is unverified and
does not constrain a later capture. `--max-bytes` remains the actual byte budget.
Client/server capacity, credential validity, roles, drivers and device extent
remain unknown; preflight makes no remote API requests. Local paths must identify
regular files/directories without observed linked/reparse ancestors. Use local
storage; non-Windows mount backends cannot be certified by these checks.

For saved local imports, `sync ... --preflight --file ORIGINAL` explicitly enables
source identity and source/output same-file checks, including hardlinks and Windows
short-path aliases. It cannot redirect the saved import. Without `--file`, those
source checks remain unknown. New acquisition output IDs are allocated only during
execution, so preflight checks their parent directory, not an as-yet-unallocated
filename. See the [preflight details](docs/acquisition.md#read-only-preflight).

## Remote capture and recovery

See the [acquisition guide](docs/acquisition.md) for artifact installation,
credentials, explicit disk selection, memory staging, interrupted transfers,
partial captures and the optional client/server fixture exercise.

```powershell
hashbrown install --velociraptor C:\IR\velociraptor.exe --api-config C:\IR\api.yaml --org root
hashbrown --root D:\HashBrownCases acquisition collect HB-2026-REPLACE `
  --client-id C.0123456789abcdef --kind memory --operator 'Analyst J' `
  --velociraptor C:\IR\velociraptor.exe --api-config C:\IR\api.yaml
hashbrown --root D:\HashBrownCases acquisition status HB-2026-REPLACE
hashbrown --root D:\HashBrownCases acquisition sync HB-2026-REPLACE --job ACQ-REPLACE `
  --velociraptor C:\IR\velociraptor.exe --api-config C:\IR\api.yaml `
  --download-api-config C:\IR\export-api.yaml
```

The download API identity needs `SERVER_ADMIN` in the bound organization because
binary reads use `fs_sparse`. The optional separate download credential is used
only for binary retrieval. Credential contents are never stored in the case.

## Notes, reports and verification

```powershell
hashbrown --root D:\HashBrownCases acquisition note HB-2026-REPLACE --job ACQ-REPLACE `
  --operator 'Analyst J' --text 'Original acquisition time and method recorded in laboratory notebook.' `
  --reference 'Notebook 4, page 12'
hashbrown --root D:\HashBrownCases report HB-2026-REPLACE
hashbrown --root D:\HashBrownCases acquisition verify HB-2026-REPLACE
```

References are freeform analyst statements. They do not link to another tool's
case, resolve events, or prove that the referenced evidence occurs in an image.
The offline report escapes notes and has no scripts or remote assets. Keep the
case directory together for its relative evidence links.

Full verification checks original metadata, image bytes, partial checkpoints and
the local custody chain. Report generation checks presence, size and modification
time and shows the last full verification time; it does not reread gigabytes.
A valid received-byte hash can coexist with a **partial capture**. The custody
chain is locally tamper-evident, not signed or immutable; a party able to rewrite
the entire case can rewrite its chain. Protect the directory and retain an
independently controlled copy or hash anchor.

Results are JSON on stdout; operational errors go to stderr. Exit code `0` means
success, `1` an operational/integrity error, and `2` a pending/partial acquisition
or reported gaps. Argument usage errors also exit `2`. `acquisition status`
returns `0` after successful inspection; inspect each job's `status` and `integrity`.
The global `--root` option goes **before** the command. Its default is `./hashbrown-cases`.

## Validation and limits

```powershell
python -m unittest discover -s tests -v
```

Fifty-two tests cover preserved hashes, interruption/resume, wrong endpoint/path,
changed images, tampering, partial captures, custody, case isolation, metadata,
artifact export, read-only preflight and the inert CLI demo. Read the [validation record](docs/validation.md)
for precise boundaries. **Actual physical-device imaging and kernel-driver RAM
capture have not been exercised.** The artifacts implement these operations,
but the designated Windows VM acceptance step remains outstanding. Large-image
throughput and multi-terabyte operation have not been benchmarked.

HashBrown provides acquisition and preservation. It does not supply filesystem
analysis, Volatility analysis, write blocking, forensic conclusions, multiuser
authorization, independent custody signatures or automatic incident correlation.

MIT license. Selected earlier MIT-licensed acquisition code was adapted; see
[third-party notices](THIRD_PARTY_NOTICES.md). HashBrown is independently installable
and maintains its own source, artifacts, tests and storage format.
