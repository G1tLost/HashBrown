# Detached evidence handoff (A4)

HashBrown 0.3.0 can export selected committed images' acquisition records and verify
their bytes after relocation. The recipient needs an installed HashBrown package,
the JSON manifest and a directory containing the selected images. The original
case, source image, Velociraptor server, configuration and credentials are unnecessary.
Neither command makes API calls, repairs cases, creates a case lock, opens historical
source paths, or changes image bytes/modification times. No images are copied or moved.

## Producer

Choose saved acquisition IDs from an existing case. Create a private output directory
outside the entire source case store; that directory must already exist. Stop writes
to the case while preparing the handoff.

```powershell
hashbrown --root D:\HashBrownCases acquisition status HB-2026-REPLACE
hashbrown --root D:\HashBrownCases handoff create HB-2026-REPLACE `
  --job ACQ-REPLACE --job ACQ-SECOND --output D:\PrivateHandoff\incident.json
```

`--job` is mandatory and repeatable; no implicit selection occurs. The producer
checks the whole source custody chain and all registered original metadata, including
unselected metadata, before exporting. It freshly streams each selected image's
SHA-256 and length against its saved record and custody receipt. It then rereads the
source ledger, case/manifest and original metadata and compares hashes, file identities
and modification times before publication. A detected concurrent change aborts.
These checks require a stable local store; they are not a filesystem snapshot or a
defense against a privileged actor racing and restoring files.

Only committed images with verified received bytes are eligible. An unfinished
transfer is refused. A committed **partial capture** remains partial and can be handed
off with its original capture issue. Any missing, changed or truncated selected
source image prevents publication. A pending transaction is refused without repair.

The result includes `manifest_file_sha256`, `image_copy_performed: false` and a
readable summary. `--format text` prints that summary instead of result JSON; the
output file is always JSON. Exchange the complete file hash with the intended recipient
through a separately controlled channel and establish who supplied it. The manifest's
embedded digest detects accidental changes but cannot authenticate its author.

The output is written to an exclusive temporary file, flushed, and atomically
published through an exclusive hardlink, then the temporary name is removed. It
never replaces an existing destination. **The output filesystem must support local
hardlinks** (for example, NTFS); unsupported filesystems fail without publishing a
manifest. Ordinary failure cleans up the temporary file; a process/power crash can
leave a temporary name. No such file is placed inside the source case store.

## Relocation and recipient

Copy the images yourself, preserving each manifest-relative path beneath your chosen
evidence directory. For example, the source case's
`images/ACQ-0123456789abcdef/image.bin` goes to
`E:\Received\images\ACQ-0123456789abcdef\image.bin`. The directory need not contain
a HashBrown case. Keep the detached JSON separately or within the recipient directory.
No automatic discovery of nearby files, dependent disk segments or source stores occurs.

```powershell
hashbrown handoff verify --manifest E:\Received\incident.json `
  --evidence-root E:\Received --manifest-sha256 INDEPENDENT_MANIFEST_FILE_SHA256
hashbrown handoff verify --manifest E:\Received\incident.json `
  --evidence-root E:\Received --format text
```

Replace the sample names and hash. Omit `--manifest-sha256` only if no independent
hash is available; the result explicitly says whether one was matched. HashBrown
still reports external authenticity as `not_verified_unsigned` even when it matches:
it cannot assess the trustworthiness of the channel or sender.

The verifier validates the strict schema, bindings, acquisition request, exported
original metadata, selected custody receipts and their declared chain links. It
streams a fresh hash of every selected relocated image. Remote original flow,
capture and upload metadata must agree with the acquisition, including the capture
issue. Historical source paths and original client/flow paths remain informational
strings; they are never opened or contacted. Unlisted files under the recipient root
are outside the selection and are not verified.

The JSON result reports per-image `integrity`, observed length/hash where available,
`capture_status`, `capture_issue` and `simulation`. Exit codes are:

| Code | Meaning |
| --- | --- |
| 0 | Manifest created, or all selected received bytes match with no recorded partial capture. |
| 1 | Operational, schema, binding, metadata, path or byte-integrity failure; verification refused/failed. |
| 2 | All selected bytes match, but at least one committed capture remains partial. Argparse usage errors also use 2. |

Invalid manifest/schema errors go to stderr. Image errors appear individually in
verification JSON/text; other selected images are still checked. No repair or
promotion occurs. `native_qualification` always remains `not_granted`.

## Schema and bounded scope

The JSON format is `hashbrown-evidence-handoff`, schema integer `1`. Unknown top-level
fields, acquisition fields and embedded wrapper fields are rejected; versions must
be canonical numeric `major.minor.patch`. Duplicate JSON keys are rejected, including
within original metadata. The selected historical payloads remain original bytes,
not a new cross-tool evidence schema.

| Field | Content |
| --- | --- |
| `producer_version`, `created_at`, `source_case` | Export version/time and source case ID, label, creation time and version. |
| `items` | Selected full saved acquisition records, endpoint bindings, and fixed relative image path/length/SHA-256. |
| `metadata` | Referenced original flow/capture/upload bytes as base64 with relative identifiers, lengths and SHA-256. |
| `custody` | All declared sequence/previous/hash links; complete event bodies only for selected acquisitions. |
| `limitations`, `summary` | Explicit qualification limits and the readable selected-image summary. |
| `manifest_sha256` | SHA-256 of canonical JSON excluding this field (UTF-8, sorted keys, indent 2, trailing newline). Not a signature. |

Limits: 64 selected images; 256 jobs and 10,000 custody events in the source ledger;
512 original metadata files; 4 MiB per original and 32 MiB original bytes total;
10,000 object rows per original; 16 MiB each for source case/ledger/manifest JSON;
64 MiB detached manifest. Source label enumeration is capped at 10,000 and raw-tree
entries at 2,048. Images are streamed in at most 4 MiB chunks, must match their
recorded exact length, and cannot exceed their saved positive acquisition byte budget
(normally 256 GiB). There is no image format parser, segment collector or native
capture/readability test in this feature.

All inspected input paths must be canonical regular local files/directories, without
observed symlink/reparse ancestors, device namespaces, traversal, alternate streams,
hardlinks or Windows short-name aliases. Use the canonical long path. The fixed
image path is `images/ACQ-<16 lowercase hex>/image.bin`; arbitrary manifest paths
cannot escape the explicitly chosen root. Windows mapped network drives/UNC paths
are rejected. Other operating systems' mount backends cannot be certified as local;
use known local storage. No claim is made against adversarial concurrent filesystem
replacement.

## What the result establishes

`selected_custody_bodies_verified` counts exported event bodies whose hashes were
recomputed. `omitted_custody_bodies_unverified` counts events whose bodies were not
exported; only their declared hash links are checked for continuity. **A consistent
projection does not independently verify omitted bodies or the entire historical
custody chain.** Selected notes remain attributed operator statements.

A person able to rewrite a manifest and its evidence can recompute all unsigned
digests and declarations. Protect the original case and the independent manifest
hash. The handoff can contain sensitive filenames, operators, client identities,
notes and acquisition metadata; transfer it through an appropriate private channel.

Matching bytes establish integrity relative to the manifest. They do not establish
complete physical capture, original source authenticity, incident-time consistency,
filesystem readability, driver compatibility or independent forensic conclusions.
Synthetic evidence remains synthetic, and partial captures remain partial. A2's
designated-VM physical acquisition and independent reader acceptance remain separate
and unexecuted in this milestone.
