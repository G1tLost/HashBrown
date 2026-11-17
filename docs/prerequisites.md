# Prerequisites: offline HashBrown

## Required

- Python **3.12 or newer** with `venv` support. Check `python --version` on Windows
  or `python3 --version` on macOS/Linux before proceeding.
- A local checkout of this repository. Run the commands below from its root.
- Local storage for explicit existing evidence files and newly created manifests.
  The manifest output directory must already exist, be outside the evidence root,
  and support hardlinks for exclusive publication. Use stable local storage, not
  linked paths; symlinks, hardlinks and special evidence files are rejected.
- Permission to read the selected files and write your separate output directory.

The offline package has **no runtime Python dependencies**. It requires no cloud
credentials, GAM, PowerShell modules, Velociraptor server/client, elevated privileges
or capture driver. Native acquisition is separate and is not approved in this scope.
Do not run `hashbrown install`, `acquisition collect`, or remote `acquisition sync`
for this offline workflow. No live tooling setup is necessary here.

## Optional isolated interpreter

These commands are instructions only; no environment or dependency installation is
performed by this document. The source-tree workflow does not need `pip install`.

Windows PowerShell (use an installed Python 3.12+):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

macOS/Linux (use an installed Python 3.12+):

```sh
python3 -m venv .venv
.venv/bin/python --version
.venv/bin/python -m unittest discover -s tests -v
```

Activation is unnecessary. Below, `PYTHON` means that platform's explicit venv
interpreter path, not a literal command. Source-tree commands must run from this
repository's root. Installing a distribution would additionally require build
requirements from `pyproject.toml`; that is not needed for this offline validation.

## Safe validation and synthetic demo

```text
PYTHON -m unittest discover -s tests -v
PYTHON -m hashbrown_ir --root ./offline-demo-cases demo
PYTHON -m hashbrown_ir --root ./offline-demo-cases verify HB-ID-RETURNED-BY-DEMO
```

Tests and demo use synthetic files and API doubles, not physical disks or RAM.
The demo writes a new local case, two generated fixture images and a report. Its
memory fixture is not a Windows RAM dump. The last command checks the synthetic
case and writes local verification history/report; it is not a non-mutating check.
Use a new output directory; replace the case ID with the actual returned ID.

## Existing-file registration and non-mutating verification

Prepare the explicit JSON specification described in
[offline evidence registration](offline-evidence.md), including provenance class,
scope, source and same-manifest parent relationships. Use canonical absolute local
paths for the root, specification and output; select only authorized existing files.

```text
PYTHON -m hashbrown_ir.evidence register --evidence-root /ABS/EVIDENCE --spec /ABS/spec.json --output /ABS/OUT/new-manifest.json
PYTHON -m hashbrown_ir.evidence verify --evidence-root /ABS/EVIDENCE --manifest /ABS/OUT/new-manifest.json --manifest-sha256 INDEPENDENT_MANIFEST_SHA256
```

On Windows substitute canonical paths such as `C:\Evidence` and
`C:\EvidenceOutput\new-manifest.json`; quote any path containing spaces.
Registration reads files, leaves their bytes unchanged and writes only a new
manifest. Verification reads selected files/manifest and writes nothing. Retain the
returned whole-manifest SHA-256 independently before verification; a hash supplied
alongside an untrusted manifest is not an independent trust anchor. Matching hashes
prove byte agreement only, not completeness, source authenticity or legal custody.

Native disk/RAM acquisition, driver compatibility, forensic-reader qualification
and installed-package smoke validation are outside this offline prerequisite check.
