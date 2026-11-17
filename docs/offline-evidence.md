# Offline evidence registration (local prototype)

This separate suite-facing command registers **explicit existing regular files**:
cloud original exports, EVTX files, manifests and derived reports. It does not parse
or validate their format. It never opens another tool's case store automatically,
collects targets, contacts APIs, installs artifacts or starts drivers.

Use Python 3.12+ with `python -m hashbrown_ir.evidence`. Existing `hashbrown`
disk/RAM commands are unchanged and are **not** the suite-facing read-only entrypoint.

Create a JSON specification outside your evidence directory:

```json
{"items":[
  {"id":"export-1","path":"original.json","provenance_class":"original","scope":"CASE-123","parents":[],"source":"BEC explicit offline export","media_type":"application/json"},
  {"id":"timeline-1","path":"timeline.csv","provenance_class":"derived","scope":"CASE-123","parents":["export-1"],"source":"Analyst timeline transform","media_type":"text/csv"}
]}
```

```text
python -m hashbrown_ir.evidence register --evidence-root /absolute/evidence --spec /absolute/spec.json --output /absolute/new-manifest.json
python -m hashbrown_ir.evidence verify --evidence-root /absolute/received --manifest /absolute/new-manifest.json --manifest-sha256 INDEPENDENTLY_RETAINED_HASH
```

Registration hashes original bytes without copying/modifying them; it exclusively
publishes a new manifest outside the evidence root. Transfer selected files manually,
keeping relative paths, and retain/exchange the returned whole-manifest SHA-256
through an independent trusted channel. Verification requires that anchor and writes
nothing. Neither command modifies HashBrown's acquisition ledger or custody chain.

Every item declares a nonempty scope, source and media type. Classes are `original`,
`derived` or `synthetic`. Originals and synthetic roots have no parents. Derived
items require existing, same-scope parents within this manifest; cycles are rejected.
These are operator claims, not proven attribution. Ancestors may be synthetic, so
`derived` never implies genuine incident evidence. IDs are local to the manifest.

Limits: 256 explicit files; 256 GiB per file; 1 MiB specification/manifest; canonical
local paths only; no symlinks, hardlinks, special files, traversal or overwrite.
The output filesystem must support exclusive hardlink publication. Local stable
storage is required. There is no filesystem snapshot or defense against a privileged
concurrent attacker. Registration rehashes before publication, and verification
freshly hashes every item. Hash matches do not prove completeness, capture quality,
format readability, original acquisition time, legal custody or source authenticity.
No signatures, external custody store, multiuser authorization or automatic suite
integration is claimed. Empty files can be registered and their zero length is explicit.
