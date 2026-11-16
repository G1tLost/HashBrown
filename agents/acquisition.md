# Acquisition role

Own HashBrown's disk/RAM acquisition, binary preservation, endpoint binding and
custody evidence. Keep its storage format and runtime independent of all sibling
tools. Notes may contain plain external references; never resolve another store.

Preserve these invariants:

- Bind the actual client ID, normalized server hostname and Velociraptor org.
- Require an explicit disk number for physical disk capture. Synthetic mode
  requires an explicit source file; never silently substitute fixture bytes.
- Default to 24-hour collection timeout and 256 GiB byte budget; persist both.
- Keep source/flow metadata, original SHA-256, acquisition window, named operator
  and collector identity. Do not record API credential contents.
- Keep server upload path within the exact bound client/flow; reject changed
  request identities and changed remote hashes after a checkpoint.
- Checkpoint only durable bytes. Verify the prefix on resume and full SHA-256
  before promotion. Preserve failed bytes and recover a crash after rename.
- Resume the preserved server upload; never claim to resume a live physical capture.
- A correct received-byte hash must not erase a partial/error capture status.
- Preserve original metadata bytes and manifest references, and hash-chain custody
  actions. Explain that the local chain can be wholly rewritten by a privileged actor.
- Use case locks and atomic metadata writes. Reject unregistered binary/raw evidence.
- Keep the separate binary-download credential option; `fs_sparse` needs SERVER_ADMIN.
- Route read-only preflight before case locks/verification/repair. Share pure request
  validation with execution; never invoke API/collector operations from preflight.
- Inspect only explicitly named regular local inputs after checking path ancestors.
  Never open image or credential contents. Keep source/output alias checks for an
  explicitly supplied saved import source, including hardlinks and Windows short paths.
- Scope capacity observations to the analyst case filesystem, mark declarations
  unverified and remote extent/staging/roles unknown. Plans never certify capture completeness.
- Keep detached handoff creation/verification outside Case constructors, locks and repair.
  Rehash explicitly selected committed images, validate all source original metadata/custody,
  and reject detected source changes before exclusive publication outside the case store.
- Verify detached images only beneath the explicitly chosen canonical evidence root.
  Never open historical source paths, contact APIs or copy images from handoff commands.
- Distinguish verified selected custody bodies, unverified omitted bodies, declared
  link continuity and unsigned external authenticity. Partial captures stay partial;
  manifest/byte hashes never grant native capture, completeness or readability qualification.

Validate changes with meaningful interruption, path/binding, source-change,
metadata-tamper, custody and partial-capture tests. The inert demo and native file
fixture workflow are transfer tests only. WinPmem driver compatibility, physical
device reading and forensic image readability require separate live VM acceptance.

The acquisition artifacts implement raw disk reads, WinPmem staging and existing
file upload. Do not broaden them into host-policy changes, malware execution or
unbounded automated capture. Report omissions honestly rather than substituting
stubs or fabricated successful capture metadata.
