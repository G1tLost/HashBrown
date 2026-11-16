"""Repository-only A2 lab evidence helper. No collection or server provisioning.

Use HashBrown's existing preflight/collect commands for explicitly authorized lab
capture. Only sync-checkpoint connects to an existing server, and only to resume
the exact saved job and explicitly supplied target. Other commands are local.
"""
import argparse
import json
import os
import shutil
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from hashbrown_ir import __version__, acquisition as acq
from hashbrown_ir.endpoint import Velociraptor
from hashbrown_ir.preflight import case_state, entry, local_path
from hashbrown_ir.storage import CaseError, encode, now

SCHEMA = 1
JSON_LIMIT = 4 * 1024 * 1024
FILE_LIMIT = 512 * 1024 * 1024
ROLES = ("analyst-runtime", "endpoint-runtime-copy", "driver-copy", "reader-tool",
         "known-reference", "reader-output", "storage-observation", "runtime-provenance")


def regular(path, limit):
    path = local_path(path)
    info = entry(path)
    if info is None or not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        raise CaseError("An explicit nonempty regular local file within the byte limit is required.")
    return path.resolve(), info


def fingerprint(path, limit=FILE_LIMIT):
    path, before = regular(path, limit)
    sha, size = acq.hash_file(path, limit + 1)
    after = path.stat()
    if size != before.st_size or after.st_mtime_ns != before.st_mtime_ns or after.st_size != before.st_size:
        raise CaseError("File changed while hashing; retain the error and repeat after stabilizing it.")
    return dict(path=str(path), bytes=size, sha256=sha.hexdigest(), observed_at=now())


def read_json(path):
    path, _ = regular(path, JSON_LIMIT)
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise CaseError("Expected a JSON object.")
    return value


def validate_output(path, case_root=None):
    path = local_path(path)
    parent = entry(path.parent)
    if parent is None or not stat.S_ISDIR(parent.st_mode):
        raise CaseError("Create the private output directory explicitly before writing a record.")
    if entry(path) is not None:
        raise CaseError("Output already exists; acceptance records are never overwritten.")
    path = path.parent.resolve() / path.name
    if case_root is not None:
        root = local_path(case_root)
        info = entry(root)
        if info is None or not stat.S_ISDIR(info.st_mode):
            raise CaseError("Case root must be an existing regular local directory.")
        if path.is_relative_to(root.resolve()):
            raise CaseError("Acceptance outputs must be outside the case root in a separate private directory.")
    return path


def write_new(path, value, case_root=None):
    path = validate_output(path, case_root)
    with path.open("xb") as handle:
        handle.write(encode(value))
        handle.flush()
        os.fsync(handle.fileno())


def template():
    return dict(schema=SCHEMA, suite="HashBrown-A2", scope="designated-vm", authorization_reference=None,
                target=dict(client_id=None, hostname=None, org_id=None, disk_number=None),
                snapshots=dict(disk=None, memory=None), checkpoint=None,
                fingerprints=dict(analyst_runtime=None, endpoint_runtime=None, driver=None, runtime_provenance=None),
                references=dict(disk=None, memory=None),
                readers={kind: dict(tool=None, output=None) for kind in ("disk", "memory")},
                storage_observations=dict(client_staging=None, server_filestore=None, analyst_output=None),
                notes=["Null fields are missing evidence, not successful tests.",
                       "All evidence paths are relative to this private record directory.",
                       "Operator declarations and present reader output require human review; this helper never grants native qualification."])


def load_job(root, case_id, job_id):
    case, state = case_state(SimpleNamespace(root=root, case_id=case_id))
    job = state["jobs"].get(job_id)
    if not job:
        raise CaseError("Acquisition was not found in this standalone HashBrown case.")
    return case, job


def snapshot(root, case_id, job_id, image, scope, max_bytes):
    started = time.monotonic()
    case, job = load_job(root, case_id, job_id)
    expected_path = case.path / "images" / job["id"] / ("image.bin" if job.get("content_path") else "image.part")
    if job.get("content_path") and job["content_path"] != expected_path.relative_to(case.path).as_posix():
        raise CaseError("Committed image path differs from the saved acquisition layout.")
    image, info = regular(image, max_bytes)
    expected_info = entry(expected_path)
    if expected_info is None or not stat.S_ISREG(expected_info.st_mode) or not os.path.samestat(info, expected_info):
        raise CaseError("Explicit image must be the saved job's current partial or committed output.")
    observed = fingerprint(image, max_bytes)
    metadata = []
    for ref in job["metadata"]:
        receipt = fingerprint(case.path / ref["file"], JSON_LIMIT)
        if receipt["sha256"] != ref["sha256"]:
            raise CaseError("Original acquisition metadata hash differs from the case ledger.")
        metadata.append(dict(source=ref["source"], **receipt))
    capture = job.get("capture") or {}
    capture_elapsed = None
    if job.get("capture_started") and job.get("capture_finished"):
        from hashbrown_ir.storage import timestamp
        capture_elapsed = (timestamp(job["capture_finished"]) - timestamp(job["capture_started"])).total_seconds()
    memory_extent, extent_error = None, None
    if job["mode"] == "remote-memory":
        try:
            memory_extent = acq.memory_extent(capture.get("ImageInfo"))
        except (CaseError, KeyError, TypeError, ValueError) as exc:
            extent_error = str(exc)
    complete_bytes = (bool(job.get("content_path")) and observed["bytes"] == job.get("expected_size")
                      and observed["sha256"] == job.get("expected_sha256") == job.get("content_sha256"))
    physical_descriptor = (scope == "designated-vm" and not job["simulation"]
                           and job["mode"] in ("remote-disk", "remote-memory") and bool(capture))
    return dict(schema=SCHEMA, type="hashbrown-a2-snapshot", observed_at=now(), scope=scope,
                hashbrown_version=__version__, case_id=case.id, acquisition_id=job["id"],
                client_id=job["client_id"], hostname=job["hostname"], org_id=job["org_id"],
                kind=job["kind"], mode=job["mode"], simulation=job["simulation"], flow_id=job["flow_id"],
                image=observed, byte_integrity="verified" if complete_bytes else "not_verified_complete",
                native_capture="descriptor_present_unqualified" if physical_descriptor else "not_executed",
                independent_readability="not_assessed", status=job["status"], integrity=job["integrity"],
                expected_bytes=job.get("expected_size"), expected_sha256=job.get("expected_sha256"),
                offset=job["offset"], prefix_sha256=job["prefix_sha256"],
                capture=dict(started=job.get("capture_started"), finished=job.get("capture_finished"),
                             elapsed_seconds=capture_elapsed, reported_expected_bytes=capture.get("ExpectedSize"),
                             source=capture.get("SourcePath"), device_info=capture.get("DeviceInfo"),
                             image_info=capture.get("ImageInfo"), memory_extent_bytes=memory_extent,
                             extent_error=extent_error, issue=job.get("capture_issue"), error=job.get("error")),
                analyst_collector_sha256_recorded=job.get("collector_executable_sha256"),
                metadata=metadata, elapsed_hash_seconds=round(time.monotonic() - started, 6),
                analyst_output_storage=dict(path=str(case.path), free_bytes=shutil.disk_usage(case.path).free,
                                            observation="current analyst filesystem only; no storage reservation"),
                limits=["A matching source hash establishes received-byte integrity only.",
                        "A remote artifact descriptor is not independent proof of complete, consistent or readable capture.",
                        "Driver and endpoint runtime provenance require separate evidence; no driver was inspected here."])


class BoundedAPI:
    """Bound API wall time and binary bytes while reusing the normal resume path."""
    def __init__(self, api, deadline, start_offset, max_bytes):
        self.api, self.org = api, api.org
        self.deadline, self.start_offset, self.max_bytes = deadline, start_offset, max_bytes
        self.interrupted = False

    def query(self, query, variables=None, **kwargs):
        if "collect_client(" in query or "artifact_set(" in query:
            raise CaseError("A2 checkpoint helper permits no collection submission or artifact mutation.")
        remaining = self.deadline - time.monotonic()
        if remaining < 6:
            self.interrupted = True
            raise CaseError("A2 controlled stop: API time budget reached; resume this same saved job.")
        if "base64encode(" in query:
            end = variables["ByteOffset"] + variables["ByteCount"] - self.start_offset
            if end > self.max_bytes:
                self.interrupted = True
                raise CaseError("A2 controlled stop: transfer byte budget reached; resume this same saved job.")
        return self.api.query(query, variables, timeout=min(kwargs.get("timeout", 90), int(remaining)))


def sync_checkpoint(args):
    if not acq.CHUNK <= args.transfer_bytes <= 64 * acq.CHUNK or not 15 <= args.seconds <= 900:
        raise CaseError("Checkpoint transfer budget must be 1–64 MiB and API time budget 15–900 seconds.")
    case, before = load_job(args.root, args.case_id, args.job)
    supplied = (args.client_id, args.hostname.strip().rstrip(".").casefold(), args.org)
    expected = (before["client_id"], before["hostname"], before["org_id"])
    if supplied != expected:
        raise CaseError("Explicit target differs from the saved job; no API was contacted.")
    if before["mode"] not in acq.ARTIFACTS or not before.get("flow_id") or before.get("content_path"):
        raise CaseError("Use an already-submitted remote job with a saved flow and no committed image.")
    # Existence/type-check credentials; their contents are read only by the native
    # Velociraptor client when this explicitly invoked remote operation executes.
    for path in (args.velociraptor, args.api_config, args.download_api_config or args.api_config):
        regular(path, FILE_LIMIT)
    started, when = time.monotonic(), now()
    deadline = started + args.seconds
    api = BoundedAPI(Velociraptor(args.velociraptor, args.api_config, args.org), deadline, before["offset"], args.transfer_bytes)
    download = BoundedAPI(Velociraptor(args.velociraptor, args.download_api_config or args.api_config, args.org),
                          deadline, before["offset"], args.transfer_bytes)
    error = None
    with case.lock():
        case.verify(include_images=False)
        current = acq.load(case)["jobs"][args.job]
        if any(current.get(key) != before.get(key) for key in ("client_id", "hostname", "org_id", "flow_id", "offset")):
            raise CaseError("Saved job changed while waiting for the case lock; inspect it before retrying.")
        try:
            acq.resume(case, args.job, api, download)
        except CaseError as exc:
            error = str(exc)
        after = acq.load(case)["jobs"][args.job]
    controlled = api.interrupted or download.interrupted
    return dict(schema=SCHEMA, type="hashbrown-a2-checkpoint", observed_at=when,
                client_id=args.client_id, hostname=expected[1], org_id=args.org,
                case_id=case.id, acquisition_id=args.job, flow_id=before["flow_id"],
                before_offset=before["offset"], after_offset=after["offset"], prefix_sha256=after["prefix_sha256"],
                status=after["status"], error=error or after.get("error"), controlled_stop=controlled,
                interrupted_transfer_observed=controlled and after["offset"] > before["offset"] and not after.get("content_path"),
                same_flow=after["flow_id"] == before["flow_id"], submitted_collections=0,
                elapsed_seconds=round(time.monotonic() - started, 6), transfer_budget_bytes=args.transfer_bytes,
                api_time_budget_seconds=args.seconds, analyst_free_bytes=shutil.disk_usage(case.path).free,
                limits=["No collection was submitted; this resumes an existing upload only.",
                        "Time budget is checked between API calls; local filesystem stalls are not a hard real-time bound.",
                        "Controlled interruption is not an interrupted physical capture or a network-fault simulation."])


def evidence(base, relative, expected_type=None, role=None):
    if not isinstance(relative, str) or not relative:
        return None
    path = Path(relative)
    if path.is_absolute() or path.drive or ".." in path.parts:
        raise CaseError("Acceptance evidence paths must stay relative to the private record directory.")
    path = base / path
    receipt = fingerprint(path, JSON_LIMIT)
    value = read_json(path)
    if value.get("schema") != SCHEMA or expected_type and value.get("type") != expected_type:
        raise CaseError("Acceptance evidence schema/type mismatch.")
    if role and value.get("role") != role:
        raise CaseError("Acceptance fingerprint role mismatch.")
    if expected_type == "hashbrown-a2-fingerprint":
        observed = value.get("file") or {}
        if (not acq.SHA.fullmatch(str(observed.get("sha256", "")))
                or type(observed.get("bytes")) is not int or observed["bytes"] <= 0):
            raise CaseError("Acceptance fingerprint lacks a valid observed hash/length.")
        retained = Path(observed.get("path", ""))
        if not retained.is_absolute() or not retained.is_relative_to(base):
            raise CaseError("Retain fingerprinted evidence files inside the private acceptance directory before assessment.")
        actual = fingerprint(retained, FILE_LIMIT)
        if actual["sha256"] != observed["sha256"] or actual["bytes"] != observed["bytes"]:
            raise CaseError("Retained reference/runtime/reader evidence differs from its fingerprint.")
    return dict(file=relative, receipt=receipt, value=value)


def assess(record_file):
    record_path, _ = regular(record_file, JSON_LIMIT)
    record = read_json(record_path)
    if record.get("schema") != SCHEMA or record.get("suite") != "HashBrown-A2":
        raise CaseError("Not a HashBrown A2 acceptance record.")
    base = record_path.parent
    missing, observed, snapshots = [], {}, {}
    target = record.get("target") or {}
    if not record.get("authorization_reference"):
        missing.append("authorization_reference: explicit designated lab target authorization")
    for field in ("client_id", "hostname", "org_id", "disk_number"):
        if target.get(field) is None:
            missing.append("target." + field)
    for kind in ("disk", "memory"):
        item = evidence(base, record.get("snapshots", {}).get(kind), "hashbrown-a2-snapshot")
        if not item:
            missing.append("snapshots." + kind)
            continue
        value = item["value"]
        snapshots[kind] = value
        observed["snapshot_" + kind] = item["receipt"]
        if value.get("kind") != kind or any(value.get(key) != target.get(key) for key in ("client_id", "hostname", "org_id")):
            missing.append(kind + ": snapshot does not match the declared target/kind")
        if value.get("byte_integrity") != "verified" or value.get("status") != "verified":
            missing.append(kind + ": complete received bytes are not verified or capture reports a gap")
        capture = value.get("capture") or {}
        if value.get("mode") != "remote-" + kind or value.get("simulation") is not False or value.get("scope") != "designated-vm":
            missing.append(kind + ": no designated-VM physical-capture descriptor")
        if kind == "disk" and ((capture.get("device_info") or {}).get("Index") != target.get("disk_number")
                               or not capture.get("source") or not capture.get("reported_expected_bytes")):
            missing.append("disk: device identity/extent evidence missing or index differs")
        if kind == "memory" and (not capture.get("memory_extent_bytes") or capture.get("extent_error")):
            missing.append("memory: physical range/extent evidence missing or invalid")
    checkpoint = evidence(base, record.get("checkpoint"), "hashbrown-a2-checkpoint")
    resume = "not_executed"
    if checkpoint:
        observed["checkpoint"] = checkpoint["receipt"]
        value = checkpoint["value"]
        matches = [s for s in snapshots.values() if all(s.get(key) == value.get(key) for key in ("case_id", "acquisition_id", "flow_id"))]
        if (value.get("interrupted_transfer_observed") is True and value.get("same_flow") is True
                and value.get("submitted_collections") == 0 and matches and matches[0].get("byte_integrity") == "verified"
                and 0 < value.get("after_offset", 0) < matches[0].get("expected_bytes", 0)):
            resume = "same_flow_receipts_present"
        else:
            missing.append("checkpoint: no matching interrupted-prefix and complete same-flow receipts")
    else:
        missing.append("checkpoint: controlled interrupted transfer and same-flow completion")
    roles = {"analyst_runtime": "analyst-runtime", "endpoint_runtime": "endpoint-runtime-copy",
             "driver": "driver-copy", "runtime_provenance": "runtime-provenance"}
    for label, role in roles.items():
        item = evidence(base, record.get("fingerprints", {}).get(label), "hashbrown-a2-fingerprint", role)
        if item:
            observed[label] = item["receipt"]
            if label == "analyst_runtime":
                for kind, saved in snapshots.items():
                    if saved.get("mode") in ("remote-disk", "remote-memory") and saved.get("analyst_collector_sha256_recorded") != item["value"]["file"]["sha256"]:
                        missing.append(kind + ": analyst runtime hash differs from the acquisition record")
        else:
            missing.append("fingerprints." + label)
    for kind in ("disk", "memory"):
        for label, relative, role in (("reference", record.get("references", {}).get(kind), "known-reference"),
                                      ("reader_tool", record.get("readers", {}).get(kind, {}).get("tool"), "reader-tool"),
                                      ("reader_output", record.get("readers", {}).get(kind, {}).get("output"), "reader-output")):
            item = evidence(base, relative, "hashbrown-a2-fingerprint", role)
            if item:
                observed[kind + "_" + label] = item["receipt"]
            else:
                missing.append(kind + "." + label)
    for location in ("client_staging", "server_filestore", "analyst_output"):
        item = evidence(base, record.get("storage_observations", {}).get(location), "hashbrown-a2-fingerprint", "storage-observation")
        if item:
            observed["storage_" + location] = item["receipt"]
        else:
            missing.append("storage_observations." + location)
    native = {kind: ("descriptor_present_unqualified" if snapshots.get(kind, {}).get("native_capture") == "descriptor_present_unqualified"
                     else "not_executed") for kind in ("disk", "memory")}
    return dict(schema=SCHEMA, type="hashbrown-a2-assessment", observed_at=now(),
                status="incomplete" if missing else "review_required", qualification="not_granted",
                byte_integrity={kind: ("snapshot_reports_verified" if snapshots.get(kind, {}).get("byte_integrity") == "verified"
                                       else snapshots.get(kind, {}).get("byte_integrity", "not_executed")) for kind in ("disk", "memory")},
                native_capture=native, interrupted_transfer=resume,
                independent_readability={kind: "output_present_review_required" if kind + "_reader_output" in observed else "not_executed"
                                         for kind in ("disk", "memory")},
                missing=missing, observed_record_hashes=observed,
                declarations=dict(scope=record.get("scope"), authorization_reference=record.get("authorization_reference"), target=target),
                review_requirements=["Review original endpoint device/range evidence against the intended source and known reference.",
                                     "Match exact client/runtime and driver hashes to evidence of what actually ran/loaded on the VM; a file-copy hash is insufficient.",
                                     "Inspect independent reader identity, commands, output and recovered known content/structures for both images.",
                                     "Record errors, storage observations, elapsed time and any capture/readability limitations.",
                                     "Receipts are local records, not signed attestations. Operator assertions and valid SHA-256 alone never grant native/readability qualification."])


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("template").add_argument("--output", type=Path, required=True)
    fp = commands.add_parser("fingerprint")
    fp.add_argument("--file", type=Path, required=True)
    fp.add_argument("--role", choices=ROLES, required=True)
    fp.add_argument("--max-bytes", type=int, default=FILE_LIMIT)
    fp.add_argument("--output", type=Path, required=True)
    snap = commands.add_parser("snapshot")
    sync = commands.add_parser("sync-checkpoint")
    for cmd in (snap, sync):
        cmd.add_argument("--root", type=Path, required=True)
        cmd.add_argument("--case-id", required=True)
        cmd.add_argument("--job", required=True)
        cmd.add_argument("--output", type=Path, required=True)
    snap.add_argument("--image", type=Path, required=True)
    snap.add_argument("--scope", choices=("fixture-transfer", "designated-vm"), required=True)
    snap.add_argument("--max-bytes", type=int, default=acq.MAX_BYTES)
    for flag in ("client-id", "hostname", "org"):
        sync.add_argument("--" + flag, required=True)
    for flag in ("velociraptor", "api-config"):
        sync.add_argument("--" + flag, type=Path, required=True)
    sync.add_argument("--download-api-config", type=Path)
    sync.add_argument("--transfer-bytes", type=int, default=acq.CHUNK)
    sync.add_argument("--seconds", type=int, default=120)
    review = commands.add_parser("assess")
    review.add_argument("--record", type=Path, required=True)
    review.add_argument("--output", type=Path, required=True)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        # Refuse an occupied output before any potentially remote operation.
        output = validate_output(args.output, getattr(args, "root", None))
        if args.command == "template":
            result = template()
        elif args.command == "fingerprint":
            if args.max_bytes <= 0:
                raise CaseError("Fingerprint byte limit must be positive.")
            result = dict(schema=SCHEMA, type="hashbrown-a2-fingerprint", role=args.role,
                          file=fingerprint(args.file, args.max_bytes),
                          assertion="Observed local file-copy hash; source host, actual execution/loading and interpretation require separate evidence.")
        elif args.command == "snapshot":
            if args.max_bytes <= 0:
                raise CaseError("Image byte limit must be positive.")
            result = snapshot(args.root, args.case_id, args.job, args.image, args.scope, args.max_bytes)
        elif args.command == "sync-checkpoint":
            result = sync_checkpoint(args)
        else:
            result = assess(args.record)
        write_new(output, result, getattr(args, "root", None))
        print(json.dumps(result, indent=2))
        if args.command == "assess":
            return 2  # Human qualification is intentionally never automated.
        if args.command == "snapshot" and result["byte_integrity"] != "verified":
            return 2
        if args.command == "sync-checkpoint":
            if result["error"] and not result["controlled_stop"]:
                return 1
            return 2 if result["controlled_stop"] or result["status"] != "verified" else 0
        return 0
    except (CaseError, OSError, KeyError, TypeError, ValueError) as exc:
        print("a2_lab: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
