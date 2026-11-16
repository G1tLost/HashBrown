"""Detached, bounded evidence manifests. No case repair, credentials or API calls."""
import base64
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace

from . import __version__, acquisition as acq
from .preflight import entry, local_path
from .storage import CASE_ID, LABEL, CaseError, digest, encode, now, timestamp

FORMAT = "hashbrown-evidence-handoff"
SCHEMA = 1
MAX_JSON = 16 * acq.CHUNK
MAX_RAW = 4 * acq.CHUNK
MAX_RAW_TOTAL = 32 * acq.CHUNK
MAX_MANIFEST = 64 * acq.CHUNK
MAX_JOBS = 256
MAX_SELECTED = 64
MAX_METADATA = 512
MAX_ROWS = 10000
MAX_CUSTODY = 10000
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})")
JOB_FIELDS = set("id label client_id org_id hostname kind mode operator simulation max_bytes format status created_at updated_at offset prefix_sha256 metadata flow_id integrity version request expected_size expected_sha256 capture_started capture_finished capture_issue consistency content_path content_sha256 content_bytes verified_at verified_mtime_ns".split())
LIMITATIONS = [
    "Byte integrity is relative to this unsigned manifest, not independent source authenticity.",
    "Selected exported custody bodies are hashed; omitted bodies are not exported or verified. Only their declared hash links are checked.",
    "A matching hash does not establish complete, consistent, readable or qualified physical capture.",
    "Historical source paths are provenance text only and are never opened by detached verification.",
    "Exchange the complete manifest file SHA-256 through an independently controlled channel. No signature or immutable custody claim is made.",
]


def require(condition, message):
    if not condition:
        raise CaseError(message)


def keys(value, expected, name):
    require(isinstance(value, dict) and set(value) == set(expected), "Invalid " + name + " fields.")


def sha(value):
    return isinstance(value, str) and acq.SHA.fullmatch(value) is not None


def positive(value):
    return type(value) is int and value > 0


def canonical_path(path, directory=False):
    path = local_path(path)
    info = entry(path)
    require(info is not None, "Missing local evidence or metadata: " + str(path))
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "Expected a regular local " + ("directory." if directory else "file."))
    resolved = path.resolve()
    require(os.path.normcase(str(resolved)) == os.path.normcase(str(path)), "Path aliases are not accepted; supply the canonical local path.")
    if not directory:
        require(info.st_nlink == 1, "Hardlinked/aliased evidence or metadata files are not accepted.")
    return resolved, info


def signature(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def read_file(path, limit, retain=True):
    """Bounded metadata read or streamed image hash, with handle/path stability checks."""
    path, before = canonical_path(path)
    require(before.st_size <= limit, "Input exceeds the supported byte bound: " + str(path))
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    blocks, count, hasher = [], 0, hashlib.sha256()
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and signature(opened) == signature(before), "Input identity changed before reading.")
        while True:
            block = stream.read(min(4 * acq.CHUNK, limit - count + 1))
            if not block:
                break
            count += len(block)
            require(count <= limit, "Input grew beyond its byte bound while reading.")
            hasher.update(block)
            if retain:
                blocks.append(block)
        after_handle = os.fstat(stream.fileno())
    _, after_path = canonical_path(path)
    require(signature(before) == signature(after_handle) == signature(after_path) and count == before.st_size,
            "Input changed while reading; create/verify the handoff from stable evidence.")
    return b"".join(blocks) if retain else None, hasher.hexdigest(), signature(before), count


def strict_json(raw):
    def pairs(values):
        result = {}
        for name, value in values:
            require(name not in result, "Duplicate JSON keys are not accepted.")
            result[name] = value
        return result
    def constant(_):
        raise CaseError("Non-finite JSON values are not accepted.")
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs, parse_constant=constant)


def rows(raw):
    try:
        value = strict_json(raw)
    except json.JSONDecodeError:
        value = [strict_json(line) for line in raw.splitlines() if line.strip()]
    if isinstance(value, dict):
        value = [value]
    require(isinstance(value, list) and len(value) <= MAX_ROWS and all(isinstance(row, dict) for row in value), "Original metadata must contain bounded object rows.")
    return value


def image_path(job_id):
    require(isinstance(job_id, str) and acq.ID.fullmatch(job_id), "Invalid acquisition ID.")
    return "images/" + job_id + "/image.bin"


def metadata_path(value):
    require(isinstance(value, str) and re.fullmatch(r"raw/acquisition_metadata/[a-f0-9]{64}\.json", value), "Invalid relative original-metadata path.")
    return value


def inventory(directory):
    """Bounded walk without following a linked/reparse ancestor or child."""
    if entry(directory) is None:
        return set()
    canonical_path(directory, directory=True)
    pending, found, count = [directory], set(), 0
    while pending:
        parent = pending.pop()
        for child in parent.iterdir():
            count += 1
            require(count <= MAX_METADATA * 4, "Raw evidence tree exceeds the entry bound.")
            info = entry(child)
            require(info is not None, "Raw evidence changed while listing.")
            if stat.S_ISDIR(info.st_mode):
                canonical_path(child, directory=True)
                pending.append(child)
            else:
                canonical_path(child)
                found.add(child)
    return found


def source_case(root, case_id):
    root, _ = canonical_path(root, directory=True)
    require(isinstance(case_id, str) and CASE_ID.fullmatch(case_id), "Invalid HashBrown case ID.")
    matches = []
    for count, label in enumerate(root.iterdir(), 1):
        require(count <= MAX_ROWS, "Case store exceeds the bounded label search.")
        info = entry(label)
        if info is not None and stat.S_ISDIR(info.st_mode):
            canonical_path(label, directory=True)
            candidate = label / case_id
            if entry(candidate) is not None:
                canonical_path(candidate, directory=True)
                matches.append(candidate)
    require(len(matches) == 1, "Source case is missing or ambiguous.")
    path = matches[0]
    require(entry(path / ".pending-artifact.json") is None, "Pending case transaction requires separate recovery; handoff will not repair it.")
    tracked, decoded = {}, {}
    for filename in ("case.json", "evidence_manifest.json", "acquisitions.json"):
        raw, checksum, stamp, _ = read_file(path / filename, MAX_JSON)
        tracked[path / filename] = (checksum, stamp, MAX_JSON)
        decoded[filename] = strict_json(raw)
    meta, manifest, state = (decoded[name] for name in ("case.json", "evidence_manifest.json", "acquisitions.json"))
    require(meta.get("tool") == "hashbrown" and type(meta.get("schema")) is int and meta["schema"] == 1
            and meta.get("id") == case_id and meta.get("label") == path.parent.name and LABEL.fullmatch(meta["label"]), "Source case identity mismatch.")
    require(type(manifest.get("schema")) is int and manifest["schema"] == 1 and manifest.get("case_id") == case_id and manifest.get("label") == meta["label"], "Original manifest identity mismatch.")
    require(type(state.get("schema")) is int and state["schema"] == 1, "Invalid source ledger schema.")
    require(isinstance(state.get("jobs"), dict) and len(state["jobs"]) <= MAX_JOBS
            and isinstance(state.get("custody"), list) and len(state["custody"]) <= MAX_CUSTODY, "Source ledger exceeds its job/custody bounds.")
    require(isinstance(manifest.get("artifacts"), list) and len(manifest["artifacts"]) <= MAX_METADATA, "Original metadata registry exceeds its bound.")
    case = SimpleNamespace(path=path, id=case_id, label=meta["label"], meta=meta)
    acq.validate_ledger(case, state, manifest)
    originals, total, expected = {}, 0, set()
    for item in manifest["artifacts"]:
        relative = metadata_path(item["artifact"])
        require(item.get("dataset") == acq.META and item.get("label") == case.label
                and sha(item.get("sha256")) and relative == f"raw/{acq.META}/{item['sha256']}.json", "Invalid original metadata registry entry.")
        target = path / relative
        require(target not in expected, "Duplicate original metadata registry entry.")
        raw, checksum, stamp, size = read_file(target, MAX_RAW)
        total += size
        require(total <= MAX_RAW_TOTAL and checksum == item["sha256"], "Original metadata exceeds its total bound or fails SHA-256 verification.")
        rows(raw)
        tracked[target] = (checksum, stamp, MAX_RAW)
        originals[relative] = raw
        expected.add(target)
    require(inventory(path / "raw") == expected, "Unregistered or missing original raw evidence exists in the source case.")
    return root, case, state, originals, tracked, expected


def projection(state, selected):
    links = []
    for event in state["custody"]:
        links.append(dict(sequence=event["sequence"], previous=event["previous"], sha256=event["sha256"],
                          event=event if event["acquisition_id"] in selected else None))
    return dict(source_event_count=len(links), source_head=links[-1]["sha256"] if links else "0" * 64, links=links)


def validate_custody(custody, selected):
    keys(custody, ("source_event_count", "source_head", "links"), "custody projection")
    links = custody["links"]
    require(type(custody["source_event_count"]) is int and isinstance(links, list)
            and len(links) == custody["source_event_count"] <= MAX_CUSTODY, "Invalid custody count/bound.")
    previous, events, omitted = "0" * 64, [], 0
    for index, link in enumerate(links, 1):
        keys(link, ("sequence", "previous", "sha256", "event"), "custody link")
        require(type(link["sequence"]) is int and link["sequence"] == index and link["previous"] == previous and sha(link["sha256"]), "Custody link continuity failed.")
        event = link["event"]
        if event is None:
            omitted += 1
        else:
            keys(event, ("sequence", "time", "action", "acquisition_id", "operator", "details", "previous", "sha256"), "selected custody event")
            require(event["acquisition_id"] in selected and isinstance(event["details"], dict)
                    and all(event[key] == link[key] for key in ("sequence", "previous", "sha256")), "Selected custody identity differs from its link.")
            timestamp(event["time"])
            require(digest(encode({key: value for key, value in event.items() if key != "sha256"})) == event["sha256"], "Selected custody body hash failed.")
            events.append(event)
        previous = link["sha256"]
    require(previous == custody["source_head"], "Custody chain head mismatch.")
    return events, omitted


def validate_item(item, source, events, originals):
    keys(item, ("acquisition", "binding", "image"), "selected item")
    job, bound, image = item["acquisition"], item["binding"], item["image"]
    require(isinstance(job, dict), "Invalid acquisition record.")
    extra = {"source_path", "source_mtime_ns"} if job.get("mode") == "local-import" else {"artifact", "timeout", "collector_executable_sha256", "parameters", "server_state", "remote_path", "capture"}
    keys(job, JOB_FIELDS | extra, "acquisition record")
    keys(bound, ("client_id", "hostname", "org_id"), "endpoint binding")
    keys(image, ("path", "bytes", "sha256"), "image entry")
    require(isinstance(bound["client_id"], str) and re.fullmatch(r"C\.[a-fA-F0-9]{16}", bound["client_id"])
            and isinstance(bound["hostname"], str) and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,252}", bound["hostname"])
            and isinstance(bound["org_id"], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", bound["org_id"]), "Invalid source endpoint binding.")
    require(all(job.get(key) == bound[key] for key in bound) and job.get("label") == source["label"], "Acquisition/source binding mismatch.")
    require(isinstance(job.get("version"), str) and VERSION.fullmatch(job["version"]), "Malformed acquisition version.")
    timestamp(job["created_at"])
    timestamp(job["updated_at"])
    timestamp(job["verified_at"])
    acq.validate_options(job.get("kind"), job.get("operator"), job.get("max_bytes"), job.get("format"))
    require(type(job.get("simulation")) is bool and job.get("status") in ("verified", "partial") and job.get("integrity") == "verified", "Only committed verified bytes, including partial captures, can be handed off.")
    relative = image_path(job.get("id"))
    require(image["path"] == relative == job.get("content_path") and positive(image["bytes"])
            and all(positive(job.get(key)) for key in ("content_bytes", "expected_size", "offset"))
            and image["bytes"] == job.get("content_bytes") == job.get("expected_size") == job.get("offset")
            and image["bytes"] <= job["max_bytes"] and sha(image["sha256"])
            and image["sha256"] == job.get("content_sha256") == job.get("expected_sha256") == job.get("prefix_sha256"), "Image declaration differs from the acquisition record.")
    own = [event for event in events if event["acquisition_id"] == job["id"]]
    require(all(event["operator"] == job["operator"] for event in own), "Custody operator differs from the saved acquisition operator.")
    verified = [event["details"] for event in own if event["action"] == "image_verified"]
    require(verified and verified[-1].get("sha256") == image["sha256"] and verified[-1].get("bytes") == image["bytes"]
            and verified[-1].get("path") == relative and verified[-1].get("capture_issue") == job.get("capture_issue"), "Image/capture claim differs from its exported custody receipt.")
    require((job["status"] == "partial") == bool(job.get("capture_issue")), "Partial capture status must match its recorded capture issue.")
    require(isinstance(job.get("metadata"), list) and len(job["metadata"]) <= MAX_METADATA, "Invalid acquisition metadata references.")
    latest = {}
    for ref in job["metadata"]:
        keys(ref, ("file", "sha256", "source"), "original metadata reference")
        relative = metadata_path(ref["file"])
        require(relative in originals and sha(ref["sha256"]) and digest(originals[relative]) == ref["sha256"], "Acquisition metadata reference is absent or changed.")
        require(ref["source"] in ("flow", "capture", "uploads"), "Unsupported original metadata source.")
        latest[ref["source"]] = rows(originals[relative])
    mode = job.get("mode")
    if mode == "local-import":
        require(not job["metadata"] and job.get("flow_id") is None and job.get("capture_issue") is None
                and isinstance(job.get("source_path"), str) and bool(job["source_path"])
                and job.get("request") == dict(source=job.get("source_path"), kind=job["kind"]), "Invalid local import provenance.")
        imported = [event["details"] for event in own if event["action"] == "import_started"]
        require(imported and imported[0].get("source_path") == job.get("source_path")
                and imported[0].get("sha256") == image["sha256"] and imported[0].get("bytes") == image["bytes"], "Local source claim differs from its import custody receipt.")
    else:
        require(mode in acq.ARTIFACTS and job.get("artifact") == acq.ARTIFACTS[mode]
                and isinstance(job.get("flow_id"), str) and re.fullmatch(r"F\.[A-Za-z0-9_-]+", job["flow_id"])
                and set(latest) == {"flow", "capture", "uploads"}, "Remote acquisition lacks complete exported provenance.")
        require(len(latest["flow"]) == len(latest["capture"]) == 1, "Expected one original flow and capture descriptor.")
        flow = latest["flow"][0]["Flow"]
        require(flow.get("client_id") == job["client_id"] and flow.get("session_id") == job["flow_id"]
                and flow.get("request", {}).get("artifacts") == [job["artifact"]]
                and flow.get("state") == job["server_state"], "Original flow identity differs from the acquisition.")
        require(job["collector_executable_sha256"] is None or sha(job["collector_executable_sha256"]), "Malformed collector executable fingerprint.")
        supplied = {p["key"]: p["value"] for spec in flow.get("request", {}).get("specs", []) if spec.get("artifact") == job["artifact"]
                    for p in spec.get("parameters", {}).get("env", [])}
        request = job["request"]
        canonical = acq.collection_request(job["kind"], job["operator"], request.get("source"), request.get("disk_number"),
                                           job["simulation"], job["max_bytes"], job["format"], job["timeout"])
        require(request == canonical and canonical["mode"] == mode, "Collection request contradicts the acquisition.")
        parameters = dict(RequestId=job["id"], MaxBytes=str(job["max_bytes"]))
        if canonical["source"]:
            parameters.update(SourcePath=canonical["source"], EvidenceKind=job["kind"], Simulation="Y" if job["simulation"] else "N")
        elif mode == "remote-disk":
            parameters["DiskNumber"] = str(canonical["disk_number"])
        require(job.get("parameters") == parameters and all(str(supplied.get(k)) == v for k, v in parameters.items()), "Original flow parameters differ from the acquisition.")
        result = acq.descriptor(job, latest["capture"][0], latest["uploads"], flow)
        require(all(job.get(key) == result[key] for key in ("expected_size", "expected_sha256", "remote_path", "capture", "capture_started", "capture_finished", "capture_issue", "consistency")), "Original metadata contradicts the saved acquisition/capture status.")
        requested = [event["details"].get("request") for event in own if event["action"] == "requested"]
        require(requested and requested[0] == job.get("request"), "Collection request differs from its custody record.")
    return job["id"]


def summary(manifest):
    source = manifest["source_case"]
    lines = ["HashBrown evidence handoff", f"Source case: {source['id']} | Label: {source['label']}",
             "Copy the selected images yourself, preserving these paths beneath the recipient's chosen evidence root:"]
    for item in manifest["items"]:
        job, image = item["acquisition"], item["image"]
        lines.append(f"- {image['path']} | {image['bytes']} bytes | SHA-256 {image['sha256']} | {job['status']} | synthetic={job['simulation']}")
        lines.append(f"  Source binding: {job['client_id']} / {job['hostname']} / org {job['org_id']}")
    selected = sum(link["event"] is not None for link in manifest["custody"]["links"])
    omitted = len(manifest["custody"]["links"]) - selected
    lines.append(f"Custody projection: {selected} exported bodies; {omitted} omitted bodies represented only by unverified hash links.")
    lines.extend(LIMITATIONS)
    return "\n".join(lines)


def validate_manifest(manifest):
    keys(manifest, ("format", "schema", "producer_version", "created_at", "source_case", "items", "metadata", "custody", "limitations", "summary", "manifest_sha256"), "handoff manifest")
    require(manifest["format"] == FORMAT and type(manifest["schema"]) is int and manifest["schema"] == SCHEMA, "Unsupported handoff format/schema version.")
    require(isinstance(manifest["producer_version"], str) and VERSION.fullmatch(manifest["producer_version"]), "Malformed producer version.")
    require(sha(manifest["manifest_sha256"]) and digest(encode({k: v for k, v in manifest.items() if k != "manifest_sha256"})) == manifest["manifest_sha256"], "Handoff manifest digest failed.")
    timestamp(manifest["created_at"])
    source = manifest["source_case"]
    keys(source, ("id", "label", "created_at", "version"), "source case")
    require(isinstance(source["id"], str) and CASE_ID.fullmatch(source["id"]) and isinstance(source["label"], str) and LABEL.fullmatch(source["label"])
            and isinstance(source["version"], str) and VERSION.fullmatch(source["version"]), "Invalid source case identity/version.")
    timestamp(source["created_at"])
    require(isinstance(manifest["items"], list) and 1 <= len(manifest["items"]) <= MAX_SELECTED, "Invalid selected image count.")
    selected = [item["acquisition"]["id"] for item in manifest["items"]]
    require(len(set(selected)) == len(selected), "Duplicate selected acquisition/image path.")
    events, omitted = validate_custody(manifest["custody"], set(selected))
    require(isinstance(manifest["metadata"], list) and len(manifest["metadata"]) <= MAX_METADATA, "Invalid original metadata count.")
    originals, total = {}, 0
    for item in manifest["metadata"]:
        keys(item, ("file", "bytes", "sha256", "base64"), "embedded original metadata")
        relative = metadata_path(item["file"])
        require(relative not in originals and sha(item["sha256"]) and type(item["bytes"]) is int and 0 <= item["bytes"] <= MAX_RAW
                and isinstance(item["base64"], str) and len(item["base64"]) <= (MAX_RAW + 2) // 3 * 4, "Invalid or duplicate bounded metadata entry.")
        raw = base64.b64decode(item["base64"], validate=True)
        total += len(raw)
        require(total <= MAX_RAW_TOTAL and len(raw) == item["bytes"] and digest(raw) == item["sha256"]
                and relative == f"raw/{acq.META}/{item['sha256']}.json", "Embedded original metadata hash/size/path failed.")
        rows(raw)
        originals[relative] = raw
    bindings, referenced = {}, set()
    for item in manifest["items"]:
        validate_item(item, source, events, originals)
        bound = item["binding"]
        require(bound["client_id"] not in bindings or bindings[bound["client_id"]] == bound, "Conflicting source endpoint bindings.")
        bindings[bound["client_id"]] = bound
        referenced.update(ref["file"] for ref in item["acquisition"]["metadata"])
    require(referenced == set(originals), "Embedded metadata must exactly match selected acquisition references.")
    require(manifest["limitations"] == LIMITATIONS and manifest["summary"] == summary(manifest), "Handoff limitations/readable summary differ from the validated claims.")
    return len(events), omitted


def destination(path, source_root):
    path = local_path(path)
    parent, stamp = canonical_path(path.parent, directory=True)
    require(entry(path) is None, "Output already exists; handoffs never overwrite files.")
    target = parent / path.name
    require(not target.is_relative_to(source_root), "Handoff output must be outside the source case store.")
    return target, signature(stamp)


def publish(path, raw, parent_stamp):
    """Publish a complete fsynced file via exclusive hardlink, never replace()."""
    temp = path.parent / (".hashbrown-handoff-" + uuid.uuid4().hex + ".tmp")
    try:
        with temp.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        parent, info = canonical_path(path.parent, directory=True)
        # Directory mtime changes when creating our temp; compare directory identity only.
        require(signature(info)[:2] == parent_stamp[:2], "Output parent identity changed before publication.")
        os.link(temp, parent / path.name)
    finally:
        temp.unlink(missing_ok=True)


def create(root, case_id, job_ids, output):
    try:
        require(isinstance(job_ids, list) and 1 <= len(job_ids) <= MAX_SELECTED and len(set(job_ids)) == len(job_ids), "Select 1–64 distinct acquisition IDs explicitly.")
        root, case, state, originals, tracked, raw_expected = source_case(root, case_id)
        output, parent_stamp = destination(output, root)
        selected = set(job_ids)
        require(selected <= state["jobs"].keys(), "A selected acquisition is missing from the source case.")
        items, selected_raw = [], set()
        for job_id in job_ids:
            job = state["jobs"][job_id]
            require(bool(job.get("content_path")), "Selected acquisition has no committed image; incomplete transfers cannot be handed off.")
            items.append(dict(acquisition=job, binding=case.meta["endpoints"][job["client_id"]],
                              image=dict(path=image_path(job_id), bytes=job.get("content_bytes"), sha256=job.get("content_sha256"))))
            selected_raw.update(ref["file"] for ref in job["metadata"])
        manifest = dict(format=FORMAT, schema=SCHEMA, producer_version=__version__, created_at=now(),
                        source_case=dict(id=case.id, label=case.label, created_at=case.meta["created_at"], version=case.meta["version"]),
                        items=items, metadata=[dict(file=relative, bytes=len(originals[relative]), sha256=digest(originals[relative]),
                                                   base64=base64.b64encode(originals[relative]).decode("ascii")) for relative in sorted(selected_raw)],
                        custody=projection(state, selected), limitations=LIMITATIONS)
        manifest["summary"] = summary(manifest)
        manifest["manifest_sha256"] = digest(encode(manifest))
        validate_manifest(manifest)
        image_stamps = {}
        for item in items:
            image = item["image"]
            path = case.path / image["path"]
            _, checksum, stamp, size = read_file(path, image["bytes"], retain=False)
            require(checksum == image["sha256"] and size == image["bytes"], "Selected image failed fresh source SHA-256/length verification: " + item["acquisition"]["id"])
            image_stamps[path] = stamp
        # Re-read every original metadata file, including unselected originals, to
        # catch concurrent case/ledger/manifest changes without a mutating lock.
        for path, (checksum, stamp, limit) in tracked.items():
            _, current, current_stamp, _ = read_file(path, limit)
            require(current == checksum and current_stamp == stamp, "Source metadata changed during handoff; no manifest was published.")
        require(inventory(case.path / "raw") == raw_expected, "Source original-metadata inventory changed during handoff.")
        require(entry(case.path / ".pending-artifact.json") is None, "A pending source transaction appeared during handoff; no manifest was published.")
        for path, stamp in image_stamps.items():
            _, info = canonical_path(path)
            require(signature(info) == stamp, "Selected image changed before handoff publication.")
        raw = encode(manifest)
        require(len(raw) <= MAX_MANIFEST, "Detached manifest exceeds its byte bound.")
        publish(output, raw, parent_stamp)
        return dict(status="partial" if any(item["acquisition"]["status"] == "partial" for item in items) else "created",
                    manifest=str(output), manifest_file_sha256=digest(raw), images=len(items),
                    image_copy_performed=False, native_qualification="not_granted", summary=manifest["summary"])
    except (KeyError, TypeError, AttributeError, IndexError, RecursionError) as exc:
        raise CaseError("Malformed source or handoff metadata; no qualification can be made.") from exc


def verify(manifest_path, evidence_root, expected_manifest_sha256=None):
    try:
        raw, file_hash, _, _ = read_file(manifest_path, MAX_MANIFEST)
        if expected_manifest_sha256 is not None:
            require(sha(expected_manifest_sha256) and file_hash == expected_manifest_sha256, "Independently supplied manifest file SHA-256 does not match.")
        manifest = strict_json(raw)
        bodies, omitted = validate_manifest(manifest)
        root, _ = canonical_path(evidence_root, directory=True)
        results = []
        for item in manifest["items"]:
            image, job = item["image"], item["acquisition"]
            result = dict(acquisition_id=job["id"], path=image["path"], capture_status=job["status"],
                          capture_issue=job.get("capture_issue"), simulation=job["simulation"], expected_bytes=image["bytes"], expected_sha256=image["sha256"])
            try:
                path = root / image["path"]
                require(path.is_relative_to(root), "Image path escapes the selected evidence root.")
                _, checksum, _, size = read_file(path, image["bytes"], retain=False)
                result.update(actual_bytes=size, actual_sha256=checksum)
                require(size == image["bytes"] and checksum == image["sha256"], "Fresh image size/SHA-256 differs from the handoff.")
                result["integrity"] = "verified"
            except (CaseError, OSError) as exc:
                result.update(integrity="failed", error=str(exc))
            results.append(result)
        status = "failed" if any(item["integrity"] == "failed" for item in results) else "partial" if any(item["capture_status"] == "partial" for item in results) else "verified"
        return dict(status=status, manifest_file_sha256=file_hash, expected_manifest_hash_matched=expected_manifest_sha256 is not None,
                    evidence_root=str(root), items=results, selected_custody_bodies_verified=bodies,
                    omitted_custody_bodies_unverified=omitted, declared_custody_links="consistent",
                    external_authenticity="not_verified_unsigned", native_qualification="not_granted", limitations=LIMITATIONS)
    except (KeyError, TypeError, AttributeError, IndexError, RecursionError) as exc:
        raise CaseError("Malformed detached handoff; evidence verification was refused.") from exc


def render_text(result):
    if "summary" in result:
        return result["summary"] + "\nManifest file SHA-256: " + result["manifest_file_sha256"]
    lines = ["HashBrown detached verification: " + result["status"].upper()]
    for item in result["items"]:
        lines.append(f"- {item['path']}: bytes {item['integrity']}; capture {item['capture_status']}")
        if item.get("error"):
            lines.append("  " + item["error"])
    lines.append(f"Custody: {result['selected_custody_bodies_verified']} exported bodies verified; {result['omitted_custody_bodies_unverified']} omitted bodies unverified; declared links consistent.")
    lines.extend(result["limitations"])
    return "\n".join(lines)
