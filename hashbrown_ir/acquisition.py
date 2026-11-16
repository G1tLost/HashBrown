"""Bounded binary acquisition, restartable transfers and case evidence custody.

Adapted from MIT-licensed Bacon Egg and Cheese contributors; see THIRD_PARTY_NOTICES.md.
"""
import base64
import hashlib
import os
import re
import shutil
import uuid
from pathlib import Path

from . import __version__
from .endpoint import binding, records
from .storage import CaseError, digest, encode, now, read, save, timestamp

META = "acquisition_metadata"
CHUNK = 1024 * 1024
MAX_BYTES = 256 * 1024 ** 3
RESERVE_BYTES = 16 * CHUNK
ACTIVE = {"submitting", "submission_unknown", "running", "downloading", "retry", "committing"}
ARTIFACTS = {"remote-file": "Custom.HashBrown.AcquireFile", "remote-disk": "Custom.HashBrown.AcquireDisk",
             "remote-memory": "Custom.HashBrown.AcquireMemory"}
ID = re.compile(r"ACQ-[a-f0-9]{16}")
SHA = re.compile(r"[a-f0-9]{64}")


def hash_file(path, limit=None):
    h, count = hashlib.sha256(), 0
    with path.open("rb") as f:
        while limit is None or count < limit:
            block = f.read(min(4 * CHUNK, limit - count) if limit is not None else 4 * CHUNK)
            if not block:
                break
            h.update(block)
            count += len(block)
    return h, count


def load(case):
    path = case.path / "acquisitions.json"
    if not path.exists() and any(p.is_file() for p in (case.path / "images").rglob("*")):
        raise CaseError("Binary evidence exists but its acquisition ledger is missing.")
    state = read(path) if path.exists() else dict(schema=1, case_id=case.id, label=case.label, jobs={}, custody=[])
    return validate_ledger(case, state, case.manifest())


def validate_ledger(case, state, manifest):
    """Validate already-read ledger data without modifying or opening case files."""
    if state.get("schema") != 1 or state.get("case_id") != case.id or state.get("label") != case.label:
        raise CaseError("Acquisition ledger belongs to a different case or schema.")
    previous = "0" * 64
    for index, event in enumerate(state["custody"]):
        body = {k: v for k, v in event.items() if k != "sha256"}
        if event.get("sequence") != index + 1 or event.get("previous") != previous or digest(encode(body)) != event.get("sha256"):
            raise CaseError("Acquisition custody chain verification failed.")
        previous = event["sha256"]
    metadata = {(e["artifact"], e["sha256"]) for e in manifest["artifacts"] if e["dataset"] == META}
    for key, job in state["jobs"].items():
        if not ID.fullmatch(key) or job.get("id") != key or job.get("label") != case.label:
            raise CaseError("Invalid acquisition identity.")
        bound = binding(case, job["client_id"])
        if job["org_id"] != bound["org_id"] or job["hostname"] != bound["hostname"]:
            raise CaseError("Acquisition endpoint binding changed.")
        for ref in job["metadata"]:
            if (not SHA.fullmatch(ref["sha256"]) or ref["file"] != f"raw/{META}/{ref['sha256']}.json"
                    or (ref["file"], ref["sha256"]) not in metadata):
                raise CaseError("Acquisition metadata is not registered in the case evidence manifest.")
        if job.get("content_path"):
            receipts = [e["details"] for e in state["custody"] if e["action"] == "image_verified" and e["acquisition_id"] == key]
            if (not receipts or receipts[-1].get("sha256") != job.get("content_sha256")
                    or receipts[-1].get("bytes") != job.get("content_bytes")
                    or receipts[-1].get("path") != job["content_path"]
                    or job.get("expected_sha256") != job.get("content_sha256")):
                raise CaseError("Binary manifest differs from its custody receipt.")
    return state


def persist(case, state, job=None, action=None, details=None):
    if job:
        job["updated_at"] = now()
        state["jobs"][job["id"]] = job
    if action:
        history = state["custody"]
        event = dict(sequence=len(history) + 1, time=now(), action=action,
                     acquisition_id=job["id"] if job else None,
                     operator=job["operator"] if job else None, details=details or {},
                     previous=history[-1]["sha256"] if history else "0" * 64)
        event["sha256"] = digest(encode(event))
        history.append(event)
    save(case.path / "acquisitions.json", state)


def paths(case, job):
    if not ID.fullmatch(job["id"]):
        raise CaseError("Invalid acquisition ID.")
    folder = case.path / "images" / job["id"]
    for path in (folder, folder / "image.part", folder / "image.bin"):
        if not path.resolve().is_relative_to((case.path / "images").resolve()):
            raise CaseError("Binary evidence path escapes the case store.")
    if not folder.resolve().is_relative_to(case.path.resolve()):
        raise CaseError("Binary evidence directory escapes the case store.")
    return folder / "image.part", folder / "image.bin"


def validate_options(kind, operator, max_bytes=MAX_BYTES, image_format="raw"):
    """Shared, side-effect-free validation for execution and read-only planning."""
    if kind not in ("disk", "memory") or not isinstance(operator, str) or not operator.strip() or len(operator) > 200:
        raise CaseError("Specify disk or memory and a named acquisition operator.")
    if type(max_bytes) is not int or max_bytes <= 0 or image_format not in ("raw", "vhdx", "vmdk", "other"):
        raise CaseError("Provide a positive byte budget and supported image format.")


def collection_request(kind, operator, source=None, disk_number=None, simulation=False,
                       max_bytes=MAX_BYTES, image_format="raw", timeout=86400):
    validate_options(kind, operator, max_bytes, image_format)
    mode = "remote-file" if source else "remote-" + kind
    if mode not in ARTIFACTS or simulation and not source:
        raise CaseError("Simulation requires an explicit fixture file; physical acquisition is never simulated implicitly.")
    if mode == "remote-disk" and (type(disk_number) is not int or not 0 <= disk_number <= 1024):
        raise CaseError("Select the intended Windows disk number explicitly.")
    if source and disk_number is not None or kind != "disk" and disk_number is not None:
        raise CaseError("Choose a source image file or a physical disk number.")
    if not source and image_format != "raw" or type(timeout) is not int or not 60 <= timeout <= 172800:
        raise CaseError("Physical acquisition produces raw images; timeout must be between 60 and 172800 seconds.")
    return dict(mode=mode, source=str(source or ""), disk_number=disk_number, kind=kind,
                simulation=bool(simulation), max_bytes=max_bytes, format=image_format)


def flow_candidate(job, flow_id=None):
    if flow_id and (job.get("flow_id") and job["flow_id"] != flow_id
                    or not re.fullmatch(r"F\.[A-Za-z0-9_-]+", flow_id)):
        raise CaseError("Invalid or conflicting acquisition flow ID.")
    candidate = flow_id or job.get("flow_id")
    if not candidate:
        raise CaseError("Attach the already-submitted flow using --flow-id.")
    return candidate


def new_job(case, client, kind, mode, operator, simulation=False, max_bytes=MAX_BYTES, image_format="raw"):
    bound = binding(case, client)
    validate_options(kind, operator, max_bytes, image_format)
    return dict(id="ACQ-" + uuid.uuid4().hex[:16], label=case.label, client_id=client,
                org_id=bound["org_id"], hostname=bound["hostname"], kind=kind, mode=mode,
                operator=operator.strip(), simulation=bool(simulation), max_bytes=max_bytes,
                format=image_format, status="submitting", created_at=now(), offset=0,
                prefix_sha256=hashlib.sha256().hexdigest(), metadata=[], flow_id=None,
                integrity="not_verified", version=__version__)


def preserve_metadata(case, job, raw, source):
    rows = records(raw)
    sha = digest(raw)
    query = dict(acquisition_id=job["id"], client_id=job["client_id"], org_id=job["org_id"],
                 flow_id=job["flow_id"], source=source)
    case.preserve(META, raw, "velociraptor", query, len(rows), [None, None])
    pointer = dict(file=f"raw/{META}/{sha}.json", sha256=sha, source=source)
    if pointer not in job["metadata"]:
        job["metadata"].append(pointer)


def start(case, client, kind, api, operator, source=None, disk_number=None, simulation=False,
          max_bytes=MAX_BYTES, image_format="raw", timeout=86400):
    request = collection_request(kind, operator, source, disk_number, simulation, max_bytes, image_format, timeout)
    mode = request["mode"]
    job = new_job(case, client, kind, mode, operator, simulation, max_bytes, image_format)
    if api.org != job["org_id"]:
        raise CaseError("API organization differs from the case binding.")
    state = load(case)
    for old in state["jobs"].values():
        if old["client_id"] == client and old["kind"] == kind and old["status"] in ACTIVE:
            if old["request"] == request:
                return old
            raise CaseError("An unfinished acquisition already exists for this endpoint and evidence kind. Resume its saved ID.")
    _, clients = api.query("SELECT client_id, os_info FROM clients(client_id=ClientId)", {"ClientId": client})
    if (len(clients) != 1 or clients[0].get("client_id") != client
            or str(clients[0].get("os_info", {}).get("fqdn", "")).strip().rstrip(".").casefold() != job["hostname"]):
        raise CaseError("Server endpoint identity differs from the bound hostname.")
    job.update(request=request, artifact=ARTIFACTS[mode], timeout=timeout,
               collector_executable_sha256=hash_file(api.exe)[0].hexdigest() if hasattr(api, "exe") else None)
    env = dict(RequestId=job["id"], MaxBytes=str(max_bytes))
    if source:
        env.update(SourcePath=str(source), EvidenceKind=kind, Simulation="Y" if simulation else "N")
    elif mode == "remote-disk":
        env["DiskNumber"] = str(disk_number)
    job["parameters"] = env
    persist(case, state, job, "requested", {"request": request})
    try:
        _, rows = api.query("""SELECT collect_client(client_id=ClientId, artifacts=[ArtifactName],
            env=parse_json(data=Parameters), timeout=int(int=Duration), max_rows=100,
            max_bytes=int(int=ByteBudget)) AS Result FROM scope()""",
            dict(ClientId=client, ArtifactName=job["artifact"], Parameters=encode(env).decode(), Duration=timeout, ByteBudget=max_bytes))
        flow = rows[0]["Result"]["flow_id"]
        if not re.fullmatch(r"F\.[A-Za-z0-9_-]+", flow):
            raise CaseError("Invalid acquisition flow ID.")
        job.update(flow_id=flow, status="running")
    except (CaseError, KeyError, TypeError, IndexError) as exc:
        job.update(status="submission_unknown", error="Submission outcome is unknown. Inspect Velociraptor and attach the original flow with acquisition sync --flow-id.")
        persist(case, state, job, "submission_unknown")
        raise CaseError(job["id"] + ": " + job["error"]) from exc
    persist(case, state, job, "collection_started", {"flow_id": flow})
    return job


def number(value):
    return int(value, 16 if value.lower().startswith("0x") else 10) if isinstance(value, str) else int(value)


def memory_extent(info):
    runs = info.get("Run", []) if isinstance(info, dict) else []
    if not runs:
        raise CaseError("WinPmem did not report physical memory ranges.")
    end = 0
    for run in sorted(runs, key=lambda r: number(r["BaseAddress"])):
        base, size = number(run["BaseAddress"]), number(run["NumberOfBytes"])
        if base < end or size <= 0:
            raise CaseError("WinPmem returned invalid or overlapping memory ranges.")
        end = base + size
    return end


def descriptor(job, row, uploads, flow):
    if (row.get("RequestId") != job["id"] or row.get("EvidenceKind") != job["kind"]
            or row.get("Simulation") is not job["simulation"]):
        raise CaseError("Acquisition result does not match its saved request.")
    timestamp(row["Started"])
    if timestamp(row["Finished"]) < timestamp(row["Started"]):
        raise CaseError("Invalid acquisition time window.")
    upload = row.get("Upload") or {}
    size, sha = number(upload.get("Size", 0)), str(upload.get("sha256", "")).lower()
    if size <= 0 or size > job["max_bytes"] or not SHA.fullmatch(sha):
        raise CaseError("Upload is empty, exceeds the byte budget or has no endpoint SHA-256.")
    matches = [u for u in uploads if u.get("client_path") == "image.raw" and u.get("Type", "") != "idx"]
    if len(matches) != 1:
        raise CaseError("Expected exactly one image upload in the bound collection.")
    uploaded = matches[0]
    components = uploaded.get("_Components", [])
    if (components[:5] != ["clients", job["client_id"], "collections", job["flow_id"], "uploads"]
            or len(components) != 7 or components[-1] != "image.raw"
            or any(not isinstance(c, str) or c in ("", ".", "..") or re.search(r"[/\\:\x00]", c) for c in components)):
        raise CaseError("Server upload path escapes the bound collection.")
    if number(uploaded.get("file_size", 0)) != size:
        raise CaseError("Server upload length differs from the endpoint result.")
    issue = None
    if flow.get("state") != "FINISHED" or any(q.get("status", "OK") not in ("OK", 0) for q in flow.get("query_stats", [])):
        issue = "Collection ended with errors; captured bytes may be incomplete."
    if number(row.get("ExpectedSize", 0)) != size:
        issue = "Captured length differs from the expected source size."
    if job["mode"] == "remote-memory":
        try:
            expected = memory_extent(row.get("ImageInfo"))
            if expected != size:
                issue = "Memory image length differs from the reported physical address extent."
        except (CaseError, KeyError, ValueError, TypeError) as exc:
            issue = str(exc)
    return dict(expected_size=size, expected_sha256=sha, remote_path="/" + "/".join(components),
                capture_started=row["Started"], capture_finished=row["Finished"], capture=row,
                capture_issue=issue, consistency="Live capture may contain changes during acquisition." if job["mode"] != "remote-file" else "Existing image; capture history is supplied by its operator.")


def transfer(case, state, job, reader, chunk_size=CHUNK):
    if not 1 <= chunk_size <= 8 * CHUNK:
        raise CaseError("Invalid binary transfer chunk size.")
    part, final = paths(case, job)
    part.parent.mkdir(parents=True, exist_ok=True)
    expected, target_hash = job["expected_size"], job["expected_sha256"]
    if final.exists():
        h, size = hash_file(final)
        if size != expected or h.hexdigest() != target_hash:
            raise CaseError("Previously committed binary evidence does not match its acquisition.")
    else:
        if part.exists():
            if part.stat().st_size < job["offset"]:
                raise CaseError("Partial evidence is shorter than its saved checkpoint.")
            h, size = hash_file(part, job["offset"])
            if size != job["offset"] or h.hexdigest() != job["prefix_sha256"]:
                raise CaseError("Partial evidence hash differs from its saved checkpoint.")
        else:
            if job["offset"]:
                raise CaseError("Saved partial evidence is missing.")
            h = hashlib.sha256()
        if shutil.disk_usage(part.parent).free < expected - job["offset"] + RESERVE_BYTES:
            raise CaseError("Insufficient free space for the remaining image and a 16 MiB reserve.")
        job["status"] = "downloading"
        persist(case, state, job)
        with part.open("r+b" if part.exists() else "x+b") as f:
            f.truncate(job["offset"])
            f.seek(job["offset"])
            while job["offset"] < expected:
                size = min(chunk_size, expected - job["offset"])
                block = reader(job["offset"], size)
                if not isinstance(block, bytes) or len(block) != size:
                    raise CaseError("Image transfer returned a short or invalid chunk.")
                f.write(block)
                f.flush()
                os.fsync(f.fileno())
                h.update(block)
                job.update(offset=job["offset"] + size, prefix_sha256=h.hexdigest())
                persist(case, state, job)
        if h.hexdigest() != target_hash:
            job.update(status="integrity_failed", integrity="failed", error="Downloaded SHA-256 differs from the source acquisition hash.")
            persist(case, state, job, "integrity_failed")
            raise CaseError(job["error"])
        job["status"] = "committing"
        persist(case, state, job)
        os.replace(part, final)
    committed = {**job}
    committed.update(status="partial" if job.get("capture_issue") else "verified", integrity="verified",
               content_path=final.relative_to(case.path).as_posix(), content_sha256=target_hash,
               content_bytes=expected, verified_at=now(), verified_mtime_ns=final.stat().st_mtime_ns)
    committed.pop("error", None)
    persist(case, state, committed, "image_verified", {"sha256": target_hash, "bytes": expected,
              "path": committed["content_path"], "capture_issue": committed.get("capture_issue")})
    return committed


def resume(case, job_id, api=None, download_api=None, flow_id=None, chunk_size=CHUNK):
    state = load(case)
    job = state["jobs"].get(job_id)
    if not job:
        raise CaseError("Acquisition was not found.")
    if job.get("content_path"):
        verify_one(case, job)
        return job
    if job["status"] == "integrity_failed":
        raise CaseError("Integrity-failed evidence is retained. Start a separate acquisition to retry.")
    try:
        _, final = paths(case, job)
        if final.exists() and job.get("expected_size") == job["offset"] and job.get("expected_sha256") == job["prefix_sha256"]:
            return transfer(case, state, job, lambda offset, size: b"", chunk_size)
        if job["mode"] == "local-import":
            source = Path(job["source_path"])
            if source.stat().st_size != job["expected_size"] or source.stat().st_mtime_ns != job["source_mtime_ns"]:
                raise CaseError("Source image changed since this import began.")
            with source.open("rb") as f:
                def reader(offset, length):
                    f.seek(offset)
                    return f.read(length)
                return transfer(case, state, job, reader, chunk_size)
        if not api or api.org != job["org_id"]:
            raise CaseError("Use API credentials for the bound Velociraptor organization.")
        download_api = download_api or api
        if download_api.org != job["org_id"]:
            raise CaseError("Download API organization differs from the case binding.")
        candidate = flow_candidate(job, flow_id)
        variables = dict(ClientId=job["client_id"], FlowId=candidate, ArtifactName=job["artifact"])
        raw, rows = api.query("SELECT get_flow(client_id=ClientId,flow_id=FlowId) AS Flow FROM scope()", variables)
        flow = rows[0]["Flow"]
        if (flow.get("client_id") != job["client_id"] or flow.get("session_id") != candidate
                or flow.get("request", {}).get("artifacts") != [job["artifact"]]):
            raise CaseError("Flow identity differs from the saved acquisition.")
        specs = flow.get("request", {}).get("specs", [])
        supplied = {p["key"]: p["value"] for spec in specs if spec.get("artifact") == job["artifact"]
                    for p in spec.get("parameters", {}).get("env", [])}
        if any(str(supplied.get(k)) != v for k, v in job["parameters"].items()):
            raise CaseError("Flow parameters differ from the saved acquisition request.")
        if not job.get("flow_id"):
            job["flow_id"] = candidate
            persist(case, state, job, "flow_attached", {"flow_id": candidate})
        job["server_state"] = flow.get("state")
        if flow.get("state") in ("IN_PROGRESS", "RUNNING", "WAITING", "UNSET"):
            job["status"] = "running"
            persist(case, state, job)
            return job
        preserve_metadata(case, job, raw, "flow")
        raw, rows = api.query("SELECT * FROM source(client_id=ClientId,flow_id=FlowId,artifact=ArtifactName)", variables)
        preserve_metadata(case, job, raw, "capture")
        raw, uploads = api.query("SELECT * FROM uploads(client_id=ClientId,flow_id=FlowId)", variables)
        preserve_metadata(case, job, raw, "uploads")
        if len(rows) != 1:
            job.update(status="partial", error="No single completed image descriptor. Inspect Velociraptor collection logs; any server-side partial uploads remain there.")
            persist(case, state, job, "capture_incomplete")
            return job
        details = descriptor(job, rows[0], uploads, flow)
        if job.get("expected_sha256") and any(job.get(k) != details[k] for k in ("expected_sha256", "expected_size", "remote_path")):
            raise CaseError("Server image changed after the download checkpoint.")
        job.update(details)
        persist(case, state, job)
        def reader(offset, length):
            _, response = download_api.query("""SELECT base64encode(string=read_file(filename=ImagePath,
                accessor="fs_sparse",offset=int(int=ByteOffset),length=int(int=ByteCount))) AS Data FROM scope()""",
                dict(ImagePath=job["remote_path"], ByteOffset=offset, ByteCount=length))
            if len(response) != 1 or not isinstance(response[0].get("Data"), str):
                raise CaseError("Server did not return an image chunk. Check the download credential's filestore permissions.")
            return base64.b64decode(response[0]["Data"], validate=True)
        return transfer(case, state, job, reader, chunk_size)
    except (CaseError, OSError, KeyError, TypeError, IndexError, ValueError) as exc:
        if job["status"] != "integrity_failed":
            job.update(status="retry", error=str(exc))
            persist(case, state, job, "interrupted", {"offset": job["offset"], "reason": str(exc)})
        raise CaseError(f"{job_id}: {exc}") from exc


def import_image(case, client, kind, path, operator, simulation=False, max_bytes=MAX_BYTES,
                 image_format="raw", expected_sha256=None):
    path = Path(path).resolve()
    if not path.is_file() or not 0 < path.stat().st_size <= max_bytes:
        raise CaseError("Source image is missing, empty or exceeds the byte budget.")
    job = new_job(case, client, kind, "local-import", operator, simulation, max_bytes, image_format)
    before = path.stat()
    h, size = hash_file(path)
    if path.stat().st_mtime_ns != before.st_mtime_ns or size != before.st_size:
        raise CaseError("Source changed while calculating its acquisition hash.")
    sha = h.hexdigest()
    if expected_sha256 and (not SHA.fullmatch(expected_sha256.lower()) or sha != expected_sha256.lower()):
        raise CaseError("Source image differs from the supplied SHA-256.")
    job.update(source_path=str(path), source_mtime_ns=before.st_mtime_ns, expected_size=size,
               expected_sha256=sha, capture_started=None, capture_finished=None, capture_issue=None,
               consistency="Existing image; original acquisition time and method are supplied by its operator.",
               status="downloading", request=dict(source=str(path), kind=kind))
    state = load(case)
    persist(case, state, job, "import_started", {"source_path": str(path), "sha256": sha, "bytes": size})
    return resume(case, job["id"])


def verify_one(case, job):
    _, path = paths(case, job)
    if job.get("content_path") != path.relative_to(case.path).as_posix() or not path.is_file():
        raise CaseError("Binary evidence is missing or its path changed.")
    h, size = hash_file(path)
    if size != job["content_bytes"] or h.hexdigest() != job["content_sha256"]:
        raise CaseError("Binary evidence verification failed: " + job["id"])


def verify(case, record=False):
    state, count, expected = load(case), 0, set()
    for job in state["jobs"].values():
        part, final = paths(case, job)
        expected.update((part, final))
        if job.get("content_path"):
            verify_one(case, job)
            count += 1
            if record:
                job.update(verified_at=now(), verified_mtime_ns=final.stat().st_mtime_ns)
                persist(case, state, job, "reverified", {"sha256": job["content_sha256"]})
        elif job["offset"] and not final.exists():
            if not part.is_file():
                raise CaseError("Saved partial evidence is missing: " + job["id"])
            h, size = hash_file(part, job["offset"])
            if size != job["offset"] or h.hexdigest() != job["prefix_sha256"]:
                raise CaseError("Partial evidence checkpoint verification failed: " + job["id"])
        if final.exists() and not job.get("content_path"):
            h, size = hash_file(final)
            if size != job.get("expected_size") or h.hexdigest() != job.get("expected_sha256"):
                raise CaseError("Uncommitted binary image differs from its saved acquisition.")
    extra = {p for p in (case.path / "images").rglob("*") if p.is_file()} - expected
    if extra:
        raise CaseError("Unregistered binary evidence exists in the case images directory.")
    return count


def note(case, job_id, operator, text, references=()):
    state = load(case)
    job = state["jobs"].get(job_id)
    if not job or not operator.strip() or len(operator) > 200 or not text.strip() or len(text) > 4000:
        raise CaseError("Provide an acquisition ID, operator and note of 1–4000 characters.")
    if len(references) > 20 or any(not isinstance(ref, str) or not ref.strip() or len(ref) > 1000 for ref in references):
        raise CaseError("Supply at most 20 nonempty references, each at most 1000 characters.")
    persist(case, state, job, "analyst_note", {"author": operator.strip(), "note": text,
                                              "references": list(references)})


def summary(case):
    state = load(case)
    jobs, gaps = list(state["jobs"].values()), []
    for job in jobs:
        if job["status"] != "verified":
            gaps.append(dict(dataset="acquisition/" + job["kind"], value=job["id"],
                reason=job.get("capture_issue") or job.get("error") or "Acquisition " + job["status"]))
        if job.get("content_path"):
            _, path = paths(case, job)
            if not path.is_file() or path.stat().st_size != job["content_bytes"] or path.stat().st_mtime_ns != job["verified_mtime_ns"]:
                gaps.append(dict(dataset="acquisition/" + job["kind"], value=job["id"],
                    reason="Evidence changed or is missing since its last verification. Run hashbrown verify."))
    return jobs, state["custody"], gaps
