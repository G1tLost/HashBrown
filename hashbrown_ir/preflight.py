"""Read-only local acquisition planning. Never invokes a collector or opens image bytes."""
import os
import re
import shutil
import stat
from pathlib import Path

from . import __version__, acquisition as acq
from .endpoint import binding
from .storage import CASE_ID, Case, CaseError, now


class Plan:
    def __init__(self, args):
        self.value = dict(schema=1, tool="hashbrown", version=__version__, read_only=True,
                          inspected_at=now(), operation=args.action, case_id=args.case_id,
                          checks=[], unknowns=[], plan={})

    def check(self, name, status, message, **details):
        self.value["checks"].append(dict(name=name, status=status, message=message, details=details))

    def unknown(self, subject, reason):
        self.value["unknowns"].append(dict(subject=subject, reason=reason))

    def finish(self):
        levels = {item["status"] for item in self.value["checks"]}
        self.value["status"] = "fail" if "fail" in levels else "warning" if "warning" in levels else "pass"
        self.unknown("execution_state", "No lock or write probe was taken. Permissions, other writers and available space can change before execution.")
        self.unknown("filesystem_backing", "Use local storage. Known network paths are rejected, but filesystem mount backends are not certified on every platform.")
        self.unknown("byte_integrity", "No image or credential contents were read and no SHA-256 was checked. Execution performs its normal integrity checks.")
        self.unknown("capture_completeness", "A plan, declared size, fixture result or matching hash cannot establish complete or consistent physical capture.")
        return self.value


def local_path(value):
    """Reject obvious network/device namespaces before any filesystem inspection."""
    raw = str(value)
    windows = raw.replace("/", "\\")
    if (not raw or "\x00" in raw or windows.casefold().startswith(("\\\\", "\\??\\", "\\device\\"))
            or any(re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part.rstrip(" ."))
                   for part in (segment.split(":", 1)[0] for segment in windows.split("\\")))):
        raise CaseError("Use a local filesystem path; network paths and device namespaces are not inspected.")
    path = Path(value)
    if ".." in path.parts:
        raise CaseError("Parent-traversal paths are not inspected; supply a direct local path.")
    if os.name == "nt":
        # This local OS query identifies mapped network drives without opening them.
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(str(path.absolute().anchor)) == 4:
            raise CaseError("Mapped network drives are not inspected by local preflight.")
        if any(":" in part for part in path.parts if part != path.anchor):
            raise CaseError("Alternate data streams are not inspected by preflight.")
    elif path.is_absolute() and path.parts[1:2] in (("dev",), ("proc",), ("sys",)):
        raise CaseError("Device and kernel pseudo-filesystems are not inspected by preflight.")
    return path.absolute()


def entry(path):
    """Inspect ancestors before the leaf; never follow an observed linked entry."""
    path = local_path(path)
    for current in (*reversed(path.parents), path):
        try:
            value = current.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(value.st_mode) or (getattr(value, "st_file_attributes", 0) or 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise CaseError("Linked or reparse-point ancestors/entries are not inspected by preflight.")
        if current != path and not stat.S_ISDIR(value.st_mode):
            raise CaseError("A non-directory entry blocks the supplied local path.")
    return value


def regular_input(plan, name, value, executable=False):
    if value is None:
        plan.check(name, "fail", "Required local path was not supplied.")
        return None
    try:
        path = local_path(value)
        info = entry(path)
        if info is None or not stat.S_ISREG(info.st_mode):
            raise CaseError("Required path must be an existing regular file; directories, devices and FIFOs are not inspected.")
        if not info.st_size:
            raise CaseError("Required regular file is empty.")
        # Resolve only after regular-file classification; also expands Windows 8.3 aliases.
        path = path.resolve()
        local_path(path)
        if not os.access(path, os.R_OK):
            raise CaseError("Required regular file is not readable by the current process.")
        if executable and os.name != "nt" and not os.access(path, os.X_OK):
            raise CaseError("Collector file is not marked executable for the current process.")
        plan.check(name, "pass", "Regular file exists; only filesystem metadata was inspected.", path=str(path), bytes=info.st_size)
        return path, info
    except CaseError as exc:
        plan.check(name, "fail", str(exc))
    except OSError:
        # Do not render arbitrary OS or configuration data in output.
        plan.check(name, "fail", "Unable to inspect the supplied local path.")
    return None


def case_state(args):
    root = local_path(args.root)
    if not CASE_ID.fullmatch(args.case_id):
        raise CaseError("Invalid HashBrown case ID.")
    info = entry(root)
    if info is None or not stat.S_ISDIR(info.st_mode):
        raise CaseError("HashBrown case root does not exist or is not a regular directory.")
    root = root.resolve()
    local_path(root)
    matches = []
    # Do not glob through linked labels: inspect each ancestor before descending.
    for label in root.iterdir():
        try:
            label_info = entry(label)
        except CaseError:
            continue
        if label_info is not None and stat.S_ISDIR(label_info.st_mode):
            candidate = label / args.case_id
            candidate_info = entry(candidate)
            if candidate_info is not None and stat.S_ISDIR(candidate_info.st_mode):
                matches.append(candidate / "case.json")
    if len(matches) != 1:
        raise CaseError("Case not found or ambiguous in this HashBrown store.")
    path = matches[0].parent
    for directory in (path.parent, path):
        info = entry(directory)
        if info is None or not stat.S_ISDIR(info.st_mode):
            raise CaseError("Case location is not a regular directory.")
    for filename in ("case.json", "evidence_manifest.json", "acquisitions.json"):
        info = entry(path / filename)
        if info is None and filename != "acquisitions.json" or info is not None and not stat.S_ISREG(info.st_mode):
            raise CaseError("Case metadata must consist of regular files.")
    if entry(path / ".pending-artifact.json") is not None:
        raise CaseError("A pending metadata transaction needs recovery with verify before preflight; nothing was repaired.")
    images = path / "images"
    image_info = entry(images)
    if entry(path / "acquisitions.json") is None and image_info and stat.S_ISDIR(image_info.st_mode) and any(images.iterdir()):
        raise CaseError("Image entries exist but the acquisition ledger is missing.")
    case = Case(path)
    return case, acq.load(case)


def output_state(plan, case, job):
    """Check destination types and saved checkpoint lengths, never content hashes."""
    images = case.path / "images"
    folder = images / job["id"] if job else images
    output = dict(directory=str(folder), new_acquisition_id=not bool(job))
    if not job:
        output["path_template"] = str(images / "<new-acquisition-id>" / "image.bin")
    plan.value["plan"]["output"] = output
    try:
        for directory in dict.fromkeys((images, folder)):
            info = entry(directory)
            if info is not None and not stat.S_ISDIR(info.st_mode):
                raise CaseError("A file or special entry occupies a required output directory.")
        if not job:
            plan.check("output", "pass", "Existing destination directories have no blocking type collision. A new acquisition ID is allocated only during execution.", **output)
            return folder, 0
        # Classify leaves before acq.paths resolves them, so a linked output is
        # rejected before resolution could follow its target.
        infos = [entry(path) for path in (folder / "image.part", folder / "image.bin")]
        if any(info is not None and not stat.S_ISREG(info.st_mode) for info in infos):
            raise CaseError("A directory or special entry occupies an image output path.")
        part, final = acq.paths(case, job)
        output.update(partial_path=str(part), final_path=str(final))
        partial, committed = infos
        offset = job.get("offset", 0)
        size = job.get("expected_size")
        if (type(offset) is not int or offset < 0 or offset and size is None
                or size is not None and (type(size) is not int or size <= 0 or offset > size)):
            raise CaseError("Invalid saved transfer size or checkpoint offset.")
        if partial and committed:
            raise CaseError("Both partial and final outputs exist; resolve the collision before transfer.")
        if job.get("content_path") and not committed:
            raise CaseError("The committed output recorded in the ledger is missing.")
        if committed:
            if committed.st_size != size:
                raise CaseError("Existing final output length differs from the saved acquisition.")
            if not job.get("content_path") and (offset != size or job.get("prefix_sha256") != job.get("expected_sha256")):
                raise CaseError("Existing final output conflicts with the saved transfer checkpoint.")
            output["existing_final"] = True
            plan.check("output", "warning", "Existing final bytes require a full hash check during sync; preflight did not verify them.", **output)
            return folder, size
        if offset and (partial is None or partial.st_size < offset):
            raise CaseError("Saved partial bytes are missing or shorter than the checkpoint.")
        if partial and partial.st_size > offset:
            plan.check("output", "warning", "Uncheckpointed trailing bytes will be discarded by normal resume after prefix verification.", **output)
        else:
            plan.check("output", "pass", "No blocking output collision was observed; saved prefix hashes remain unchecked.", **output)
        return folder, offset
    except CaseError as exc:
        plan.check("output", "fail", str(exc), **output)
    except OSError:
        plan.check("output", "fail", "Unable to inspect output filesystem metadata.", **output)
    return None, 0


def capacity(plan, folder, size, offset, budget, basis):
    probe = folder
    try:
        while entry(probe) is None:
            probe = probe.parent
        probe = probe.resolve()
        free = shutil.disk_usage(probe).free
        remaining = max(0, (size if size is not None else budget) - offset)
        reserve = 0 if plan.value["plan"]["output"].get("existing_final") else acq.RESERVE_BYTES
        required = remaining + reserve
        value = dict(host="analyst", scope="case output filesystem", probe_path=str(probe),
                     free_bytes=free, remaining_bytes=remaining, reserve_bytes=reserve,
                     required_free_bytes=required, basis=basis if size is not None else "budget_ceiling",
                     advisory=True)
        plan.value["plan"]["capacity"] = value
        if free < required:
            status = "fail" if size is not None else "warning"
            message = "Observed analyst output free space is below the planned bytes plus reserve; no space is reserved."
        else:
            status = "pass" if size is not None else "warning"
            message = "Observed analyst output free space covers this estimate plus reserve; no space is reserved."
        plan.check("capacity", status, message, **value)
    except (OSError, CaseError):
        plan.check("capacity", "warning", "Analyst output free space could not be determined; no write probe was attempted.")
        plan.unknown("analyst_capacity", "Filesystem free-space query failed.")


def prerequisites(plan, args, remote):
    supplied = {name: getattr(args, name, None) for name in ("velociraptor", "api_config", "download_api_config")}
    if remote or any(supplied.values()):
        regular_input(plan, "velociraptor", supplied["velociraptor"], executable=True)
        regular_input(plan, "api_config", supplied["api_config"])
        if supplied["download_api_config"]:
            regular_input(plan, "download_api_config", supplied["download_api_config"])
    if remote:
        plan.check("remote_prerequisites", "warning", "Collector was not executed; server/client connectivity, artifact installation and API roles were not checked.")
        plan.unknown("remote_access", "API configuration contents were not read. Organization, credentials and roles are unvalidated; binary fs_sparse retrieval requires SERVER_ADMIN in the bound organization.")
        plan.unknown("remote_capacity", "Endpoint staging and Velociraptor server storage were not queried. Memory staging can exceed its budget before upload checks.")
        plan.unknown("physical_capture", "No device or RAM extent, driver compatibility or physical-capture capability was probed.")


def resumed_source(plan, args, job):
    """An explicit --file permits metadata comparison with the saved import source."""
    inspected = regular_input(plan, "source_file", args.file)
    if not inspected:
        return None
    path, info = inspected
    saved = local_path(job["source_path"])
    saved_info = entry(saved)
    if saved_info is None or not stat.S_ISREG(saved_info.st_mode) or not os.path.samestat(info, saved_info):
        plan.check("saved_source", "fail", "Explicit file is not the saved local import source; preflight cannot redirect a saved acquisition.")
    elif info.st_size != job.get("expected_size") or info.st_mtime_ns != job.get("source_mtime_ns"):
        plan.check("saved_source", "fail", "Local source size or modification time differs from the saved import.")
    else:
        plan.check("saved_source", "pass", "Explicit source identity, size and modification time match saved metadata; no content hash was checked.")
    return inspected


def source_collision(plan, case, job, inspected):
    if not job or inspected is None:
        return
    path, info = inspected
    for target in acq.paths(case, job):
        target_info = entry(target)
        if target_info is not None and (path == target.resolve() or os.path.samestat(info, target_info)):
            plan.check("source_destination", "fail", "The original source and an image output are the same file (including aliases or hardlinks); do not resume this layout.")
            return
    plan.check("source_destination", "pass", "Explicit source and existing image outputs have distinct filesystem identities.")


def plan(args):
    result = Plan(args)
    details = result.value["plan"]
    declared = args.declared_bytes
    if declared is not None and (type(declared) is not int or declared <= 0):
        result.check("declared_size", "fail", "Declared bytes must be a positive integer.")
        return result.finish()
    request = None
    if args.action != "sync":
        try:
            acq.validate_options(args.kind, args.operator, args.max_bytes, args.format)
            if args.action == "collect":
                request = acq.collection_request(args.kind, args.operator, args.source, args.disk_number,
                                                 args.simulation, args.max_bytes, args.format, args.timeout)
            if args.action == "import" and args.sha256 and not acq.SHA.fullmatch(args.sha256.lower()):
                raise CaseError("Supplied SHA-256 must contain 64 hexadecimal characters; preflight does not hash the source.")
            result.check("parameters", "pass", "Parameters satisfy the same validation used by acquisition.")
        except CaseError as exc:
            result.check("parameters", "fail", str(exc))
            return result.finish()
    try:
        case, state = case_state(args)
        details["case_path"] = str(case.path)
        result.check("case", "pass", "Case identity, binding references and custody structure were read without locking or repairing evidence.")
        job = state["jobs"].get(args.job) if args.action == "sync" else None
        if args.action == "sync" and not job:
            raise CaseError("Acquisition was not found.")
        if request:
            for old in state["jobs"].values():
                if old["client_id"] == args.client_id and old["kind"] == args.kind and old["status"] in acq.ACTIVE:
                    if old["request"] != request:
                        raise CaseError("An unfinished conflicting acquisition exists. Resume its saved ID.")
                    job = old
                    result.check("existing_request", "warning", "Collect would return this unfinished acquisition without resubmission; use sync to transfer it.", job_id=job["id"])
                    break
        bound = binding(case, job["client_id"] if job else args.client_id)
        details["endpoint"] = bound
        mode = job["mode"] if job else request["mode"] if request else "local-import"
        budget = job["max_bytes"] if job else args.max_bytes
        kind = job["kind"] if job else args.kind
        acq.validate_options(kind, job["operator"] if job else args.operator, budget, job["format"] if job else args.format)
        details.update(mode=mode, kind=kind, max_bytes=budget,
                       timeout_seconds=job.get("timeout") if job else getattr(args, "timeout", None))
        if job:
            details.update(job_id=job["id"], saved_status=job["status"])
            if job["status"] == "integrity_failed":
                raise CaseError("Integrity-failed evidence is retained. Start a separate acquisition to retry.")
        source = dict(host="analyst" if mode == "local-import" else "endpoint", size_bytes=None, size_basis="unknown")
        size, basis = None, "unknown"
        inspected = None
        if args.action == "import":
            inspected = regular_input(result, "source_file", args.file)
            if inspected:
                source["path"], info = str(inspected[0]), inspected[1]
                size, basis = info.st_size, "observed_file_metadata"
        elif job:
            source["path"] = job.get("source_path") or job.get("request", {}).get("source") or None
            size = job.get("expected_size")
            basis = "saved_descriptor" if size is not None else "unknown"
            if mode == "local-import" and getattr(args, "file", None):
                inspected = resumed_source(result, args, job)
                if inspected:
                    source["path"] = str(inspected[0])
            elif mode == "local-import":
                result.check("local_resume_source", "warning", "Use sync --preflight --file ORIGINAL to inspect the saved local source and check source/output aliases.")
                result.unknown("local_resume_source", "Saved source availability, unchanged metadata and same-file output collisions were not checked without explicit --file.")
            elif getattr(args, "file", None):
                result.check("source_file", "fail", "--file on sync preflight is only for a saved local import; it cannot inspect or redirect a remote source.")
        elif request:
            source["path"] = request["source"] or None
            source["disk_number"] = request["disk_number"]
        if size is not None and (type(size) is not int or size <= 0):
            raise CaseError("Saved or observed source size is invalid.")
        if declared is not None:
            source["declared_bytes"] = declared
            if size is not None and declared != size:
                result.check("declared_size", "fail", "Declared size differs from observed file metadata or the saved descriptor.", declared_bytes=declared, known_bytes=size)
            elif size is None:
                size, basis = declared, "operator_declaration"
                result.check("declared_size", "warning", "Size is an unverified planning declaration; it does not constrain a later capture.", declared_bytes=declared)
        source.update(size_bytes=size, size_basis=basis)
        details["source"] = source
        if size is None:
            result.check("source_size", "warning", "Source extent is unknown. Capacity uses the byte budget as a planning ceiling, not a measured image size.")
            result.unknown("source_extent", "A source size could not be established from the explicitly supplied local file, saved descriptor or operator declaration. No device or remote source was probed.")
        elif size > budget:
            result.check("source_size", "fail", "Source or declared size exceeds the acquisition byte budget.", size_bytes=size, max_bytes=budget)
        else:
            result.check("source_size", "pass", "Known or declared size fits the acquisition byte budget; completeness is unassessed.", size_bytes=size, basis=basis, max_bytes=budget)
        remote = mode != "local-import" and not (job and job.get("content_path"))
        prerequisites(result, args, remote)
        if args.action == "sync" and remote:
            try:
                details["flow_id"] = acq.flow_candidate(job, args.flow_id)
            except CaseError as exc:
                result.check("flow", "fail", str(exc))
        if job and (job.get("capture_issue") or job["status"] == "partial"):
            result.check("capture_status", "warning", "The saved capture is partial; verified transfer bytes cannot erase its capture gap.")
        folder, offset = output_state(result, case, job)
        if folder is not None:
            source_collision(result, case, job, inspected)
            capacity(result, folder, size, offset, budget, basis)
    except CaseError as exc:
        result.check("case_or_request", "fail", str(exc))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        result.check("case_or_request", "fail", "Unable to inspect valid local case/request metadata. No recovery or evidence writes were attempted.")
    return result.finish()


def render_text(value):
    lines = [f"HashBrown {value['version']} preflight: {value['status'].upper()}",
             f"Operation: {value['operation']} | Case: {value['case_id']}",
             "Read-only local observations; no collection, transfer or evidence writes occurred."]
    details = value["plan"]
    if "mode" in details:
        lines.append(f"Mode: {details['mode']} | Kind: {details['kind']} | Budget: {details['max_bytes']} bytes | Collection timeout: {details['timeout_seconds']}")
    if "source" in details:
        source = details["source"]
        lines.append(f"Source host: {source['host']} | Bytes: {source['size_bytes']} | Basis: {source['size_basis']}")
        if source.get("path"):
            lines.append("Source path: " + source["path"])
    if "output" in details:
        lines.append("Output directory: " + details["output"]["directory"])
        if details["output"].get("path_template"):
            lines.append("Unallocated image path: " + details["output"]["path_template"])
    for check in value["checks"]:
        lines.append(f"[{check['status'].upper()}] {check['name']}: {check['message']}")
        if check["name"] in ("velociraptor", "api_config", "download_api_config") and "path" in check["details"]:
            lines.append("  Path: " + check["details"]["path"])
        if check["name"] == "capacity":
            data = check["details"]
            if "free_bytes" in data:
                lines.append(f"  Analyst filesystem {data['probe_path']}: {data['free_bytes']} bytes free; {data['required_free_bytes']} planned including reserve (advisory).")
    lines.append("Explicit unknowns:")
    lines.extend(f"- {item['subject']}: {item['reason']}" for item in value["unknowns"])
    return "\n".join(lines)
