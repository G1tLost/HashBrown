"""HashBrown-only case storage, raw metadata manifests and process locking.

Selected helpers adapted from MIT-licensed Bacon Egg and Cheese contributors.
See THIRD_PARTY_NOTICES.md.
"""
import hashlib
import json
import os
import re
import tempfile
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from . import __version__

DATA = Path(__file__).parent / "data"
CASE_ID = re.compile(r"HB-[0-9]{4}-[a-f0-9]{12}")
LABEL = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}")
RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"{p}{i}" for p in ("COM", "LPT") for i in range(1, 10)}


class CaseError(ValueError):
    pass


def timestamp(value):
    if not isinstance(value, str) or "T" not in value and " " not in value:
        raise CaseError("An ISO date and time with timezone is required.")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise CaseError("Timestamp has no UTC offset.")
    return dt.astimezone(UTC)


def now():
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def read(path):
    return json.loads(path.read_bytes().decode("utf-8-sig"))


def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".writing-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def save(path, obj):
    atomic(path, encode(obj))


def create(root, label, operator):
    if not LABEL.fullmatch(label) or label.upper() in RESERVED:
        raise CaseError("Use a case label of 1–48 letters, digits, underscores or hyphens; no reserved device names.")
    if not isinstance(operator, str) or not operator.strip() or len(operator) > 200:
        raise CaseError("Provide a named operator of 1–200 characters.")
    case_id = f"HB-{datetime.now(UTC).year}-{uuid.uuid4().hex[:12]}"
    path = Path(root).resolve() / label / case_id
    path.mkdir(parents=True)
    save(path / "case.json", dict(tool="hashbrown", schema=1, version=__version__, id=case_id,
                                 label=label, operator=operator.strip(), created_at=now(), endpoints={}))
    save(path / "evidence_manifest.json", dict(schema=1, case_id=case_id, label=label, artifacts=[]))
    return Case(path)


class Case:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.meta = read(self.path / "case.json")
        self.label, self.id = self.meta["label"], self.meta["id"]
        if (self.meta.get("tool") != "hashbrown" or self.meta.get("schema") != 1
                or not CASE_ID.fullmatch(self.id) or not LABEL.fullmatch(self.label)
                or self.path.name != self.id or self.path.parent.name != self.label):
            raise CaseError("HashBrown case identity or directory does not match metadata.")

    @classmethod
    def find(cls, root, case_id):
        if not CASE_ID.fullmatch(case_id):
            raise CaseError("Invalid HashBrown case ID.")
        matches = list(Path(root).glob("*/" + case_id + "/case.json"))
        if len(matches) != 1:
            raise CaseError("Case not found or ambiguous in this HashBrown store.")
        return cls(matches[0].parent)

    @contextmanager
    def lock(self):
        # Kernel locks release on process termination; no stale lock-file removal.
        with (self.path / ".lock").open("a+b") as f:
            f.seek(0)
            if os.name == "nt":
                import msvcrt
                acquire = lambda: msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                acquire = lambda: fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                acquire()
            except OSError as exc:
                raise CaseError("Another process is using this case.") from exc
            # Refresh metadata after locking in case another process just bound a client.
            self.meta = read(self.path / "case.json")
            yield

    def log(self, action, **fields):
        with (self.path / "hashbrown.log").open("a", encoding="utf-8") as f:
            f.write(json.dumps(dict(time=now(), case_id=self.id, action=action, **fields)) + "\n")

    def manifest(self):
        manifest = read(self.path / "evidence_manifest.json")
        if manifest.get("schema") != 1 or manifest["label"] != self.label or manifest["case_id"] != self.id:
            raise CaseError("Manifest identity mismatch.")
        return manifest

    def raw_path(self, entry):
        path = self.path / entry["artifact"]
        expected = self.path / "raw" / entry["dataset"] / (entry["sha256"] + ".json")
        if (entry["dataset"] != "acquisition_metadata" or not re.fullmatch("[a-f0-9]{64}", entry["sha256"])
                or path != expected or not path.resolve().is_relative_to((self.path / "raw").resolve())
                or not path.resolve().is_relative_to(self.path)):
            raise CaseError("Invalid artifact location.")
        return path

    def verify(self, include_images=True):
        # Complete an interrupted raw-page/manifest transaction while holding the lock.
        journal = self.path / ".pending-artifact.json"
        if journal.exists():
            pending = read(journal)
            path = self.raw_path(pending)
            if pending["label"] != self.label:
                raise CaseError("Pending acquisition belongs to another case label.")
            if path.exists():
                if digest(path.read_bytes()) != pending["sha256"]:
                    raise CaseError("Pending artifact verification failed.")
                manifest = self.manifest()
                if not any(a["artifact"] == pending["artifact"] for a in manifest["artifacts"]):
                    manifest["artifacts"].append(pending)
                    save(self.path / "evidence_manifest.json", manifest)
            journal.unlink()
        expected = set()
        for entry in self.manifest()["artifacts"]:
            path = self.raw_path(entry)
            if entry["label"] != self.label or not path.is_file() or digest(path.read_bytes()) != entry["sha256"]:
                raise CaseError("Evidence verification failed: " + entry["artifact"])
            expected.add(path)
        extra = {p for p in (self.path / "raw").rglob("*") if p.is_file()} - expected
        if extra:
            raise CaseError("Unmanifested raw artifact: " + str(next(iter(extra))))
        count = len(expected)
        if include_images:
            from .acquisition import verify
            count += verify(self)
        return count

    def preserve(self, dataset, data, collector, query, records, actual):
        if dataset != "acquisition_metadata":
            raise CaseError("HashBrown preserves acquisition metadata only.")
        sha = digest(data)
        rel = f"raw/{dataset}/{sha}.json"
        manifest = self.manifest()
        item = dict(artifact=rel, dataset=dataset, label=self.label, sha256=sha,
                    collected_at=now(), collector=collector, version=__version__,
                    queries=[query], records=records, actual_timeframe=actual)
        path = self.raw_path(item)
        if path.exists() and digest(path.read_bytes()) != sha:
            raise CaseError("Existing evidence hash mismatch.")
        for existing in manifest["artifacts"]:
            if existing["artifact"] == rel:
                if query not in existing["queries"]:
                    existing["queries"].append(query)
                    save(self.path / "evidence_manifest.json", manifest)
                return
        journal = self.path / ".pending-artifact.json"
        save(journal, item)
        if not path.exists():
            atomic(path, data)
        manifest["artifacts"].append(item)
        save(self.path / "evidence_manifest.json", manifest)
        journal.unlink()
