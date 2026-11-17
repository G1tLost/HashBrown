"""Offline, detached generic evidence registration. No acquisition or case linkage."""
import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath

from .handoff import (canonical_path, destination, keys, publish, read_file,
                      require, sha, strict_json)
from .storage import CaseError, digest, encode, now

FORMAT = "hashbrown-offline-evidence"
MAX_METADATA = 1024 * 1024
MAX_BYTES = 256 * 1024 ** 3
CLASSES = {"original", "derived", "synthetic"}
FIELDS = {"id", "path", "provenance_class", "scope", "parents", "source", "media_type"}
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
LIMITATIONS = ["Unsigned operator-declared provenance; not independent source authenticity.",
              "Byte integrity does not establish completeness, readability or capture qualification.",
              "Parent references apply only within this manifest; no other case store is opened."]


def validate(items, hashed=False):
    require(isinstance(items, list) and 1 <= len(items) <= 256, "Select 1–256 explicit items.")
    identifiers, paths = set(), set()
    for item in items:
        keys(item, FIELDS | ({"bytes", "sha256"} if hashed else set()), "evidence item")
        require(isinstance(item["id"], str) and ID.fullmatch(item["id"]), "Invalid evidence ID.")
        require(item["id"] not in identifiers, "Duplicate evidence ID.")
        identifiers.add(item["id"])
        p = item["path"]
        require(isinstance(p, str) and p and "\\" not in p and ":" not in p,
                "Use canonical relative POSIX evidence paths.")
        parts = p.split("/")
        require(all(x not in ("", ".", "..") for x in parts) and not PurePosixPath(p).is_absolute(), "Unsafe evidence path.")
        require(p not in paths, "Duplicate evidence path.")
        paths.add(p)
        require(item["provenance_class"] in CLASSES, "Unknown provenance class.")
        for field in ("scope", "source", "media_type"):
            require(isinstance(item[field], str) and 0 < len(item[field].strip()) <= 1000, "Missing/bounded " + field + " required.")
        parents = item["parents"]
        require(isinstance(parents, list) and len(parents) <= 256 and all(isinstance(x, str) for x in parents)
                and len(set(parents)) == len(parents), "Invalid parent references.")
        require(bool(parents) if item["provenance_class"] == "derived" else not parents,
                "Derived evidence requires parents; originals/synthetic roots must have none.")
        if hashed:
            require(type(item["bytes"]) is int and 0 <= item["bytes"] <= MAX_BYTES and sha(item["sha256"]), "Invalid size/hash.")
    by_id = {i["id"]: i for i in items}
    done, visiting = set(), set()
    def visit(identifier):
        require(identifier in by_id and identifier not in visiting, "Missing parent or provenance cycle.")
        if identifier in done:
            return
        visiting.add(identifier)
        for parent in by_id[identifier]["parents"]:
            require(parent in by_id and by_id[parent]["scope"] == by_id[identifier]["scope"], "Parent scope mismatch or missing parent.")
            visit(parent)
        visiting.remove(identifier)
        done.add(identifier)
    for identifier in identifiers:
        visit(identifier)


def target(root, relative):
    path, _ = canonical_path(root / relative)
    require(path.is_relative_to(root), "Evidence path escapes selected root.")
    return path


def register(root, spec, output):
    root, _ = canonical_path(root, directory=True)
    raw, _, _, _ = read_file(spec, MAX_METADATA)
    document = strict_json(raw)
    keys(document, {"items"}, "registration request")
    validate(document["items"])
    output, parent_stamp = destination(output, root)
    items = []
    for item in document["items"]:
        _, checksum, _, size = read_file(target(root, item["path"]), MAX_BYTES, retain=False)
        items.append(dict(item, bytes=size, sha256=checksum))
    manifest = dict(format=FORMAT, schema=1, registered_at=now(), items=items, limitations=LIMITATIONS)
    # Recheck all selected bytes before publication, not just stat metadata.
    for item in items:
        _, checksum, _, size = read_file(target(root, item["path"]), MAX_BYTES, retain=False)
        require(checksum == item["sha256"] and size == item["bytes"], "Evidence changed during registration.")
    raw = encode(manifest)
    require(len(raw) <= MAX_METADATA, "Manifest exceeds metadata bound.")
    publish(output, raw, parent_stamp)
    return dict(status="registered", manifest=str(output), manifest_sha256=digest(raw), items=len(items), copied=False)


def verify(root, manifest, expected_sha256):
    require(isinstance(expected_sha256, str) and sha(expected_sha256), "Independent manifest SHA-256 required.")
    root, _ = canonical_path(root, directory=True)
    raw, checksum, _, _ = read_file(manifest, MAX_METADATA)
    require(checksum == expected_sha256, "Manifest does not match independently retained SHA-256.")
    doc = strict_json(raw)
    keys(doc, {"format", "schema", "registered_at", "items", "limitations"}, "evidence manifest")
    require(doc["format"] == FORMAT and type(doc["schema"]) is int and doc["schema"] == 1
            and doc["limitations"] == LIMITATIONS, "Unsupported manifest or altered limitations.")
    from .storage import timestamp
    timestamp(doc["registered_at"])
    validate(doc["items"], hashed=True)
    for item in doc["items"]:
        _, checksum, _, size = read_file(target(root, item["path"]), MAX_BYTES, retain=False)
        require(checksum == item["sha256"] and size == item["bytes"], "Evidence integrity failed: " + item["id"])
    return dict(status="verified", items=len(doc["items"]), limitations=LIMITATIONS)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline generic evidence only; no target/API/acquisition operations.")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("register", "verify"):
        p = sub.add_parser(action)
        p.add_argument("--evidence-root", type=Path, required=True)
        if action == "register":
            p.add_argument("--spec", type=Path, required=True)
            p.add_argument("--output", type=Path, required=True)
        else:
            p.add_argument("--manifest", type=Path, required=True)
            p.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = register(args.evidence_root, args.spec, args.output) if args.action == "register" else verify(args.evidence_root, args.manifest, args.manifest_sha256)
        print(json.dumps(result, indent=2))
        return 0
    except (CaseError, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print("hashbrown-evidence: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
