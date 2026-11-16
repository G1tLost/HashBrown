"""Minimal Velociraptor API adapter and immutable HashBrown client binding.

API invocation and binding adapted from MIT-licensed Bacon Egg and Cheese.
"""
import json
import os
import re
import subprocess
from pathlib import Path

from .storage import CaseError, DATA, save

ARTIFACTS = tuple("Custom.HashBrown.Acquire" + suffix for suffix in ("File", "Disk", "Memory"))


def records(raw):
    text = raw.decode("utf-8-sig")
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise CaseError("Expected JSON object rows or JSONL from Velociraptor.")
    return rows


def bind(case, client, hostname, org="root"):
    if not re.fullmatch(r"C\.[a-fA-F0-9]{16}", client):
        raise CaseError("Use a Velociraptor client ID such as C.0123456789abcdef.")
    hostname = hostname.strip().rstrip(".").casefold()
    if not hostname or re.search(r"[\s/\\]", hostname) or not re.fullmatch(r"[A-Za-z0-9_.-]+", org):
        raise CaseError("Provide the server-reported hostname and a valid organization ID.")
    value = dict(client_id=client, hostname=hostname, org_id=org)
    endpoints = case.meta.setdefault("endpoints", {})
    if client in endpoints and endpoints[client] != value:
        raise CaseError("An existing endpoint binding is immutable. Create a new case for changed identity.")
    if any(v["hostname"] == hostname and k != client for k, v in endpoints.items()):
        raise CaseError("A hostname is already bound to another client in this case.")
    endpoints[client] = value
    save(case.path / "case.json", case.meta)
    case.log("endpoint_bind", **value)
    return value


def binding(case, client):
    value = case.meta.get("endpoints", {}).get(client)
    if not value:
        raise CaseError("Bind this endpoint to the case first.")
    return value


class Velociraptor:
    def __init__(self, executable, api_config, org="root"):
        self.exe = Path(executable).resolve()
        self.api = Path(api_config).resolve()
        self.org = org
        if not self.exe.is_file() or not self.api.is_file():
            raise CaseError("Velociraptor executable or API configuration file is missing.")

    def query(self, query, variables=None, timeout=90):
        cmd = [str(self.exe), "--api_config", str(self.api), "--org", self.org,
               "query", "--format", "jsonl", "--timeout", str(timeout - 5)]
        for key, value in (variables or {}).items():
            cmd += ["--env", f"{key}={value}"]
        cmd.append(query)
        env = os.environ.copy()
        if os.name == "nt":
            env["__COMPAT_LAYER"] = "RunAsInvoker"
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired as exc:
            raise CaseError("Velociraptor API query timed out. Resume the saved acquisition.") from exc
        if proc.returncode or re.search(rb"(?im)^.*\[(error|fatal)\]|^.*: error:", proc.stderr):
            raise CaseError("Velociraptor query failed. Check connectivity, artifacts, API roles and endpoint privileges.")
        try:
            rows = records(proc.stdout)
        except (ValueError, UnicodeError) as exc:
            raise CaseError("Velociraptor returned invalid JSON results.") from exc
        return proc.stdout, rows

    def install(self):
        for name in ARTIFACTS:
            definition = (DATA / "velociraptor" / (name + ".yaml")).read_text(encoding="utf-8")
            _, rows = self.query("SELECT artifact_set(definition=Definition) AS Artifact FROM scope()", {"Definition": definition})
            if not rows or not rows[0].get("Artifact"):
                raise CaseError("Artifact installation returned no result. Check artifact-writer permissions.")
        return list(ARTIFACTS)


def export_artifacts(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    outputs = []
    for name in ARTIFACTS:
        source = DATA / "velociraptor" / (name + ".yaml")
        target = directory / source.name
        if target.exists() and target.read_bytes() != source.read_bytes():
            raise CaseError("Artifact export would replace a different file: " + str(target))
        outputs.append((source, target))
    for source, target in outputs:
        if not target.exists():
            target.write_bytes(source.read_bytes())
    return [str(target.resolve()) for _, target in outputs]
