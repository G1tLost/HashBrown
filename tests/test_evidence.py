"""Synthetic offline evidence tests. Never acquire live evidence."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hashbrown_ir import evidence as ev
from hashbrown_ir.storage import CaseError


class GenericEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.root = self.home / "bytes"
        self.root.mkdir()
        (self.root / "cloud.json").write_bytes(b'{"synthetic":true}\n')
        (self.root / "timeline.csv").write_bytes(b"time,event\n")
        self.items = [dict(id="raw-1", path="cloud.json", provenance_class="original", scope="synthetic-case", parents=[], source="fixture export", media_type="application/json"),
                      dict(id="report-1", path="timeline.csv", provenance_class="derived", scope="synthetic-case", parents=["raw-1"], source="fixture transform", media_type="text/csv")]
        self.spec = self.home / "spec.json"
        self.out = self.home / "manifest.json"

    def register(self):
        self.spec.write_text(json.dumps(dict(items=self.items)))
        return ev.register(self.root, self.spec, self.out)

    def test_roundtrip_preserves_bytes_and_mtimes(self):
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        result = self.register()
        self.assertEqual(ev.verify(self.root, self.out, result["manifest_sha256"])["status"], "verified")
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()})

    def test_relocated_evidence(self):
        result = self.register()
        moved = self.home / "moved"
        self.root.rename(moved)
        self.assertEqual(ev.verify(moved, self.out, result["manifest_sha256"])["items"], 2)

    def test_changed_and_missing_evidence(self):
        result = self.register()
        (self.root / "cloud.json").write_bytes(b"tampered")
        with self.assertRaises(CaseError):
            ev.verify(self.root, self.out, result["manifest_sha256"])
        (self.root / "cloud.json").unlink()
        with self.assertRaises(CaseError):
            ev.verify(self.root, self.out, result["manifest_sha256"])

    def test_manifest_tamper_and_missing_anchor(self):
        result = self.register()
        self.out.write_bytes(self.out.read_bytes() + b" ")
        with self.assertRaises(CaseError):
            ev.verify(self.root, self.out, result["manifest_sha256"])
        with self.assertRaises(CaseError):
            ev.verify(self.root, self.out, None)

    def test_invalid_provenance(self):
        for field, value in [("parents", ["missing"]), ("parents", ["report-1"]), ("scope", "other"), ("provenance_class", "trusted")]:
            with self.subTest(field=field, value=value):
                items = copy.deepcopy(self.items)
                items[1][field] = value
                with self.assertRaises(CaseError):
                    ev.validate(items)

    def test_path_escapes(self):
        for path in ("../spec.json", "/etc/passwd", "a/../cloud.json", "a//b", "a\\b", "C:file", "./cloud.json"):
            with self.subTest(path=path):
                items = copy.deepcopy(self.items)
                items[0]["path"] = path
                with self.assertRaises(CaseError):
                    ev.validate(items)

    def test_no_overwrite_and_no_manifest_inside_evidence(self):
        self.register()
        with self.assertRaises(CaseError):
            self.register()
        with self.assertRaises(CaseError):
            ev.register(self.root, self.spec, self.root / "manifest.json")

    def test_symlink_rejection(self):
        (self.root / "cloud.json").unlink()
        (self.root / "cloud.json").symlink_to(self.root / "timeline.csv")
        with self.assertRaises(CaseError):
            self.register()

    def test_hardlink_rejection(self):
        import os
        os.link(self.root / "cloud.json", self.home / "alias")
        with self.assertRaises(CaseError):
            self.register()

    def test_duplicate_json_rejection(self):
        self.spec.write_text('{"items": [], "items": []}')
        with self.assertRaises(CaseError):
            ev.register(self.root, self.spec, self.out)

    def test_no_acquisition_api_invocation(self):
        with patch("hashbrown_ir.endpoint.Velociraptor", side_effect=AssertionError("No network")):
            result = self.register()
            ev.verify(self.root, self.out, result["manifest_sha256"])

    def test_source_change_before_publication(self):
        original = ev.read_file
        calls = 0
        def changing(path, *args, **kwargs):
            nonlocal calls
            result = original(path, *args, **kwargs)
            calls += 1
            if calls == 3:
                (self.root / "cloud.json").write_bytes(b"changed")
            return result
        with patch.object(ev, "read_file", side_effect=changing):
            with self.assertRaises(CaseError):
                self.register()
        self.assertFalse(self.out.exists())

    def test_cli_roundtrip_and_tamper_exit(self):
        import contextlib
        import io
        self.spec.write_text(json.dumps(dict(items=self.items)))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ev.main(["register", "--evidence-root", str(self.root), "--spec", str(self.spec), "--output", str(self.out)]), 0)
        checksum = json.loads(output.getvalue())["manifest_sha256"]
        argv = ["verify", "--evidence-root", str(self.root), "--manifest", str(self.out), "--manifest-sha256", checksum]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ev.main(argv), 0)
        (self.root / "cloud.json").write_bytes(b"tampered")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ev.main(argv), 1)

    def test_forged_schema_rejected_even_with_matching_anchor(self):
        self.register()
        doc = json.loads(self.out.read_text())
        doc["schema"] = True
        self.out.write_text(json.dumps(doc))
        checksum = hashlib.sha256(self.out.read_bytes()).hexdigest()
        with self.assertRaises(CaseError):
            ev.verify(self.root, self.out, checksum)
