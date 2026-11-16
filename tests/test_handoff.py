"""Detached handoff acceptance using inert bytes and an in-process API double."""
import copy
import ctypes
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from hashbrown_ir import acquisition as acq, handoff
from hashbrown_ir.cli import main
from hashbrown_ir.endpoint import bind
from hashbrown_ir.storage import CaseError, create, digest, encode
from test_acquisition import API, CLIENT


class HandoffTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hb-handoff-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "cases"
        self.case = create(self.root, "LAB", "Analyst")
        bind(self.case, CLIENT, "lab-win01")
        self.source = self.base / "fixture.raw"
        self.source.write_bytes(bytes(range(256)) * 513)
        self.job = acq.import_image(self.case, CLIENT, "disk", self.source, "Analyst", simulation=True)
        self.output = self.base / "handoff.json"
        self.recipient = self.base / "recipient"
        self.recipient.mkdir()

    def produce(self, jobs=None):
        return handoff.create(self.root, self.case.id, jobs or [self.job["id"]], self.output)

    def relocate(self, jobs=None):
        for job in jobs or [self.job]:
            target = self.recipient / job["content_path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.case.path / job["content_path"], target)
        return self.recipient / (jobs or [self.job])[0]["content_path"]

    def snapshot(self, directory):
        return {str(p.relative_to(directory)): (p.stat().st_mtime_ns, digest(p.read_bytes()) if p.is_file() else None)
                for p in [directory, *directory.rglob("*")]}

    def changed_manifest(self, change):
        value = json.loads(self.output.read_bytes())
        change(value)
        value["summary"] = handoff.summary(value)
        value["manifest_sha256"] = digest(encode({k: v for k, v in value.items() if k != "manifest_sha256"}))
        self.output.write_bytes(encode(value))

    def remote(self, partial=False):
        api = API(self.source.read_bytes())
        if partial:
            api.source_extra = 512
        job = acq.start(self.case, CLIENT, "memory", api, "Analyst", source="C:\\Lab\\memory.raw", simulation=True)
        return acq.resume(self.case, job["id"], api)

    def test_relocated_without_source_case_or_source_image(self):
        second = acq.import_image(self.case, CLIENT, "memory", self.source, "Unrelated operator", simulation=True)
        acq.note(self.case, second["id"], "Unrelated", "PRIVATE UNSELECTED NOTE")
        before = self.snapshot(self.root)
        result = self.produce()
        self.assertEqual(self.snapshot(self.root), before)
        self.assertFalse(result["image_copy_performed"])
        self.assertNotIn("PRIVATE UNSELECTED NOTE", self.output.read_text())
        self.relocate()
        self.root.rename(self.base / "unavailable-cases")
        self.source.unlink()
        before = self.snapshot(self.recipient)
        with patch("hashbrown_ir.endpoint.Velociraptor", side_effect=AssertionError("No API")):
            verified = handoff.verify(self.output, self.recipient, result["manifest_file_sha256"])
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(verified["selected_custody_bodies_verified"], 2)
        self.assertEqual(verified["omitted_custody_bodies_unverified"], 3)
        self.assertEqual(verified["external_authenticity"], "not_verified_unsigned")
        self.assertEqual(verified["native_qualification"], "not_granted")
        self.assertEqual(self.snapshot(self.recipient), before)

    def test_changed_truncated_missing_images_fail(self):
        self.produce()
        image = self.relocate()
        for contents in (b"X" * image.stat().st_size, b"short", b"X" * (image.stat().st_size + 1), None):
            with self.subTest(size=None if contents is None else len(contents)):
                if contents is None:
                    image.unlink()
                else:
                    image.write_bytes(contents)
                before = self.snapshot(self.recipient)
                result = handoff.verify(self.output, self.recipient)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["items"][0]["integrity"], "failed")
                self.assertEqual(self.snapshot(self.recipient), before)

    def test_source_image_tamper_prevents_publication(self):
        (self.case.path / self.job["content_path"]).write_bytes(b"X" * self.job["content_bytes"])
        before = self.snapshot(self.root)
        with self.assertRaisesRegex(CaseError, "fresh source"):
            self.produce()
        self.assertFalse(self.output.exists())
        self.assertEqual(self.snapshot(self.root), before)

    def test_source_missing_or_truncated_image_prevents_publication(self):
        image = self.case.path / self.job["content_path"]
        for missing in (False, True):
            if missing:
                image.unlink()
            else:
                image.write_bytes(b"short")
            with self.assertRaises(CaseError):
                self.produce()
            self.assertFalse(self.output.exists())

    def test_partial_capture_remains_partial(self):
        job = self.remote(partial=True)
        result = self.produce([job["id"]])
        self.assertEqual(result["status"], "partial")
        self.relocate([job])
        result = handoff.verify(self.output, self.recipient)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["items"][0]["integrity"], "verified")
        self.assertEqual(result["items"][0]["capture_issue"], job["capture_issue"])
        self.assertEqual(result["native_qualification"], "not_granted")

    def test_remote_metadata_verifies_after_relocation(self):
        job = self.remote()
        self.produce([job["id"]])
        self.relocate([job])
        self.root.rename(self.base / "absent")
        result = handoff.verify(self.output, self.recipient)
        self.assertEqual(result["status"], "verified")

    def test_partial_upgrade_is_rejected_even_with_new_manifest_digest(self):
        job = self.remote(partial=True)
        self.produce([job["id"]])
        self.changed_manifest(lambda m: m["items"][0]["acquisition"].update(status="verified", capture_issue=None))
        with self.assertRaises(CaseError):
            handoff.verify(self.output, self.recipient)

    def test_missing_or_changed_embedded_metadata_is_rejected(self):
        job = self.remote()
        self.produce([job["id"]])
        original = self.output.read_bytes()
        changes = [lambda m: m["metadata"].pop(), lambda m: m["metadata"][0].update(base64="e30=")]
        for change in changes:
            self.output.write_bytes(original)
            self.changed_manifest(change)
            with self.assertRaises(CaseError):
                handoff.verify(self.output, self.recipient)

    def test_path_schema_version_and_binding_tampering(self):
        self.produce()
        original = self.output.read_bytes()
        changes = [lambda m: m.update(schema=True), lambda m: m.update(schema=2),
                   lambda m: m.update(producer_version="0.3.0+unknown"),
                   lambda m: m["items"][0]["binding"].update(hostname="another-host"),
                   lambda m: m["items"].append(copy.deepcopy(m["items"][0])),
                   lambda m: m.update(unrecognized=True)]
        changes += [lambda m, p=p: m["items"][0]["image"].update(path=p)
                    for p in ("../escape", "/absolute/image.bin", "images\\wrong\\image.bin", "C:/image.bin")]
        for change in changes:
            self.output.write_bytes(original)
            self.changed_manifest(change)
            with self.assertRaises(CaseError):
                handoff.verify(self.output, self.recipient)

    def test_duplicate_json_keys_are_rejected(self):
        self.produce()
        raw = self.output.read_bytes()
        self.output.write_bytes(b'{"schema":1,' + raw[1:])
        with self.assertRaisesRegex(CaseError, "Duplicate"):
            handoff.verify(self.output, self.recipient)

    def test_custody_body_and_link_tampering(self):
        self.produce()
        original = self.output.read_bytes()
        for change in (lambda m: m["custody"]["links"][0]["event"].update(operator="changed"),
                       lambda m: m["custody"]["links"][1].update(previous="0" * 64)):
            self.output.write_bytes(original)
            self.changed_manifest(change)
            with self.assertRaises(CaseError):
                handoff.verify(self.output, self.recipient)

    def test_all_original_metadata_is_checked_even_when_unselected(self):
        job = self.remote()
        raw = self.case.path / job["metadata"][0]["file"]
        raw.write_bytes(b"{}")
        with self.assertRaisesRegex(CaseError, "Original metadata"):
            self.produce()
        self.assertFalse(self.output.exists())

    def test_unregistered_or_oversized_metadata_prevents_publication(self):
        job = self.remote()
        raw = self.case.path / job["metadata"][0]["file"]
        with patch.object(handoff, "MAX_RAW", raw.stat().st_size - 1):
            with self.assertRaisesRegex(CaseError, "byte bound"):
                self.produce()
        extra = raw.parent / "unregistered.json"
        extra.write_text("[]")
        with self.assertRaisesRegex(CaseError, "Unregistered"):
            self.produce()
        self.assertFalse(self.output.exists())

    def test_unknown_job_fields_and_weakened_remote_parameters_are_rejected(self):
        job = self.remote()
        self.produce([job["id"]])
        original = self.output.read_bytes()
        for change in (lambda m: m["items"][0]["acquisition"].update(parameters={}),
                       lambda m: m["items"][0]["acquisition"].update(native_qualified=True)):
            self.output.write_bytes(original)
            self.changed_manifest(change)
            with self.assertRaises(CaseError):
                handoff.verify(self.output, self.recipient)

    def test_metadata_change_during_image_hash_prevents_publication(self):
        reader = handoff.read_file
        def changing(path, *args, **kwargs):
            result = reader(path, *args, **kwargs)
            if Path(path).name == "image.bin":
                case_json = self.case.path / "case.json"
                case_json.write_bytes(case_json.read_bytes() + b"\n")
            return result
        with patch.object(handoff, "read_file", side_effect=changing):
            with self.assertRaisesRegex(CaseError, "changed during handoff"):
                self.produce()
        self.assertFalse(self.output.exists())

    def test_pending_transaction_is_not_repaired(self):
        pending = self.case.path / ".pending-artifact.json"
        pending.write_text("{}")
        before = self.snapshot(self.root)
        with self.assertRaisesRegex(CaseError, "separate recovery"):
            self.produce()
        self.assertEqual(self.snapshot(self.root), before)
        pending.unlink()
        reader = handoff.read_file
        def changing(path, *args, **kwargs):
            result = reader(path, *args, **kwargs)
            if Path(path).name == "image.bin":
                pending.write_text("{}")
            return result
        with patch.object(handoff, "read_file", side_effect=changing):
            with self.assertRaisesRegex(CaseError, "pending source transaction appeared"):
                self.produce()
        self.assertEqual(pending.read_text(), "{}")
        self.assertFalse(self.output.exists())

    def test_output_is_external_exclusive_and_atomic(self):
        before = self.snapshot(self.root)
        for output in (self.case.path / "handoff.json", self.root / "handoff.json"):
            with self.assertRaisesRegex(CaseError, "outside"):
                handoff.create(self.root, self.case.id, [self.job["id"]], output)
        self.assertEqual(self.snapshot(self.root), before)
        self.output.write_bytes(b"existing")
        with self.assertRaisesRegex(CaseError, "already exists"):
            self.produce()
        self.assertEqual(self.output.read_bytes(), b"existing")
        self.output.unlink()
        with patch.object(handoff.os, "link", side_effect=OSError("No hardlink support")):
            with self.assertRaises(OSError):
                self.produce()
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.base.glob(".hashbrown-handoff-*.tmp")))

    def test_missing_store_is_not_initialized(self):
        absent = self.base / "absent"
        with self.assertRaises(CaseError):
            handoff.create(absent, self.case.id, [self.job["id"]], self.output)
        self.assertFalse(absent.exists())
        with self.assertRaises(CaseError):
            handoff.create(self.root, "HB-2026-000000000000", [self.job["id"]], self.output)
        self.assertFalse(self.output.exists())

    def test_hardlinks_rejected_in_producer_and_recipient(self):
        self.produce()
        image = self.relocate()
        os.link(image, self.base / "alias")
        self.assertEqual(handoff.verify(self.output, self.recipient)["status"], "failed")
        os.link(self.case.path / self.job["content_path"], self.base / "source-alias")
        self.output.unlink()
        with self.assertRaisesRegex(CaseError, "Hardlinked"):
            self.produce()

    def test_linked_ancestor_rejected_before_file_open(self):
        self.produce()
        image = self.relocate()
        directory = image.parent
        moved = self.base / "moved-image"
        directory.rename(moved)
        try:
            directory.symlink_to(moved, target_is_directory=True)
        except OSError:
            self.skipTest("Creating symlinks is unavailable on this host")
        with patch.object(handoff.os, "open", wraps=os.open) as opened:
            result = handoff.verify(self.output, self.recipient)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(opened.call_count, 1, "Only the explicit manifest may be opened")

    def test_windows_short_path_alias_is_rejected(self):
        if os.name != "nt":
            self.skipTest("Windows alias test")
        self.produce()
        image = self.relocate()
        buffer = ctypes.create_unicode_buffer(32768)
        count = ctypes.windll.kernel32.GetShortPathNameW(str(self.recipient), buffer, len(buffer))
        if not count or os.path.normcase(buffer.value) == os.path.normcase(str(self.recipient)):
            self.skipTest("8.3 aliases unavailable")
        with self.assertRaisesRegex(CaseError, "aliases"):
            handoff.verify(self.output, Path(buffer.value))

    def test_special_file_is_rejected_without_opening(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO unavailable on this platform")
        self.produce()
        image = self.relocate()
        image.unlink()
        os.mkfifo(image)
        with patch.object(handoff.os, "open", wraps=os.open) as opened:
            result = handoff.verify(self.output, self.recipient)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(opened.call_count, 1)

    def test_incomplete_transfer_is_not_exported(self):
        api = API(self.source.read_bytes())
        job = acq.start(self.case, CLIENT, "memory", api, "Analyst", source="fixture", simulation=True)
        with self.assertRaisesRegex(CaseError, "no committed image"):
            self.produce([job["id"]])

    def test_manifest_self_digest_and_independent_file_hash(self):
        result = self.produce()
        with self.assertRaisesRegex(CaseError, "Independently"):
            handoff.verify(self.output, self.recipient, "0" * 64)
        raw = self.output.read_bytes().replace(b'"schema": 1', b'"schema": 2')
        self.output.write_bytes(raw)
        with self.assertRaises(CaseError):
            handoff.verify(self.output, self.recipient)
        self.assertNotEqual(digest(raw), result["manifest_file_sha256"])

    def test_cli_json_text_and_partial_exit_status(self):
        job = self.remote(partial=True)
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
            code = main(["--root", str(self.root), "handoff", "create", self.case.id, "--job", job["id"], "--output", str(self.output)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "partial")
        self.relocate([job])
        with redirect_stdout(io.StringIO()) as out:
            code = main(["handoff", "verify", "--manifest", str(self.output), "--evidence-root", str(self.recipient), "--format", "text"])
        self.assertEqual(code, 2)
        self.assertIn("bytes verified; capture partial", out.getvalue())
        self.assertIn("omitted bodies unverified", out.getvalue())


if __name__ == "__main__":
    unittest.main()
