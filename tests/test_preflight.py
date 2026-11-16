import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from collections import namedtuple
from pathlib import Path
from unittest.mock import patch

from hashbrown_ir import acquisition as acq
from hashbrown_ir.cli import main
from hashbrown_ir.endpoint import bind
from hashbrown_ir.lab_images import disk_fixture
from hashbrown_ir.preflight import render_text
from hashbrown_ir.storage import Case, CaseError, create, digest


CLIENT = "C.0123456789abcdef"
Usage = namedtuple("Usage", "total used free")


class PreflightTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hashbrown-preflight-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.case = create(self.root / "cases", "LAB", "Analyst")
        bind(self.case, CLIENT, "lab-win01")
        self.source = self.root / "source.img"
        self.source.write_bytes(disk_fixture())
        self.exe = self.root / "collector.exe"
        self.exe.write_bytes(b"inert executable placeholder; never executed")
        self.exe.chmod(0o700)
        self.api = self.root / "api.yaml"
        self.secret = "PRIVATE_KEY_CONTENT_MUST_NEVER_BE_RENDERED"
        self.api.write_text("private_key: " + self.secret, encoding="utf-8")

    def args(self, action="import", *extra):
        args = ["--root", str(self.root / "cases"), "acquisition", action, self.case.id, "--preflight"]
        if action != "sync":
            args += ["--client-id", CLIENT, "--kind", "disk", "--operator", "Analyst"]
        if action == "import":
            args += ["--file", str(self.source), "--simulation"]
        return args + list(extra)

    def invoke(self, args, free=10**15, text=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr),
              patch("hashbrown_ir.preflight.shutil.disk_usage", return_value=Usage(10**15, 0, free))):
            code = main(args)
        self.assertNotIn(self.secret, stdout.getvalue() + stderr.getvalue())
        return code, stdout.getvalue() if text else json.loads(stdout.getvalue()), stderr.getvalue()

    def check(self, result, name):
        return next(value for value in result["checks"] if value["name"] == name)

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in self.root.rglob("*") if path.is_file()}

    def remote(self, *extra):
        return self.args("collect", "--velociraptor", str(self.exe), "--api-config", str(self.api), *extra)

    def local_job(self):
        job = acq.new_job(self.case, CLIENT, "disk", "local-import", "Analyst", simulation=True)
        source_info = self.source.stat()
        job.update(source_path=str(self.source), source_mtime_ns=source_info.st_mtime_ns,
                   expected_size=source_info.st_size, expected_sha256=digest(self.source.read_bytes()),
                   status="retry", request=dict(source=str(self.source), kind="disk"))
        acq.persist(self.case, acq.load(self.case), job, "import_started")
        return job

    def test_fixture_size_plan_and_guards_leave_files_unchanged(self):
        before = self.snapshot()
        with (patch.object(Case, "lock", side_effect=AssertionError("no lock")),
              patch.object(Case, "verify", side_effect=AssertionError("no repair")),
              patch("hashbrown_ir.endpoint.Velociraptor", side_effect=AssertionError("no API")),
              patch("hashbrown_ir.acquisition.import_image", side_effect=AssertionError("no import")),
              patch("hashbrown_ir.acquisition.start", side_effect=AssertionError("no collection")),
              patch("hashbrown_ir.acquisition.resume", side_effect=AssertionError("no transfer"))):
            code, result, stderr = self.invoke(self.args())
        self.assertEqual((code, result["status"], stderr), (0, "pass", ""))
        self.assertEqual(result["plan"]["source"]["size_bytes"], 1474560)
        self.assertEqual(result["plan"]["source"]["size_basis"], "observed_file_metadata")
        self.assertEqual(result["plan"]["capacity"]["host"], "analyst")
        self.assertTrue(result["plan"]["capacity"]["advisory"])
        self.assertIn("<new-acquisition-id>", result["plan"]["output"]["path_template"])
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.case.path / ".lock").exists())

    def test_insufficient_space_is_an_advisory_failure_on_analyst_volume(self):
        code, result, _ = self.invoke(self.args(), free=1474560 + acq.RESERVE_BYTES - 1)
        self.assertEqual(code, 1)
        check = self.check(result, "capacity")
        self.assertEqual(check["status"], "fail")
        self.assertEqual(check["details"]["probe_path"], str(self.case.path))
        self.assertEqual(check["details"]["required_free_bytes"], 1474560 + acq.RESERVE_BYTES)

    def test_output_directory_file_collision(self):
        (self.case.path / "images").write_bytes(b"keep me")
        before = self.snapshot()
        code, result, _ = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertEqual(self.check(result, "output")["status"], "fail")
        self.assertEqual(self.snapshot(), before)

    def test_missing_prerequisites_are_json_checks_without_subprocesses(self):
        with patch("subprocess.run", side_effect=AssertionError("no executable invocation")):
            code, result, _ = self.invoke(self.args("collect", "--disk-number", "1"))
        self.assertEqual(code, 1)
        self.assertEqual(self.check(result, "velociraptor")["status"], "fail")
        self.assertEqual(self.check(result, "api_config")["status"], "fail")

    def test_credentials_and_image_contents_are_never_opened_or_rendered(self):
        original = Path.open
        def protected(path, *args, **kwargs):
            if path in (self.source, self.exe, self.api):
                raise AssertionError("preflight must only stat explicit inputs")
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", protected):
            code, local, _ = self.invoke(self.args())
            self.assertEqual(code, 0)
            for output in ("json", "text"):
                code, result, error = self.invoke(self.remote("--kind", "memory", "--plan-format", output), text=output == "text")
                self.assertEqual(code, 2)
                self.assertNotIn(self.secret, json.dumps(result) + error)
        readable = render_text(local)
        self.assertIn("Explicit unknowns", readable)
        self.assertIn("capture_completeness", readable)

    def test_unreadable_config_failure_does_not_render_contents(self):
        access = os.access
        with patch("hashbrown_ir.preflight.os.access", side_effect=lambda path, mode: False if path == self.api else access(path, mode)):
            for output in ("json", "text"):
                code, result, error = self.invoke(self.remote("--disk-number", "1", "--plan-format", output), text=output == "text")
                self.assertEqual(code, 1)
                self.assertNotIn(self.secret, json.dumps(result) + error)

    def test_physical_extents_are_unknown_and_budget_is_not_a_measurement(self):
        for extra in (("--kind", "memory"), ("--disk-number", "2")):
            with self.subTest(extra=extra), patch("subprocess.run", side_effect=AssertionError("no device probe")):
                code, result, _ = self.invoke(self.remote(*extra), free=0)
            self.assertEqual(code, 2)
            self.assertIsNone(result["plan"]["source"]["size_bytes"])
            self.assertEqual(result["plan"]["capacity"]["basis"], "budget_ceiling")
            self.assertEqual(self.check(result, "capacity")["status"], "warning")
            self.assertIn("remote_capacity", {u["subject"] for u in result["unknowns"]})

    def test_declared_remote_size_is_unverified_and_budget_checked(self):
        code, result, _ = self.invoke(self.remote("--kind", "memory", "--declared-bytes", "4096"))
        self.assertEqual(code, 2)
        self.assertEqual(result["plan"]["source"]["size_basis"], "operator_declaration")
        code, result, _ = self.invoke(self.remote("--kind", "memory", "--declared-bytes", "4096", "--max-bytes", "1024"))
        self.assertEqual(code, 1)
        self.assertEqual(self.check(result, "source_size")["status"], "fail")

    def test_declared_local_size_mismatch_is_a_failure(self):
        code, result, _ = self.invoke(self.args("import", "--declared-bytes", "4096"))
        self.assertEqual(code, 1)
        self.assertEqual(self.check(result, "declared_size")["status"], "fail")

    def test_invalid_budgets_declarations_and_hash_syntax_fail_without_mutation(self):
        before = self.snapshot()
        for extra in (("--max-bytes", "0"), ("--max-bytes", "-1"), ("--declared-bytes", "0"),
                      ("--declared-bytes", "-1"), ("--sha256", "not-a-sha256")):
            with self.subTest(extra=extra):
                code, result, _ = self.invoke(self.args("import", *extra))
                self.assertEqual((code, result["status"]), (1, "fail"))
        self.assertEqual(self.snapshot(), before)
        with self.assertRaises(CaseError):
            acq.validate_options("disk", "Analyst", 0)

    def test_collect_validation_is_shared_with_real_requests(self):
        for extra in ((), ("--disk-number", "1", "--simulation"), ("--disk-number", "1", "--timeout", "59"),
                      ("--disk-number", "1", "--format", "vhdx")):
            with self.subTest(extra=extra):
                code, result, _ = self.invoke(self.remote(*extra))
                self.assertEqual(code, 1)
                self.assertEqual(self.check(result, "parameters")["status"], "fail")
        with self.assertRaises(CaseError):
            acq.collection_request("disk", "Analyst")

    def test_missing_case_and_root_leave_filesystem_untouched(self):
        before = self.snapshot()
        for root in (self.root / "cases", self.root / "does-not-exist" / "nested"):
            args = self.args()
            args[1], args[4] = str(root), "HB-2026-000000000000"
            code, result, _ = self.invoke(args)
            self.assertEqual((code, result["status"]), (1, "fail"))
        self.assertFalse((self.root / "does-not-exist").exists())
        self.assertEqual(self.snapshot(), before)

    def test_device_names_are_rejected_before_leaf_metadata_probe(self):
        names = [r"\\.\PhysicalDrive0", r"\\?\GLOBALROOT\Device\PhysicalMemory", "NUL", "CON.txt", "NUL:"]
        if os.name != "nt":
            names.append("/dev/zero")
        original = Path.lstat
        for name in names:
            def guard(path, *args, **kwargs):
                if str(path) == name:
                    raise AssertionError("device leaf must not be probed")
                return original(path, *args, **kwargs)
            with self.subTest(name=name), patch.object(Path, "lstat", guard):
                code, result, _ = self.invoke(self.args("import", "--file", name))
            self.assertEqual(code, 1)
            self.assertEqual(self.check(result, "source_file")["status"], "fail")

    def test_fifo_is_rejected_using_type_metadata_without_opening(self):
        original = Path.lstat
        def fifo(path, *args, **kwargs):
            if path == self.source:
                return os.stat_result((stat.S_IFIFO | 0o600, 1, 1, 1, 0, 0, 4096, 0, 0, 0))
            return original(path, *args, **kwargs)
        with patch.object(Path, "lstat", fifo):
            code, result, _ = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("regular file", self.check(result, "source_file")["message"])

    def test_linked_ancestor_is_rejected_before_probing_its_child(self):
        linked = self.root / "linked"
        leaf = linked / "should-never-be-probed.img"
        original = Path.lstat
        def ancestor(path, *args, **kwargs):
            if path == linked:
                return os.stat_result((stat.S_IFLNK | 0o777, 1, 1, 1, 0, 0, 0, 0, 0, 0))
            if path == leaf:
                raise AssertionError("linked ancestor must stop descent")
            return original(path, *args, **kwargs)
        with patch.object(Path, "lstat", ancestor):
            code, result, _ = self.invoke(self.args("import", "--file", str(leaf)))
        self.assertEqual(code, 1)
        self.assertIn("ancestors", self.check(result, "source_file")["message"])

    def test_pending_metadata_transaction_is_not_repaired(self):
        (self.case.path / ".pending-artifact.json").write_text("intentionally incomplete", encoding="utf-8")
        before = self.snapshot()
        code, result, _ = self.invoke(self.args())
        self.assertEqual(code, 1)
        self.assertIn("nothing was repaired", self.check(result, "case_or_request")["message"])
        self.assertEqual(self.snapshot(), before)

    def test_local_sync_requires_explicit_source_for_identity_check(self):
        job = self.local_job()
        code, result, _ = self.invoke(self.args("sync", "--job", job["id"]))
        self.assertEqual(code, 2)
        self.assertEqual(self.check(result, "local_resume_source")["status"], "warning")
        code, result, _ = self.invoke(self.args("sync", "--job", job["id"], "--file", str(self.source)))
        self.assertEqual(code, 0)
        self.assertEqual(self.check(result, "saved_source")["status"], "pass")
        self.assertEqual(self.check(result, "source_destination")["status"], "pass")

    def test_sync_detects_hardlinked_source_output_without_truncation(self):
        job = self.local_job()
        part, _ = acq.paths(self.case, job)
        part.parent.mkdir(parents=True)
        os.link(self.source, part)
        before = self.snapshot()
        code, result, _ = self.invoke(self.args("sync", "--job", job["id"], "--file", str(self.source)))
        self.assertEqual(code, 1)
        self.assertEqual(self.check(result, "source_destination")["status"], "fail")
        self.assertEqual(self.snapshot(), before)

    def test_sync_checkpoint_capacity_uses_remaining_bytes(self):
        job = self.local_job()
        part, _ = acq.paths(self.case, job)
        part.parent.mkdir(parents=True)
        prefix = self.source.read_bytes()[:4096]
        part.write_bytes(prefix)
        state = acq.load(self.case)
        job.update(offset=len(prefix), prefix_sha256=digest(prefix))
        acq.persist(self.case, state, job)
        code, result, _ = self.invoke(self.args("sync", "--job", job["id"], "--file", str(self.source)))
        self.assertEqual(code, 0)
        self.assertEqual(result["plan"]["capacity"]["remaining_bytes"], self.source.stat().st_size - 4096)
        part.write_bytes(b"short")
        code, result, _ = self.invoke(self.args("sync", "--job", job["id"], "--file", str(self.source)))
        self.assertEqual(code, 1)
        self.assertEqual(self.check(result, "output")["status"], "fail")

    def test_sync_rejects_both_part_and_final_outputs(self):
        job = self.local_job()
        part, final = acq.paths(self.case, job)
        part.parent.mkdir(parents=True)
        part.write_bytes(b"partial")
        final.write_bytes(b"final")
        code, result, _ = self.invoke(self.args("sync", "--job", job["id"], "--file", str(self.source)))
        self.assertEqual(code, 1)
        self.assertIn("Both partial and final", self.check(result, "output")["message"])

    @unittest.skipUnless(os.name == "nt", "Windows 8.3 alias check")
    def test_windows_short_aliases_are_canonical_for_collision_checks(self):
        import ctypes
        job = self.local_job()
        part, _ = acq.paths(self.case, job)
        part.parent.mkdir(parents=True)
        os.link(self.source, part)
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetShortPathNameW(str(self.source), buffer, len(buffer))
        if not length:
            self.skipTest("Filesystem does not expose short-path aliases")
        code, result, _ = self.invoke(self.args("sync", "--job", job["id"], "--file", buffer.value))
        self.assertEqual(code, 1)
        self.assertEqual(result["plan"]["source"]["path"], str(self.source))
        self.assertEqual(self.check(result, "source_destination")["status"], "fail")

    def test_preflight_only_options_cannot_redirect_a_real_sync(self):
        job = self.local_job()
        args = self.args("sync", "--job", job["id"], "--file", str(self.source))
        args.remove("--preflight")
        before = self.snapshot()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        self.assertEqual(code, 1)
        self.assertIn("requires --preflight", stderr.getvalue())
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
