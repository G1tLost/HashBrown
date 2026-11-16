import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hashbrown_ir import acquisition as acq
from hashbrown_ir.cli import main
from hashbrown_ir.endpoint import bind, export_artifacts, records
from hashbrown_ir.storage import Case, CaseError, create, encode
from test_acquisition import API, CLIENT


class StandaloneTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.case = create(self.root, "LAB", "Analyst")
        bind(self.case, CLIENT, "lab-win01")
        self.data = bytes(range(256)) * 33

    def start(self):
        api = API(self.data)
        job = acq.start(self.case, CLIENT, "memory", api, "A", source="C:\\Lab\\memory.raw", simulation=True)
        return api, job

    def test_case_namespace_and_immutable_binding(self):
        self.assertTrue(self.case.id.startswith("HB-"))
        with self.assertRaises(CaseError):
            Case.find(self.root, "INC-2026-012345abcdef")
        with self.assertRaises(CaseError):
            bind(self.case, CLIENT, "changed-host")
        with self.assertRaises(CaseError):
            create(self.root, "../outside", "A")
        with self.assertRaises(CaseError):
            create(self.root, "CON", "A")

    def test_remote_fixture_still_checks_actual_endpoint_and_org(self):
        api = API(self.data)
        api.org = "other"
        with self.assertRaisesRegex(CaseError, "organization"):
            acq.start(self.case, CLIENT, "memory", api, "A", source="fixture.raw", simulation=True)
        api.org = "root"
        query = api.query
        def wrong_host(text, variables=None):
            if "clients(" in text:
                rows = [dict(client_id=CLIENT, os_info={"fqdn": "other-host"})]
                return encode(rows), rows
            return query(text, variables)
        with patch.object(api, "query", side_effect=wrong_host):
            with self.assertRaisesRegex(CaseError, "hostname"):
                acq.start(self.case, CLIENT, "memory", api, "A", source="fixture.raw", simulation=True)
        self.assertEqual(api.starts, 0)

    def test_download_credential_org_is_checked(self):
        api, job = self.start()
        export = API(self.data)
        export.org = "other"
        with self.assertRaisesRegex(CaseError, "Download API organization"):
            acq.resume(self.case, job["id"], api, export)
        self.assertFalse(any("base64encode" in q for q, _ in export.calls))

    def test_original_metadata_tampering_fails_verification(self):
        api, job = self.start()
        result = acq.resume(self.case, job["id"], api)
        self.case.verify()
        original = self.case.path / result["metadata"][0]["file"]
        original.write_bytes(b"[]")
        with self.assertRaisesRegex(CaseError, "Evidence verification"):
            self.case.verify()

    def test_changed_server_image_blocks_resume_at_saved_checkpoint(self):
        api, job = self.start()
        api.fail_offset = 4096
        with self.assertRaises(CaseError):
            acq.resume(self.case, job["id"], api, chunk_size=4096)
        api.fail_offset = None
        api.data = b"X" + self.data[1:]
        with self.assertRaisesRegex(CaseError, "Server image changed"):
            acq.resume(self.case, job["id"], api)
        self.assertEqual(acq.load(self.case)["jobs"][job["id"]]["offset"], 4096)

    def test_flow_error_keeps_verified_bytes_marked_partial(self):
        api, job = self.start()
        api.state = "ERROR"
        result = acq.resume(self.case, job["id"], api)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["integrity"], "verified")
        self.assertIn("errors", result["capture_issue"])

    def test_missing_descriptor_does_not_claim_image_capture(self):
        api, job = self.start()
        query = api.query
        def incomplete(text, variables=None):
            return (b"[]", []) if "source(" in text else query(text, variables)
        with patch.object(api, "query", side_effect=incomplete):
            result = acq.resume(self.case, job["id"], api)
        self.assertEqual(result["status"], "partial")
        self.assertNotIn("content_path", result)
        self.assertEqual(acq.verify(self.case), 0)

    def test_local_import_resume_rejects_changed_original(self):
        source = self.root / "original.raw"
        source.write_bytes(self.data)
        transfer = acq.transfer
        def interrupted(case, state, job, reader, chunk_size=acq.CHUNK):
            def fail(offset, size):
                if offset:
                    raise CaseError("Disconnected local source")
                return reader(offset, size)
            return transfer(case, state, job, fail, chunk_size=4096)
        with patch("hashbrown_ir.acquisition.transfer", side_effect=interrupted):
            with self.assertRaises(CaseError):
                acq.import_image(self.case, CLIENT, "disk", source, "A")
        job = next(iter(acq.load(self.case)["jobs"].values()))
        source.write_bytes(b"changed")
        with self.assertRaisesRegex(CaseError, "Source image changed"):
            acq.resume(self.case, job["id"])

    def test_demo_cli_creates_two_verified_inert_images_and_offline_report(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--root", str(self.root), "demo"])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(result["verified_images"], 2)
        self.assertEqual(result["gaps"], [])
        case = Case.find(self.root, result["case_id"])
        self.assertTrue(Path(result["report"]).is_file())
        self.assertTrue(all(j["simulation"] for j in acq.load(case)["jobs"].values()))
        self.assertEqual(case.verify(), 2)

    def test_artifacts_are_owned_and_export_will_not_overwrite(self):
        output = self.root / "artifacts"
        files = export_artifacts(output)
        self.assertEqual(len(files), 3)
        self.assertTrue(all(Path(path).name.startswith("Custom.HashBrown.") for path in files))
        Path(files[0]).write_text("do not overwrite", encoding="utf-8")
        with self.assertRaises(CaseError):
            export_artifacts(output)

    def test_jsonl_metadata_preserves_unicode_and_rejects_nonobjects(self):
        self.assertEqual(records('{"name":"é"}\n{"value":2}\n'.encode()), [{"name": "é"}, {"value": 2}])
        self.assertEqual(records(b""), [])
        with self.assertRaises(CaseError):
            records(b"[1]")


if __name__ == "__main__":
    unittest.main()
