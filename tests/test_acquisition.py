"""Acquisition tests adapted from MIT-licensed Bacon Egg and Cheese contributors."""
import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hashbrown_ir import acquisition as acq
from hashbrown_ir.endpoint import bind
CLIENT = "C.0123456789abcdef"
from hashbrown_ir.lab_images import create_fixtures, disk_fixture, memory_fixture
from hashbrown_ir.reporting import report
from hashbrown_ir.storage import CaseError, create, digest, encode, read, save


class API:
    org = "root"

    def __init__(self, data):
        self.data, self.calls, self.starts = data, [], 0
        self.fail_offset = None
        self.corrupt = False
        self.state = "FINISHED"
        self.client = CLIENT
        self.source_extra = 0
        self.upload_components = None

    def query(self, query, variables=None, **kwargs):
        self.calls.append((query, variables))
        if "collect_client(" in query:
            self.starts += 1
            self.parameters = json.loads(variables["Parameters"])
            self.artifact = variables["ArtifactName"]
            rows = [{"Result": {"flow_id": "F.image"}}]
        elif "get_flow(" in query:
            rows = [{"Flow": dict(client_id=self.client, session_id="F.image", state=self.state,
                request=dict(artifacts=[self.artifact], specs=[dict(artifact=self.artifact,
                    parameters={"env": [dict(key=k, value=v) for k, v in self.parameters.items()]})]), query_stats=[{"status": "OK"}])}]
        elif "source(" in query:
            rows = [dict(RequestId=self.parameters["RequestId"], EvidenceKind=self.parameters.get("EvidenceKind", "memory"),
                         Simulation=self.parameters.get("Simulation") == "Y", Started="2026-11-15T12:00:00Z", Finished="2026-11-15T12:01:00Z",
                         ExpectedSize=len(self.data) + self.source_extra, SourcePath="lab.raw",
                         Upload=dict(Size=len(self.data), sha256=digest(self.data)))]
        elif "uploads(" in query:
            rows = [dict(client_path="image.raw", file_size=len(self.data),
                _Components=self.upload_components or ["clients", CLIENT, "collections", "F.image", "uploads", "file", "image.raw"])]
        elif "base64encode(" in query:
            offset, length = variables["ByteOffset"], variables["ByteCount"]
            if offset == self.fail_offset:
                raise CaseError("Injected disconnect")
            block = self.data[offset:offset + length]
            if self.corrupt:
                block = b"X" * len(block)
            rows = [{"Data": base64.b64encode(block).decode()}]
        elif "clients(" in query:
            rows = [dict(client_id=CLIENT, os_info={"fqdn": "lab-win01"})]
        else:
            raise AssertionError(query)
        return encode(rows), rows


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.case = create(self.root, "LAB", "Analyst A")
        bind(self.case, CLIENT, "lab-win01")
        self.source = self.root / "original.raw"
        self.data = bytes(range(256)) * 513
        self.source.write_bytes(self.data)

    def start(self, api=None):
        api = api or API(self.data)
        job = acq.start(self.case, CLIENT, "memory", api, "Analyst A", source="C:\\Lab\\memory.raw", simulation=True)
        return api, job

    def test_import_streams_and_tracks_original_hash(self):
        job = acq.import_image(self.case, CLIENT, "disk", self.source, "Analyst A", expected_sha256=digest(self.data))
        self.assertEqual(job["status"], "verified")
        self.assertEqual((self.case.path / job["content_path"]).read_bytes(), self.data)
        self.assertEqual(self.source.read_bytes(), self.data)
        self.assertEqual(self.case.verify(), 1)
        self.assertEqual([e["action"] for e in acq.load(self.case)["custody"]], ["import_started", "image_verified"])

    def test_remote_resume_and_no_duplicate_collection(self):
        api, job = self.start()
        self.assertEqual(self.start(api)[1]["id"], job["id"])
        api.fail_offset = 4096
        with self.assertRaisesRegex(CaseError, "disconnect"):
            acq.resume(self.case, job["id"], api, chunk_size=4096)
        saved = acq.load(self.case)["jobs"][job["id"]]
        self.assertEqual(saved["offset"], 4096)
        self.assertEqual(saved["prefix_sha256"], digest(self.data[:4096]))
        api.fail_offset = None
        finished = acq.resume(self.case, job["id"], api, chunk_size=4096)
        self.assertEqual(finished["status"], "verified")
        self.assertEqual(api.starts, 1)
        self.assertEqual(acq.verify(self.case), 1)

    def test_corrupted_download_is_not_promoted(self):
        api, job = self.start()
        api.corrupt = True
        with self.assertRaisesRegex(CaseError, "SHA-256"):
            acq.resume(self.case, job["id"], api)
        saved = acq.load(self.case)["jobs"][job["id"]]
        self.assertEqual(saved["status"], "integrity_failed")
        part, final = acq.paths(self.case, saved)
        self.assertTrue(part.exists())
        self.assertFalse(final.exists())

    def test_partial_file_tamper_blocks_resume(self):
        api, job = self.start()
        api.fail_offset = 4096
        with self.assertRaises(CaseError):
            acq.resume(self.case, job["id"], api, chunk_size=4096)
        part, _ = acq.paths(self.case, job)
        with part.open("r+b") as f:
            f.write(b"tamper")
        api.fail_offset = None
        with self.assertRaisesRegex(CaseError, "checkpoint"):
            acq.resume(self.case, job["id"], api, chunk_size=4096)
        with self.assertRaises(CaseError):
            acq.verify(self.case)

    def test_uncheckpointed_tail_is_replaced_on_resume(self):
        api, job = self.start()
        api.fail_offset = 4096
        with self.assertRaises(CaseError):
            acq.resume(self.case, job["id"], api, chunk_size=4096)
        part, _ = acq.paths(self.case, job)
        with part.open("ab") as f:
            f.write(b"uncommitted tail")
        api.fail_offset = None
        self.assertEqual(acq.resume(self.case, job["id"], api)["status"], "verified")

    def test_crash_after_rename_can_be_recovered(self):
        api, job = self.start()
        import os
        original = os.replace
        def rename_then_disconnect(src, dst):
            original(src, dst)
            if str(dst).endswith("image.bin"):
                raise OSError("Injected crash after rename")
        with patch("hashbrown_ir.acquisition.os.replace", side_effect=rename_then_disconnect):
            with self.assertRaisesRegex(CaseError, "rename"):
                acq.resume(self.case, job["id"], api)
        finished = acq.resume(self.case, job["id"])
        self.assertEqual(finished["status"], "verified")
        self.assertEqual(acq.verify(self.case), 1)

    def test_tampered_committed_image_and_custody_are_detected(self):
        job = acq.import_image(self.case, CLIENT, "disk", self.source, "A")
        image = self.case.path / job["content_path"]
        image.write_bytes(b"X" * len(self.data))
        with self.assertRaises(CaseError):
            self.case.verify()
        self.assertTrue(acq.summary(self.case)[2])
        state = read(self.case.path / "acquisitions.json")
        state["custody"][0]["operator"] = "Changed"
        save(self.case.path / "acquisitions.json", state)
        with self.assertRaisesRegex(CaseError, "custody"):
            acq.load(self.case)

    def test_manifest_cannot_disagree_with_verification_receipt(self):
        job = acq.import_image(self.case, CLIENT, "disk", self.source, "A")
        state = acq.load(self.case)
        state["jobs"][job["id"]]["content_sha256"] = "f" * 64
        save(self.case.path / "acquisitions.json", state)
        with self.assertRaisesRegex(CaseError, "receipt"):
            acq.load(self.case)

    def test_missing_ledger_does_not_hide_binary_evidence(self):
        acq.import_image(self.case, CLIENT, "disk", self.source, "A")
        (self.case.path / "acquisitions.json").unlink()
        with self.assertRaisesRegex(CaseError, "ledger is missing"):
            self.case.verify()

    def test_missing_partial_evidence_is_reported(self):
        api, job = self.start()
        api.fail_offset = 4096
        with self.assertRaises(CaseError):
            acq.resume(self.case, job["id"], api, chunk_size=4096)
        acq.paths(self.case, job)[0].unlink()
        with self.assertRaisesRegex(CaseError, "partial evidence is missing"):
            acq.verify(self.case)

    def test_metadata_links_must_reference_preserved_evidence(self):
        api, job = self.start()
        acq.resume(self.case, job["id"], api)
        state = acq.load(self.case)
        state["jobs"][job["id"]]["metadata"][0]["file"] = "../another-case.json"
        save(self.case.path / "acquisitions.json", state)
        with self.assertRaisesRegex(CaseError, "metadata is not registered"):
            acq.load(self.case)

    def test_flow_and_upload_boundaries(self):
        for mutation in ("client", "path", "request"):
            with self.subTest(mutation=mutation):
                api, job = self.start()
                api.parameters = copy.deepcopy(job["parameters"])
                api.artifact = job["artifact"]
                if mutation == "client":
                    api.client = "C.aaaaaaaaaaaaaaaa"
                elif mutation == "path":
                    api.upload_components = ["clients", CLIENT, "collections", "F.image", "uploads", "..", "image.raw"]
                else:
                    api.parameters["RequestId"] = "different-case"
                with self.assertRaises(CaseError):
                    acq.resume(self.case, job["id"], api)
                self.assertEqual(acq.load(self.case)["jobs"][job["id"]]["offset"], 0)

    def test_insufficient_space_and_wrong_supplied_hash(self):
        api, job = self.start()
        from collections import namedtuple
        usage = namedtuple("usage", "total used free")(100, 100, 0)
        with patch("hashbrown_ir.acquisition.shutil.disk_usage", return_value=usage):
            with self.assertRaisesRegex(CaseError, "space"):
                acq.resume(self.case, job["id"], api)
        with self.assertRaisesRegex(CaseError, "SHA-256"):
            acq.import_image(self.case, CLIENT, "disk", self.source, "A", expected_sha256="f" * 64)

    def test_short_capture_keeps_partial_status_despite_correct_hash(self):
        api, job = self.start()
        api.source_extra = 512
        result = acq.resume(self.case, job["id"], api)
        self.assertEqual((result["status"], result["integrity"]), ("partial", "verified"))
        self.assertTrue(acq.summary(self.case)[2])
        self.assertEqual(acq.verify(self.case), 1)

    def test_memory_extent_checks_holes_and_bad_ranges(self):
        info = {"Run": [{"BaseAddress": "0x1000", "NumberOfBytes": "0x1000"}, {"BaseAddress": 16384, "NumberOfBytes": 8192}]}
        self.assertEqual(acq.memory_extent(info), 24576)
        info["Run"][1]["BaseAddress"] = 5000
        with self.assertRaises(CaseError):
            acq.memory_extent(info)
        with self.assertRaises(CaseError):
            acq.memory_extent({})

    def test_capture_options_and_budget_are_explicit(self):
        api = API(self.data)
        with self.assertRaises(CaseError):
            acq.start(self.case, CLIENT, "disk", api, "A")
        with self.assertRaises(CaseError):
            acq.start(self.case, CLIENT, "memory", api, "A", simulation=True)
        with self.assertRaises(CaseError):
            acq.import_image(self.case, CLIENT, "disk", self.source, "A", max_bytes=1)
        acq.start(self.case, CLIENT, "disk", api, "A", disk_number=2)
        self.assertEqual(api.artifact, "Custom.HashBrown.AcquireDisk")
        self.assertEqual(api.parameters["DiskNumber"], "2")
        self.assertIn("max_bytes=", api.calls[-1][0])

    def test_lost_submission_response_does_not_resubmit(self):
        api = API(self.data)
        original = api.query
        def lost(*args, **kwargs):
            result = original(*args, **kwargs)
            if "collect_client(" in args[0]:
                raise CaseError("Lost submission response")
            return result
        with patch.object(api, "query", side_effect=lost):
            with self.assertRaises(CaseError):
                self.start(api)
        _, job = self.start(api)
        self.assertEqual(api.starts, 1)
        self.assertEqual(job["status"], "submission_unknown")
        self.assertEqual(acq.resume(self.case, job["id"], api, flow_id="F.image")["status"], "verified")

    def test_note_is_escaped_and_references_are_plain_text(self):
        job = acq.import_image(self.case, CLIENT, "disk", self.source, "A", simulation=True)
        report(self.case)
        acq.note(self.case, job["id"], "B", "review", ["External lab notebook page 4"])
        acq.note(self.case, job["id"], "B", '<script>alert("unsafe")</script>')
        report(self.case)
        self.assertNotIn('<script>alert("unsafe")</script>', (self.case.path / "report.html").read_text())
        self.assertEqual(acq.load(self.case)["custody"][-1]["details"]["author"], "B")

    def test_fixtures_are_reproducible_and_never_overwrite_different_data(self):
        path = self.root / "fixtures"
        first = create_fixtures(path)
        self.assertEqual(create_fixtures(path), first)
        disk = disk_fixture()
        self.assertEqual(disk[510:512], b"\x55\xaa")
        self.assertEqual(disk[19 * 512:19 * 512 + 11], b"README  TXT")
        self.assertIn(b"NOT A LIVE MEMORY IMAGE", memory_fixture())
        (path / "memory.raw").write_bytes(b"unrelated data")
        with self.assertRaises(CaseError):
            create_fixtures(path)


if __name__ == "__main__":
    unittest.main()
