"""Standalone HashBrown command line. JSON results on stdout, errors on stderr."""
import argparse
import json
import sys
from pathlib import Path

from . import __version__, acquisition as acq, endpoint
from .lab_images import create_fixtures
from .reporting import report
from .storage import Case, CaseError, create


def parser():
    root = argparse.ArgumentParser(prog="hashbrown", description="Disk and RAM acquisition with independent evidence custody.")
    root.add_argument("--version", action="version", version=__version__)
    root.add_argument("--root", type=Path, default=Path("hashbrown-cases"), help="HashBrown's own case store (default: ./hashbrown-cases)")
    cmd = root.add_subparsers(dest="command", required=True)
    case_cmd = cmd.add_parser("case", help="create, inspect or bind a HashBrown case").add_subparsers(dest="action", required=True)
    sub = case_cmd.add_parser("create")
    sub.add_argument("--label", required=True)
    sub.add_argument("--operator", required=True)
    sub = case_cmd.add_parser("bind")
    sub.add_argument("case_id")
    sub.add_argument("--client-id", required=True)
    sub.add_argument("--hostname", required=True, help="actual server-reported FQDN")
    sub.add_argument("--org", default="root")
    case_cmd.add_parser("show").add_argument("case_id")
    for action in ("fixtures", "artifacts"):
        sub = cmd.add_parser(action)
        sub.add_argument("--output", type=Path, required=True)
    sub = cmd.add_parser("install", help="install the three HashBrown artifacts on a Velociraptor server")
    sub.add_argument("--velociraptor", type=Path, required=True)
    sub.add_argument("--api-config", type=Path, required=True)
    sub.add_argument("--org", default="root")
    cmd.add_parser("demo", help="generate inert fixtures, import both into a new case, verify and report")
    handoff_cmd = cmd.add_parser("handoff", help="create or verify a detached portable evidence manifest").add_subparsers(dest="action", required=True)
    sub = handoff_cmd.add_parser("create")
    sub.add_argument("case_id")
    sub.add_argument("--job", action="append", required=True, help="explicit saved acquisition ID; repeat to select more")
    sub.add_argument("--output", type=Path, required=True, help="new JSON outside the source case store; parent must exist")
    sub.add_argument("--format", choices=("json", "text"), default="json")
    sub = handoff_cmd.add_parser("verify")
    sub.add_argument("--manifest", type=Path, required=True)
    sub.add_argument("--evidence-root", type=Path, required=True)
    sub.add_argument("--manifest-sha256", help="complete manifest file SHA-256 obtained independently")
    sub.add_argument("--format", choices=("json", "text"), default="json")
    for action in ("verify", "report"):
        cmd.add_parser(action).add_argument("case_id")
    acq_cmd = cmd.add_parser("acquisition", help="collect, import, resume, verify and annotate images").add_subparsers(dest="action", required=True)
    for action in ("collect", "sync", "import", "status", "verify", "note"):
        sub = acq_cmd.add_parser(action)
        sub.add_argument("case_id")
        if action in ("collect", "import"):
            sub.add_argument("--client-id", required=True)
            sub.add_argument("--kind", choices=("disk", "memory"), required=True)
            sub.add_argument("--operator", required=True)
            sub.add_argument("--simulation", action="store_true", help="mark explicit existing fixture bytes as synthetic")
            sub.add_argument("--max-bytes", type=int, default=acq.MAX_BYTES)
            sub.add_argument("--format", choices=("raw", "vhdx", "vmdk", "other"), default="raw")
        if action in ("collect", "sync"):
            sub.add_argument("--velociraptor", type=Path)
            sub.add_argument("--api-config", type=Path)
        if action in ("collect", "sync", "import"):
            sub.add_argument("--preflight", action="store_true", help="read-only local plan; never submit, capture or write evidence")
            sub.add_argument("--plan-format", choices=("json", "text"), help="preflight output format (default: json)")
            sub.add_argument("--declared-bytes", type=int, help="preflight-only size estimate; does not constrain a later capture")
        if action == "collect":
            source = sub.add_mutually_exclusive_group()
            source.add_argument("--source", help="existing image file on the bound endpoint")
            source.add_argument("--disk-number", type=int, help="explicit Windows disk index")
            sub.add_argument("--timeout", type=int, default=86400)
        if action in ("sync", "note"):
            sub.add_argument("--job", required=True)
        if action == "sync":
            sub.add_argument("--flow-id")
            sub.add_argument("--download-api-config", type=Path)
            sub.add_argument("--file", type=Path, help="preflight-only explicit local import source for identity/collision checks")
        if action == "import":
            sub.add_argument("--file", type=Path, required=True)
            sub.add_argument("--sha256", help="original source SHA-256, if available")
        if action == "note":
            sub.add_argument("--operator", required=True)
            sub.add_argument("--text", required=True)
            sub.add_argument("--reference", action="append", default=[], help="freeform source/reference; repeat as needed")
    return root


def demo(root):
    case = create(root, "DEMO", "Synthetic fixture demonstration")
    client = "C.0123456789abcdef"
    with case.lock():
        endpoint.bind(case, client, "synthetic-fixture")
        directory = case.path / "fixtures"
        manifest = create_fixtures(directory)
        for kind, filename in (("disk", "disk.img"), ("memory", "memory.raw")):
            acq.import_image(case, client, kind, directory / filename, "Synthetic fixture demonstration",
                             simulation=True, expected_sha256=manifest["files"][filename]["sha256"])
        case.verify()
        result = report(case)
    return dict(**result, case_path=str(case.path), simulation=True,
                note="Generated bytes only. memory.raw is not a Windows RAM dump; no host disks or memory were read.")


def run_acquisition(args, case):
    state = acq.load(case)
    if args.action == "status":
        return state, 0
    if args.action == "verify":
        count = acq.verify(case, record=True)
        result = report(case)
        return dict(**result, verified_image_count=count), 2 if result["gaps"] else 0
    if args.action == "note":
        acq.note(case, args.job, args.operator, args.text, args.reference)
        return report(case), 0
    if args.action == "import":
        result = acq.import_image(case, args.client_id, args.kind, args.file, args.operator,
                                  args.simulation, args.max_bytes, args.format, args.sha256)
    else:
        old = state["jobs"].get(getattr(args, "job", None))
        if args.action == "sync" and not old:
            raise CaseError("Acquisition was not found.")
        client = old["client_id"] if old else args.client_id
        bound = endpoint.binding(case, client)
        api = download = None
        if bool(args.api_config) != bool(args.velociraptor):
            raise CaseError("Supply both --velociraptor and --api-config for remote synchronization.")
        if args.api_config:
            api = endpoint.Velociraptor(args.velociraptor, args.api_config, bound["org_id"])
        if getattr(args, "download_api_config", None):
            if not api:
                raise CaseError("A download credential also requires --velociraptor and --api-config.")
            download = endpoint.Velociraptor(args.velociraptor, args.download_api_config, bound["org_id"])
        if args.action == "collect":
            if not api:
                raise CaseError("Supply --velociraptor and --api-config for remote collection.")
            result = acq.start(case, client, args.kind, api, args.operator, args.source, args.disk_number,
                               args.simulation, args.max_bytes, args.format, args.timeout)
        else:
            result = acq.resume(case, args.job, api, download, args.flow_id)
    report(case)
    return result, 0 if result["status"] == "verified" else 2


def run(args):
    if args.command == "handoff":
        from . import handoff
        result = handoff.create(args.root, args.case_id, args.job, args.output) if args.action == "create" else handoff.verify(args.manifest, args.evidence_root, args.manifest_sha256)
        return result, {"created": 0, "verified": 0, "partial": 2, "failed": 1}[result["status"]]
    if getattr(args, "preflight", False):
        from .preflight import plan
        result = plan(args)
        return result, {"pass": 0, "warning": 2, "fail": 1}[result["status"]]
    if getattr(args, "plan_format", None) or getattr(args, "declared_bytes", None) is not None:
        raise CaseError("--plan-format and --declared-bytes require --preflight.")
    if args.command == "acquisition" and args.action == "sync" and args.file:
        raise CaseError("--file on sync requires --preflight; a saved acquisition cannot be redirected.")
    if args.command == "fixtures":
        return create_fixtures(args.output), 0
    if args.command == "artifacts":
        return dict(artifacts=endpoint.export_artifacts(args.output)), 0
    if args.command == "install":
        return dict(installed=endpoint.Velociraptor(args.velociraptor, args.api_config, args.org).install()), 0
    if args.command == "demo":
        return demo(args.root), 0
    if args.command == "case" and args.action == "create":
        case = create(args.root, args.label, args.operator)
        return dict(case_id=case.id, case_path=str(case.path)), 0
    case = Case.find(args.root, args.case_id)
    with case.lock():
        case.verify(include_images=False)
        if args.command == "case":
            if args.action == "bind":
                return endpoint.bind(case, args.client_id, args.hostname, args.org), 0
            return case.meta, 0
        if args.command == "verify":
            count = acq.verify(case, record=True)
            result = report(case)
            return dict(**result, verified_image_count=count), 2 if result["gaps"] else 0
        if args.command == "report":
            result = report(case)
            return result, 2 if result["gaps"] else 0
        return run_acquisition(args, case)


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result, code = run(args)
        if args.command == "handoff" and args.format == "text":
            from .handoff import render_text
            print(render_text(result))
        elif getattr(args, "preflight", False) and args.plan_format == "text":
            from .preflight import render_text
            print(render_text(result))
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return code
    except (CaseError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"hashbrown: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
