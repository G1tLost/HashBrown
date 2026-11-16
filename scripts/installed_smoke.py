"""Check the installed distribution using inert binary fixtures only."""
import json
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


def run(directory, *args, expected=0, text=False):
    result = subprocess.run([sys.executable, '-I', '-m', 'hashbrown_ir', *args], cwd=directory,
                            capture_output=True, text=True, timeout=90)
    if result.returncode != expected:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout if text else json.loads(result.stdout)


def snapshot(directory):
    return {str(path.relative_to(directory)): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
            for path in directory.rglob('*') if path.is_file()}


with tempfile.TemporaryDirectory(prefix='hashbrown-installed-') as folder:
    # Windows runner temp paths may use an 8.3 alias; compare canonical paths.
    root = (Path(folder) / 'cases').resolve()
    summary = run(folder, '--root', str(root), 'demo')
    assert summary['images'] == 2 and summary['verified_images'] == 2 and summary['gaps'] == []
    case = Path(summary['case_path']).resolve()
    assert case.is_relative_to(root), (case, root)
    assert (case / 'report.html').is_file(), case
    run(folder, '--root', str(root), 'verify', summary['case_id'])
    original = snapshot(root)
    preflight = ('--root', str(root), 'acquisition', 'import', summary['case_id'],
                 '--client-id', 'C.0123456789abcdef', '--kind', 'disk', '--operator', 'Installed smoke',
                 '--file', str(case / 'fixtures' / 'disk.img'), '--simulation', '--preflight')
    plan = run(folder, *preflight)
    assert plan['version'] == '0.2.0' and plan['read_only'] and plan['status'] == 'pass'
    assert plan['plan']['source']['size_bytes'] == 1474560
    assert plan['plan']['capacity']['host'] == 'analyst' and plan['plan']['capacity']['advisory']
    readable = run(folder, *preflight, '--plan-format', 'text', text=True)
    assert '[PASS]' in readable and 'capture_completeness' in readable
    failed = run(folder, *preflight, '--max-bytes', '0', expected=1)
    assert failed['status'] == 'fail'
    missing_root = Path(folder) / 'must-not-be-created'
    missing = run(folder, '--root', str(missing_root), *preflight[2:], expected=1)
    assert missing['status'] == 'fail' and not missing_root.exists()
    assert snapshot(root) == original, 'Preflight changed case contents or modification times'
    print('Installed HashBrown: two inert images verified; JSON/text preflight and failure paths left evidence unchanged. No device/driver capture.')
