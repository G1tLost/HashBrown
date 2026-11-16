"""Check the installed distribution using inert binary fixtures only."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def run(directory, *args):
    result = subprocess.run([sys.executable, '-I', '-m', 'hashbrown_ir', *args], cwd=directory,
                            capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return json.loads(result.stdout)


with tempfile.TemporaryDirectory(prefix='hashbrown-installed-') as folder:
    # Windows runner temp paths may use an 8.3 alias; compare canonical paths.
    root = (Path(folder) / 'cases').resolve()
    summary = run(folder, '--root', str(root), 'demo')
    assert summary['images'] == 2 and summary['verified_images'] == 2 and summary['gaps'] == []
    case = Path(summary['case_path']).resolve()
    assert case.is_relative_to(root), (case, root)
    assert (case / 'report.html').is_file(), case
    run(folder, '--root', str(root), 'verify', summary['case_id'])
    print('Installed HashBrown: two inert images acquired and verified outside checkout; no device/driver capture.')
