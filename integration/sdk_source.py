"""Exact Git/source provenance for the isolated native fixture overlay."""
from pathlib import Path
import hashlib
import re
import subprocess

OVERLAY_PATHS = (
    'testing/tests/bark_sdk/mod.rs',
    'testing/tests/bark_sdk/simulator_vertical.rs',
)


def fixture_source_receipt(source, expected_commit, harness_source, *, expected_tree=None):
    """Inspect source only; never edit, build, or run a native fixture.

    A caller-selected SDK commit is an exact source pin. It does not establish
    that this historical harness has the right economics for that architecture.
    """
    source = Path(source).resolve()
    for value in (expected_commit, expected_tree):
        if value is not None and not re.fullmatch(r'[0-9a-f]{40}', value):
            raise ValueError('full lowercase SDK commit/tree required')

    def git(*args):
        return subprocess.check_output(
            ['git', '-C', str(source), *args], stderr=subprocess.PIPE)

    try:
        if Path(git('rev-parse', '--show-toplevel').decode().strip()).resolve() != source:
            raise ValueError('fixture SDK source must be the repository root')
        head = git('rev-parse', 'HEAD').decode().strip()
        tree = git('rev-parse', 'HEAD^{tree}').decode().strip()
        status = git('status', '--porcelain=v1', '-z', '--untracked-files=all')
    except subprocess.CalledProcessError as exc:
        raise ValueError('fixture SDK Git identity unavailable') from exc
    if head != expected_commit or expected_tree is not None and tree != expected_tree:
        raise ValueError('fixture SDK commit/tree differs from declaration')
    entries = [entry for entry in status.split(b'\0') if entry]
    if (len(entries) != len(OVERLAY_PATHS)
            or any(entry[:2] not in (b' M', b'M ', b'MM', b' A', b'A ', b'??') for entry in entries)
            or sorted(entry[3:].decode() for entry in entries) != sorted(OVERLAY_PATHS)):
        raise ValueError('fixture SDK requires exactly the declared two-path overlay')
    hashes = {}
    for name in OVERLAY_PATHS:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('fixture overlay must contain regular source files')
        raw = path.read_bytes()
        if name.endswith('/simulator_vertical.rs') and raw != Path(harness_source).read_bytes():
            raise ValueError('fixture harness differs from shared source')
        hashes[name] = hashlib.sha256(raw).hexdigest()
    if (git('status', '--porcelain=v1', '-z', '--untracked-files=all') != status
            or git('rev-parse', 'HEAD').decode().strip() != head):
        raise ValueError('fixture SDK changed during source observation')
    return {'head': head, 'tree': tree, 'overlay_sha256': hashes,
            'scope': 'exact source provenance only; architecture-specific harness qualification is separate'}
