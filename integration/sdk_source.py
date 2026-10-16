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


def fixture_driver_sdk_receipt(source, sdk_commit, harness_commit):
    """Separate the qualified driver SDK from a test-only harness child.

    The launcher's immutable executable declaration supplies the driver hash.
    This check proves the selected harness has the same committed SDK bytes;
    it does not turn metadata into financial readiness.
    """
    for value in (sdk_commit, harness_commit):
        if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{40}', value):
            raise ValueError('explicit fixture requires an exact qualified driver SDK commit')
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args], stderr=subprocess.PIPE)
    try:
        git('merge-base', '--is-ancestor', sdk_commit, harness_commit)
        changed = git('diff', '--name-only', sdk_commit, harness_commit, '--').decode().splitlines()
    except subprocess.CalledProcessError as exc:
        raise ValueError('qualified driver SDK is not the declared harness ancestor') from exc
    if any(not path.startswith('testing/') for path in changed):
        raise ValueError('fixture harness differs from qualified SDK outside tests')
    return {'sdk_commit': sdk_commit, 'harness_commit': harness_commit,
            'test_only_committed_paths': changed,
            'scope': 'Git SDK byte identity; qualified executable hash is separately declared'}
