"""Source-only proposed extension of the existing protected C manifest.

Call only after the unchanged legacy deployment validator and actual protected
file reader have authenticated the original manifest/source bytes. This pure
function grants no deployment, resource or financial operating authority.
"""
import hashlib
import importlib.util
from pathlib import Path
import re

CONTRACT_SHA256 = '91890edd02af0a6b70b47c3abeb4aaa62009d85088ee2bea1c97536b56b24ecb'
EXTENSION = 'closed_frontier_v2'
SOURCE_FILES = frozenset({'adapter_v3.py', 'frontier_v2_contract.py',
                          'dbapi_adapter.py', 'frontier_stream.py',
                          'public-projections.json', 'wiring_contract.py',
                          'protected_files.py', 'target_worker.py', 'controller_wrapper.py'})


def contract():
    path = Path(__file__).resolve().with_name('frontier_v2_contract.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != CONTRACT_SHA256:
        raise ValueError('frozen frontier integration contract differs')
    spec = importlib.util.spec_from_file_location('protected_frontier_contract', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def derive_expected(validated_manifest, actual_manifest_sha256):
    """Bind v2 to the actual whole protected deployment bytes without a hash loop.

    The manifest contains resource bounds and fixed public database/server facts,
    not a contract digest that itself includes the manifest digest. Controller
    expectations must independently match this exact derived contract. Neither
    request fields nor producer stream claims may supply these expectations.
    """
    c = contract()
    if (not isinstance(actual_manifest_sha256, str)
            or re.fullmatch('[0-9a-f]{64}', actual_manifest_sha256) is None):
        raise ValueError('actual protected deployment file digest required')
    ext = validated_manifest.get(EXTENSION)
    if (not isinstance(ext, dict)
            or set(ext) != {'resource_declaration', 'database', 'server_pubkey', 'source_files'}):
        raise ValueError('explicit fixed v2 protected extension required')
    if (not isinstance(ext['database'], str)
            or re.fullmatch('[a-zA-Z_][a-zA-Z_0-9]{0,62}', ext['database']) is None):
        raise ValueError('bounded explicit database identity required')
    files = ext['source_files']
    if (not isinstance(files, dict) or set(files) != SOURCE_FILES
            or any(not isinstance(v, str) or re.fullmatch('[0-9a-f]{64}', v) is None
                   for v in files.values())):
        raise ValueError('all exact fixed v2 source hashes required')
    return c.expected_contract({
        'resource_declaration': ext['resource_declaration'],
        'source_binding': {
            'network': 'signet', 'genesis': validated_manifest['genesis'],
            'schema_sha256': validated_manifest['financial_pins']['schema_sha256'],
            'deployment_sha256': actual_manifest_sha256,
            'observer_sha256': validated_manifest['observer_files']['server-observer.py'],
            'database': ext['database'], 'server_pubkey': ext['server_pubkey'],
        },
        'financial_pins': validated_manifest['financial_pins'],
        'deployment_id': validated_manifest['deployment_id'],
    })


def validate_installed_sources(validated_manifest, actual_fixed_source_hashes):
    """Compare hashes from the existing protected file reader, never requests.

    The caller must read each fixed sibling in SOURCE_FILES using the existing
    checked_file/O_NOFOLLOW/root-owner implementation. This pure comparison is
    not a substitute for that protected read or its unchanged legacy checks.
    """
    ext = validated_manifest.get(EXTENSION)
    if (not isinstance(ext, dict) or set(actual_fixed_source_hashes) != SOURCE_FILES
            or actual_fixed_source_hashes != ext.get('source_files')):
        raise ValueError('actual installed fixed v2 source set differs')
    return True
