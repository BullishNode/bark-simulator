"""Prepare PRIVATE captured-native audit input; no tool or financial authority.

Only a separately admitted caller supplies expected native identity and original
source references. This module does not discover files, invoke processes/RPC,
change the Store, calculate native fees, or validate signatures/current rights.
The entire original packet remains unchanged. The first native ABI omits legacy
DirectRecord/allocation closure, which remains an explicit financial HOLD.
"""
import copy
import json
import re
from . import c_private_fee_cut as fee
from . import c_private_joint_fee_cut as source
from . import c_private_native_body_cut as body
from . import c_private_normal_cut as normal
from .c_private_fee_package import MAX_MEMBERS,_sha
from .normal_source_deadline import ACTIVE,Deadline

FORMAT='c-native-captured-audit-v1'
MAX_BYTES=normal.MAX_PAYLOAD_BYTES
EXPECTED={'server_pubkey','genesis','policy_sha256','opening_sha256'}
REFERENCES={'archive_sha256','manifest_sha256','source_sha256','body_source_sha256',
    'source_observation_id','file_sha256','joint_source_sha256','joint_abi_sha256','round_abi_sha256'}
GROUPS={'publication_files':'publications','round_rights_files':'round_rights','opening_files':'opening'}


def _text(raw,maximum,*,empty=False):
    if not isinstance(raw,bytes)or len(raw)>maximum or(not raw and not empty):
        raise ValueError('bounded original native UTF8 bytes required')
    # No trim, replacement, JSON parsing, newline normalization or serialization
    # of a native file. Native canonical interpretation belongs to its owner.
    value=raw.decode('utf-8','strict')
    if value.encode('utf-8','strict')!=raw:raise ValueError('native original UTF8 byte roundtrip differs')
    return value


def _encode(value,deadline):
    data=bytearray()
    encoder=json.JSONEncoder(sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
    for chunk in encoder.iterencode(value):
        deadline.remaining();raw=chunk.encode('utf-8','strict')
        if len(data)+len(raw)>MAX_BYTES:raise ValueError('whole native request exceeds unchanged32MiB bound')
        data.extend(raw)
    deadline.remaining()
    return bytes(data)


def prepare(loaded,*,expected,source_observation,original_source_references):
    """Return private request bytes plus small safe transport facts ONLY.

    `loaded` is the actual strict V4 loader result. Trusted caller independently
    binds its original references/observation and externally admitted native
    expected identity. Matching these values is not proof of their authority;
    process/ELF/runtime/Core/source admissions remain the caller's responsibility.
    No command, filesystem path, output callback or ready flag is accepted.
    """
    if(not isinstance(expected,dict)or set(expected)!=EXPECTED
            or not isinstance(expected['server_pubkey'],str)
            or re.fullmatch('0[23][0-9a-f]{64}',expected['server_pubkey'])is None):
        raise ValueError('exact externally admitted native expected identity required')
    for name in ('genesis','policy_sha256','opening_sha256'):_sha(expected[name])
    if not isinstance(source_observation,dict):raise ValueError('original source observation required')
    # Retain the existing observation's absolute age even outside an Engine
    # context. This never starts a new90s allowance from preparation time.
    deadline=ACTIVE.get()or Deadline(source_observation.get('started_at'))
    deadline.remaining()
    value=copy.deepcopy(loaded);refs=copy.deepcopy(original_source_references);expected=copy.deepcopy(expected)
    if(not isinstance(value,dict)or not isinstance(refs,dict)or set(refs)!=REFERENCES
            or value.get('original_private_source_references')!=refs
            or value.get('native_validation_required')is not True
            or value.get('complete')is not False or value.get('qualified')is not False):
        raise ValueError('strict original V4 source/reference result required')
    manifest=value.get('manifest');files=value.get('originals')
    if(not isinstance(manifest,dict)or not isinstance(files,dict)or len(files)+1>MAX_MEMBERS
            or not isinstance(refs['file_sha256'],dict)or set(files)!=set(refs['file_sha256'])):
        raise ValueError('whole original source member/reference coverage required')
    total=0
    for name,raw in files.items():
        deadline.remaining();source._name(name)
        if not isinstance(raw,bytes)or len(raw)>fee.MAX_BYTES:raise ValueError('bounded original source file required')
        total+=len(raw)
        if total>MAX_BYTES or refs['file_sha256'][name]!=fee.digest(raw):
            raise ValueError('whole original source bytes/hash differ')
    for name in REFERENCES-{'source_observation_id','file_sha256'}:_sha(refs[name])
    manifest_raw=fee.canonical(manifest).encode()
    if fee.digest(manifest_raw)!=refs['manifest_sha256']:raise ValueError('independent original manifest reference differs')
    source._manifest({**files,'manifest.json':manifest_raw})
    if(manifest['schema_version']!=4 or manifest['source_observation']!=source_observation
            or refs['source_observation_id']!=source_observation.get('id')
            or any(refs[name]!=manifest[name]for name in ('source_sha256','body_source_sha256','joint_source_sha256','joint_abi_sha256','round_abi_sha256'))
            or manifest['chain'].get('genesis')!=expected['genesis']or expected['genesis']!=fee.SIGNET_GENESIS):
        raise ValueError('actual original V4 observation/source/native chain differs')
    fee._observation({'source_observation':source_observation},manifest['financial_pins'],manifest['chain']['height'],manifest['chain']['tip_hash'])
    identity=fee._json(files['history/identity.json'])
    if identity.get('server_pubkey')!=expected['server_pubkey']:raise ValueError('external expected native owner differs from original source')
    # Recheck original source representations without invoking a native proof,
    # public producer, PG connection or transport terminal a second time.
    joint=value.get('joint_pg');native=value.get('private_pg');database=value.get('database')
    if(not isinstance(joint,dict)or not isinstance(native,dict)or not isinstance(database,dict)
            or fee.canonical(joint).encode()!=files['joint-pg.json']
            or fee.canonical(native).encode()!=files['private-pg.json']):
        raise ValueError('original captured row representations differ')
    source.assemble(joint,database['database_identity'],fee._json(files['joint-preflight.json']))
    sizes=fee._json(files['cut.json'])['preflight']
    body._assemble(native,{'identity':database['database_identity']},database['rows'],sizes)
    groups=value.get('joint_witnesses')
    witnesses,index=source._witness_files(groups,manifest['history_identity'])
    if(fee.canonical(index).encode()!=files['joint-files.json']
            or set(witnesses)!={n for n in files if n.startswith('joint-witness/')}
            or any(files[name]!=raw for name,raw in witnesses.items())):
        raise ValueError('whole original native witness source differs')
    request={'format':FORMAT,'expected':expected,
        'policy_utf8':_text(files['history/ordinary-fee-policy.json'],1024),
        'history_utf8':_text(files['history/ordinary-fee-budget'],2*1024*1024,empty=True),
        'joint_rows':joint,'body_rows':native}
    counts={}
    for field,group in GROUPS.items():
        deadline.remaining();entries=groups[group]['files']
        # Missing, initialized-empty and nonempty source are distinct. None is
        # never an assertion that omitted history or obligations were empty.
        request[field]=None if entries is None else {name:_text(entry['raw'],source.MAX_FILE_BYTES,
            empty=(group=='round_rights'and name=='history'))for name,entry in entries.items()}
        counts[field]=None if entries is None else len(entries)
    private=_encode(request,deadline)
    deadline.remaining()
    safe={'format':FORMAT,'request_sha256':fee.digest(private),'request_bytes':len(private),
        'source_observation_id':source_observation['id'],'archive_sha256':refs['archive_sha256'],
        'manifest_sha256':refs['manifest_sha256'],'original_source_references_sha256':fee.digest(fee.canonical(refs).encode()),
        'file_counts':counts,'complete':False,'qualified':False,'financial_readiness':False,
        'scope':'Private narrow native request preparation only; legacy DirectRecord/allocation closure excluded; no source/tool/runtime/current ownership or financial authority'}
    return {'private_request':private,'safe':safe}
