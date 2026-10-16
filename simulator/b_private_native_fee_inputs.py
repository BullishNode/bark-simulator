"""Prepare exact private originals for the fixed native fee verifier.

This is byte/hash/framing glue for the EXISTING private TargetTarReader, not a
producer/query admission, SQL completeness verifier, native codec or proof.
Caller first authenticates the protected runtime and source/query admission.
Returned request contains private signed packages and MUST NOT enter Store,
public traces/logs or a generic public RPC operation.
"""
from .b_native_owner_snapshot import owner_snapshot,need
from .two_step_normal import digest,strict_json

# Existing native16MiB signed packages become32MiB hex before SQL/ledger.
# Match the frozen native64MiB whole request, within TargetTarReader128MiB.
MAX_ORIGINAL_BYTES=64*1024*1024
AUXILIARY={'b_native_fee_originals':'b-native-fee-originals.json',
           'b_native_fee_snapshot':'b-native-fee-snapshot.json'}
DATABASE_FIELDS={'native_funding_fee_intent','native_funding_fee_input',
                 'native_funding_fee_resolution','nursery_tx'}


def prepare_native_fee_request(target,runtime,*,expected_product_commit,expected_tool_commit,observation):
    """Bind private original bytes, preserving the same SQL transaction output.

    The new protected producer must emit one literal RR transaction containing
    both original JSON lines. The trusted query/source admission establishes
    actual PostgreSQL isolation/membership. Framing text/response flags alone do
    not. No legacy separate-query or missing-table fallback is accepted.
    """
    need(type(expected_tool_commit) is str and len(expected_tool_commit)==40
        and all(c in '0123456789abcdef' for c in expected_tool_commit),
        'independent actual proof tool source absent')
    manifest=target.get('manifest',{});files=target.get('auxiliary_originals',{})
    mapping=manifest.get('auxiliary_originals',{});entries=manifest.get('files',{})
    selected={}
    for role,name in AUXILIARY.items():
        need(mapping.get(role)==name and type(files.get(name)) is bytes,
             'fixed private original missing '+role)
        raw=files[name];entry=entries.get(name)
        need(0<len(raw)<=MAX_ORIGINAL_BYTES and type(entry) is dict
            and set(entry)=={'sha256','size_bytes'} and type(entry['size_bytes']) is int
            and entry['size_bytes']==len(raw) and entry['sha256']==digest(raw),
            'private auxiliary original hash/size differs '+role)
        selected[role]=raw
    private=strict_json(selected['b_native_fee_originals'])
    need(type(private) is dict and set(private)=={'policy_raw','opening_raw','journal_raw','sql_raw'}
        and all(type(value) is str for value in private.values()),'exact private UTF8 originals required')
    need(sum(len(v.encode())for v in private.values())<=MAX_ORIGINAL_BYTES,
         'private fee original aggregate exceeds bound')
    partition=owner_snapshot(selected['b_native_fee_snapshot'],runtime,
        expected_product_commit=expected_product_commit)
    expected={'policy_raw':partition['policy_sha256'],'opening_raw':partition['opening_sha256'],
              'journal_raw':partition['journal_sha256']}
    for role,sha in expected.items():
        name={'policy_raw':'ordinary-fee-policy.json','opening_raw':'ordinary-fee-opening.json',
              'journal_raw':'ordinary-fee-budget'}[role]
        actual=runtime['native_budget']['files'][name]
        need(digest(private[role].encode())==sha and len(private[role].encode())==actual.get('bytes'),
             'private original differs from actual owning file '+role)
    sql=private['sql_raw'].encode();lines=sql.splitlines()
    need(sql.endswith(b'\n') and len(lines)==6 and lines[:3]==[b'BEGIN',b'SET',b'DO']
        and lines[-1]==b'COMMIT','same bounded single RR transaction framing required')
    whole=target.get('raw_sql')
    need(type(whole) is bytes and whole in (lines[3],lines[3]+b'\n')
        and manifest.get('original_sha256',{}).get('native_sql')==digest(whole),
        'same captured whole B frontier differs')
    database_raw=lines[4]
    database=strict_json(database_raw)
    need(type(database) is dict and set(database)==DATABASE_FIELDS
        and all(type(rows) is list for rows in database.values()),
        'all native fee SQL domains required; native proof validates their rows')
    need(type(observation) is dict and set(observation)=={'id','height','tip_hash'}
        and type(observation['id']) is str and len(observation['id'])==32
        and all(c in '0123456789abcdef' for c in observation['id'])
        and type(observation['height']) is int and 0<=observation['height']<2**32
        and type(observation['tip_hash']) is str and len(observation['tip_hash'])==64
        and all(c in '0123456789abcdef' for c in observation['tip_hash']),
        'fixed current source observation required')
    originals={name:private[name]for name in ('policy_raw','opening_raw','journal_raw')}
    originals['database_raw']=database_raw.decode()
    return {'schema':1,'kind':'b-native-fee-source-request','sdk_commit':expected_tool_commit,
        'source_observation':observation,
        'expected':{'genesis':partition['genesis'],'server_pubkey':partition['server_pubkey'],
            'policy_sha256':partition['policy_sha256'],'opening_sha256':partition['opening_sha256'],
            'journal_sha256':partition['journal_sha256'],'database_sha256':digest(database_raw)},
        'originals':originals}


def verify_native_fee_sources(target,runtime,*,tool,expected_product_commit,expected_tool_commit,observation):
    """Execute the ACTUAL admitted native helper, then bind its safe result.

    This fixed B callback has no supplied-reply shortcut. Existing collector
    source admission authenticates this module/tool configuration first. Actual
    protected producer/query/runtime custody is separately mandatory. Returning
    a native row proof does not activate financial paths or retire liabilities.
    """
    from .two_step_normal import run_native_fee_source_proof
    from .b_native_fee_reply import bind_native_fee_reply
    need(tool.get('sdk_commit')==expected_tool_commit,'source-admitted actual proof tool differs')
    request=prepare_native_fee_request(target,runtime,expected_product_commit=expected_product_commit,
        expected_tool_commit=expected_tool_commit,observation=observation)
    request_raw,reply_raw=run_native_fee_source_proof(tool,request)
    snapshot=target['auxiliary_originals'][AUXILIARY['b_native_fee_snapshot']]
    return bind_native_fee_reply(request_raw,reply_raw,snapshot,expected_tool_commit=expected_tool_commit)
