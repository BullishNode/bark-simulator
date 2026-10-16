"""C client public-binding compatibility component, with exact execution pins.

This executes a qualified new public verifier over original retained inputs.
It does not open a wallet, qualify stored-wallet migration or server runtime,
change bootstrap/configuration authority, or grant any financial readiness.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import time

from .final_campaign import _source_event
from .model import canonical, integer, public_payload, SIGNET_GENESIS
from .process import json_command, decode_object
from .trace import partition_paths, readonly, record_hash, SCHEMA_VERSION

KIND='c_client_original_bindings_reverified'
TRACE_KIND='c.client_key.stdout'


def _digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()


def _origin(store):
    from .c_cohort import seal
    from .identity_bootstrap import declaration
    opening=seal(store);original=declaration(store)
    if opening is None or opening.get('opening_kind')!='unfunded_initial12' or original is None:
        raise ValueError('explicit preserved pre-money original identity required')
    zero_event,zero=_source_event(store,opening['source_sequence'])
    event,native=_source_event(store,zero.get('driver_response_sequence'))
    response=native.get('response',{});action=store.db.execute("SELECT * FROM action WHERE id='c_create_01'").fetchone()
    if (zero_event['kind']!='identity_bootstrap_zero_assets_verified'
            or zero.get('actor')!='actor-01' or zero.get('action_id')!='c_create_01'
            or event['kind']!='driver_response' or native.get('action_id')!='c_create_01'
            or action is None or action['actor_id']!='actor-01' or action['operation']!='create'
            or action['state']!='completed' or action['actual_fee_sat']!=0 or action['fee_reservation_sat']!=0
            or json.loads(action['result'])!=response or response.get('action_id')!='c_create_01'
            or _digest(response)!=zero.get('native_response_sha256') or event['hash']!=zero.get('source_event_hash')):
        raise ValueError('original identity/native source changed')
    return opening,original,event,response


def _file(path,expected_sha=None,*,maximum=None):
    from .identity_bootstrap import _hash
    path=Path(path)
    digest=_hash(path)
    if expected_sha is not None and digest!=expected_sha:raise ValueError('qualified client artifact changed')
    if maximum is not None and path.stat().st_size>maximum:raise ValueError('client source exceeds byte bound')
    return digest



def _json_file(path,expected_sha=None,*,maximum):
    digest=_file(path,expected_sha,maximum=maximum);raw=Path(path).read_bytes()
    if len(raw)>maximum or hashlib.sha256(raw).hexdigest()!=digest:
        raise ValueError('client source changed while reading')
    return decode_object(raw.decode()),digest


def _client_inputs(config,original,manifest_path,manifest_sha,previous_driver_config_path,proof_command):
    if not isinstance(manifest_sha,str) or re.fullmatch('[0-9a-f]{64}',manifest_sha) is None:
        raise ValueError('exact independent client build manifest hash required')
    manifest,_=_json_file(manifest_path,manifest_sha,maximum=2*1024*1024)
    if (manifest.get('feature')!='direct-per-key' or manifest.get('runtime_profile')!='direct_per_key'
            or manifest.get('SDK')!=config.expected_sdk_commit or manifest.get('GIT_HASH')!=manifest.get('SDK')
            or not isinstance(manifest.get('SDK'),str) or re.fullmatch('[0-9a-f]{40}',manifest['SDK']) is None
            or not isinstance(manifest.get('common'),str) or re.fullmatch('[0-9a-f]{40}',manifest['common']) is None
            or not isinstance(manifest.get('tree'),str) or re.fullmatch('[0-9a-f]{40}',manifest['tree']) is None
            or not isinstance(manifest.get('SDK_tree'),str) or re.fullmatch('[0-9a-f]{40}',manifest['SDK_tree']) is None
            or len(config.driver_command)!=1 or len(proof_command)!=4
            or proof_command[3]!=config.expected_server_pubkey
            or config.architecture_profile!='direct_per_key' or config.network!='signet'):
        raise ValueError('actual qualified C client build/context required')
    artifacts=manifest.get('artifacts',{})
    driver=artifacts.get('bark-sim-driver',{});verifier=artifacts.get('vtxo-proof',{})
    for name,path,item in (('driver',config.driver_command[0],driver),('verifier',proof_command[0],verifier)):
        if (not isinstance(item.get('sha256'),str) or re.fullmatch('[0-9a-f]{64}',item['sha256']) is None
                or type(item.get('bytes')) is not int or item['bytes']<=0):
            raise ValueError('qualified '+name+' artifact missing')
        _file(path,item['sha256'])
        if Path(path).stat().st_size!=item['bytes']:raise ValueError('qualified artifact byte identity differs')
    old=original['declaration']
    if manifest['SDK']==old['pins']['sdk_commit']:
        raise ValueError('original SDK is not a new client qualification')
    previous,_=_json_file(previous_driver_config_path,old['driver_config_sha256'],maximum=65536)
    current_path=Path(os.environ.get('SIM_DRIVER_CONFIG',''))
    if not current_path.is_absolute():raise ValueError('actual private new driver configuration required')
    current,current_sha=_json_file(current_path,maximum=65536)
    if (current.get('architecture_profile')!='direct_per_key'
            or any(current.get(k)!=previous.get(k) for k in ('network','wallet_root','ark_endpoint'))
            or current.get('network')!='signet' or current.get('wallet_root')!=old['wallet_root']
            or str(config.wallet_root)!=old['wallet_root']):
        raise ValueError('client transition cannot redirect original root/network/Ark endpoint')
    wallet_config=current.get('wallet_config')
    if not isinstance(wallet_config,str) or not Path(wallet_config).is_absolute():
        raise ValueError('actual new wallet configuration required')
    wallet_sha=_file(wallet_config,maximum=65536)
    identity={'network':config.network,'genesis':config.expected_genesis,'container':config.expected_container,
              'image_digest':config.expected_image,'server_pubkey':config.expected_server_pubkey}
    for key in ('network','genesis','container','server_pubkey'):
        if identity[key]!=old['identity'][key]:raise ValueError('client transition changes original target identity')
    return {'sdk_commit':manifest['SDK'],'sdk_tree':manifest['SDK_tree'],'common_build_commit':manifest.get('common'),
        'client_manifest_sha256':manifest_sha,'driver_sha256':driver['sha256'],'verifier_sha256':verifier['sha256'],
        'driver_config_sha256':current_sha,'wallet_config_sha256':wallet_sha,'execution_identity':identity}


def _proof(store,reference,request,execution):
    if not isinstance(reference,dict) or set(reference)!={'partition','seq','hash'}:
        raise ValueError('original final-client proof trace required')
    integer(reference['seq'],'public proof trace sequence',1)
    paths=[p for p in partition_paths(store.trace.root) if p.name==reference['partition']]
    if len(paths)!=1:raise ValueError('original final-client trace unavailable')
    connection=readonly(paths[0])
    try:row=connection.execute('SELECT * FROM trace WHERE seq=?',(reference['seq'],)).fetchone()
    finally:connection.close()
    if (row is None or row['schema_version']!=SCHEMA_VERSION or row['hash']!=reference['hash']
            or record_hash(row)!=reference['hash'] or row['kind']!=TRACE_KIND
            or row['actor']!='actor-01' or row['action_id']!='c_create_01'
            or not isinstance(row['raw'],bytes) or not 0<len(row['raw'])<=2*1024*1024):
        raise ValueError('original final-client proof trace changed')
    payload=decode_object(row['payload'])
    if (payload.get('request')!=request or payload.get('sdk_commit')!=execution['sdk_commit']
            or payload.get('verifier_sha256')!=execution['verifier_sha256'] or payload.get('truncated') is True):
        raise ValueError('final-client proof invocation/source differs')
    proof=decode_object(row['raw'].decode())
    from .per_key import proof_matches,binding_matches
    if (proof.get('genesis')!=SIGNET_GENESIS or not proof_matches(proof,request)
            or not binding_matches(proof.get('binding',{}),request['binding'])):
        raise ValueError('final-client native signature/network proof refused')
    return proof


async def reverify_original_bindings(store,config,*,identifier,manifest_path,manifest_sha256,
        previous_driver_config_path,proof_command):
    """Execute all51 public proofs anew; no cached result or wallet operation.

    Native child calls have a180s combined monotonic allowance. Synchronous
    hashing/SQLite I/O is not claimed to be OS-interruptible by this component.
    Full client context remains blocked pending real stored-wallet/native-runtime
    qualification; this event expressly does not authorize the new SDK to open01.
    """
    from .c_cohort import _no_money,_quiescent,_verify_key_sources
    _quiescent(store);_no_money(store)
    if (not isinstance(identifier,str) or re.fullmatch('[a-zA-Z0-9_-]{1,100}',identifier) is None
            or getattr(store,'trace',None) is None):raise ValueError('owned traced qualification identity required')
    if store.db.execute('SELECT 1 FROM event WHERE kind=? AND json_extract(payload,\'$.id\')=?',(KIND,identifier)).fetchone():
        raise ValueError('retain completed qualification; never relabel/reuse its id')
    opening,original,native_event,response=_origin(store)
    from .identity_bootstrap import _sole_writer,_root
    _sole_writer(opening['wallet_root'])
    if _root(opening['wallet_root'])!=opening['wallet_root_identity']:raise ValueError('original wallet root changed')
    execution=_client_inputs(config,original,manifest_path,manifest_sha256,previous_driver_config_path,proof_command)
    from .per_key import initial_origins
    origins=initial_origins(response.get('data',{}))
    _verify_key_sources(store,'actor-01','c_create_01',response['data'],opening['pins'])
    first_row=_digest(dict(store.db.execute("SELECT * FROM action WHERE id='c_create_01'").fetchone()))
    proofs=[];started=time.monotonic()
    try:
        for request in origins:
            remaining=min(30,180-(time.monotonic()-started))
            if remaining<=0:raise ValueError('public signature revalidation native deadline exceeded')
            captured=[]
            def stdout(record):
                captured.append(store.trace_capture(TRACE_KIND,{
                    'request':request,'sdk_commit':execution['sdk_commit'],'verifier_sha256':execution['verifier_sha256'],
                    'truncated':record.get('truncated',False)},actor='actor-01',action_id='c_create_01',raw=record['raw']))
            result=await json_command(list(proof_command),request,timeout=remaining,on_stdout_raw=stdout)
            if len(captured)!=1:raise ValueError('complete original native stdout required')
            actual=_proof(store,captured[0],request,execution)
            if result!=actual:raise ValueError('decoded final-client proof differs from original stdout')
            proofs.append({'request_sha256':_digest(request),'proof_sha256':_digest(actual),'trace':captured[0]})
    except Exception as error:
        store.event('c_client_signature_qualification_held',{'id':identifier,'reason':type(error).__name__,
            'completed_public_keys':len(proofs),'scope':'public signature qualification only; no wallet/runtime/financial authority'})
        raise ValueError('new client public signature qualification incomplete; originals retained') from None
    _quiescent(store);_no_money(store)
    if _digest(dict(store.db.execute("SELECT * FROM action WHERE id='c_create_01'").fetchone()))!=first_row:
        raise ValueError('original create changed during independent signature qualification')
    if _client_inputs(config,original,manifest_path,manifest_sha256,previous_driver_config_path,proof_command)!=execution:
        raise ValueError('qualified client context changed during signature verification')
    value={'id':identifier,'origin_financial_pins':opening['pins'],'origin_native_sequence':native_event['sequence'],
        'origin_native_event_hash':native_event['hash'],'origin_native_response_sha256':_digest(response),
        'execution_client':execution,'proofs':proofs,'observed_at':time.time(),
        'wallet_load_qualified':False,'runtime_qualified':False,'financial_readiness':False,
        'scope':'actual new verifier signature/domain compatibility for original51 public bindings only; oldwallet load/serverruntime remain separate'}
    public_payload(value);store.event(KIND,value)
    return store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]


def verified_original_bindings(store,sequence):
    """Replay immutable final-verifier raw output, without changing owner rows."""
    event,value=_source_event(store,sequence)
    if event['kind']!=KIND:raise ValueError('original client signature component required')
    opening,original,native_event,response=_origin(store)
    if (value.get('origin_financial_pins')!=opening['pins']
            or value.get('origin_native_sequence')!=native_event['sequence']
            or value.get('origin_native_event_hash')!=native_event['hash']
            or value.get('origin_native_response_sha256')!=_digest(response)
            or value.get('wallet_load_qualified') is not False or value.get('runtime_qualified') is not False
            or value.get('financial_readiness') is not False):
        raise ValueError('origin versus execution qualification scope differs')
    from .per_key import initial_origins
    origins=initial_origins(response['data']);proofs=value.get('proofs')
    if not isinstance(proofs,list) or len(proofs)!=51:raise ValueError('all51 original final-verifier proofs required')
    store.trace.verify()
    references=set()
    for request,item in zip(origins,proofs):
        encoded=canonical(item.get('trace'))
        if encoded in references or item.get('request_sha256')!=_digest(request):
            raise ValueError('missing/reused/wrong original key proof')
        references.add(encoded)
        if _digest(_proof(store,item['trace'],request,value['execution_client']))!=item.get('proof_sha256'):
            raise ValueError('original final-verifier output changed')
    return value
