"""C pre-money client/runtime transition with immutable original provenance.

An activation is not financial readiness. Native results must come from the
independently admitted copy-only producer and actual target runtime verification.
No original wallet, action, declaration, budget or clock is rewritten.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time

from .model import canonical, public_payload, SIGNET_GENESIS
from .final_campaign import _pins, _source_event
from . import c_client_transition as signatures

NATIVE_KIND='c_original_stored_wallet_load_verified'
KIND='c_execution_context_activated'
KEY='c_execution_context'


def _sha(value):
    if not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}',value) is None:
        raise ValueError('exact independent source SHA256 required')
    return value


def _read_item(item,*,maximum=2*1024*1024):
    if not isinstance(item,dict) or set(item)!={'path','sha256'}:
        raise ValueError('independent source path and SHA256 required')
    _sha(item['sha256'])
    value,digest=signatures._json_file(item['path'],item['sha256'],maximum=maximum)
    raw=Path(item['path']).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('original source changed while reading')
    return value,digest,raw


def _trace(store,kind,raw,context):
    reference=store.trace_capture(kind,context,actor='actor-01',action_id='c_create_01',raw=raw)
    if not isinstance(reference,dict):raise ValueError('complete original trace capture required')
    return reference


def _replay(store,reference,kind):
    from .trace import partition_paths,readonly,record_hash,SCHEMA_VERSION
    if not isinstance(reference,dict) or set(reference)!={'partition','seq','hash'}:
        raise ValueError('original transition trace required')
    paths=[p for p in partition_paths(store.trace.root) if p.name==reference['partition']]
    if len(paths)!=1:raise ValueError('transition original trace unavailable')
    connection=readonly(paths[0])
    try:row=connection.execute('SELECT * FROM trace WHERE seq=?',(reference['seq'],)).fetchone()
    finally:connection.close()
    if (row is None or row['schema_version']!=SCHEMA_VERSION or row['hash']!=reference['hash']
            or record_hash(row)!=reference['hash'] or row['kind']!=kind
            or row['actor']!='actor-01' or row['action_id']!='c_create_01'
            or not isinstance(row['raw'],bytes)):
        raise ValueError('transition original trace changed')
    from .process import decode_object
    return decode_object(row['raw'].decode()),json.loads(row['payload']),row['raw']


def _public_identity(response):
    from .per_key import initial_origins
    data=response['data'];binding=data['binding'];origins=initial_origins(data)
    keys=[[index,origin['user_pubkey'],origin['key_link_attestation'],int(index==0)]
          for index,origin in enumerate(origins)]
    return {'mailbox_pk':binding['mailbox_pk'],
        'fallback_record_sha256':hashlib.sha256(bytes.fromhex(binding['fallback_record'])).hexdigest(),
        'payout_spk_hex':binding['spk'],'keys_sha256':hashlib.sha256(json.dumps(keys,separators=(',',':')).encode()).hexdigest()}


def record_stored_load_source(store,*,signature_sequence,admission_path,admission_sha256):
    """Import real independently frozen native runner artifacts, never flags.

    The admitted private launcher supplies the independent admission SHA. Paths
    cannot be selected by an observer, wallet action or payment body. INPUTS and
    original filenames stay private; only safe original RESULT/runner bytes and
    their checked public projections enter TraceStore.
    """
    from .c_cohort import _quiescent,_no_money
    _quiescent(store);_no_money(store)
    if store.db.execute("SELECT 1 FROM event WHERE kind=? AND json_extract(payload,'$.admission_sha256')=?",(NATIVE_KIND,admission_sha256)).fetchone():
        raise ValueError('retain original stored-load evidence; no receipt relabeling')
    signed=signatures.verified_original_bindings(store,signature_sequence)
    opening,original,native_event,response=signatures._origin(store)
    from .identity_bootstrap import _sole_writer
    _sole_writer(opening['wallet_root'])
    admission,_=signatures._json_file(admission_path,_sha(admission_sha256),maximum=65536)
    required={'schema_version','contract','build','binary','inputs','result','runner','original_manifest','original_database','projection'}
    if not isinstance(admission,dict) or set(admission)!=required or admission['schema_version']!=1:
        raise ValueError('exact independently admitted stored-load sources required')
    contract,contract_sha,_=_read_item(admission['contract'])
    build,build_sha,_=_read_item(admission['build'])
    inputs,inputs_sha,_=_read_item(admission['inputs'],maximum=65536)
    result,result_sha,result_raw=_read_item(admission['result'],maximum=65536)
    runner,runner_sha,runner_raw=_read_item(admission['runner'],maximum=65536)
    source_manifest,source_manifest_sha,_=_read_item(admission['original_manifest'],maximum=65536)
    projection,projection_sha,_=_read_item(admission['projection'],maximum=65536)
    expected=contract.get('INPUTS_exact_required_fields',{})
    fixed=contract.get('RESULT_fixed_values',{})
    component=contract.get('SDK_component');baseline=contract.get('SDK_baseline')
    if (contract.get('contract_revision')!=3 or signed['execution_client']['sdk_commit']!=baseline
            or build.get('actual_source')!=contract.get('frozen_source')
            or build.get('actual_tree')!=contract.get('tree')
            or build.get('source_archive_sha256')!=contract.get('source_archive_sha256')
            or build.get('SDK_component')!=component or build.get('SDK_baseline')!=baseline):
        raise ValueError('actual native source/component differs from independent contract')
    binary=build.get('artifacts',{}).get('per-key',{})
    if (admission['binary'].get('sha256')!=binary.get('sha256')
            or type(binary.get('bytes')) is not int or binary['bytes']<=0):
        raise ValueError('independently compiled native test ELF required')
    signatures._file(admission['binary']['path'],_sha(binary['sha256']))
    if Path(admission['binary']['path']).stat().st_size!=binary['bytes']:
        raise ValueError('actual native test ELF size differs')
    static=('schema_version','actor','old_sdk_source','new_sdk_source','new_sdk_baseline',
            'original_source_manifest_sha256','qualified_copy_seal_sha256','projection_contract_sha256','network')
    if (any(inputs.get(k)!=expected.get(k) for k in static)
            or any(inputs.get(k) is not True for k in ('copies_independently_verified','original_snapshots_unchanged','copy_is_not_original'))):
        raise ValueError('native INPUTS differ from frozen actor01 contract')
    if inputs.get('old_sdk_source')!=opening['pins']['sdk_commit'] or inputs.get('genesis')!=SIGNET_GENESIS:
        raise ValueError('native stored load changes original SDK/network lineage')
    if source_manifest_sha!=inputs.get('original_source_manifest_sha256'):
        raise ValueError('original sealed source manifest differs')
    files=source_manifest.get('source_files')
    if not isinstance(files,dict) or len(files)!=5:
        raise ValueError('complete original five-file provenance required')
    expected_files={hashlib.sha256(name.encode()).hexdigest():_sha(row['sha256']) for name,row in files.items()}
    if (runner.get('original_files_before')!=expected_files or runner.get('original_files_after')!=expected_files
            or runner.get('original_locks_held') is not True or runner.get('copy_lock_held') is not False):
        raise ValueError('actual independent original-file immutability and native lock cut required')
    db=admission['original_database'];signatures._file(db['path'],_sha(db['sha256']),maximum=32*1024*1024)
    if db['sha256']!=fixed.get('old_database_sha256') or files.get('db.sqlite',{}).get('sha256')!=db['sha256']:
        raise ValueError('original database copy differs')
    # Public property only, from the sealed OLD copy, not the new SDK result.
    connection=sqlite3.connect(Path(db['path']).as_uri()+'?mode=ro&immutable=1',uri=True,timeout=2)
    try:
        connection.execute('PRAGMA query_only=ON')
        properties=connection.execute('SELECT fingerprint FROM bark_properties WHERE id=1').fetchall()
    finally:connection.close()
    if len(properties)!=1 or not isinstance(properties[0][0],str) or re.fullmatch('[0-9a-f]{8}',properties[0][0]) is None:
        raise ValueError('old public fingerprint required')
    identity={'fingerprint':properties[0][0],**_public_identity(response)}
    if any(inputs.get(k)!=v for k,v in identity.items() if k!='keys_sha256') or result.get('identity')!=identity:
        raise ValueError('stored wallet identity differs from original native bytes/old public properties')
    if (any(result.get(k)!=v or type(result.get(k)) is not type(v) for k,v in fixed.items())
            or result.get('actor')!='c_create_01' or result.get('schema_version')!=1
            or result.get('old_sdk_source')!=opening['pins']['sdk_commit']
            or result.get('new_sdk_source')!=component or result.get('new_sdk_baseline')!=baseline
            or result.get('inputs_sha256')!=inputs_sha or result.get('genesis')!=SIGNET_GENESIS
            or result.get('original_source_manifest_sha256')!=source_manifest_sha
            or result.get('qualified_copy_seal_sha256')!=inputs.get('qualified_copy_seal_sha256')
            or result.get('all_tables_sha256')!=inputs.get('all_tables_sha256')
            or projection.get('all_tables_sha256')!=inputs.get('all_tables_sha256')
            or projection.get('original_DB_sha256')!=db['sha256'] or projection.get('schema_version')!=43
            or projection.get('table_count')!=33 or projection.get('retained_key_count')!=51
            or projection.get('key_indices')!=list(range(51)) or projection.get('issued_indices')!=[0]):
        raise ValueError('actual complete stored-load result/projection differs')
    selector=contract.get('selector',{}).get('name')
    if (runner.get('source_commit')!=contract['frozen_source'] or runner.get('source_tree')!=contract['tree']
            or runner.get('source_archive_sha256')!=contract['source_archive_sha256']
            or runner.get('binary_sha256')!=binary['sha256'] or runner.get('selector')!=selector
            or runner.get('inputs_sha256')!=inputs_sha or runner.get('result_sha256')!=result_sha
            or type(runner.get('exit_code')) is not int or runner['exit_code']!=0
            or type(runner.get('listed_tests')) is not int or runner['listed_tests']!=1
            or type(runner.get('passed_tests')) is not int or runner['passed_tests']!=1
            or not isinstance(runner.get('argv'),list) or not runner['argv']
            or runner['argv'][0]!=admission['binary']['path'] or runner['argv'].count(selector)!=1
            or '--exact' not in runner['argv']
            or runner.get('contract_sha256')!=contract_sha or runner.get('build_manifest_sha256')!=build_sha
            or runner.get('projection_sha256')!=projection_sha
            or runner.get('original_source_manifest_sha256')!=source_manifest_sha
            or runner.get('qualified_copy_seal_sha256')!=inputs['qualified_copy_seal_sha256']
            or runner.get('readonly_core_genesis')!=SIGNET_GENESIS):
        raise ValueError('actual exact native runner source/ELF/one-test PASS required')
    context={'admission_sha256':admission_sha256,'signature_sequence':signature_sequence,
        'origin_native_event_hash':native_event['hash'],'contract_sha256':contract_sha,'build_sha256':build_sha,
        'inputs_sha256':inputs_sha,'result_sha256':result_sha,'runner_sha256':runner_sha,'projection_sha256':projection_sha}
    result_ref=_trace(store,'c.stored_load.result',result_raw,context)
    runner_ref=_trace(store,'c.stored_load.runner',runner_raw,context)
    value={**context,'origin_financial_pins':opening['pins'],'execution_client':signed['execution_client'],
        'native_source':contract['frozen_source'],'native_tree':contract['tree'],
        'SDK_component':component,'SDK_baseline':baseline,'identity':identity,'result_trace':result_ref,'runner_trace':runner_ref,
        'wallet_load_qualified':True,'financial_readiness':False,'observed_at':time.time()}
    public_payload(value);store.event(NATIVE_KIND,value)
    return store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]


def verified_stored_load(store,sequence):
    event,value=_source_event(store,sequence)
    if event['kind']!=NATIVE_KIND or value.get('wallet_load_qualified') is not True or value.get('financial_readiness') is not False:
        raise ValueError('original qualified stored-load source required')
    signed=signatures.verified_original_bindings(store,value['signature_sequence'])
    opening,_,native_event,response=signatures._origin(store)
    if (value.get('origin_financial_pins')!=opening['pins'] or value.get('execution_client')!=signed['execution_client']
            or value.get('origin_native_event_hash')!=native_event['hash']):raise ValueError('stored-load lineage differs')
    store.trace.verify()
    context={k:value[k] for k in ('admission_sha256','signature_sequence','origin_native_event_hash','contract_sha256',
        'build_sha256','inputs_sha256','result_sha256','runner_sha256','projection_sha256')}
    for key,kind,sha in (('result_trace','c.stored_load.result','result_sha256'),('runner_trace','c.stored_load.runner','runner_sha256')):
        decoded,actual,raw=_replay(store,value[key],kind)
        if actual!=context or hashlib.sha256(raw).hexdigest()!=value[sha]:raise ValueError('stored-load raw evidence differs')
        if key=='result_trace' and decoded.get('identity')!=value.get('identity'):raise ValueError('stored identity differs')
    if any(value['identity'].get(k)!=v for k,v in _public_identity(response).items()):
        raise ValueError('stored-load original native key/payout identity differs')
    return value


def active(store):
    encoded=store.get_meta(KEY)
    rows=store.db.execute('SELECT sequence FROM event WHERE kind=?',(KIND,)).fetchall()
    if encoded is None:
        if rows:raise ValueError('C execution metadata missing over retained activation')
        return None
    if len(rows)!=1:raise ValueError('unique C execution activation required')
    event,value=_source_event(store,rows[0][0])
    if canonical(value)!=encoded:raise ValueError('C execution metadata differs from original activation')
    if store.db.execute("SELECT 1 FROM event WHERE kind='target_epoch_declared' LIMIT 1").fetchone():
        raise ValueError('C dedicated transition cannot share B target epochs')
    opening,original,_,_=signatures._origin(store)
    native=verified_stored_load(store,value['stored_load_sequence'])
    signed=signatures.verified_original_bindings(store,value['signature_sequence'])
    if (value['origin_financial_pins']!=opening['pins'] or native['signature_sequence']!=value['signature_sequence']
            or value['execution_client']!=signed['execution_client'] or value['previous_identity']!=original['declaration']['identity']
            or value['target_metadata_sha256']!=hashlib.sha256((store.get_meta('target_identity') or '').encode()).hexdigest()):
        raise ValueError('C activation original lineage changed')
    runtime_event,runtime=_source_event(store,value['runtime_source_sequence'])
    if (runtime_event['kind']!='owned_runtime_configuration_verified'
            or runtime.get('execution_release')!=value['execution_release']
            or runtime.get('current_source_sha256')!=value['activation_current_source_sha256']
            or runtime.get('startup_source_sha256')!=value['startup_source_sha256']):
        raise ValueError('C activation original runtime source changed')
    return {**value,'activation_sequence':event['sequence'],'deployment_epoch_id':value['id'],
            'context_kind':'c_pre_money_execution'}


def effective_pins(store,origin):
    """Current actual financial pins; original source pins stay unchanged."""
    value=active(store)
    if value is None:return origin
    if origin not in (value['origin_financial_pins'],value['financial_pins']):
        raise ValueError('C financial pins have no preserved transition lineage')
    return copy.deepcopy(value['financial_pins'])


def source_pins(store,sequence,origin):
    value=active(store)
    if value is None:return origin
    if origin not in (value['origin_financial_pins'],value['financial_pins']):
        raise ValueError('C source financial pins have no transition lineage')
    return value['origin_financial_pins'] if sequence<value['activation_sequence'] else value['financial_pins']


def verify_runtime_source(store,sequence,*,financial_pins,current_source_sha256):
    event,runtime=_source_event(store,sequence);value=active(store)
    if value is None:return None
    if (financial_pins!=value['financial_pins'] or event['kind']!='owned_runtime_configuration_verified'
            or runtime.get('loaded_configuration_identity_verified') is not True
            or runtime.get('execution_release')!=value['execution_release']
            or runtime.get('product_commit')!=value['execution_release']['product_commit']
            or runtime.get('schema_sha256')!=value['financial_pins']['schema_sha256']
            or runtime.get('current_source_sha256')!=current_source_sha256
            or runtime.get('startup_source_sha256')!=value['startup_source_sha256']
            or not 0<=time.time()-runtime.get('observed_at',-1)<=90):
        raise ValueError('actual fresh C runtime differs from activated release')
    return runtime


def verify_execution_snapshot(store,snapshot):
    value=active(store)
    if value is None:return None
    if (snapshot.get('financial_pins')!=value['financial_pins']
            or snapshot.get('origin_financial_pins')!=value['origin_financial_pins']
            or snapshot.get('financial_pins_scope')!='active_execution_with_preserved_origin'
            or snapshot.get('execution_release')!=value['execution_release']
            or snapshot.get('deployment_epoch_id')!=value['id']
            or snapshot.get('identity')!=value['execution_client']['execution_identity']
            or not 0<=time.time()-snapshot.get('observed_at',-1)<=90):
        raise ValueError('actual fresh C snapshot execution context required')
    _,runtime=_source_event(store,snapshot.get('runtime_source_sequence'))
    verify_runtime_source(store,snapshot['runtime_source_sequence'],financial_pins=value['financial_pins'],
        current_source_sha256=runtime.get('current_source_sha256'))
    return {'execution_release':value['execution_release'],'deployment_epoch_id':value['id'],
        'runtime_source_sequence':snapshot['runtime_source_sequence'],
        'financial_pins_scope':'active_execution_with_preserved_origin','origin_financial_pins':value['origin_financial_pins']}


def validate_driver_context(store,config,declaration):
    value=active(store)
    if value is None:return None
    expected=value['execution_client'];origin=value['origin_financial_pins']
    signatures._file(value['configuration_path'],value['financial_pins']['configuration_sha256'],maximum=1024*1024)
    from .config import Config
    if Config.load(Path(value['configuration_path']))!=config:
        raise ValueError('current actual configuration differs from activated file')
    if (declaration['pins'] not in (origin,value['financial_pins'])
            or declaration['identity']!=value['previous_identity']
            or declaration['wallet_root']!=str(config.wallet_root)
            or config.expected_sdk_commit!=value['financial_pins']['sdk_commit']
            or tuple(config.driver_command)!=(value['driver_path'],)):
        raise ValueError('C declaration does not belong to activated original/client lineage')
    identity={'network':config.network,'genesis':config.expected_genesis,'container':config.expected_container,
        'image_digest':config.expected_image,'server_pubkey':config.expected_server_pubkey}
    if identity!=expected['execution_identity']:raise ValueError('actual C target differs from activation')
    signatures._file(value['driver_path'],expected['driver_sha256'])
    path=Path(os.environ.get('SIM_DRIVER_CONFIG',''))
    if str(path)!=value['driver_config_path']:raise ValueError('actual C private driver path changed')
    cfg,_=signatures._json_file(path,expected['driver_config_sha256'],maximum=65536)
    signatures._file(cfg['wallet_config'],expected['wallet_config_sha256'],maximum=65536)
    from .identity_bootstrap import _root
    if _root(declaration['wallet_root'])!=value['wallet_root_identity']:raise ValueError('original C wallet root changed')
    return {k:expected[k] for k in ('driver_sha256','driver_config_sha256','wallet_config_sha256')}


def activate(store,config,chain,*,identifier,signature_sequence,stored_load_sequence,new_financial_pins,
             build_manifest_path,build_manifest_sha256,configuration_path,expected_runtime,
             startup_path,current_path):
    """One pre-money transition, after genuine components exist. No dispatch."""
    from .c_cohort import _no_money,_quiescent
    _quiescent(store);_no_money(store)
    if active(store) is not None:raise ValueError('C execution activation is immutable; never reset it')
    if (not isinstance(identifier,str) or re.fullmatch('[a-zA-Z0-9:_-]{1,100}',identifier) is None
            or [r[0] for r in store.db.execute('SELECT id FROM action ORDER BY id')]!=['c_create_01']):
        raise ValueError('pre-money original01 only; every existing wallet requires its own stored-load proof')
    signed=signatures.verified_original_bindings(store,signature_sequence)
    loaded=verified_stored_load(store,stored_load_sequence)
    opening,original,_,_=signatures._origin(store)
    if loaded['signature_sequence']!=signature_sequence:raise ValueError('exact signature/stored-load pair required')
    release,release_sha=signatures._json_file(build_manifest_path,_sha(build_manifest_sha256),maximum=65536)
    pins=_pins(new_financial_pins);client=signed['execution_client']
    config_sha=signatures._file(configuration_path,maximum=1024*1024)
    from .config import Config
    if Config.load(Path(configuration_path))!=config:
        raise ValueError('actual loaded financial configuration differs from pinned file')
    bins=release.get('bins',{})
    if (pins['product_commit']!=release.get('financial_product_component')
            or pins['sdk_commit']!=client['sdk_commit'] or pins['driver_sha256']!=client['driver_sha256']
            or pins['configuration_sha256']!=config_sha
            or loaded['SDK_component']!=release.get('SDK_component')
            or expected_runtime.get('product_commit')!=release.get('actual_GIT_HASH')
            or expected_runtime.get('schema_sha256')!=pins['schema_sha256']
            or config.expected_sdk_commit!=pins['sdk_commit']):
        raise ValueError('actual new financial/component/build/configuration pins differ')
    for name in ('captaind','watchmand'):
        if expected_runtime.get('services',{}).get(name,{}).get('executable_sha256')!=bins.get(name,{}).get('sha256'):
            raise ValueError('actual daemon build ELF differs from expected deployment')
    if (config.expected_image!='sha256:'+bins['captaind']['sha256']
            or client['execution_identity']!={'network':config.network,'genesis':config.expected_genesis,
                'container':config.expected_container,'image_digest':config.expected_image,'server_pubkey':config.expected_server_pubkey}):
        raise ValueError('actual new target identity differs from independent signature component')
    tip=chain.identity()
    if (chain.call('getblockhash',0)!=SIGNET_GENESIS or tip.get('chain')!='signet' or tip.get('initialblockdownload') is not False):
        raise ValueError('actual independent synchronized Signet transition required')
    execution={'product_commit':release['actual_GIT_HASH'],'financial_product_component':pins['product_commit'],
        'sdk_commit':pins['sdk_commit'],'SDK_component':loaded['SDK_component'],
        'schema_sha256':pins['schema_sha256'],'driver_sha256':pins['driver_sha256'],
        'configuration_sha256':pins['configuration_sha256']}
    from .c_runtime import verify
    runtime=verify(store,startup_path,current_path,expected=expected_runtime,execution_release=execution)
    runtime_sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    from .identity_bootstrap import _sole_writer
    _sole_writer(opening['wallet_root']);_quiescent(store);_no_money(store)
    value={'id':identifier,'origin_financial_pins':opening['pins'],'financial_pins':pins,
        'signature_sequence':signature_sequence,'stored_load_sequence':stored_load_sequence,
        'execution_client':client,'execution_release':execution,'previous_identity':original['declaration']['identity'],
        'driver_path':str(config.driver_command[0]),'driver_config_path':str(Path(os.environ['SIM_DRIVER_CONFIG'])),
        'configuration_path':str(configuration_path),
        'wallet_root_identity':opening['wallet_root_identity'],'expected':expected_runtime,
        'build_manifest_sha256':release_sha,'runtime_source_sequence':runtime_sequence,
        'startup_source_sha256':runtime['startup_source_sha256'],
        'activation_current_source_sha256':runtime['current_source_sha256'],
        'target_metadata_sha256':hashlib.sha256((store.get_meta('target_identity') or '').encode()).hexdigest(),
        'preserved_fee_budgets_sat':{'ordinary':60000,'urgent':40000},'financial_readiness':False,'observed_at':time.time()}
    public_payload(value)
    with store.transaction():
        _quiescent(store);_no_money(store)
        if store.get_meta(KEY) is not None:raise ValueError('C execution concurrent activation')
        store._event(KIND,value)
        store.db.execute('INSERT INTO meta VALUES(?,?)',(KEY,canonical(value)))
    return active(store)
