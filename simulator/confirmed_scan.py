"""Block-bound confirmed descriptor scans, never cached financial readiness.

Only original complete Core results may be reused. Every caller still owns its
fresh mempool/gettxout/wallet/database/runtime/fee and final-chain checks.
"""
import hashlib
import json
import re
from decimal import Decimal

from .final_campaign import _source_event, _pins
from .model import btc_to_sat, canonical, public_payload, SIGNET_GENESIS
from .trace import normalized, partition_paths, readonly, record_hash, public_raw, SCHEMA_VERSION

KEY='last_complete_confirmed_descriptor_scan'
KIND='confirmed_descriptor_scan_verified'


def _digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()


def _sha(value,length=64):
    if not isinstance(value,str) or re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is None:raise ValueError('exact confirmed scan identity hash required')
    return value


def _identity(store,config,chain,current,*,pins,boundary_id,members):
    from .identity_bootstrap import declaration,_context
    from . import target_epochs
    _pins(pins)
    bootstrap=declaration(store)
    if bootstrap is None:raise ValueError('original native identity required for confirmed scan')
    native=_context(config,bootstrap['declaration'],store=store)
    if native.get('driver_sha256')!=pins['driver_sha256'] or config.expected_sdk_commit!=pins['sdk_commit']:
        raise ValueError('actual scan SDK/driver identity differs')
    if chain.url!=config.proof_command[1] or chain.expected!=config.expected_genesis:raise ValueError('actual independent Core endpoint/genesis differs')
    release=_sha(current.get('product_commit'),40);daemons={}
    from .architecture import DIRECT_PER_KEY,profile
    per_key=profile(store)==DIRECT_PER_KEY
    if current.get('kind')!=('owned_native_startup_source' if per_key else 'owned_startup_source') or set(current.get('daemons',{}))!={'captaind','watchmand'}:
        raise ValueError('actual daemon identities required for confirmed scan')
    for service,row in sorted(current['daemons'].items()):
        if per_key:
            if (current.get('architecture_profile')!=DIRECT_PER_KEY or current.get('runtime_transport')!='systemd'
                    or release!=pins['product_commit'] or current.get('schema_sha256')!=pins['schema_sha256']
                    or row.get('running') is not True or type(row.get('pid')) is not int or row['pid']<=0
                    or row.get('process_exe_sha256')!=row.get('binary_sha256')
                    or service=='captaind' and (row.get('unit')!=config.expected_container
                        or 'sha256:'+str(row.get('process_exe_sha256'))!=config.expected_image)):
                raise ValueError('actual C native scan identity differs')
            _sha(row.get('binary_sha256'));_sha(row.get('config_sha256'))
            daemons[service]={key:row[key] for key in ('unit','boot_id','start_ticks','binary_sha256','config_sha256','pid','started_at')}
            continue
        if (row.get('image_sha256')!=config.expected_image or row.get('running') is not True
                or type(row.get('pid')) is not int or row['pid']<=0 or not isinstance(row.get('started_at'),str)
                or row.get('process_exe_sha256')!=row.get('binary_sha256')):raise ValueError('actual running scan image identity differs')
        _sha(row['image_sha256'].removeprefix('sha256:'));_sha(row.get('binary_sha256'));_sha(row.get('config_sha256'))
        daemons[service]={key:row[key] for key in ('container','image_sha256','binary_sha256','config_sha256','pid','started_at')}
    active=target_epochs.active_identity(store)
    if active is not None and active!={'network':config.network,'genesis':config.expected_genesis,
            'container':config.expected_container,'image_digest':config.expected_image,'server_pubkey':config.expected_server_pubkey}:
        raise ValueError('actual scan target identity differs from active registry')
    epochs=store.db.execute("SELECT sequence FROM event WHERE kind='target_epoch_declared' ORDER BY sequence DESC LIMIT 1").fetchone()
    epoch=None
    if epochs:
        event,value=_source_event(store,epochs[0]);epoch={'id':value['id'],'event_hash':event['hash']}
    manifest_reader=getattr(target_epochs,'active_runtime_manifest',None)
    if manifest_reader is not None:
        manifest=manifest_reader(store)
        if manifest is not None:
            if manifest['execution_release']['product_commit']!=release:raise ValueError('actual scan execution release differs')
            epoch={'id':manifest['deployment_epoch_id'],'execution_release':manifest['execution_release'],
                'registry':epoch}
    owners=[{key:member[key] for key in ('id','identity','kind','role','descriptors')} for member in members]
    context={'financial_pins':pins,'boundary_id':boundary_id,'owners':sorted(owners,key=lambda row:row['id']),
        'network':config.network,'genesis':config.expected_genesis,'core_endpoint':chain.url,
        'sdk_commit':config.expected_sdk_commit,'native':native,'wallet_root':str(config.wallet_root),
        'actual_product_commit':release,'daemons':daemons,'active_epoch':epoch}
    public_payload(context)
    return context


def _coverage(members,specs):
    owners={};coverage=[]
    if (not isinstance(members,list) or not 1<=len(members)<=16 or len({member['id'] for member in members})!=len(members)):raise ValueError('bounded confirmed scan owners required')
    for member in sorted(members,key=lambda row:row['id']):
        for index,descriptor in enumerate(member['descriptors']):
            interval=specs.get(descriptor)
            if (descriptor in owners or not isinstance(descriptor,str) or not 1<=len(descriptor)<=4096
                    or not isinstance(interval,list) or len(interval)!=2 or interval[0]!=0 or type(interval[0]) is not int
                    or type(interval[1]) is not int or not 19<=interval[1]<2000):raise ValueError('complete bounded descriptor coverage required')
            owners[descriptor]={'member_id':member['id'],'descriptor_index':index}
            coverage.append({'desc':descriptor,'range':list(interval)})
    if (not 1<=len(coverage)<=16 or sum(row['range'][1]+1 for row in coverage)>2000
            or set(specs)!=set(owners)):raise ValueError('confirmed descriptor/script bound or membership differs')
    return owners,coverage


def _tip(chain,tip):
    if chain.call('getblockhash',0)!=SIGNET_GENESIS:raise ValueError('confirmed scan genesis differs')
    actual=chain.call('getblockchaininfo')
    if (actual.get('chain')!='signet' or actual.get('initialblockdownload') is not False
            or (actual.get('blocks'),actual.get('bestblockhash'))!=tip):raise ValueError('confirmed scan actual chain tip differs')


def _result(result,tip,scripts):
    if (not isinstance(result,dict) or result.get('success') is not True
            or (result.get('height'),result.get('bestblock'))!=tip or not isinstance(result.get('unspents'),list)
            or len(result['unspents'])>2000):raise ValueError('complete bounded confirmed scan result required')
    points=set();total=0
    for coin in result['unspents']:
        point=coin['txid']+':'+str(coin['vout']);amount=btc_to_sat(coin['amount'])
        if (point in points or coin.get('scriptPubKey') not in scripts or type(coin['vout']) is not int
                or not 0<=coin['vout']<=0xffffffff or amount<=0):raise ValueError('confirmed scan has duplicate or unowned output')
        _sha(coin['txid']);points.add(point);total+=amount
    if total!=btc_to_sat(result['total_amount']):raise ValueError('complete confirmed scan total differs')


def _raw_trace(store,reference,coverage,result):
    if (not isinstance(reference,dict) or set(reference)!={'partition','seq','hash'}
            or type(reference['seq']) is not int or reference['seq']<1):raise ValueError('original confirmed scan RPC trace required')
    _sha(reference['hash'])
    matches=[path for path in partition_paths(store.trace.root) if path.name==reference['partition']]
    if len(matches)!=1:raise ValueError('original confirmed scan trace unavailable')
    conn=readonly(matches[0])
    try:
        conn.execute('BEGIN')
        sizes=conn.execute('SELECT length(raw),length(payload) FROM trace WHERE seq=?',(reference['seq'],)).fetchone()
        if sizes is None or sizes[0] is None or max(sizes)>16*1024*1024:raise ValueError('original confirmed scan raw trace unavailable or oversized')
        row=conn.execute('SELECT * FROM trace WHERE seq=?',(reference['seq'],)).fetchone()
    finally:conn.close()
    if (row is None or row['schema_version']!=SCHEMA_VERSION or row['hash']!=reference['hash']
            or record_hash(row)!=reference['hash'] or row['kind']!='chain.rpc' or row['raw'] is None
            or len(row['raw'])>16*1024*1024):raise ValueError('original confirmed scan trace changed or incomplete')
    payload=json.loads(row['payload']);raw=normalized(json.loads(row['raw'],parse_float=Decimal))
    if (payload.get('method')!='scantxoutset' or payload.get('params')!=['start',coverage]
            or payload.get('error') is not None or payload.get('result')!=result
            or raw.get('error') is not None or raw.get('result')!=result):raise ValueError('original confirmed scan raw response differs')
    public_raw(row['raw'])
    return hashlib.sha256(row['raw']).hexdigest(),row['utc']


def confirmed_scan(store,config,chain,current,*,pins,boundary_id,members,specs,tip):
    """Return fresh derived scripts and either a real or exact block-bound scan."""
    if (not isinstance(tip,tuple) or len(tip)!=2 or type(tip[0]) is not int or tip[0]<0):raise ValueError('exact confirmed scan tip required')
    _sha(tip[1])
    if config.network!='signet' or config.expected_genesis!=SIGNET_GENESIS or getattr(store,'trace',None) is None:
        raise ValueError('traced independent signet confirmed scan required')
    identity=_identity(store,config,chain,current,pins=pins,boundary_id=boundary_id,members=members)
    owners,required=_coverage(members,specs);coverage=required;cached=None;event=None
    encoded=store.get_meta(KEY)
    latest=store.db.execute('SELECT max(sequence) FROM event WHERE kind=?',(KIND,)).fetchone()[0]
    if encoded is None and latest is not None:raise ValueError('confirmed scan pointer missing from original history')
    if encoded is not None:
        try:sequence=int(encoded)
        except (ValueError,TypeError):raise ValueError('confirmed scan pointer changed') from None
        if sequence!=latest:raise ValueError('confirmed scan pointer differs from latest original receipt')
        event,cached=_source_event(store,sequence)
        if (event['kind']!=KIND or cached.get('complete') is not True or cached.get('identity_sha256')!=_digest(cached.get('identity'))
                or cached.get('result_sha256')!=_digest(cached.get('result'))):raise ValueError('confirmed scan original receipt changed or incomplete')
        original_tip=(cached['height'],cached['tip_hash']);_sha(original_tip[1])
        if type(original_tip[0]) is not int or original_tip[0]<0:raise ValueError('original confirmed scan height differs')
        original_rows=cached['result'].get('unspents')
        if not isinstance(original_rows,list):raise ValueError('incomplete original confirmed scan rows')
        _result(cached['result'],original_tip,{row['scriptPubKey']:True for row in original_rows})
        old_specs={row['desc']:row['range'] for row in cached['descriptor_ranges']}
        _,old_coverage=_coverage(cached['identity']['owners'],old_specs)
        if old_coverage!=cached['descriptor_ranges']:raise ValueError('confirmed scan retained coverage changed')
        raw_sha,original_at=_raw_trace(store,cached['raw_trace'],old_coverage,cached['result'])
        if raw_sha!=cached['raw_response_sha256'] or original_at!=cached['observed_at']:raise ValueError('original confirmed scan provenance differs')
        same_context=(cached['identity']==identity and (cached['height'],cached['tip_hash'])==tip)
        if same_context and all(old_specs[descriptor][1]>=interval[1] for descriptor,interval in specs.items()):
            coverage=old_coverage
        else:cached=None
    _tip(chain,tip);scripts={}
    for row in coverage:
        descriptor,interval=row['desc'],row['range'];info=chain.call('getdescriptorinfo',descriptor)
        if info.get('hasprivatekeys') is not False or info.get('descriptor')!=descriptor or info.get('isrange') is not True:
            raise ValueError('actual canonical public confirmed descriptor required')
        addresses=chain.call('deriveaddresses',descriptor,interval)
        if not isinstance(addresses,list) or len(addresses)!=interval[1]+1:raise ValueError('complete confirmed script derivation required')
        for index,address in enumerate(addresses):
            actual=chain.call('validateaddress',address);script=actual.get('scriptPubKey')
            if actual.get('isvalid') is not True or not isinstance(script,str) or script in scripts:raise ValueError('unique actual confirmed owning scripts required')
            scripts[script]={**owners[descriptor],'child_index':index}
    if cached is not None:
        result=cached['result'];_result(result,tip,scripts)
        raw_sha,original_at=_raw_trace(store,cached['raw_trace'],coverage,result)
        if raw_sha!=cached['raw_response_sha256'] or original_at!=cached['observed_at']:raise ValueError('original confirmed scan provenance differs')
    else:
        if chain.call('scantxoutset','status') is not None:raise ValueError('existing Core scan running; confirmed source held')
        result=normalized(chain.call('scantxoutset','start',coverage,timeout=120));_result(result,tip,scripts)
        reference=getattr(chain,'last_capture',None)
        raw_sha,original_at=_raw_trace(store,reference,coverage,result)
        _tip(chain,tip)
        receipt={'identity':identity,'identity_sha256':_digest(identity),'height':tip[0],'tip_hash':tip[1],
            'descriptor_ranges':coverage,'result':result,'result_sha256':_digest(result),'complete':True,
            'observed_at':original_at,'raw_trace':reference,'raw_response_sha256':raw_sha,
            'scope':'original complete confirmed Core descriptor projection only; no mempool, wallet, eligibility or financial readiness claim'}
        public_payload(receipt)
        with store.transaction():
            store._event(KIND,receipt);sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
            store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',(KEY,str(sequence)))
        event,cached_receipt=_source_event(store,sequence)
    _tip(chain,tip)
    original=cached if cached is not None else cached_receipt
    provenance={'reused':cached is not None,'original_scan_sequence':event['sequence'],'original_scan_event_hash':event['hash'],
        'original_scan_observed_at':original['observed_at'],'result_sha256':original['result_sha256'],
        'raw_trace':original['raw_trace'],'raw_response_sha256':original['raw_response_sha256'],
        'identity_sha256':original['identity_sha256'],'descriptor_ranges':coverage,
        'scope':'confirmed projection at the exact original block only; all dynamic source checks remain fresh'}
    return scripts,coverage,result,provenance
