"""Root-admitted zero-server-assets private fee diagnostic, never activation.

Runs only in a fresh private diagnostic Store. Existing campaign state, wallet,
native budget and services are never opened or changed. Actual archive/transport
facts are independently hash-admitted root artifacts, not producer assertions.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import subprocess
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parent.parent
JOIN_SHA='41ce415ba8ff0a76cdca3a0b5222a01d5bdff9132fe5d979a6ffbba3c4834540'
CORE_CLI=Path('/opt/track-c/core-31.0/bin/bitcoin-cli')
NONMONETARY=frozenset({'links','records','journal_links','journal_records','lightning_nodes'})


def digest(raw):return hashlib.sha256(raw).hexdigest()
def strict(raw):
    def pairs(rows):
        out={}
        for key,value in rows:
            if key in out:raise ValueError('duplicate diagnostic source field')
            out[key]=value
        return out
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError('nonfinite diagnostic source')))


def private_file(item,*,maximum=2*1024*1024,owner=None,private=True):
    if not isinstance(item,dict)or set(item)!={'path','sha256'}or re.fullmatch('[0-9a-f]{64}',item['sha256'])is None:raise ValueError('independently admitted private original required')
    p=Path(item['path'])
    if not p.is_absolute()or any(v.is_symlink()for v in[p,*p.parents]):raise ValueError('absolute nonsymlink private original required')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as f:
        a=os.fstat(f.fileno());raw=f.read(maximum+1);b=os.fstat(f.fileno())
    key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    if(not stat.S_ISREG(a.st_mode)or a.st_uid!=(os.getuid()if owner is None else owner)or a.st_nlink!=1
            or(private and stat.S_IMODE(a.st_mode)!=0o600)or(not private and a.st_mode&0o022)or len(raw)>maximum or key(a)!=key(b)
            or digest(raw)!=item['sha256']):raise ValueError('private source hash/identity/permission differs')
    return raw


def validate_terminal(terminal,observation,binding,archive,*,archive_bytes,expected_binding_sha256):
    """Field names are the explicit root fixed-capture receipt ABI, not tar data."""
    import uuid
    fields={'schema_version','kind','nonce','observation_id','started_utc','ended_utc','argv','executed_worker_sha256','source_binding_sha256','returncode','timed_out','reaped','stdout_bytes','stdout_sha256','archive_path','receiver_exit'}
    if(set(terminal)!=fields or type(terminal.get('schema_version'))is not int or terminal.get('schema_version')!=1 or terminal.get('kind')!='c-native-fee-diagnostic-transport'
            or terminal.get('nonce')!=str(uuid.UUID(observation['id']))or terminal.get('observation_id')!=observation['id']
            or type(terminal.get('returncode'))is not int or terminal['returncode']!=0
            or terminal.get('timed_out')is not False or terminal.get('reaped')is not True
            or type(terminal.get('receiver_exit'))is not int or terminal['receiver_exit']!=0
            or type(terminal.get('stdout_bytes'))is not int or terminal.get('stdout_bytes')!=archive_bytes or terminal.get('stdout_sha256')!=archive['sha256']
            or terminal.get('archive_path')!=archive['path']or terminal.get('source_binding_sha256')!=expected_binding_sha256
            or terminal.get('executed_worker_sha256')!=binding['source_files']['c-private-fee-worker.py']
            or not isinstance(terminal.get('argv'),list)or not terminal['argv']
            or any(not isinstance(v,str)or '\0'in v for v in terminal['argv'])):
        raise ValueError('actual admitted fixed worker/nonce/exit/reap/archive context differs')
    from datetime import datetime
    start=datetime.fromisoformat(terminal['started_utc'].replace('Z','+00:00'));end=datetime.fromisoformat(terminal['ended_utc'].replace('Z','+00:00'))
    if start.tzinfo is None or end.tzinfo is None or not 0<=(end-start).total_seconds()<=45:raise ValueError('actual transport timestamps differ')


class DiagnosticCore:
    """Only identity methods; this zero-history scope cannot query/pay a wallet."""
    def call(self,method,*args):
        if(method,args)not in {('getblockchaininfo',()),('getblockhash',(0,))}:
            raise ValueError('zero-source diagnostic permits only independent chain identity')
        argv=[str(CORE_CLI),'-datadir=/srv/track-c/bitcoin','-signet',method,*map(str,args)]
        p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=4,check=True)
        if len(p.stdout)>65536:raise ValueError('Core identity reply exceeds bound')
        if method=='getblockhash':
            value=p.stdout.decode('ascii').strip()
            if re.fullmatch('[0-9a-f]{64}',value)is None:raise ValueError('invalid actual Core genesis reply')
            return value
        return strict(p.stdout)
    def identity(self):
        from .model import SIGNET_GENESIS
        if self.call('getblockhash',0)!=SIGNET_GENESIS:raise ValueError('independent ownCore genesis differs')
        info=self.call('getblockchaininfo')
        if info.get('chain')!='signet' or info.get('initialblockdownload')is not False:raise ValueError('independent ownCore not synchronizedSignet')
        return info
    def tx(self,txid):raise ValueError('unexpected carrier exceeds zero-history diagnostic scope')


def reduce_in_diagnostic_store(store,loaded,*,controller,expected,config,chain,observation,target_binding,actual_exit):
    """All originals use existing protected contract, actual TraceStore and reducer.

    This is never called with the real campaign Store. No readiness is emitted.
    Caller supplied controller is the actual preauthenticated installed controller.
    """
    from .model import canonical,public_payload
    from . import c_native_fee_sources as fees
    adapter=controller.adapter();contract=adapter.contract();limits=expected['resource_declaration']
    def capture_line(metadata,raw):return store.trace.capture('frontier_v2.original_line',metadata,raw=raw)
    def load_line(ref):return adapter._load(store.trace,ref,limits)
    frame=contract.consume_original(iter(loaded['public_lines']),actual_exit,expected,public_payload,capture_line,load_line)
    # Repeat from actual stored originals; never substitute the inline frame.
    if contract.verify_snapshot(frame,expected,load_line)!=frame:raise ValueError('TraceStore original replay differs')
    counts={name:len(rows)for name,rows in frame['rows'].items()}
    monetary={name:count for name,count in counts.items()if name not in NONMONETARY and count}
    if monetary:raise ValueError('zero-server-monetary diagnostic scope exceeded')
    store.event('closed_cohort_original_source',{'source_kind':'closed_frontier','financial_pins':expected['financial_pins'],
        'response':frame,'response_sha256':digest(canonical(frame).encode()),'diagnostic_only':True})
    database_sequence=store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
    source={'financial_pins':expected['financial_pins'],'source_observation':observation,'database':frame,
            'database_source_sequence':database_sequence,'private_native_fee_sha256':digest(loaded['private_cut']),
            'native_history_root_identity':target_binding['history_identity'],
            'native_fee_policy_sha256':target_binding['policy_sha256'],'direct_carrier_max_miner_fee_sat':20000,
            'members':[],'original_private_source_references':loaded['original_private_source_references'],
            'scope':'ISOLATED_DIAGNOSTIC_ONLY_NOT_NORMAL_ACTIVATION_OR_READINESS'}
    store.event('normal_financial_source',source)
    sequence=store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
    from .final_campaign import _source_event
    event,_=_source_event(store,sequence)
    result=fees.collect_cost_records(store,chain,config=config,private_cut=loaded['private_cut'],source_event=event,source=source,
         expected_history_identity=target_binding['history_identity'],expected_policy_sha256=target_binding['policy_sha256'],
         expected_server_pubkey=expected['source_binding']['server_pubkey'])
    if(result['cost_records']or result['flow_records']or result['pending_carriers']or result['native_fee']['history_txids']
            or result['native_fee']['ordinary_booked_sat']!=0):raise ValueError('zero-history diagnostic has retained cost/reservation exposure')
    joined,_=fees.journal_cost_records(store,result,event,source)
    if(store.db.execute('SELECT count(*)FROM action').fetchone()[0]
            or store.db.execute("SELECT count(*)FROM event WHERE kind IN ('financial_cost_verified','treasury_flow_verified','financial_readiness_verified','c_execution_context_activated')").fetchone()[0]):raise ValueError('diagnostic mutated financial readiness/history')
    store.verify_event_chain()
    return {'status':'PRIVATE_FEE_ZERO_SERVER_SOURCE_DIAGNOSTIC_ONLY','financial_pins':expected['financial_pins'],
            'source_observation_id':observation['id'],'height':observation['height'],'tip_hash':observation['tip_hash'],
            'public_table_counts':counts,'original_private_source_references':loaded['original_private_source_references'],
            'native_fee':result['native_fee'],'trace_original_lines':len(loaded['public_lines']),
            'source_event_sequence':sequence,'diagnostic_join_sequence':joined['sequence'],
            'cost_records':0,'flow_records':0,'actual_operator_fee_liquidity_sat':None,'urgent_liquidity_deficit_sat':None,
            'pool_router_urgent_cost_coverage':None,'normal_activation':False,'financial_readiness':False,'complete':False,'qualified':False}


def run(admission):
    fields={'schema_version','kind','source_files','archive','transport','observation','target_binding',
            'controller_binding_sha256','shared_join','core_cli_sha256','output_root'}
    if(set(admission)!=fields or type(admission['schema_version'])is not int or admission['schema_version']!=1
            or admission['kind']!='c-native-fee-zero-diagnostic'):raise ValueError('exact root diagnostic admission required')
    # Whole common runtime source is independently admitted BEFORE local imports.
    actual={str(p.relative_to(ROOT))for p in(ROOT/'simulator').rglob('*.py')}|{'simulator/bip39-english.txt'}
    if not isinstance(admission['source_files'],dict)or set(admission['source_files'])!=actual:raise ValueError('whole runtime source map required')
    for name,sha in admission['source_files'].items():
        path=ROOT/name
        info=path.lstat()
        if(path.is_symlink()or not stat.S_ISREG(info.st_mode)or info.st_uid!=os.getuid()or info.st_mode&0o022
                or digest(path.read_bytes())!=sha):raise ValueError('actual diagnostic runtime source differs')
    if not __package__:
        # Explicit -I file entry: add ONLY the hash-verified frozen source root.
        globals()['__package__']='simulator';sys.path.insert(0,str(ROOT))
    from . import frontier_source as frontier
    from . import c_private_fee_cut as capture
    from . import c_private_fee_package as package
    from .model import SIGNET_GENESIS,public_payload
    from .store import Store
    controller,binding,binding_sha=frontier._bootstrap()
    if binding_sha!=admission['controller_binding_sha256']:raise ValueError('independently admitted real controller binding differs')
    expected=frontier._context(controller,binding,None,binding['expected_contract']['financial_pins'])
    target=strict(private_file(admission['target_binding'],maximum=65536));observation=strict(private_file(admission['observation'],maximum=65536))
    terminal=strict(private_file(admission['transport'],maximum=65536))
    if(target['financial_pins']!=expected['financial_pins']or target['source_files']['c_private_fee_cut.py']!=digest(Path(capture.__file__).read_bytes())):raise ValueError('target execution/source pins differ from admitted real controller')
    # Streamed tar is not read wholesale by this helper; loader enforces48MiB.
    archive=Path(admission['archive']['path']);archive_bytes=archive.stat().st_size
    validate_terminal(terminal,observation,target,admission['archive'],archive_bytes=archive_bytes,expected_binding_sha256=admission['target_binding']['sha256'])
    config=SimpleNamespace(closed_frontier_schema=2,architecture_profile='direct_per_key',trace_enabled=True,
        network='signet',expected_genesis=SIGNET_GENESIS,expected_server_pubkey=expected['source_binding']['server_pubkey'])
    loaded=package.load_target_tar(archive,expected_package_sha256=admission['archive']['sha256'],
        expected_source_sha256=target['source_files']['c_private_fee_cut.py'],expected_financial_pins=expected['financial_pins'],
        expected_observation=observation,expected_history_identity=target['history_identity'],expected_policy_sha256=target['policy_sha256'],
        expected_server_pubkey=config.expected_server_pubkey,adapter=controller.adapter().contract().adapter(),
        limits=expected['resource_declaration'],binding=expected['source_binding'],producer_exit=lambda:terminal['returncode'])
    join_raw=private_file(admission['shared_join'],maximum=65536,private=False)
    if digest(join_raw)!=JOIN_SHA:raise ValueError('corrected shared importer actual source differs')
    # Existing41ce source, never a copied/fake join. Root hash admission owns path.
    spec=importlib.util.spec_from_file_location('simulator.normal_money_join',admission['shared_join']['path'])
    join=importlib.util.module_from_spec(spec);exec(compile(join_raw,admission['shared_join']['path'],'exec'),join.__dict__);sys.modules['simulator.normal_money_join']=join
    if frontier.checked_file(CORE_CLI,maximum=16*1024*1024)[1]!=admission['core_cli_sha256']:raise ValueError('actual ownCore CLI source differs')
    output=Path(admission['output_root'])
    if not output.is_absolute()or output.exists()or any(p.is_symlink()for p in output.parents):raise ValueError('fresh isolated private diagnostic output only')
    if output.parent.stat().st_uid!=os.getuid()or output.parent.stat().st_mode&0o077:raise ValueError('owned0700 diagnostic parent required')
    output.mkdir(mode=0o700)
    store=Store(output/'state','c-private-fee-readonly-diagnostic',architecture_profile='direct_per_key');store.attach_trace()
    try:
        chain=DiagnosticCore()
        result=reduce_in_diagnostic_store(store,loaded,controller=controller,expected=expected,config=config,chain=chain,
                    observation=observation,target_binding=target,actual_exit=lambda:terminal['returncode'])
        # Recheck ownCore/controller admission after the complete use.
        if frontier.checked_file(CORE_CLI,maximum=16*1024*1024)[1]!=admission['core_cli_sha256']:raise ValueError('actual ownCore CLI changed')
        if frontier.checked_file(frontier.BINDING,maximum=65536)[1]!=binding_sha:raise ValueError('real controller binding changed')
        public_payload(result)
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        fd=os.open(output/'SAFE-RESULT.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
        return result
    finally:store.close()


def main():
    if(len(sys.argv)!=3 or re.fullmatch('[0-9a-f]{64}',sys.argv[2])is None):raise ValueError('root admission path and independent SHA required')
    raw=private_file({'path':sys.argv[1],'sha256':sys.argv[2]},maximum=256*1024)
    result=run(strict(raw));print(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False))

if __name__=='__main__':
    try:main()
    except Exception:
        print('{"status":"HOLD","error_code":"PRIVATE_SOURCE_DIAGNOSTIC_UNAVAILABLE","financial_readiness":false}',file=sys.stderr);sys.exit(1)
