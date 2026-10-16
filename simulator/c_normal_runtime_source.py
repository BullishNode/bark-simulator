"""Fresh C runtime source in the existing normal observation, without recursion.

Reuse the installed inventory command's literal financial_readiness request and
existing systemd startup verifier. No Engine.observe, SDK open, new startup base,
service operation, financial admission or response-selected source authority.
"""
import copy
import datetime
import hashlib
import os
import re
from pathlib import Path
import stat
import time
import uuid

from .c_normal_source import _context
from . import c_runtime, c_runtime_profile
from .final_campaign import _source_event
from .model import SIGNET_GENESIS,canonical,public_payload
from .normal_source_deadline import check as deadline_check,timeout as source_timeout
from .process import json_command,public_command_capture,decode_object
from .runtime_startup import verify_owned_startup_sources
from .two_step_normal import module_hash

KIND='c_normal_runtime_source_collected'
RAW_KIND='c_normal_runtime.original'
FIELDS={'command','command_files','startup_path','startup_sha256','expected_path',
    'expected_sha256','schema_artifact_path','source_dir'}


def digest(raw):return hashlib.sha256(raw).hexdigest()


def _path(value):
    path=Path(value)
    if(not isinstance(value,str)or not path.is_absolute()or str(path)!=value
            or path!=Path(os.path.abspath(path))or any(p.is_symlink()for p in [path,*path.parents])):
        raise ValueError('fixed unaliased absolute C runtime source path required')
    return path


def _public_file(path,expected,maximum):
    path=_path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb')as source:
        before=os.fstat(source.fileno())
        if(not stat.S_ISREG(before.st_mode)or before.st_uid not in {0,os.getuid()}
                or before.st_nlink!=1 or before.st_mode&0o022 or not 0<before.st_size<=maximum):
            raise ValueError('bounded protected C runtime component required')
        raw=source.read(maximum+1);after=os.fstat(source.fileno())
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid)
    if identity(before)!=identity(after)or len(raw)!=before.st_size or digest(raw)!=expected:
        raise ValueError('actual C runtime source component changed')
    deadline_check();return raw


def replay_original(store,reference,observation):
    """Re-read the immutable actual child stdout; do not trust saved summaries."""
    from .trace import partition_paths,readonly,record_hash,SCHEMA_VERSION
    if not isinstance(reference,dict)or set(reference)!={'partition','seq','hash'}:
        raise ValueError('original C runtime trace reference required')
    paths=[p for p in partition_paths(store.trace.root)if p.name==reference['partition']]
    if len(paths)!=1:raise ValueError('original C runtime trace partition missing')
    db=readonly(paths[0])
    try:
        size=db.execute('SELECT length(raw)FROM trace WHERE seq=?',(reference['seq'],)).fetchone()
        if size is None or type(size[0])is not int or not 0<size[0]<=2*1024*1024:
            raise ValueError('bounded original C runtime stdout missing')
        row=db.execute('SELECT * FROM trace WHERE seq=?',(reference['seq'],)).fetchone()
    finally:db.close()
    expected={'request':{'kind':'financial_readiness'},'source_observation':observation,
        'exit_code':0,'truncated':False,'bytes':len(row['raw'])}
    if(row['schema_version']!=SCHEMA_VERSION or row['kind']!=RAW_KIND or row['hash']!=reference['hash']
            or record_hash(row)!=reference['hash']or decode_object(row['payload'])!=expected):
        raise ValueError('original C runtime trace scope/hash differs')
    return decode_object(row['raw'].decode()),row['raw']


class RuntimeSource:
    """Fixed admitted constructor data only; no observer-selected reader/plugin."""
    def __init__(self,configuration,qualification_sequence):
        if(not isinstance(configuration,dict)or set(configuration)!=FIELDS
                or not isinstance(configuration['command'],list)or not 1<=len(configuration['command'])<=40
                or any(not isinstance(s,str)or not s or '\0'in s for s in configuration['command'])
                or not isinstance(configuration['command_files'],dict)or not 1<=len(configuration['command_files'])<=16
                or configuration['command'][0] not in configuration['command_files']
                or type(qualification_sequence)is not int or qualification_sequence<1):
            raise ValueError('exact fixed C runtime producer configuration required')
        public_payload(configuration)
        for value in [*configuration['command_files'],*[configuration[n]for n in ('startup_path','expected_path','schema_artifact_path','source_dir')]]:_path(value)
        for sha in [*configuration['command_files'].values(),configuration['startup_sha256'],configuration['expected_sha256']]:
            if not isinstance(sha,str)or re.fullmatch('[0-9a-f]{64}',sha)is None:raise ValueError('exact C runtime source hash required')
        self.configuration=copy.deepcopy(configuration);self.qualification_sequence=qualification_sequence

    def requirement(self,pins):
        return {'architecture_profile':'direct_per_key','financial_pins':pins,'configuration':copy.deepcopy(self.configuration),
            'component_sha256':{'producer':digest(Path(__file__).read_bytes()),
                'startup_verifier':module_hash(verify_owned_startup_sources),
                'c_verifier':module_hash(c_runtime.verify),
                'operating_policy':module_hash(c_runtime_profile.verify_loaded),
                'process':module_hash(json_command)}}

    def admission(self,store,config,observation):
        cfg=self.configuration;event,value=_source_event(store,self.qualification_sequence)
        if(event['kind']!='c_normal_runtime_source_qualified'or value!=self.requirement(observation['financial_pins'])
                or list(config.inventory_command)!=cfg['command']or config.expected_sdk_commit!=observation['financial_pins']['sdk_commit']):
            raise ValueError('actual fixed C runtime producer qualification/configuration missing')
        for path,sha in cfg['command_files'].items():_public_file(path,sha,32*1024*1024)
        startup=_public_file(cfg['startup_path'],cfg['startup_sha256'],2*1024*1024)
        expected=decode_object(_public_file(cfg['expected_path'],cfg['expected_sha256'],65536).decode())
        _public_file(cfg['schema_artifact_path'],observation['financial_pins']['schema_sha256'],16*1024*1024)
        if(expected.get('architecture_profile')!='direct_per_key'or expected.get('product_commit')!=observation['financial_pins']['product_commit']
                or expected.get('schema_sha256')!=observation['financial_pins']['schema_sha256']):
            raise ValueError('actual C runtime expectations differ from execution pins')
        directory=_path(cfg['source_dir']);info=directory.stat()
        if(not stat.S_ISDIR(info.st_mode)or info.st_uid!=os.getuid()or stat.S_IMODE(info.st_mode)!=0o700
                or directory==config.wallet_root or config.wallet_root in directory.parents):
            raise ValueError('private C runtime evidence must be outside wallet roots')
        # The original startup capture is independently fixed. A normal read may
        # NEVER initialize it from its own current response.
        return expected,startup

    async def collect(self,store,config,chain,observation):
        _context(store,observation);deadline_check()
        if getattr(store,'trace',None)is None:raise ValueError('original C runtime trace required')
        if store.db.execute("SELECT 1 FROM event WHERE kind=? AND json_extract(payload,'$.source_observation.id')=?",(KIND,observation['id'])).fetchone():
            raise ValueError('runtime source observation already collected; never relabel/retry')
        original=canonical(observation);admitted=canonical(self.requirement(observation['financial_pins']))
        expected,_=self.admission(store,config,observation)
        def identity():
            current=chain.identity()
            if(chain.call('getblockhash',0)!=SIGNET_GENESIS or current.get('chain')!='signet'or current.get('initialblockdownload')is not False
                    or(current.get('blocks'),current.get('bestblockhash'))!=(observation['height'],observation['tip_hash'])):
                raise ValueError('actual independent runtime source chain changed')
        identity();request={'kind':'financial_readiness'};captured=[]
        hooks=public_command_capture(store,'c_normal.runtime',request)
        def stdout(record):
            if(not isinstance(record.get('raw'),bytes)or record.get('truncated')is not False
                    or type(record.get('exit_code'))is not int or record['exit_code']!=0
                    or type(record.get('bytes'))is not int or record['bytes']!=len(record['raw'])or not 0<len(record['raw'])<=2*1024*1024):
                raise ValueError('actual complete successful runtime stdout required')
            reference=store.trace_capture(RAW_KIND,{'request':request,'source_observation':observation,
                'exit_code':record['exit_code'],'truncated':False,'bytes':record['bytes']},raw=record['raw'])
            captured.append((record['raw'],reference))
        hooks['on_stdout_raw']=stdout
        began=time.time();frame=await json_command(list(config.inventory_command),request,
            timeout=source_timeout(30),**hooks);deadline_check()
        if(len(captured)!=1 or decode_object(captured[0][0].decode())!=frame
                or frame.get('kind')!='financial_readiness'or frame.get('network')!='signet'or frame.get('genesis')!=SIGNET_GENESIS
                or frame.get('runtime_transport')!='systemd'or frame.get('stable_tip')is not True
                or frame.get('initial_block_download')is not False
                or type(frame.get('observed_at'))not in(int,float)
                or not observation['started_at']<=began<=time.time()
                or not observation['started_at']<=frame['observed_at']<=time.time()
                or(frame.get('height'),frame.get('tip_hash'))!=(observation['height'],observation['tip_hash'])):
            raise ValueError('this invocation must produce original fresh aligned C runtime')
        replayed,original_raw=replay_original(store,captured[0][1],observation)
        if replayed!=frame or original_raw!=captured[0][0]:raise ValueError('original C runtime replay differs')
        daemons=frame.get('native_runtime',{});owners=frame.get('runtime_wallet_inventory',{}).get('frames',{})
        if(set(daemons)!={'captaind','watchmand'}or set(owners)!={'rounds','watchman'}
                or any(row.get('available')is not True or not isinstance(row.get('source'),dict)for row in owners.values())):
            raise ValueError('both actual native daemons and owning inventories required')
        source={'kind':'owned_native_startup_source','architecture_profile':'direct_per_key','runtime_transport':'systemd',
            'product_commit':observation['financial_pins']['product_commit'],'schema_sha256':observation['financial_pins']['schema_sha256'],
            'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'daemons':daemons,
            'rounds_inventory':owners['rounds']['source'],'watchman_inventory':owners['watchman']['source']}
        public_payload(source);cfg=self.configuration;directory=_path(cfg['source_dir'])
        current=directory/(observation['id']+'-'+uuid.uuid4().hex+'.json');raw=(canonical(source)+'\n').encode()
        fd=os.open(current,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.admission(store,config,observation);identity();deadline_check()
        if canonical(observation)!=original or canonical(self.requirement(observation['financial_pins']))!=admitted:
            raise ValueError('C runtime observation/constructor changed')
        # The existing verifier commits its own immutable source event. It may
        # remain truthful history even if a later chain check holds this normal
        # invocation; never wrap its Store.event in a nested SQLite transaction.
        receipt=verify_owned_startup_sources(store,cfg['startup_path'],str(current),expected=expected)
        sequence=store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        event,original_receipt=_source_event(store,sequence)
        if(event['kind']!='owned_runtime_configuration_verified'or original_receipt!=receipt
                or receipt.get('current_source_sha256')!=digest(raw)or receipt.get('startup_source_sha256')!=cfg['startup_sha256']
                or not observation['started_at']<=receipt.get('observed_at',-1)<=time.time()):
            raise ValueError('fresh original native verifier receipt missing')
        identity();deadline_check()
        with store.transaction():
            store.verify_event_chain()
            if _source_event(store,sequence)!=(event,original_receipt):raise ValueError('original C runtime source changed')
            result={'source_observation':copy.deepcopy(observation),'financial_pins':observation['financial_pins'],
                'runtime_source_sequence':sequence,'runtime_source_event_hash':event['hash'],
                'current_startup_path':str(current),'current_source_sha256':digest(raw),
                'qualification_sequence':self.qualification_sequence,'original_trace':captured[0][1],
                'original_response_sha256':digest(captured[0][0]),'complete':False,'qualified':False,'financial_readiness':False}
            public_payload(result);store._event(KIND,result)
            result['source_sequence']=store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
        return {'safe':result,'private_runtime_source':source,'private_owning_frames':owners}
