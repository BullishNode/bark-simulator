"""Join the actual C runtime and existing owning-wallet original sources.

This is the next fixed C capture stage, not another collector or money kernel.
It invokes the existing owning source, replays its before/after bytes and binds
its independently scanned inventory to the same runtime and checked target cut.
No customer/CLN/pool/current-debt/joint-fee or normal readiness is invented.
"""
import copy
from dataclasses import dataclass
import time

from . import c_owning_wallet_source as owning
from . import c_normal_runtime_source as runtime_source
from .c_normal_source import _context
from .final_campaign import _source_event
from .model import canonical,public_payload
from .normal_source_deadline import check as deadline_check
from .ownership import EvidenceGap

KIND='c_normal_owning_source_joined'


@dataclass(frozen=True)
class OwningBinding:
    reader: owning.FixedOwningReader
    qualification_sequence: int

    def check(self):
        if(type(self.reader)is not owning.FixedOwningReader
                or set(self.reader.__dict__)!={'commands','ops_sha256'}
                or type(self.qualification_sequence)is not int or self.qualification_sequence<1):
            raise EvidenceGap('fixed C owning reader/source qualification required')
        return {'commands_sha256':self.reader.hashes(),'ops_sha256':self.reader.ops_sha256,
            'qualification_sequence':self.qualification_sequence}


def _original(store,sequence,kind,result,observation):
    if type(sequence)is not int or sequence<1:raise EvidenceGap('actual original C source sequence required')
    event,proof=_source_event(store,sequence)
    safe={k:v for k,v in result.items()if k!='source_sequence'}
    if(event['kind']!=kind or proof!=safe or proof.get('source_observation')!=observation
            or proof.get('financial_pins')!=observation['financial_pins']
            or proof.get('complete')is not False or proof.get('qualified')is not False or proof.get('financial_readiness')is not False):
        raise EvidenceGap('original same-invocation C component source differs')
    return event,proof


async def collect(store,config,chain,observation,*,boundary,checked,runtime,binding):
    """Fixed caller passes results just produced by checked target and runtime.

    Existing owning.collect owns actual fixed RPCs, original TraceStore replay,
    complete before/after wallet equality, independent descriptor+Core activity,
    source qualification, UTXO projection and native fee-eligible money checks.
    This join adds no flags or substitute source implementation.
    """
    _context(store,observation);deadline_check()
    if type(binding)is not OwningBinding:raise EvidenceGap('typed C owning source binding required')
    original_binding=canonical(binding.check());original_observation=canonical(observation)
    if(boundary['pins']!=observation['financial_pins']or boundary['id']!=observation['boundary_id']
            or checked.get('kind')!='c-checked-native-target-source'or checked.get('source_observation')!=observation
            or checked.get('loaded',{}).get('manifest',{}).get('financial_pins')!=observation['financial_pins']
            or checked['loaded']['manifest'].get('source_observation')!=observation):
        raise EvidenceGap('actual C target/runtime/member observation differs')
    safe=runtime.get('safe',{})
    runtime_event,_=_original(store,safe.get('source_sequence'),runtime_source.KIND,safe,observation)
    verified_event,verified=_source_event(store,safe.get('runtime_source_sequence'))
    if(verified_event['kind']!='owned_runtime_configuration_verified'
            or verified_event['hash']!=safe.get('runtime_source_event_hash')
            or not observation['started_at']<=verified.get('observed_at',-1)<=time.time()
            or verified.get('current_source_sha256')!=safe.get('current_source_sha256')
            or verified.get('product_commit')!=observation['financial_pins']['product_commit']
            or verified.get('schema_sha256')!=observation['financial_pins']['schema_sha256']):
        raise EvidenceGap('fresh original C same-process runtime source missing')
    raw=runtime_source._public_file(safe['current_startup_path'],safe['current_source_sha256'],2*1024*1024)
    source=runtime_source.decode_object(raw.decode())
    literal,original_raw=runtime_source.replay_original(store,safe['original_trace'],observation)
    owners=literal.get('runtime_wallet_inventory',{}).get('frames',{})
    if(source!=runtime.get('private_runtime_source')or owners!=runtime.get('private_owning_frames')
            or set(owners)!={'rounds','watchman'}or literal.get('native_runtime')!=source['daemons']
            or verified.get('daemons')!=source['daemons']
            or runtime_source.digest(original_raw)!=safe.get('original_response_sha256')
            or any(v.get('available')is not True or v.get('source')!=source[o+'_inventory']for o,v in owners.items())):
        raise EvidenceGap('actual runtime/owning originals differ from retained private file')
    first=store.db.execute('SELECT coalesce(max(sequence),0)FROM event').fetchone()[0]
    result=await owning.collect(store,config,chain,observation,boundary=boundary,reader=binding.reader,
        qualification_sequence=binding.qualification_sequence,
        runtime_source_sequence=safe['runtime_source_sequence'],current_startup_path=safe['current_startup_path'])
    event,component=_original(store,result.get('source_sequence'),owning.KIND,result,observation)
    if(event['sequence']<=first or component.get('runtime_source_sequence')!=safe['runtime_source_sequence']
            or component.get('qualification_sequence')!=binding.qualification_sequence
            or set(component.get('inventory_sequences',{}))!=set(owning.OWNERS)
            or set(component.get('inventory_source_sequences',{}))!=set(owning.OWNERS)):
        raise EvidenceGap('this invocation did not produce both actual C owning sources')
    for owner in owning.OWNERS:
        for phase in ('before','after'):
            frame,_=owning.replay_original(store,component['original_traces'][phase+':'+owner],
                owner=owner,phase=phase,observation=observation)
            if frame!=owners[owner]['source']:
                raise EvidenceGap('owning wallet changed between actual runtime and independent before/after scan')
    if(runtime_source._public_file(safe['current_startup_path'],safe['current_source_sha256'],2*1024*1024)!=raw
            or canonical(binding.check())!=original_binding or canonical(observation)!=original_observation):
        raise EvidenceGap('C runtime/owning constructor or original source changed')
    owning._tip(chain,observation);deadline_check()
    joined={'source_observation':copy.deepcopy(observation),'financial_pins':observation['financial_pins'],
        'boundary_id':boundary['id'],'height':observation['height'],'tip_hash':observation['tip_hash'],
        'observed_at':time.time(),'runtime_component_sequence':runtime_event['sequence'],
        'runtime_component_event_hash':runtime_event['hash'],'runtime_source_sequence':safe['runtime_source_sequence'],
        'owning_component_sequence':event['sequence'],'owning_component_event_hash':event['hash'],
        'inventory_sequences':component['inventory_sequences'],'inventory_source_sequences':component['inventory_source_sequences'],
        'target_original_private_source_references':checked['original_private_source_references'],
        'original_runtime_response_sha256':safe['original_response_sha256'],
        'original_owning_traces':component['original_traces'],
        'complete':False,'qualified':False,'financial_readiness':False,
        'scope':'runtime plus two independently scanned owning members only; full cohort/CLN/current liabilities/joint fees remain separate'}
    public_payload(joined);store.event(KIND,joined)
    joined['source_sequence']=store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
    return {'safe':joined,'private_owning_component':result,'private_owning_frames':owners}
