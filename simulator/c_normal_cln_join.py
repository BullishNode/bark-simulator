"""Join C's actual two-host CLN sources with the same runtime/owning cut.

The existing CLN reader and treasury reducer own RPC validation and physical
asset accounting. This fixed composition adds original-source binding only;
it does not resolve conditional rights, router policy or normal readiness.
"""
import copy
from dataclasses import dataclass
import time

from . import c_cln_normal_source as cln
from . import c_normal_owning_join as owning_join
from . import c_normal_runtime_source as runtime_source
from .c_normal_source import _context
from .model import canonical, public_payload
from .normal_source_deadline import check as deadline_check
from .ownership import EvidenceGap

KIND = 'c_normal_cln_source_joined'


@dataclass(frozen=True)
class ClnBinding:
    reader: cln.FixedClnReads
    member_ids: dict
    context_sha256: str
    qualification_sequence: int

    def check(self):
        if (type(self.reader) is not cln.FixedClnReads
                or set(self.reader.__dict__) != {'commands'}
                or not isinstance(self.member_ids, dict) or set(self.member_ids) != set(cln.ALIASES)
                or any(not isinstance(v, str) or not v for v in self.member_ids.values())
                or len(set(self.member_ids.values())) != 2
                or set(self.member_ids.values()) & set(owning_join.owning.OWNERS)
                or type(self.qualification_sequence) is not int or self.qualification_sequence < 1):
            raise EvidenceGap('fixed distinct C two-host CLN binding required')
        cln.native._hex(self.context_sha256)
        return {'commands_sha256':self.reader.hashes(), 'member_ids':copy.deepcopy(self.member_ids),
            'context_sha256':self.context_sha256, 'qualification_sequence':self.qualification_sequence}


async def collect(store, config, chain, observation, *, boundary, checked, runtime, owning, binding):
    """Use newly produced originals, then check the four-member union once.

    Each component retains its own original events. Joining four actual member
    inventories through the existing treasury reducer catches cash/channel or
    duplicate-output overlap that separate two-member subtotals cannot catch.
    The full customer/bank cohort and native liabilities remain separate.
    """
    _context(store, observation); deadline_check()
    if type(binding) is not ClnBinding:
        raise EvidenceGap('typed C CLN binding required')
    constructor = canonical(binding.check()); original = canonical(observation)
    if store.db.execute("SELECT 1 FROM event WHERE kind=? AND json_extract(payload,'$.source_observation.id')=?",
            (KIND, observation['id'])).fetchone():
        raise EvidenceGap('C CLN join observation already collected')
    if (boundary['id'] != observation['boundary_id'] or boundary['pins'] != observation['financial_pins']
            or checked.get('kind') != 'c-checked-native-target-source'
            or checked.get('source_observation') != observation
            or checked.get('loaded', {}).get('manifest', {}).get('source_observation') != observation
            or checked['loaded']['manifest'].get('financial_pins') != observation['financial_pins']):
        raise EvidenceGap('C CLN target observation differs')
    runtime_safe = runtime.get('safe', {}); owning_safe = owning.get('safe', {})
    runtime_event, _ = owning_join._original(store, runtime_safe.get('source_sequence'),
        runtime_source.KIND, runtime_safe, observation)
    owning_event, _ = owning_join._original(store, owning_safe.get('source_sequence'),
        owning_join.KIND, owning_safe, observation)
    if (owning_safe.get('runtime_component_sequence') != runtime_event['sequence']
            or owning_safe.get('runtime_component_event_hash') != runtime_event['hash']
            or owning_safe.get('runtime_source_sequence') != runtime_safe.get('runtime_source_sequence')
            or owning_safe.get('target_original_private_source_references') != checked['original_private_source_references']
            or set(owning_safe.get('inventory_sequences', {})) != set(owning_join.owning.OWNERS)):
        raise EvidenceGap('same-invocation original C owning/runtime join required')
    component = owning.get('private_owning_component', {})
    component_event, _ = owning_join._original(store, component.get('source_sequence'),
        owning_join.owning.KIND, component, observation)
    if (component_event['sequence'] != owning_safe.get('owning_component_sequence')
            or component_event['hash'] != owning_safe.get('owning_component_event_hash')
            or component.get('inventory_sequences') != owning_safe['inventory_sequences']
            or component.get('inventory_source_sequences') != owning_safe.get('inventory_source_sequences')):
        raise EvidenceGap('original C owning inventory source differs')
    raw = runtime_source._public_file(runtime_safe['current_startup_path'],
        runtime_safe['current_source_sha256'], 2*1024*1024)
    literal, original_runtime = runtime_source.replay_original(store, runtime_safe['original_trace'], observation)
    source = runtime_source.decode_object(raw.decode())
    if (runtime_source.digest(original_runtime) != runtime_safe.get('original_response_sha256')
            or source != runtime.get('private_runtime_source')
            or literal.get('native_runtime') != source.get('daemons')
            or literal.get('runtime_wallet_inventory', {}).get('frames') != owning.get('private_owning_frames')):
        raise EvidenceGap('original C runtime bytes differ before CLN collection')
    first = store.db.execute('SELECT coalesce(max(sequence),0) FROM event').fetchone()[0]
    result = await cln.collect(store, config, chain, observation, boundary=boundary, reader=binding.reader,
        member_ids=binding.member_ids, context_sha256=binding.context_sha256,
        qualification_sequence=binding.qualification_sequence,
        runtime_source_sequence=runtime_safe['runtime_source_sequence'],
        current_startup_path=runtime_safe['current_startup_path'])
    event, proof = owning_join._original(store, result.get('source_sequence'), cln.KIND, result, observation)
    if (event['sequence'] <= first or proof.get('runtime_source_sequence') != runtime_safe['runtime_source_sequence']
            or proof.get('qualification_sequence') != binding.qualification_sequence
            or set(proof.get('inventory_sequences', {})) != set(binding.member_ids.values())
            or set(proof.get('inventory_source_sequences', {})) != set(binding.member_ids.values())):
        raise EvidenceGap('this invocation did not produce both C CLN sources')
    hashes = binding.reader.hashes()
    if set(proof.get('original_traces', {})) != {a+':'+m for a in cln.ALIASES for m in cln.native.METHODS}:
        raise EvidenceGap('all six original C CLN replies required')
    for alias in cln.ALIASES:
        for method in cln.native.METHODS:
            frame, _ = cln.replay_original(store, proof['original_traces'][alias+':'+method],
                alias=alias, method=method, observation=observation, command_sha256=hashes[alias][method])
            if frame != proof['source']['nodes'][alias][method]:
                raise EvidenceGap('original C CLN reply differs from joined source')
    inventories = {**owning_safe['inventory_sequences'], **proof['inventory_sequences']}
    from .treasury import _capture_assets, _members
    members = _members(boundary)
    if len(inventories) != 4 or not set(inventories) <= set(members):
        raise EvidenceGap('four distinct declared owning/CLN members required')
    assets = _capture_assets(store, {**boundary, 'members':[members[k] for k in inventories]}, inventories, chain)
    if (runtime_source._public_file(runtime_safe['current_startup_path'], runtime_safe['current_source_sha256'], 2*1024*1024) != raw
            or canonical(binding.check()) != constructor or canonical(observation) != original):
        raise EvidenceGap('C runtime or CLN constructor changed during join')
    owning_join.owning._tip(chain, observation); deadline_check()
    joined = {'source_observation':copy.deepcopy(observation), 'financial_pins':observation['financial_pins'],
        'boundary_id':boundary['id'], 'height':observation['height'], 'tip_hash':observation['tip_hash'],
        'observed_at':time.time(), 'runtime_component_sequence':runtime_event['sequence'],
        'runtime_component_event_hash':runtime_event['hash'], 'runtime_source_sequence':runtime_safe['runtime_source_sequence'],
        'owning_join_sequence':owning_event['sequence'], 'owning_join_event_hash':owning_event['hash'],
        'cln_component_sequence':event['sequence'], 'cln_component_event_hash':event['hash'],
        'inventory_sequences':inventories,
        'inventory_source_sequences':{**owning_safe['inventory_source_sequences'], **proof['inventory_source_sequences']},
        'target_original_private_source_references':checked['original_private_source_references'],
        'original_cln_traces':proof['original_traces'], 'actual_owning_and_cln_assets':assets,
        'channel_route_observed':proof['channel_route_observed'],
        'complete':False, 'qualified':False, 'financial_readiness':False,
        'scope':'four actual owning/CLN members only; full customer/bank/current-liability/fee joins remain required'}
    public_payload(joined); store.event(KIND, joined)
    joined['source_sequence'] = store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    return {'safe':joined, 'private_cln_component':result, 'private_owning_join':owning}
