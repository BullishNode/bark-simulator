"""Fixed final-owner B profile wiring for the existing collector.

The native executable validates private fee codecs/SQL/packages. This module
preserves their original bytes and source identities across capture/reduction;
it does not treat those proofs as Core ownership or financial readiness.
"""
import copy
import re

from .b_continuing_profile import ContinuingDirectProfile
from .b_normal_profile_adapter import runtime_from_target, _require
from .b_native_owner_snapshot import owner_snapshot
from .b_private_native_fee_inputs import AUXILIARY, prepare_native_fee_request
from .b_native_fee_reply import bind_native_fee_reply
from .model import canonical
from .two_step_normal import digest, module_hash, strict_json, run_native_fee_source_proof

PRODUCT = '15e4fd7085802ba5f7b1d9a2c87aab7277d5a7e4'
PRIVATE = 'b_native_fee_private'


def checked_owner(runtime):
    budget = runtime.get('native_budget', {})
    raw = budget.get('owner_snapshot_raw')
    _require(type(raw) is str and digest(raw.encode()) == budget.get('owner_snapshot_raw_sha256'),
             'exact actual owner CLI stdout/hash missing')
    _require(canonical(strict_json(raw)) == canonical(budget.get('owner_snapshot')),
             'owner CLI bytes and canonical object differ')
    # The protected producer/source admission proves process/route/custody;
    # this independent decoder validates exact native fields/arithmetic.
    return owner_snapshot(raw.encode(), runtime, expected_product_commit=PRODUCT)


def checked_owner_original(target,runtime):
    partition=checked_owner(runtime)
    _require(target.get('auxiliary_originals',{}).get(AUXILIARY['b_native_fee_snapshot'])==
        runtime['native_budget']['owner_snapshot_raw'].encode(),
        'private owner snapshot is not the exact protected CLI original')
    return partition


class FinalNativeDirectProfile(ContinuingDirectProfile):
    """Only the fixed native_fee tool set can construct this installed profile."""
    def __init__(self, tool):
        self.native_fee_tool = copy.deepcopy(tool)

    def validate_proof_tools(self, tools, admitted):
        tool = tools.get('native_fee', {})
        _require(set(tools) == {'policy', 'binding', 'pending', 'native_fee'}
            and tool == self.native_fee_tool
            and set(tool) == {'command', 'sha256', 'evidence_directory', 'sdk_commit'}
            and type(tool['command']) is list and len(tool['command']) == 2
            and tool['command'][1] == 'native-fee-source-proof'
            and type(tool['sdk_commit']) is str and re.fullmatch('[0-9a-f]{40}', tool['sdk_commit'])
            and admitted.get('b_native_fee_tool_commit') == tool['sdk_commit'],
            'explicit independently source-admitted native fee tool required')
        return True

    def component_hashes(self):
        from .b_final_native_fees import final_ordinary_fee_facts
        from .b_native_normal_verifier import retained_fee_accounting
        from .b_private_native_fee_cut import sql as native_cut_sql
        from .b_private_native_fee_capture import capture_private_cut
        return {**super().component_hashes(),
            'b_final_native_profile':module_hash(checked_owner),
            'b_native_owner_snapshot':module_hash(owner_snapshot),
            'b_private_native_fee_inputs':module_hash(prepare_native_fee_request),
            'b_native_fee_reply':module_hash(bind_native_fee_reply),
            'b_final_native_fees':module_hash(final_ordinary_fee_facts),
            'b_retained_fee_accounting':module_hash(retained_fee_accounting),
            'b_private_native_fee_cut':module_hash(native_cut_sql),
            'b_private_native_fee_capture':module_hash(capture_private_cut)}

    def prepare_target(self, target, admitted, observation, tools):
        self.validate_proof_tools(tools, admitted)
        runtime = runtime_from_target(target, admitted)
        checked_owner_original(target,runtime)
        selected = {k:observation[k] for k in ('id','height','tip_hash')}
        request = prepare_native_fee_request(target, runtime,
            expected_product_commit=PRODUCT, expected_tool_commit=self.native_fee_tool['sdk_commit'],
            observation=selected)
        request_raw, reply_raw = run_native_fee_source_proof(self.native_fee_tool, request)
        bind_native_fee_reply(request_raw, reply_raw,
            target['auxiliary_originals'][AUXILIARY['b_native_fee_snapshot']],
            expected_tool_commit=self.native_fee_tool['sdk_commit'])
        # Local pure proof output is private capture state, not a target member
        # or a new transport assertion. Existing source_fields hashes bind it.
        target = dict(target)
        target[PRIVATE] = {'request_raw':request_raw, 'reply_raw':reply_raw}
        return target

    def native_server(self, runtime):
        return checked_owner(runtime)['server_pubkey']

    def native_projection(self, store, chain, target, scripts, tip, admission, boundary, context):
        runtime = runtime_from_target(target, admission)
        partition = checked_owner_original(target,runtime)
        proof = target.get(PRIVATE)
        _require(type(proof) is dict and set(proof) == {'request_raw','reply_raw'},
                 'actual native private proof originals absent')
        prepared = prepare_native_fee_request(target, runtime, expected_product_commit=PRODUCT,
            expected_tool_commit=self.native_fee_tool['sdk_commit'],
            observation={'id':strict_json(proof['request_raw'])['source_observation']['id'],
                         'height':tip[0], 'tip_hash':tip[1]})
        _require(canonical(prepared).encode() == proof['request_raw'],
                 'actual native request differs from same captured originals/tip')
        reply = bind_native_fee_reply(proof['request_raw'], proof['reply_raw'],
            target['auxiliary_originals'][AUXILIARY['b_native_fee_snapshot']],
            expected_tool_commit=self.native_fee_tool['sdk_commit'])
        result = super().native_projection(store,chain,target,scripts,tip,admission,boundary,context)
        public_nursery=result['database']['rows']['nursery']
        private_nursery=reply['nursery_inventory']
        _require(len({r['txid']for r in public_nursery})==len(public_nursery)
            and {(r['txid'],r['kind'])for r in public_nursery}==
                {(r['txid'],r['kind'])for r in private_nursery},
            'same public/private whole nursery membership differs')
        result['native_fee_source'] = {'partition':partition, 'reply':reply}
        return result

    def proof_hashes(self,target):
        proof = target[PRIVATE]
        return {**{role:digest(target['auxiliary_originals'][name])for role,name in AUXILIARY.items()},
            'request_raw':digest(proof['request_raw']), 'reply_raw':digest(proof['reply_raw'])}

    def source_fields(self, context, target):
        return {**super().source_fields(context,target),
            'b_native_fee_original_sha256':self.proof_hashes(target),
            'b_native_fee_tool_commit':self.native_fee_tool['sdk_commit']}

    def originals(self,target,additional):
        return {**super().originals(target,additional), PRIVATE:{
            'proof':target[PRIVATE], 'manifest':copy.deepcopy(target['manifest']),
            'auxiliary_originals':{name:target['auxiliary_originals'][name]for name in AUXILIARY.values()}}}

    def replay_target(self,captured,originals,source):
        target = super().replay_target(captured,originals,source)
        saved = captured.get(PRIVATE)
        _require(type(saved) is dict and set(saved)=={'proof','manifest','auxiliary_originals'},
                 'retained exact native fee capture originals missing')
        target.update(manifest=saved['manifest'],auxiliary_originals=saved['auxiliary_originals'])
        target[PRIVATE] = saved['proof']
        _require(source.get('b_native_fee_tool_commit')==self.native_fee_tool['sdk_commit']
            and source.get('b_native_fee_original_sha256')==self.proof_hashes(target)
            and target['manifest']['original_sha256']['native_sql']==digest(originals['native_sql'])
            and strict_json(target[PRIVATE]['request_raw'])['source_observation']=={k:source['source_observation'][k]
                for k in ('id','height','tip_hash')},
            'source event/native private originals differ')
        return target

    def loaded_fee_policy(self,runtime,*,network):
        from .b_native_fee_policy import loaded_final_native_fee_policy
        return loaded_final_native_fee_policy(runtime,network=network)

    def fee_projection(self,runtime,*,context,**kwargs):
        from .b_final_native_fees import final_ordinary_fee_facts
        kwargs.pop('selected_points')
        watch=next(m for m in context['boundary']['members']if m['id']=='watchman')
        return final_ordinary_fee_facts(runtime,native_fee_source=context['native_fee_source'],
            versions=context['versions'],wallet_context={
                'member':watch,'scripts':context['scripts'],'scan':context['normalized_scan'],
                'tip':(context['tip_height'],context['tip_hash'])},**kwargs)
