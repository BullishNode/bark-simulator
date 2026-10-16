"""Fixed B continuing ordinary profile for the EXISTING full collector.

Only ordinary signed sources/direct versions are supported. Conditional/LN,
urgent private publication and unknown f/g/r budget records HOLD. No writer,
transport package substitute or source-completeness flag is introduced.
"""
from .b_normal_profile_adapter import InitialDirectProfile,_require
from . import b_initial_normal_profile as initial
from . import b_native_normal_verifier as native
from .b_current_native_liabilities import current_ordinary_liabilities
from .b_native_signed_versions import retained_ordinary_versions
from .b_pending_wallet import owning_projection
from .b_continuing_native_fees import ordinary_fee_facts
from .b_native_ordinary_money import current_ordinary_miner_costs,opening_money_deltas
from .architecture import DIRECT,profile
from .financial_transition import _current_claims
from .model import btc_to_sat
from .two_step_normal import digest,module_hash,native_wallet,strict_json


def continuing_profile(store,requested):
    _require(requested==DIRECT and profile(store)==DIRECT,'explicit matching continuing direct_xpub required')
    return ContinuingDirectProfile()


def _projection(store,chain,target,runtime,scripts,scan,*,server,backing,actors,tip,depth,members):
    raw=target['raw_sql']
    _require(isinstance(raw,bytes)and len(raw)<=2*1024*1024
        and digest(raw)==target['manifest']['original_sha256']['native_sql'],
        'same complete ordinary native SQL original differs')
    _require(actors and len(set(actors.values()))==len(actors)
        and all(name in members and members[name]['kind']=='wallet'and members[name]['role']=='customer'
                for name in actors.values()),'exact declared customer mapping missing')
    database=strict_json(raw)
    rights=current_ordinary_liabilities(store,chain,database,server_pubkey=server,
        borrower=backing,tip=tip,minimum_confirmations=depth,actor_member_ids=actors)
    versions=retained_ordinary_versions(store,chain,database,rights,scripts=scripts,tip=tip)
    for checked in versions['checked_candidates'].values():
        for allocation,owner in checked['owners']:
            _require(scripts.get(allocation['spk'],{}).get('member_id')==actors.get(owner['actor']),
                'current fallback destination is outside its declared customer wallet')
    normalized=[{'txid':r['txid'],'vout':r['vout'],'amount_sat':btc_to_sat(r['amount']),
                 'script':r['scriptPubKey']}for r in scan['unspents']]
    wallets={}
    # Exact configured member IDs are supplied by the admitted profile caller,
    # not inferred from arbitrary labels or a target owner flag.
    return {'database':database,'direct':rights,'pending_liabilities':rights['liabilities'],
        'versions':versions,'normalized_scan':normalized,'actor_member_ids':actors,
        'native_source_sha256':digest(raw),'wallet_projections':wallets,'chain':chain,'members':members}


class ContinuingDirectProfile(InitialDirectProfile):
    backing_source_kind = 'checked_current_ordinary_backing'
    def component_hashes(self):
        from .direct_settlements import check_pending_candidate
        from .owned_mempool import decode_activity_reply
        from .chain import ChainReader
        from .normal_source_deadline import DeadlineChain
        from .b_native_fee_partition import partition_native_fee_authorizations
        return {**super().component_hashes(),'b_continuing_profile':module_hash(continuing_profile),
            'b_current_rights':module_hash(current_ordinary_liabilities),
            'b_signed_versions':module_hash(retained_ordinary_versions),
            'b_pending_wallet':module_hash(owning_projection),'b_continuing_fees':module_hash(ordinary_fee_facts),
            'b_ordinary_money':module_hash(opening_money_deltas),
            'b_candidate_accounting':module_hash(check_pending_candidate),
            'b_owned_activity_decoder':module_hash(decode_activity_reply),
            'b_chain_transport':module_hash(ChainReader.owned_activity),
            'b_source_deadline':module_hash(DeadlineChain.owned_activity),
            'b_fee_partition':module_hash(partition_native_fee_authorizations)}

    def activity_context(self,store,chain,target,runtime,scripts,scan,cfg,tip,members):
        return _projection(store,chain,target,runtime,scripts,scan,
            server=runtime['native_budget']['disk_budget']['server_pubkey'],backing=cfg['backing_member_id'],
            actors=cfg['actor_member_ids'],tip=tip,depth=cfg['b_runtime_admission']['b_sweep_min_confs'],members=members)

    def check_operator_inventory(self,owning,scanned,name,activity,tip,scripts):
        member=activity['members'][name]
        report,coins=owning_projection(member,owning,scripts=scripts,scan=activity['normalized_scan'],
            versions=activity['versions'],chain=activity['chain'],tip=tip)

    def native_projection(self,store,chain,target,scripts,tip,admission,boundary,context):
        members={m['id']:m for m in boundary['members']}
        runtime=runtime_from_target(target,admission)
        server=runtime['native_budget']['disk_budget']['server_pubkey']
        _require(server==context['_server_pubkey'],'protected native server differs from public server')
        backings=[m['id']for m in boundary['members']if m['kind']=='ark_backing'and m['identity']==server]
        _require(len(backings)==1,'exact declared signed server backing required')
        # The scan replay is already authenticated by the inherited decode.
        scan={'unspents':context['_scan_unspents']}
        result=_projection(store,chain,target,runtime,scripts,scan,server=server,backing=backings[0],
            actors=context['actor_member_ids'],tip=tip,depth=admission['b_sweep_min_confs'],members=members)
        for name,label,key in ((admission['rounds_member_id'],'rounds','raw_rounds_inventory'),
                               (admission['watchman_member_id'],'watchman','raw_watchman_inventory')):
            result['wallet_projections'][name]=owning_projection(members[name],native_wallet(target[key],label),
                scripts=scripts,scan=result['normalized_scan'],versions=result['versions'],chain=chain,tip=tip)
        result.pop('chain');result.pop('members')
        return result

    def public_pending(self,member_id,activity,scripts):
        return public_pending(member_id,activity['versions'],scripts)

    def public_wallet_projection(self,member,raw,*,height,tip_hash,context,chain):
        from .two_step_capture import public_wallet_projection
        expected=public_pending(member['id'],context['versions'],context['scripts'])
        return public_wallet_projection(member,raw,height=height,tip_hash=tip_hash,checked_pending=expected)

    def backing(self,member,context):
        _require(member['kind']=='ark_backing'and member['id']==context['backing_member_id'],
            'exact ordinary backing member required')
        roots=context['direct']['backing_roots'];inside=sorted({member['id'],*context['actor_member_ids'].values()})
        return ({point:{'outpoint':point,**row}for point,row in roots.items()},
            [{'outpoint':point,'script':row['script'],'financial_pins':context['boundary']['pins'],
              'inside_members':inside,'server_identity':member['identity'],
              'native_source_sha256':context['native_source_sha256']}for point,row in roots.items()])

    def wallet_projection(self,member,native,*,height,tip_hash,context,chain):
        return owning_projection(member,native,scripts=context['scripts'],scan=context['normalized_scan'],
            versions=context['versions'],chain=chain,tip=(height,tip_hash))

    def money_projection(self,store,chain,old_boundary,boundary,context):
        projection=current_ordinary_miner_costs(store,chain,boundary=boundary,scripts=context['scripts'],
            groups=context['direct']['groups'],tip=(context['tip_height'],context['tip_hash']),
            bank_member_id='bank',backing_member_id=context['backing_member_id'])
        historical=initial.historical_money(store,chain,old_boundary,boundary,context['scripts'],
            context['direct']['groups'],historical_costs=[r for r in projection['costs']if r['sequence']in initial.COST_SEQUENCES])
        return {**historical,**projection,**opening_money_deltas(store,projection)}

    def fee_projection(self,runtime,*,context,**kwargs):
        kwargs.pop('selected_points')
        watch=next(m for m in context['boundary']['members']if m['id']=='watchman')
        return ordinary_fee_facts(runtime,versions=context['versions'],wallet_context={
            'member':watch,'scripts':context['scripts'],'scan':context['normalized_scan'],
            'tip':(context['tip_height'],context['tip_hash'])},**kwargs)

    def checked_claims(self,store,source,context,money,opening):
        observed=[{k:v for k,v in row.items()if k!='source_sequence'}for row in source['pending_liabilities']]
        _require(observed==context['pending_liabilities'],'actual captured liability source differs')
        _require(source['cost_sequences']==money['cost_sequences']and source['flow_sequences']==money['flow_sequences'],
            'actual full cost/flow coverage differs')
        pending={r['id'][5:]for r in context['pending_liabilities']}
        return [r for r in _current_claims(store)if r['coin_id']in pending]


def runtime_from_target(target,admission):
    from .b_normal_profile_adapter import runtime_from_target as replay
    return replay(target,admission)


def public_pending(member_id,versions,scripts):
    mine={s for s,o in scripts.items()if o['member_id']==member_id}
    return [tx for txid,tx in sorted(versions['versions'].items())
        if versions['states'][txid]=='mempool'and any(c['script']in mine for c in tx['inputs']+tx['outputs'])]
