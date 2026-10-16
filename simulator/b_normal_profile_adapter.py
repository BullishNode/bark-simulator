"""Fixed direct/xpub initial-terminal profile for the shared normal collector.

This is an explicit installed source dependency, never a plugin selected by an
observer. No new dispatcher, lease, RPC allowlist, source receipt or readiness
label is introduced. Missing original facts refuse the shared collector.
"""
from pathlib import Path

from .architecture import DIRECT, profile
from . import b_initial_normal_profile as initial
from . import b_native_normal_verifier as native
from . import b_normal_runtime_source as runtime_source
from .b_native_fee_policy import loaded_native_fee_policy
from .model import canonical, integer, SIGNET_GENESIS, btc_to_sat
from .ownership import EvidenceGap
from .two_step_normal import digest, module_hash, native_wallet, strict_json


def initial_profile(store, requested):
    if requested != DIRECT or profile(store) != DIRECT:
        raise EvidenceGap('only explicit matching direct_xpub initial profile is supported')
    return InitialDirectProfile()


def require_profile(value):
    from .b_continuing_profile import ContinuingDirectProfile
    if type(value) not in (InitialDirectProfile,ContinuingDirectProfile):
        raise EvidenceGap('fixed installed B initial profile required; arbitrary reducers refused')


def _require(value, text):
    if not value: raise EvidenceGap('B initial collector: '+text)


def runtime_from_target(target, admission):
    """Original raw protected buffers inside one private runtime transport object.

    The new envelope is an explicit producer ABI requirement. A legacy derived
    receipt or a caller complete bit cannot substitute for these originals.
    """
    raw = strict_json(target['raw_runtime'])
    _require(set(raw) == {'expected_raw','checkpoint_raw','observation_raw','protected_receipt_raw'},
             'protected raw runtime declaration/observation originals required')
    buffers = initial.RuntimeBuffers(*(raw[k].encode() for k in
        ('expected_raw','checkpoint_raw','observation_raw','protected_receipt_raw')))
    return initial.checked_runtime(buffers, admission)


class InitialDirectProfile:
    architecture = DIRECT
    backing_source_kind = 'b_original_direct_backing'

    def opening(self, store):
        from .preserved_treasury_upgrade import recorded
        value = recorded(store)
        return None if value is None else {'b_upgrade':value,'opening_assets':value['closing_assets']}

    def component_hashes(self):
        return {'b_profile':module_hash(initial_profile),
                'b_native_join':module_hash(native.captured_direct_source),
                'b_initial_money':module_hash(initial.historical_money),
                'b_native_fee_policy':module_hash(loaded_native_fee_policy),
                'b_runtime':module_hash(runtime_source.verify)}

    def activity_context(self,store,chain,target,runtime,scripts,scan,cfg,tip,members):
        from .owned_mempool import arguments,MAX_RESPONSE_BYTES
        _require(chain.call('getdescriptoractivity',*arguments(set(scripts)),max_response_bytes=MAX_RESPONSE_BYTES)
                 == {'activity':[]}, 'owned matching-script mempool activity unresolved')
        return None

    def check_operator_inventory(self,owning,scanned,name,activity,tip,scripts):
        _require(not owning['pending_transactions'] and not owning['unavailable_parent_txids'],
                 'owning operator pending source unresolved')
        _require(sorted((r['outpoint'],r['value_sat'],r['script_pubkey'])for r in owning['utxos'])==
                 sorted((r['outpoint'],r['amount_sat'],r['script'])for r in scanned),
                 'whole operator BDK set differs from complete Core scan')

    def public_pending(self,member_id,activity,scripts):
        return []

    def public_wallet_projection(self,member,raw,*,height,tip_hash,context,chain):
        from .two_step_capture import public_wallet_projection
        return public_wallet_projection(member,raw,height=height,tip_hash=tip_hash)

    def wallet_projection(self,member,native,*,height,tip_hash,context,chain):
        from .two_step_capture import wallet_projection
        return wallet_projection(member,native,height=height,tip_hash=tip_hash)

    def native_projection(self,store,chain,target,scripts,tip,admission,boundary,context):
        return initial.InitialTerminalProfile().native_projection(store,chain,target['raw_sql'],
            target['manifest']['original_sha256']['native_sql'],scripts=scripts,tip=tip,
            minimum_confirmations=admission['b_sweep_min_confs'],boundary=boundary)

    def money_projection(self,store,chain,old_boundary,boundary,context):
        return initial.historical_money(store,chain,old_boundary,boundary,
            context['scripts'],context['direct']['groups'])

    def fee_projection(self,runtime,*,context,**kwargs):
        return initial.InitialTerminalProfile().fee_projection(runtime,**kwargs)

    def checked_claims(self,store,source,context,money,opening):
        _require(not source['pending_liabilities'] and not context['pending_liabilities'],
                 'unsettled original liability not supported by initial profile')
        references={row['sequence']for row in opening['b_upgrade']['sources']}
        _require(set(money['source_sequences'])|{r['sequence']for r in money['costs']} <= references,
            'preserved upgrade omitted original reconciliation/flow/cost sources')
        return []

    def member_frames(self, store, config, chain, cfg, observation, members, target,
                      originals, manifest, rpc_records):
        """Use the SAME authenticated literal helper + public metadata + Core.

        Cold SQLite reads only public BDK descriptor/index/lock columns. No SDK
        wallet, signer, sync or original actor daemon is opened here.
        """
        from .normal_member_source import private_file, bank_projection
        from .public_wallet_metadata import wallet_metadata
        from . import confirmed_scan
        from .owned_mempool import arguments, MAX_RESPONSE_BYTES
        from .final_campaign import _source_event
        _require(config is not None, 'actual owning Config required for scan identity')
        runtime = runtime_from_target(target, cfg['b_runtime_admission'])
        _require(runtime['execution_release']['sdk_commit'] == config.expected_sdk_commit,
                 'actual SDK differs from protected release')
        prepared_raw = private_file(cfg['prepared_descriptors'],65536)
        _require(digest(prepared_raw) == cfg['prepared_descriptors_sha256'],
                 'original public descriptor declaration changed')
        prepared = strict_json(prepared_raw)
        actors = {row['actor']:row for row in prepared['actors']}
        _require(set(actors) == set(cfg['actor_member_ids']), 'exact declared actor set required')
        metadata = {}; specs = {r['desc']:r['range'] for r in cfg['b_descriptor_ranges']}
        _require(len(specs) == len(cfg['b_descriptor_ranges']), 'descriptor interval repeated')
        for actor, member_id in cfg['actor_member_ids'].items():
            # Public metadata is source captured independently, never a wallet
            # inventory claim or a zero-balance boolean.
            path = Path(cfg['wallet_root'])/actor/'db.sqlite'
            item = wallet_metadata(path)
            member = members[member_id]; descriptor = actors[actor]['public_descriptor']
            _require(member['kind'] == 'wallet' and member['role'] == 'customer'
                and member['descriptors'] == [descriptor] == [item['wallet']['descriptor']]
                and descriptor in specs and specs[descriptor][0] == 0
                and specs[descriptor][1] >= max(19,item['issued_frontier']),
                'current public actor descriptor/frontier exceeds admitted scan')
            metadata[actor] = item
        # The fixed protected producer already verifies both actual running
        # processes. Project its literal identity into the existing scan API;
        # no disk completeness/runtime-loaded label is consumed.
        current = {'kind':'owned_startup_source','product_commit':runtime['product_commit'],
            'schema_sha256':runtime['schema_sha256'],'daemons':{
                name:{**row,'running':True}for name,row in runtime['daemons'].items()}}
        scripts, coverage, result, provenance = confirmed_scan.confirmed_scan(store,config,chain,current,
            pins=observation['financial_pins'],boundary_id=observation['boundary_id'],
            members=list(members.values()),specs=specs,tip=(observation['height'],observation['tip_hash']))
        activity=self.activity_context(store,chain,target,runtime,scripts,result,cfg,
            (observation['height'],observation['tip_hash']),members)
        rows={name:[]for name in members}
        for coin in result['unspents']:
            owner=scripts[coin['scriptPubKey']]
            rows[owner['member_id']].append({'outpoint':coin['txid']+':'+str(coin['vout']),
                'amount_sat':btc_to_sat(coin['amount']),'script':coin['scriptPubKey'],
                'descriptor_index':owner['descriptor_index'],'child_index':owner['child_index']})
        for name,label,key in ((cfg['rounds_member_id'],'rounds','raw_rounds_inventory'),
                               (cfg['watchman_member_id'],'watchman','raw_watchman_inventory')):
            owning=native_wallet(target[key],label)
            _require(owning['public_descriptor'] in specs
                and specs[owning['public_descriptor']][1] >= max(19,owning['last_revealed_index'])
                and not owning['unavailable_parent_txids'],
                'owning operator frontier/pending source exceeds full scan')
            self.check_operator_inventory(owning,rows[name],name,activity,
                (observation['height'],observation['tip_hash']),scripts)
        frames={}
        for actor, member_id in cfg['actor_member_ids'].items():
            frames[member_id]={'source_kind':'core_descriptor_scan','network':'signet',
                'height':observation['height'],'tip_hash':observation['tip_hash'],
                'public_descriptors':members[member_id]['descriptors'],
                'pending_transactions':self.public_pending(member_id,activity,scripts),
                'reserved_outpoints':[r['txid']+':'+str(r['vout'])for r in metadata[actor]['locked_outpoints']],
                'discovery_gaps':[],'utxos':rows[member_id],
                'source_records':[provenance['raw_response_sha256'],*rpc_records]}
        bank=cfg['bank_member_id']; fixture=cfg['fixture_member_id']; target_cln=cfg['target_cln_member_id']
        bank_raw=strict_json(originals[manifest['originals_map']['bank']],decimals=True)
        frames[bank]=bank_projection(bank_raw,members[bank],chain,height=observation['height'],
            tip_hash=observation['tip_hash'],records=rpc_records)
        _require(sorted(frames[bank]['utxos'],key=lambda r:r['outpoint']) == sorted(rows[bank],key=lambda r:r['outpoint']),
                 'complete descriptor scan and actual bank inventory differ')
        frames[fixture]=strict_json(originals[manifest['originals_map']['fixture_cln']])
        cln_name=target['manifest']['auxiliary_originals']['target_cln']
        frames[target_cln]=strict_json(target['auxiliary_originals'][cln_name])
        frames[cfg['backing_member_id']]={'source_kind':self.backing_source_kind}
        context={'current_startup':current,'metadata':metadata,'actor_member_ids':cfg['actor_member_ids'],'descriptor_ranges':coverage,
            'confirmed_scan_sequence':provenance['original_scan_sequence'],
            'confirmed_scan_event_hash':provenance['original_scan_event_hash']}
        return frames, context

    def decode(self, store, config, chain, snapshot, observation, boundary, target, additional, admission):
        runtime=runtime_from_target(target, admission)
        release=runtime['execution_release']
        _require(all(release[key] == value for key,value in observation['financial_pins'].items()),
            'protected execution release differs from exact new financial pins')
        _require(isinstance(additional.get('b_public_context'),dict),
            'same captured public metadata/scan context missing')
        context=additional['b_public_context'];raw_context=canonical(context).encode()
        _require(digest(raw_context) == additional['manifest']['b_public_context_sha256'],
                 'authenticated public metadata/scan context changed')
        from .final_campaign import _source_event
        scan_event,_ = _source_event(store,context['confirmed_scan_sequence'])
        _require(scan_event['hash'] == context['confirmed_scan_event_hash'],
            'original captured scan event identity differs')
        specs={r['desc']:r['range']for r in context['descriptor_ranges']}
        scripts,scan=native.captured_scan(store,config,chain,context['current_startup'],
            sequence=context['confirmed_scan_sequence'],pins=observation['financial_pins'],
            boundary_id=boundary['id'],members=boundary['members'],specs=specs,
            tip=(observation['height'],observation['tip_hash']))
        projected=self.native_projection(store,chain,target,scripts,
            (observation['height'],observation['tip_hash']),admission,boundary,
            {**context,'_scan_unspents':scan['unspents'],'_server_pubkey':snapshot['identity']['server_pubkey']})
        # Preserve common source event identity fields; their values are joined
        # to the protected actual release, never to caller reported booleans.
        common_runtime={'identity':snapshot['identity'],'binary_sha256':admission['binary_sha256']}
        for name,sha in admission['binary_sha256'].items():
            _require(runtime['daemons'][name]['binary_sha256'] == sha,'actual shipping ELF differs')
        backing = [m['id']for m in boundary['members']if m['kind']=='ark_backing'
            and m['identity']==snapshot['identity']['server_pubkey']]
        _require(len(backing)==1,'exact original server backing member required')
        return common_runtime,projected['database'],{
            **projected,'scripts':scripts,'scan':scan,'runtime':runtime,'backing_member_id':backing[0],
            'public_context_sha256':digest(raw_context),'boundary':boundary,
            'tip_height':observation['height'],'tip_hash':observation['tip_hash']}

    def backing(self, member, context):
        _require(member['kind'] == 'ark_backing' and member['id']==context['backing_member_id']
            and not context['pending_liabilities']
            and context['direct']['groups'] and context['direct']['outstanding_liability_sat'] == 0,
            'only the authenticated original terminal backing is supported')
        # Exact group/current-chain validation accounts every customer root as
        # consumed. Operator change is discovered in owning wallet inventories.
        return {}, []

    def source_fields(self, context, target):
        return {'native_architecture':DIRECT,
            'b_public_context_sha256':context['public_context_sha256'],
            'b_original_sha256':{name:digest(target[key])for name,key in
                [('runtime','raw_runtime'),('watchman_inventory','raw_watchman_inventory')]}}

    def originals(self, target, additional):
        return {'raw_runtime':target['raw_runtime'],'raw_watchman_inventory':target['raw_watchman_inventory'],
                'b_public_context':additional['b_public_context']}

    def reduce(self, store, config, chain, boundary, envelope, captured, source_event, source,
               originals, admitted, opening, now):
        """B native facts only; shared deadline/admission/assets/final writer stay shared."""
        from .two_step_normal import source_members, verify_cln_members, _capture_assets
        from .treasury import reconcile_edge
        from .preserved_treasury_upgrade import _originals
        from .final_campaign import _source_event
        # Native semantics are independently replayed from the SAME original
        # target/runtime/watchman/public scan buffers admitted by the capture.
        target={'raw_sql':originals['native_sql'],'raw_runtime':captured['raw_runtime'],
            'raw_watchman_inventory':captured['raw_watchman_inventory'],
            'raw_rounds_inventory':originals['rounds_inventory'],
            'manifest':{'original_sha256':{'native_sql':source['original_sha256']['native_sql']}}}
        context=captured['b_public_context'];additional={'b_public_context':context,
            'manifest':{'b_public_context_sha256':source['b_public_context_sha256']}}
        _,_,native_context=self.decode(store,config,chain,{'identity':source['identity']},
            source['source_observation'],boundary,target,additional,admitted)
        _require(source['native_architecture'] == DIRECT and source['b_original_sha256'] == {
            'runtime':digest(captured['raw_runtime']),'watchman_inventory':digest(captured['raw_watchman_inventory'])},
            'same captured runtime/watchman buffer differs')
        members=source_members(store,boundary,captured['inventory_sequences'],source,now=now)
        verify_cln_members(store,members,source,captured['inventory_sequences'],chain)
        assets=_capture_assets(store,boundary,captured['inventory_sequences'],chain)
        _require((assets['height'],assets['tip_hash']) == (source['height'],source['tip_hash']),
                 'full treasury/native source tips differ')
        money=self.money_projection(store,chain,_originals(store)[0][0],boundary,native_context)
        runtime=native_context['runtime'];physical={}
        for name, member in members.items():
            if member['kind'] != 'wallet':continue
            _, inventory = _source_event(store,captured['inventory_sequences'][name])
            for row in inventory['utxos']:
                _require(row['outpoint'] not in physical,'physical owning output duplicated')
                physical[row['outpoint']] = {'amount_sat':row['amount_sat'],
                    'script':row['script'],'member_id':name}
        fee=self.fee_projection(runtime,context=native_context,costs=money['costs'],
            groups=native_context['direct']['groups'],accounting_receipt_sha256=admitted['b_accounting_receipt_sha256'],
            watchman_raw=captured['raw_watchman_inventory'],physical=physical,selected_points=set(),
            chain=chain,server_pubkey=source['identity']['server_pubkey'])
        # This is an explicit remaining source obligation, not authority from a
        # configured ceiling. The protected producer must export the literal
        # reviewed public loaded fee-policy projection before this can pass.
        public_policy=runtime.get('public_configuration')
        _require(public_policy is not None and public_policy == admitted['b_public_configuration'],
                 'actual protected loaded public fee-policy source unavailable/different')
        limits=loaded_native_fee_policy(runtime,network=config.network)['fee_ceilings_sat_kvb']
        _require(limits == envelope['fee_ceilings_sat_kvb'], 'envelope differs from actual supported fee paths')
        _require(opening is not None and 'b_upgrade' in opening,
            'strict preserved treasury upgrade required; no A first-opening alias')
        claims=self.checked_claims(store,source,native_context,money,opening)
        # The original opening already conserved historical flows/costs. Only
        # newly authenticated conservation deltas may follow that fixed cut.
        edge=reconcile_edge(opening['opening_assets'],assets,money.get('delta_flows',[]),
            native_context['pending_liabilities'],members)
        # Owning whole-input proof is explicit. A future prepare cannot recycle
        # pending change or claim unsupported urgent metadata as ordinary cash.
        available=sum(fee['confirmed_whole_input_urgent_reserve'].values())*1000
        used={category:sum(r['amount_msat']for r in money['costs']if r['budget']==category)
              for category in ('ordinary','urgent')}
        _require(available >= sum(max(0,envelope['fee_budgets_msat'][k]-used[k])for k in used),
                 'owning confirmed unencumbered fee cash cannot back remaining budgets')
        pending_fees=fee.get('pending_native_fee_exposure_msat',{'ordinary':0,'urgent':0})
        return assets,claims,fee,limits,pending_fees,None,None,edge,available,source_event,source
