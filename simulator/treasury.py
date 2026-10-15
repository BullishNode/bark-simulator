"""Declared treasury and confirmed-tip accounting from checked source inventories.

Physical chain outputs are checked through independent Core. Channel inventories
must contain full owned balances (including owned reserves/in-flight claims), not
merely spendable liquidity. Missing producer coverage never becomes zero assets.
Liabilities are ownership obligations, not additional physical assets.
"""
import json
from .model import SIGNET_GENESIS, InvariantError, btc_to_sat, canonical, integer, public_payload
from .final_campaign import _pins, _source_event

KEY='conserved_treasury_boundary'
ROLES={'operator','customer','funding_bank','forwarder','fixture_peer'}
KINDS={'wallet','ark_backing','lightning_peer'}


def _cln_cash(store,member,entry,declaration,tip,height,confirmations,sources):
    """Match node cash to its original public native frame and declared node.

    The authenticated native collector and exhaustive discovery remain producer
    prerequisites; a named event or a complete label cannot replace them.
    """
    sequence=integer(entry['source_sequence'],'CLN wallet source sequence',1)
    if sequence not in sources['frames']:
        size=store.db.execute('SELECT length(CAST(payload AS BLOB)) FROM event WHERE sequence=?',(sequence,)).fetchone()
        if size is None or type(size[0]) is not int or size[0]<=0:
            raise ValueError('original CLN wallet source missing or outside byte bound')
        if sources['bytes']+size[0]>2*1024*1024:
            raise ValueError('aggregate CLN wallet source exceeds byte bound')
        sources['bytes']+=size[0]
        event,source=_source_event(store,sequence)
        if (event['kind']!='treasury_cln_wallet_source'
                or source.get('member_id')!=member['id'] or source.get('identity')!=member['identity']
                or source.get('member_verification_sequence')!=member['verification_sequence']
                or source.get('financial_pins')!=declaration['pins'] or source.get('genesis')!=SIGNET_GENESIS
                or source.get('height')!=height or source.get('tip_hash')!=tip):
            raise ValueError('original CLN wallet source scope differs from declared member/tip/pins')
        member_event,member_proof=_source_event(store,member['verification_sequence'])
        if (member_event['kind']!='treasury_member_verified'
                or member_proof.get('member')!={k:v for k,v in member.items() if k!='verification_sequence'}
                or member_proof.get('genesis')!=SIGNET_GENESIS or member_proof.get('financial_pins')!=declaration['pins']):
            raise ValueError('original CLN member source proof differs')
        info=source['getinfo'];funds=source['listfunds']
        if (not isinstance(info,dict) or not isinstance(funds,dict)
                or info.get('id')!=member['identity'] or info.get('network')!='signet' or info.get('blockheight')!=height):
            raise ValueError('original CLN wallet source node/network/height differs')
        outputs=funds['outputs'];channels=funds['channels']
        if not isinstance(outputs,list) or not isinstance(channels,list):
            raise ValueError('bounded original CLN wallet source rows required')
        sources['rows']+=len(outputs)+len(channels)
        if sources['rows']>2000:
            raise ValueError('aggregate CLN wallet source exceeds byte/row bound')
        if any(not isinstance(row,dict) for row in outputs+channels):
            raise ValueError('original CLN wallet source rows must be objects')
        sources['frames'][sequence]=source
    source=sources['frames'][sequence]
    # Do not reuse one node's source frame for another declared member.
    if source['member_id']!=member['id']:raise ValueError('CLN wallet source belongs to another member')
    txid,index=entry['outpoint'].rsplit(':',1)
    matches=[row for row in source['listfunds']['outputs']
             if row.get('txid')==txid and type(row.get('output')) is int and row['output']==int(index)]
    if len(matches)!=1:raise ValueError('CLN wallet output absent or repeated in original native source')
    row=matches[0]
    amount=integer(row['amount_msat'],'native CLN onchain amount')
    if (amount!=integer(entry['amount_sat'],'CLN wallet amount')*1000
            or row.get('scriptpubkey')!=entry['script'] or row.get('status')!='confirmed'
            or not 1<=integer(row['blockheight'],'native CLN output blockheight')<=height
            or height-row['blockheight']+1!=confirmations):
        raise InvariantError('CLN wallet output differs from original native source')


def _members(declaration):
    if set(declaration)!={'id','genesis','pins','members','excluded'} or declaration['genesis']!=SIGNET_GENESIS:
        raise ValueError('explicit owned signet treasury boundary required')
    _pins(declaration['pins']);public_payload(declaration)
    if not isinstance(declaration['id'],str) or not 1<=len(declaration['id'])<=100:
        raise ValueError('boundary identifier missing')
    if not isinstance(declaration['members'],list) or not 1<=len(declaration['members'])<=1024:
        raise ValueError('bounded actual treasury members required')
    members={};identities=set()
    for member in declaration['members']:
        if set(member)!={'id','kind','role','identity','descriptors','verification_sequence'}:
            raise ValueError('member identity/descriptors/proof required')
        if member['kind'] not in KINDS or member['role'] not in ROLES or not member['identity']:
            raise ValueError('member type or actual identity invalid')
        identity=(member['kind'],member['identity'])
        if member['id'] in members or identity in identities:
            raise InvariantError('same wallet/node identity declared twice')
        if member['kind']=='wallet' and (not isinstance(member['descriptors'],list) or not member['descriptors']):
            raise ValueError('actual public wallet descriptors required')
        if member['kind']!='wallet' and member['descriptors']:
            raise ValueError('non-wallet identity cannot impersonate a descriptor wallet')
        members[member['id']]=member;identities.add(identity)
    if not isinstance(declaration['excluded'],list) or len(set(declaration['excluded']))!=len(declaration['excluded']):
        raise ValueError('explicit unique excluded identities required')
    if any(m['identity'] in declaration['excluded'] for m in members.values()):
        raise InvariantError('identity is both inside and outside treasury')
    return members


def declare_boundary(store,declaration,chain):
    """Record actual independently observed membership before allocating capital."""
    members=_members(declaration)
    chain.identity()
    for member in members.values():
        event,proof=_source_event(store,member['verification_sequence'])
        if (event['kind']!='treasury_member_verified' or proof.get('member')!={k:v for k,v in member.items() if k!='verification_sequence'}
                or proof.get('genesis')!=declaration['genesis'] or proof.get('financial_pins')!=declaration['pins']):
            raise ValueError('original actual member identity proof does not match declaration')
        for descriptor in member['descriptors']:
            details=chain.call('getdescriptorinfo',descriptor)
            if details.get('hasprivatekeys') is not False or details.get('descriptor')!=descriptor:
                raise ValueError('canonical public descriptor independently verified by Core required')
    encoded=canonical(declaration)
    with store.transaction():
        previous=store.get_meta(KEY)
        if previous is not None:
            if previous!=encoded:raise ValueError('treasury boundary immutable; use a fresh namespace')
            return False
        if not store.get_meta('paused'):raise ValueError('declare actual boundary while dispatch is paused')
        if store.db.execute("SELECT 1 FROM action WHERE state IN ('dispatched','outcome_unknown') LIMIT 1").fetchone():
            raise ValueError('reconcile old unknown actions before declaring boundary')
        if store.db.execute("SELECT 1 FROM event WHERE kind IN ('fixture_funding_intent','fixture_funding_prepared','fixture_funding_broadcast_intent','action_dispatched') LIMIT 1").fetchone():
            raise ValueError('actual boundary must be declared before funding or dispatch')
        store.db.execute('INSERT INTO meta VALUES (?,?)',(KEY,encoded))
        store._event('treasury_boundary_declared',declaration)
    return True


def boundary(store):
    value=store.get_meta(KEY)
    if value is None:raise ValueError('actual conserved treasury boundary has not been declared')
    declaration=json.loads(value);_members(declaration)
    rows=store.db.execute("SELECT payload FROM event WHERE kind='treasury_boundary_declared'").fetchall()
    if len(rows)!=1 or rows[0][0]!=canonical(declaration):
        raise ValueError('treasury declaration differs from immutable record')
    return declaration


def capture_assets(store,inventory_sequences,chain):
    """Validate complete producer inventories at one confirmed tip, in exact msat.

    A producer must report all declared wallet/backing/channel assets. This API
    cannot qualify a missing producer or infer completeness from a balance label.
    Core ignores mempool spends here: unconfirmed carriers are separate pending
    obligations/projections, never added alongside their confirmed backing.
    """
    declaration=boundary(store);members=_members(declaration)
    start=chain.identity();tip=start['bestblockhash'];height=start['blocks']
    if start.get('initialblockdownload') is not False:raise ValueError('independent chain not synchronized')
    if set(inventory_sequences)!=set(members):raise ValueError('inventory missing an actual boundary member')
    assets={};channels={};physical_channels=set();physical_utxos=set();operator_controlled=0
    cln_sources={'frames':{},'bytes':0,'rows':0}
    for identity,member in members.items():
        event,inventory=_source_event(store,inventory_sequences[identity])
        if (event['kind']!='treasury_inventory' or inventory.get('member_id')!=identity
                or inventory.get('identity')!=member['identity'] or inventory.get('financial_pins')!=declaration['pins']
                or inventory.get('tip_hash')!=tip or inventory.get('height')!=height or inventory.get('complete') is not True):
            raise ValueError('actual inventory identity/pins/confirmed tip/coverage not verified')
        if member['kind']=='lightning_peer':
            if 'utxos' not in inventory or 'channels' not in inventory:
                raise ValueError('full CLN wallet and channel inventory coverage required')
            wallet_rows=inventory['utxos'];channel_rows=inventory['channels']
            if not isinstance(wallet_rows,list) or not isinstance(channel_rows,list) or len(wallet_rows)+len(channel_rows)>20000:
                raise ValueError('bounded CLN wallet and channel inventory rows required')
            entries=[('cash',row) for row in wallet_rows]+[('channel',row) for row in channel_rows]
        else:
            if not isinstance(inventory['utxos'],list) or len(inventory['utxos'])>20000:
                raise ValueError('inventory exceeds bounded coverage')
            entries=[('cash',row) for row in inventory['utxos']]
        for kind,entry in entries:
            outpoint=entry['funding_outpoint'] if kind=='channel' else entry['outpoint']
            txid,index=outpoint.rsplit(':',1);index=int(index)
            coin=chain.call('gettxout',txid,index,False)
            if coin is None or coin.get('confirmations',0)<1:raise ValueError('actual confirmed unspent backing missing')
            sat=btc_to_sat(coin['value']);script=coin['scriptPubKey']['hex']
            if kind=='channel':
                physical=(member['identity'],outpoint)
                if physical in physical_channels:raise InvariantError('same node physical channel counted twice under different aliases')
                physical_channels.add(physical)
                amount=integer(entry['owned_balance_msat'],'full owned channel balance')
                asset_id=member['identity']+'/'+entry['channel_id']
                peer=entry.get('peer_identity')
                if not peer:raise ValueError('actual channel counterparty identity missing')
                group=channels.setdefault(outpoint,{'capacity_msat':sat*1000,'owned_msat':0,'peers':set(),'inside':set()})
                group['peers'].update((member['identity'],peer));group['inside'].add(member['identity'])
                if group['capacity_msat']!=sat*1000:raise InvariantError('channel backing value changed')
                group['owned_msat']+=amount
            else:
                amount=sat*1000;asset_id=outpoint
                if outpoint in physical_utxos:raise InvariantError('same physical output counted twice')
                physical_utxos.add(outpoint)
                if entry['amount_sat']!=sat or entry['script']!=script:raise InvariantError('wallet inventory differs from actual chain output')
                if member['kind']=='wallet':
                    descriptor=member['descriptors'][integer(entry['descriptor_index'],'descriptor index')]
                    child=integer(entry['child_index'],'public wallet child')
                    if child>=2**31:raise ValueError('ordinary public wallet child required')
                    addresses=chain.call('deriveaddresses',descriptor,[child,child])
                    if len(addresses)!=1 or chain.call('validateaddress',addresses[0]).get('scriptPubKey')!=script:
                        raise InvariantError('actual output does not derive from declared wallet descriptor')
                elif member['kind']=='lightning_peer':
                    _cln_cash(store,member,entry,declaration,tip,height,coin['confirmations'],cln_sources)
                else:
                    proof_event,backing=_source_event(store,entry['verification_sequence'])
                    if (proof_event['kind']!='treasury_backing_verified' or backing.get('outpoint')!=outpoint
                            or backing.get('script')!=script or backing.get('financial_pins')!=declaration['pins']
                            or not backing.get('inside_members') or backing.get('server_identity')!=member['identity']
                            or set(backing.get('inside_members',[]))-set(members)):
                        raise ValueError('Ark backing ownership coverage unverified')
            if asset_id in assets:raise InvariantError('same physical asset/node balance counted twice')
            assets[asset_id]={'member':identity,'amount_msat':amount,'backing_outpoint':outpoint,'role':member['role']}
            if member['role']=='operator':operator_controlled+=amount
    for outpoint,group in channels.items():
        if outpoint in physical_utxos:raise InvariantError('channel funding and local balance counted as two physical assets')
        if group['owned_msat']>group['capacity_msat']:raise InvariantError('owned channel balances exceed physical capacity')
        declared_peers={m['identity'] for m in members.values() if m['kind']=='lightning_peer'}
        if group['peers']<=declared_peers and (group['inside']!=group['peers'] or group['owned_msat']!=group['capacity_msat']):
            raise ValueError('included channel peers/reserves/in-flight ownership do not cover physical capacity')
    end=chain.identity()
    if end['bestblockhash']!=tip:raise ValueError('chain changed during asset observation')
    return {'tip_hash':tip,'height':height,'assets':assets,'total_msat':sum(a['amount_msat'] for a in assets.values()),
            'operator_controlled_msat':operator_controlled,'scope':'confirmed tip and checked full owned channel inventories; accessibility and liabilities reported separately'}


def reconcile_edge(opening,closing,flows,liabilities,members):
    """Arithmetic only, not source/chain qualification. Inputs must be verified first.

    IDs deduplicate already evidenced flows; this helper cannot establish that a
    receipt happened or that an inventory is complete. capture_assets performs
    actual chain asset checks independently.
    """
    receipts=injections=payments=costs=0;seen=set()
    for flow in flows:
        if flow['id'] in seen:raise InvariantError('same monetary receipt/payment/injection counted twice')
        seen.add(flow['id']);amount=integer(flow['amount_msat'],'exact flow amount')
        source=flow['source'];destination=flow['destination']
        inside_source=source in members;inside_destination=destination in members
        kind=flow['kind']
        if inside_source and inside_destination:
            if kind!='internal_transfer':raise InvariantError('internal movement cannot be new income or external cost')
        elif not inside_source and inside_destination:
            if kind=='injection':injections+=amount
            elif kind=='external_receipt':receipts+=amount
            else:raise InvariantError('external inflow lacks its actual receipt/injection classification')
        elif inside_source and not inside_destination:
            if kind=='external_payment':payments+=amount
            elif kind in {'miner_cost','router_cost'}:costs+=amount
            else:raise InvariantError('external outflow classification missing')
        else:raise ValueError('unrelated outside transfer cannot affect conserved treasury')
    left=integer(opening['total_msat'],'opening assets')+receipts+injections
    right=integer(closing['total_msat'],'closing assets')+payments+costs
    if left!=right:raise InvariantError('treasury does not conserve to exact msat')
    operator_debt=0;liability_ids=set()
    for obligation in liabilities:
        if obligation['id'] in liability_ids:raise InvariantError('same liability counted twice')
        liability_ids.add(obligation['id']);amount=integer(obligation['amount_msat'],'liability')
        if obligation['borrower'] not in members:raise ValueError('liability borrower outside declared treasury')
        if members[obligation['borrower']]['role']=='operator':operator_debt+=amount
    return {'opening_msat':opening['total_msat'],'external_receipts_msat':receipts,'declared_injections_msat':injections,
            'closing_msat':closing['total_msat'],'external_payments_msat':payments,'miner_router_cost_msat':costs,
            'operator_controlled_msat':closing['operator_controlled_msat'],'operator_liabilities_msat':operator_debt,
            'operator_equity_msat':closing['operator_controlled_msat']-operator_debt,
            'liabilities':liabilities,'scope':'arithmetic only; flows require independent evidence; liabilities never added to physical assets'}
