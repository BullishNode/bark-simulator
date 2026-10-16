"""Same-capture ordinary signed carrier versions, never premature paid credit."""
from . import direct_settlements as direct
from .b_current_native_liabilities import _whole_journal
from .bundle_audit import decode_transaction
from .confirmed_scan import _tip
from .model import btc_to_sat,integer
from .ownership import EvidenceGap


def _need(value,message):
    if not value:raise EvidenceGap('B retained ordinary versions: '+message)


def activity_identity(row):
    from .owned_mempool import activity_result
    activity_result({'activity':[row]})
    if row['type']=='spend':
        return ('spend',row['spend_txid'],row['spend_vin'],
            row['prevout_txid']+':'+str(row['prevout_vout']),btc_to_sat(row['amount']),row['prevout_spk']['hex'])
    return ('receive',row['txid'],row['vout'],None,btc_to_sat(row['amount']),row['output_spk']['hex'])


def retained_ordinary_versions(store,chain,database,rights,*,scripts,tip):
    """Check all journal versions plus COMPLETE matching mempool activity.

    rights is the internally checked current_ordinary_liabilities result for
    these exact database bytes. Core unknown/missing versions hold. A replaced
    version is known only through an exact confirmed conflicting winner of its
    SAME freeze set; no ancestor/all-spent shortcut. No witness/raw bytes leave
    ChainReader's existing private/public projection boundary.
    """
    _tip(chain,tip);_,journal=_whole_journal(database)
    confirmed={g['result']['freeze_set']:g for g in rights['groups']}
    rows=journal['rows'];versions={};states={};checked={};selected=set();matching=set(scripts)
    for carrier in rows['carriers']:
        txid=carrier['txid']
        try:tx,raw=chain.transaction(txid),chain.tx(txid)
        except Exception as error:raise EvidenceGap('B retained ordinary versions: missing current Core version '+txid)from error
        body=decode_transaction(raw['hex'],public_body=True)
        _need(txid==body['txid']==tx.get('txid') and body['outputs']==tx['outputs']
            and [i['outpoint']for i in body['inputs']]==[i['outpoint']for i in tx['inputs']]
            and body['weight']==raw.get('weight') and body['vsize']==raw.get('vsize')
            and integer(tx['fee_sat'],'actual candidate fee')==carrier['miner_fee_sat']
            and sum(i['amount_sat']for i in tx['inputs'])-sum(o['amount_sat']for o in tx['outputs'])==tx['fee_sat'],
            'exact public body/prevouts/fee differs '+txid)
        allocations=[r for r in rows['allocations']if any(m['txid']==txid and m['allocation_id']==r['id']for m in rows['mappings'])]
        freezes={r['freeze_set']for r in allocations};_need(len(freezes)==1,'exact freeze identity absent '+txid)
        freeze=next(iter(freezes));winner=confirmed.get(freeze)
        if tx.get('confirmations',0)>0:
            _need(winner is not None and winner['transaction']==tx,'confirmed version lacks exact whole-group winner '+txid)
            result=winner['result'];state='confirmed'
        else:
            _need(tx.get('confirmations',0)==0 and tx.get('blockhash')is None,'unknown/conflicted Core outcome '+txid)
            result=direct.check_pending_candidate(store,journal,freeze,txid,tx)
            state='replaced'if winner is not None and set(result['physical_inputs'])&set(winner['result']['physical_inputs'])else 'mempool'
        checked[txid]=result;versions[txid]=tx;states[txid]=state
        selected.update(i['outpoint']for i in carrier['fee_inputs'])
        matching.update(i['script']for i in tx['inputs'])
    _need(len(matching)<=2000,'complete matching script bound')
    activity=chain.owned_activity(matching)
    expected=set()
    for txid,tx in versions.items():
        if states[txid]!='mempool':continue
        for index,coin in enumerate(tx['inputs']):
            if coin['script']in matching:expected.add(('spend',txid,index,coin['outpoint'],coin['amount_sat'],coin['script']))
        for coin in tx['outputs']:
            if coin['script']in matching:expected.add(('receive',txid,coin['vout'],None,coin['amount_sat'],coin['script']))
    actual=[activity_identity(row)for row in activity['activity']]
    _need(len(set(actual))==len(actual) and set(actual)==expected,'complete current mempool inputs/outputs differ')
    _need(chain.owned_activity(matching)==activity,'matching mempool state changed during observation')
    _tip(chain,tip)
    return {'versions':versions,'states':states,'checked_candidates':checked,
        'selected_fee_outpoints':sorted(selected),'mempool_activity':activity,
        'matching_scripts':sorted(matching),'pending_txids':sorted(k for k,v in states.items()if v=='mempool')}
