"""Exact B owning public pending graph versus same-cut Core/descriptor scan."""
from .bundle_audit import decode_transaction
from .model import integer,canonical
from .ownership import EvidenceGap
from .two_step_capture import WALLET_FIELDS,UTXO_FIELDS


def need(value,text):
    if not value:raise EvidenceGap('B pending owning wallet: '+text)


def owning_projection(member,native,*,scripts,scan,versions,chain,tip):
    need(native['network']=='signet' and (native['tip_height'],native['tip_hash'])==tip
        and member['descriptors']==[native['public_descriptor']]
        and not native['unavailable_parent_txids'],'identity/tip/descriptor or unavailable parent')
    pending=native['pending_transactions'];parents=native.get('pending_parents',[])
    need(all(isinstance(rows,list)and len(rows)<=2000 for rows in (pending,parents,native['utxos']))
        and len(canonical(native).encode())<=8*1024*1024,'whole owning source bounds')
    mine={s for s,o in scripts.items()if o['member_id']==member['id']}
    expected_pending={txid:tx for txid,tx in versions['versions'].items()
        if versions['states'][txid]=='mempool' and any(c['script']in mine for c in tx['inputs']+tx['outputs'])}
    need(len({r['txid']for r in pending})==len(pending)and {r['txid']for r in pending}==set(expected_pending),
        'whole pending identity set differs from Core')
    all_rows={};core_raw={}
    for row in pending+parents:
        need(set(row)=={'txid','transaction_body','signed_weight_wu','encoding'}
            and row['encoding']=='bitcoin-stripped-body-v1','public pending/parent encoding differs')
        body=decode_transaction(row['transaction_body'],public_body=True)
        need(body['witness_redacted']is False and body['txid']==row['txid'],'stripped identity differs')
        raw=chain.tx(row['txid']);core=decode_transaction(raw['hex'],public_body=True)
        need(body['stripped_hex']==core['stripped_hex']and row['signed_weight_wu']==raw['weight'],
            'public body/actual signed weight differs')
        need(row['txid']not in all_rows,'duplicate pending/parent identity')
        all_rows[row['txid']]=body;core_raw[row['txid']]=raw
    expected_parents={i['outpoint'].split(':')[0]for tx in expected_pending.values()for i in tx['inputs']}
    need({r['txid']for r in parents}==expected_parents,'complete pending parent set differs')
    confirmed={c['txid']+':'+str(c['vout']):{'outpoint':c['txid']+':'+str(c['vout']),
        'amount_sat':c['amount_sat'],'script':c['script'],'descriptor_index':scripts[c['script']]['descriptor_index'],
        'child_index':scripts[c['script']]['child_index']}for c in scan if c['script']in mine}
    spent={i['outpoint']for tx in expected_pending.values()for i in tx['inputs']if i['script']in mine}
    outputs={txid+':'+str(c['vout']):(c['amount_sat'],c['script'])for txid,tx in expected_pending.items()
        for c in tx['outputs']if c['script']in mine}
    expected={k:(v['amount_sat'],v['script'])for k,v in confirmed.items()if k not in spent}
    expected.update(outputs);seen={}
    for coin in native['utxos']:
        point=coin['outpoint'];integer(coin['value_sat'],'owning amount',1)
        need(point not in seen and coin['script_pubkey']in mine and coin['keychain']=='external'
            and coin['derivation_index']==scripts[coin['script_pubkey']]['child_index'],
            'exact owning derivation or duplicate differs')
        need(type(coin['confirmations'])is int and coin['confirmations']>=0,'confirmation source absent')
        for flag in ('mature','trusted','reserved','confirmed_fee_eligible'):
            need(type(coin.get(flag))is bool,'actual '+flag+' absent')
        if point in outputs:
            need(coin['confirmations']==0 and coin['confirmed_fee_eligible']is False,'pending change cannot fund fees')
        else:need(coin['confirmations']>=1,'unclassified unconfirmed output')
        seen[point]=(coin['value_sat'],coin['script_pubkey'])
    need(seen==expected,'whole native unspent graph differs from Core confirmed cut plus pending edges')
    reserved=set(native['reserved_outpoints'])
    need(len(reserved)==len(native['reserved_outpoints'])and reserved<=set(confirmed)|set(outputs),
        'unknown/duplicate native reservation')
    for point in spent:
        need(point in confirmed,'pending owned input missing from complete confirmed scan')
    report={key:native[key]for key in WALLET_FIELDS}
    report['pending_parents']=parents
    report['utxos']=[{key:r[key]for key in UTXO_FIELDS}for r in native['utxos']]
    # Confirmed physical inventory is independently from Core; the literal BDK
    # graph above remains intact. Mempool-selected inputs stay physical at this
    # confirmed cut but are RESERVED, never reusable urgent cash.
    report['reserved_outpoints']=sorted(reserved|spent)
    return report,list(confirmed.values())
