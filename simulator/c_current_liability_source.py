"""Conservative C current-source join; unresolved sources are never free cash.

Reuses retained-right/signed supersession rules. Native Full proof establishes
path validity only. This module does not run expiry classification with a future
height, resolve HTLC grants, or infer operator ownership from a missing client.
"""
import json
import time
from . import c_native_body_proof as native
from .c_private_native_body_cut import SOURCES
from .financial_transition import _current_claims
from .model import canonical,integer,public_payload,btc_to_sat
from .ownership import EvidenceGap,has_owner_record
from .per_key import record_bytes,link_bytes,binding_matches
from .normal_source_deadline import check as deadline_check


def reduce(store,loaded,paths,*,observation,server_pubkey,backings):
    """Pure source join AFTER collect_paths; every retained row remains covered.

    Output is an auxiliary audit, not treasury_liability_verified or readiness.
    The normal factory must refuse any unresolved source. It must separately
    authenticate this loaded cut, actual tool execution and current observation.
    """
    from .c_normal_source import _context
    _context(store,observation);deadline_check()
    if(paths.get('kind')!='c-native-body-path-auxiliary'or paths.get('source_observation')!=observation
            or paths.get('financial_pins')!=observation['financial_pins']or paths.get('complete')is not False
            or paths.get('qualified')is not False or paths.get('current_economic_ownership_complete')is not False
            or loaded['manifest']['source_observation']!=observation
            or loaded['manifest']['financial_pins']!=observation['financial_pins']):
        raise ValueError('original current C native cut/proof context differs')
    pg=loaded['private_pg'];database=loaded['database'];rows=database['rows']
    expected=[(table,row['metadata']['vtxo_id'])for table in SOURCES for row in pg[table]]
    supplied=[(p['source_table'],p['coin_id'])for p in paths['paths']]
    if len(supplied)!=len(set(supplied))or sorted(supplied)!=sorted(expected):raise ValueError('every actual native body requires one original path proof')
    by={(p['source_table'],p['coin_id']):p for p in paths['paths']};unresolved=[];supported=[]
    # The shared reducer removes only authenticated economic supersession, never
    # generic SDK Spent/expiry. Conditional public proofs remain unsupported here.
    try:claims=_current_claims(store)
    except (ValueError,KeyError,TypeError):
        claims=None
        unresolved.append({'source':'client_originals','id':'retained_rights','reason':'shared original-right reducer cannot authenticate whole current set'})
    claimed={}if claims is None else {v['coin_id']:v for v in claims}
    if claims is not None and len(claimed)!=len(claims):raise ValueError('original current rights duplicated')
    known={v['id']:dict(v)for v in store.db.execute('SELECT c.*,k.actor,k.mailbox FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey')}
    for table in SOURCES:
        for row in pg[table]:
            deadline_check();meta=row['metadata'];ident=meta['vtxo_id'];path=by[table,ident];proof=path['proof']
            # Rebind safe proof identity to SAME actual source, not a supplied
            # classification result or an unrelated native proof for this ID.
            if(path['economic_ownership']!='UNRESOLVED_REQUIRES_SAME_RR_CURRENT_SOURCE'
                    or proof['id']!=ident or proof['server_pubkey']!=server_pubkey
                    or path['body_sha256']!=native._sha(bytes.fromhex(row['body_hex']))):
                raise ValueError('same-RR native path/body binding differs')
            why=None
            if not path['signed_path_valid']:why='native signed path unresolved'
            elif table=='pool':why='pool retained/spent/retirement needs dedicated current operator-source classification'
            elif table=='pending_boards':why='pending board acceptance/physical transition needs independent current source'
            elif meta['policy_type']!='pubkey' or proof['policy_type']!='pubkey':why='conditional/delegated policy needs exact native current grant/attempt/round predicate'
            elif row['lightning_htlc_subscription_id']is not None or any(v['vtxo_id']==ident for v in pg['payment_links']):why='native payment/grant association remains economic source-specific'
            elif meta['spent_in_round']is not None or meta['offboarded_in']is not None:why='round/offboard transition needs exact current economic closure'
            elif any(meta[k]is not None for k in ('onchain_spent_height','onchain_spent_txid','oor_spent_txid')):why='actual registered physical/spend transition remains unresolved'
            elif meta['spend_state']!='spendable':why='registered status is not an authenticated current spendable customer right'
            elif ident not in claimed:why='no authenticated retained current customer right; never infer operator ownership'
            else:
                claim=claimed[ident];original=known.get(ident)
                if original is None:raise ValueError('current claimed original missing')
                original_proof=json.loads(original['proof'])
                if (original['pubkey']!=proof['user_pubkey']or claim['amount_sat']!=proof['amount_sat']
                        or meta['amount']!=proof['amount_sat']or meta['anchor_point']!=proof['chain_anchor']
                        or original_proof.get('chain_anchor')!=proof['chain_anchor']):
                    raise ValueError('native current customer identity/amount/anchor differs from original')
                bound=original_proof.get('binding',{})
                matching_links=[r for r in rows['links']if r['user_pubkey']==original['pubkey']]
                matching_records=[r for r in rows['records']if r['mailbox_pk']==original['mailbox']]
                if len(matching_links)!=1 or len(matching_records)!=1:
                    raise EvidenceGap('same-RR canonical customer record/key link missing or ambiguous')
                link=matching_links[0];record=matching_records[0]
                if (link['mailbox_pk']!=original['mailbox']or bound.get('mailbox_pk')!=original['mailbox']
                        or link_bytes(link)!=bound.get('key_link_attestation')
                        or not binding_matches(bound,{'mailbox_pk':record['mailbox_pk'],'spk':record['spk'],'fallback_record':record_bytes(record)})
                        or not has_owner_record(store,original['actor'],bound)):
                    raise ValueError('same-RR immutable V4/V1 payout binding differs from original customer proof')
                anchor=proof['chain_anchor'];backing=backings.get(anchor)
                if backing is None:
                    unresolved.append({'source':table,'id':ident,'reason':'independent current physical root absent/spent; no unpaid/paid inference'})
                    continue
                funding=paths['funding_originals'][anchor.split(':')[0]]['raw']
                decoded=native.decode_transaction(funding.hex());index=int(anchor.split(':')[1]);output=decoded['outputs'][index]
                if (type(backing.get('confirmations'))is not int or backing['confirmations']<1
                        or backing.get('bestblock')!=observation['tip_hash']or backing.get('coinbase')is not False
                        or btc_to_sat(backing['value'])!=output['amount_sat']or backing['scriptPubKey']['hex']!=output['script']):
                    raise ValueError('independent current root amount/script/tip differs from original funding')
                supported.append({'chain_anchor':anchor,'root_amount_sat':output['amount_sat'],'coin_id':ident,'actor':claim['actor'],'amount_msat':integer(claim['amount_sat'],'original customer principal',1)*1000,
                  'original_signed_hash':claim['signed_hash'],'native_response_sha256':path['response_sha256'],
                  'native_body_sha256':path['body_sha256'],'mailbox_pk':original['mailbox'],'fallback_record_sha256':native._sha(bytes.fromhex(bound['fallback_record'])),
                  'key_link_sha256':native._sha(bytes.fromhex(bound['key_link_attestation'])),'source_table':table,'status':'retained_customer_right'})
            if why:unresolved.append({'source':table,'id':ident,'reason':why})
    for anchor in {r['chain_anchor']for r in supported}:
        selected=[r for r in supported if r['chain_anchor']==anchor]
        if sum(r['amount_msat']for r in selected)>selected[0]['root_amount_sat']*1000:raise ValueError('customer claims exceed original physical root')
    checked={r['coin_id']for r in supported}
    for ident,claim in claimed.items():
        if ident not in checked and not any(v['id']==ident for v in unresolved):
            unresolved.append({'source':'client_originals','id':ident,'reason':'retained right absent from supported same-RR source; independent current unregistered/retirement source required'})
    # Noncoin economic association records must never disappear behind an empty
    # customer list. Presence is a source requirement, not an ownership verdict.
    for name in ('payments','receives','htlcs','rounds','participations','participation_inputs','participation_outputs'):
        if rows[name]:unresolved.append({'source':name,'id':'whole_retained_table','reason':'actual conditional/round source needs current economic reconciliation'})
    result={'kind':'c-current-liability-source-audit','source_observation':observation,'financial_pins':observation['financial_pins'],
      'height':observation['height'],'tip_hash':observation['tip_hash'],'observed_at':time.time(),
      'supported_retained_customer_rights':supported,'unresolved':unresolved,
      'original_private_source_references':loaded['original_private_source_references'],
      'native_path_response_sha256':[p['response_sha256']for p in paths['paths']],
      'complete':False,'qualified':False,'financial_readiness':False,
      'scope':'current source audit only; supported rights remain liabilities, unresolved never becomes operator capital or paid'}
    public_payload(result);deadline_check();return result


def collect(store,chain,loaded,tool,*,tool_identity,observation,server_pubkey):
    """Compose the existing actual native tool lifecycle, then conservative join."""
    original=canonical(observation)
    paths=native.collect_paths(loaded,chain,tool,tool_identity=tool_identity,observation=observation,server_pubkey=server_pubkey)
    backings={}
    for path in paths['paths']:
        anchor=path['proof']['chain_anchor']
        if anchor not in backings:
            txid,index=native._point(anchor);backings[anchor]=chain.call('gettxout',txid,index,True)
    current=chain.identity()
    if (current.get('blocks'),current.get('bestblockhash'))!=(observation['height'],observation['tip_hash']):raise ValueError('current backing source tip changed')
    result=reduce(store,loaded,paths,observation=observation,server_pubkey=server_pubkey,backings=backings)
    if canonical(observation)!=original:raise ValueError('native liability observation mutated')
    return {'safe':result,'private_path_originals':paths,'private_core_backings':backings}


def require_resolved(audit):
    """No blanket nativeFull/signature flag can promote unresolved ownership."""
    if audit.get('kind')!='c-current-liability-source-audit'or audit.get('unresolved'):
        raise EvidenceGap('complete current conditional/round/pool/retirement economic source missing')
    return audit['supported_retained_customer_rights']
