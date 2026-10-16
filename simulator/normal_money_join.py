"""Append verified money records without rewriting original source/history.

This module is a journal join, not a money verifier. Its caller must execute the
separately source-qualified verifier against actual Core/native/intent sources.
"""
from .final_campaign import _source_event
from .model import integer,public_payload


def journal_money_sources(store,result,source_event,source,*,helper_sha256):
    checkpoint=store.db.execute('SELECT COALESCE(max(sequence),0) FROM event').fetchone()[0]
    kinds={'cost_records':'financial_cost_verified','flow_records':'treasury_flow_verified'}
    supplied={};known={};all_ids=set();record_ids=set()
    for field,kind in kinds.items():
        existing={}
        for row in store.db.execute('SELECT sequence FROM event WHERE kind=? ORDER BY sequence',(kind,)):
            event,body=_source_event(store,row[0]);identifier=body['monetary_id']
            if identifier in all_ids:raise ValueError('historical monetary ID repeated')
            all_ids.add(identifier);existing[identifier]=body
        known[field]=existing;records=result[field]
        if not isinstance(records,list) or len(records)>20000:raise ValueError('bounded verified monetary records required')
        supplied[field]={}
        for body in records:
            public_payload(body);identifier=body['monetary_id'];integer(body['amount_msat'],'actual monetary amount',1)
            if identifier in record_ids:raise ValueError('same verified monetary record supplied twice')
            record_ids.add(identifier)
            if identifier in existing:
                if existing[identifier]!=body:raise ValueError('original monetary record cannot be rewritten')
            else:
                if identifier in all_ids or body.get('financial_pins')!=source['financial_pins']:
                    raise ValueError('new monetary record identity/pins differ')
                if field=='cost_records' and (body.get('kind')!='miner_cost' or identifier!='miner:'+body['txid'] or body.get('budget') not in {'ordinary','urgent'}):
                    raise ValueError('confirmed positive miner-cost source required')
                if field=='flow_records' and body.get('kind') not in {'injection','internal_transfer'}:
                    raise ValueError('unresolved external receipt/payment needs its own verifier')
            supplied[field][identifier]=body
        reused=result['reused_cost_ids' if field=='cost_records' else 'reused_flow_ids']
        if not isinstance(reused,list) or len(set(reused))!=len(reused) or set(reused)-set(existing):
            raise ValueError('reused monetary IDs are not existing immutable records')
    parent,original=_source_event(store,source_event['sequence'])
    if parent['hash']!=source_event['hash'] or original!=source:
        raise ValueError('original financial source changed before monetary join')
    with store.transaction():
        store.verify_event_chain()
        if store.db.execute('SELECT COALESCE(max(sequence),0) FROM event').fetchone()[0] != checkpoint:
            raise ValueError('source journal changed before monetary join')
        for field,kind in kinds.items():
            for identifier,body in supplied[field].items():
                if identifier not in known[field]:store._event(kind,body)
        sequences={field:[row[0] for row in store.db.execute('SELECT sequence FROM event WHERE kind=? ORDER BY sequence',(kind,))]
            for field,kind in [('cost_sequences','financial_cost_verified'),('flow_sequences','treasury_flow_verified')]}
        joined={**source,**sequences,'original_source_sequence':parent['sequence'],'original_source_hash':parent['hash'],
            'money_helper_sha256':helper_sha256,'money_evidence_hashes':result['evidence_hashes'],
            'zero_fee_carriers':result['zero_fee_carriers'],'pending_money_carriers':result['pending_carriers'],
            'client_service_charges':result.get('client_service_charges',[])}
        public_payload(joined);store._event('normal_financial_source_cost_join',joined)
        sequence=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    event,body=_source_event(store,sequence)
    return event,body
