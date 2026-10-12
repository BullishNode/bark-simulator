#!/usr/bin/env python3
"""Explicit exit phases and independent accounting on a declared regtest fixture.

This controller cannot fund or mine. Only start/advance/inspect opens an online
fixture wallet; audit consumes public signed proofs and read-only Core evidence.
"""
import asyncio,json,os,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from simulator.chain import ChainReader
from simulator.model import canonical,public_payload
from simulator.ownership import record_candidates,record_verified,verify_client_evidence
from simulator.process import json_command
from simulator.store import Store
from simulator.unknown_outcomes import resolve


async def run(phase,manifest,command):
    m=json.loads(Path(manifest).read_text())
    assert m.get('exit_fixture') is True and m['network']=='regtest'
    assert m['core_url'].startswith('http://127.0.0.1:')
    assert phase in {'start','advance','inspect','probe_cap','audit'}
    os.environ['SIM_DRIVER_CONFIG']=m['driver_config']
    store=Store(Path(m['state_dir']),'live',m.get('fee_budget_sat',100000))
    try:
        store.verify_event_chain()
        assert not store.get_meta('paused')
        chain=ChainReader(m['core_url'],m['core_cookie'],m['genesis'])
        chain.identity()
        action_id=command['action_id'];actor=command['actor']
        assert actor not in {'actor-09','actor-10'}
        actor_row=store.db.execute('SELECT * FROM actor WHERE id=?',(actor,)).fetchone()
        assert actor_row is not None
        if phase=='start':
            assert store.online(actor)
            assert not store.db.execute("SELECT 1 FROM action WHERE operation='exit' AND state IN ('queued','dispatched','outcome_unknown')").fetchone()
            args=command['args'];assert args.get('phase','start')=='start'
            store.queue(action_id,actor,'H34','exit',args,command['maximum_fee_sat'])
            action=store.claim({'exit'});assert action and action['id']==action_id
            action['state']='dispatched' # claim returns the pre-transition row.
        else:
            row=store.db.execute('SELECT * FROM action WHERE id=?',(action_id,)).fetchone()
            assert row is not None and row['actor_id']==actor and row['operation']=='exit'
            action=dict(row);action['args']=json.loads(row['args'])
        if phase=='audit':
            rows=store.db.execute("SELECT payload FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')='exit_proposal' AND json_extract(payload,'$.data.stage') IN ('cpfp','claim')",(action_id,)).fetchall()
            transactions={}
            for row in rows:
                txid=json.loads(row[0])['data']['txid']
                try:transactions[txid]=chain.transaction(txid)
                except ValueError:pass # Unconfirmed/missing proof retains the full reservation.
            proved=resolve(store,action_id,transactions)
            row=store.db.execute('SELECT state,actual_fee_sat FROM action WHERE id=?',(action_id,)).fetchone()
            print(canonical({'resolved':proved,'state':row['state'],'actual_fee_sat':row['actual_fee_sat'],'transactions':transactions,'wallet_opened':False}))
            return
        details=json.loads(actor_row['details'])
        assert store.online(actor) and not details.get('permanent_absence')
        assert action['state'] in {'dispatched','outcome_unknown'}
        args={**action['args'],'phase':'inspect' if phase=='probe_cap' else phase}
        request={'action_id':action_id,'operation':'exit','actor_dir':str(Path(m['wallet_root'])/actor),
            'expected_server_pubkey':m['server_pubkey'],'args':args,
            'maximum_fee_sat':action['fee_reservation_sat']+(1 if phase=='probe_cap' else 0)}
        frames=[];boundaries=[]
        def event(value):
            public_payload(value)
            assert value['action_id']==action_id
            store.event('driver_evidence',{'action_id':action_id,'actor':actor,'operation':'exit','event':value['event'],'data':value['data']})
            if value['event'] in {'client_evidence_before','client_evidence_after'}:
                assert value['data']['fresh'] is True
                boundaries.append(value['event'])
                frames.append(value['data']['evidence'])
        store.event('fixture_exit_phase',{'action_id':action_id,'phase':phase,'request':request})
        try:
            response=await json_command([m['driver']],request,timeout=120,on_event=event)
            assert response['action_id']==action_id
            store.event('driver_response',{'action_id':action_id,'actor':actor,'response':response})
        except Exception:
            if phase=='start':store.finish(action_id,'outcome_unknown',{'reason':'exit fixture lost native response'})
            raise
        if phase=='start':
            # Persisted exit intent is not completion, even when its first call
            # broadcasts. Independent confirmation closes the original budget.
            store.finish(action_id,'outcome_unknown',response)
        assert boundaries==['client_evidence_before','client_evidence_after']
        for frame in frames:
            data={'evidence':frame}
            record_candidates(store,actor,action_id,data)
            checked=await verify_client_evidence(store,actor,'exit',data,
                (m['proof'],m['core_url'],m['core_cookie'],m['server_pubkey']))
            assert checked is not None
            record_verified(store,actor,action_id,checked)
        if phase=='probe_cap':assert response['status']=='error'
        else:assert response['status']=='ok',response
        row=store.db.execute('SELECT state,actual_fee_sat FROM action WHERE id=?',(action_id,)).fetchone()
        assert row['state']=='outcome_unknown' and row['actual_fee_sat'] is None
        print(canonical(response))
    finally:
        store.verify_event_chain()
        store.close()


if __name__=='__main__':
    asyncio.run(run(sys.argv[1],sys.argv[2],json.loads(sys.argv[3])))
