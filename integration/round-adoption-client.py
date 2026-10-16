#!/usr/bin/env python3
"""A declared regtest fixture drives the normal confirmed-round scheduler.

No funding or mining RPCs are accepted. The wrapper supplies public server
inventory; each customer sync is selected and fenced by the actual scheduler.
"""
import asyncio,json,os,sys,time
from dataclasses import replace
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from simulator.config import Config
from integration.fixture_runtime import fixture_profile
from simulator.engine import Engine,initialize
from simulator.store import Store
from simulator.ownership import record_server_page
from simulator.padding import collect as collect_decoder
from simulator.round_adoption import candidate_rounds,collect_input_params,runtime_parameters
from simulator.continuous import schedule

m=json.loads(Path(sys.argv[1]).read_text());phase=sys.argv[2]
assert m['network']=='regtest' and m['core_url'].startswith('http://127.0.0.1:')
profile=fixture_profile(m)
os.environ['SIM_DRIVER_CONFIG']=m['driver_config']
cfg=Config(architecture_profile=profile,expected_sdk_commit=m.get('sdk_commit'),state_dir=Path(m['state_dir']),wallet_root=Path(m['wallet_root']),
    observer_command=(sys.executable,str(ROOT/'integration/regtest-client.py'),'observer',sys.argv[1]),
    driver_command=(m['driver'],),expected_genesis=m['genesis'],expected_container='regtest-local-captaind',
    expected_image='sha256:'+m['server_binary_sha256'],expected_server_pubkey=m['server_pubkey'],
    fee_budget_sat=m['fee_budget_sat'],interval_seconds=1,action_timeout_seconds=120,active=True,network='regtest',
    proof_command=(m['proof'],m['core_url'],m['core_cookie'],m['server_pubkey']),
    campaign_seed='confirmed-round-fixture-v1',absence_hazard_per_day=0,absent_payment_probability=0,dispatch_per_tick=2,
    server_policy_command=(m['server_policy'],))
store=Store(cfg.state_dir,'live',cfg.fee_budget_sat,architecture_profile=profile);initialize(store)
actors=('actor-02','actor-08')
try:
    refreshes=list(store.db.execute("SELECT * FROM action WHERE operation IN ('refresh','refresh_delegated')"))
    assert len(refreshes)==2 and {r['actor_id'] for r in refreshes}==set(actors)
    assert all(r['state']=='completed' and r['actual_fee_sat'] is None for r in refreshes)
    input_ids=[]
    for actor in actors:
        parameters=runtime_parameters(store,actor)
        assert parameters['round_tx_required_confirmations']==1 and parameters['vtxo_exit_margin']==12
        movements=[json.loads(r[0]) for r in store.db.execute('SELECT payload FROM movement_evidence WHERE actor=?',(actor,))]
        pending=[v for v in movements if v['status']=='pending' and v['subsystem']=='bark.round' and v['input_vtxos']]
        assert len(pending)==1
        input_ids.extend(pending[0]['input_vtxos'])
    if phase=='pending':
        print(json.dumps({'pending_actors':list(actors),'source':'actual native movement evidence','wallet_calls':0,'input_coin_ids':input_ids}))
    else:
        assert phase=='cycle'
        inventory=json.loads((Path(m['out_dir'])/'round-scheduler-inventory.json').read_text())
        for kind in ('coins','nursery'):
            rows=inventory[kind]
            for start in range(0,len(rows),100):record_server_page(store,{'kind':kind,'rows':rows[start:start+100],'next':None,'inventory_consistent':False})
        async def cycle():
            await collect_decoder(store,cfg.server_policy_command,cfg.expected_server_pubkey,limit=32)
            await collect_input_params(store,cfg,limit=32)
            engine=Engine(cfg,store)
            snapshot=await engine.observe()
            candidates=candidate_rounds(store,cfg)
            assert {c['actor'] for c in candidates}==set(actors),'real pending rounds must match exact decoded confirmed nursery anchors'
            assert all(snapshot['height']-c['confirmed_height']+1>=1 for c in candidates)
            before=store.db.execute('SELECT count(*) FROM action').fetchone()[0]
            schedule(store,cfg,snapshot)
            queued=list(store.db.execute("SELECT * FROM action WHERE state='queued'"))
            assert len(queued)==2 and {q['actor_id'] for q in queued}==set(actors)
            assert all(q['operation']=='sync' and q['fee_reservation_sat']==2000 for q in queued)
            tick=json.loads(store.db.execute("SELECT payload FROM event WHERE kind='scheduler_tick' ORDER BY sequence DESC LIMIT 1").fetchone()[0])
            assert all(d['rule_id']=='round_confirmed_sync' and d['outcome']=='queued' for d in tick['actors'])
            assert await engine.dispatch_batch()
            for candidate in candidates:
                actor=candidate['actor'];action=next(q for q in queued if q['actor_id']==actor)
                result=store.db.execute('SELECT state,result FROM action WHERE id=?',(action['id'],)).fetchone()
                assert result['state']=='completed'
                for coin in candidate['replacement_outputs']:
                    observed=store.db.execute("SELECT c.amount_sat,c.pubkey,k.actor FROM coin_observation o JOIN owned_coin c ON c.id=o.coin_id JOIN owner_key k ON k.pubkey=c.pubkey WHERE o.action_id=? AND o.coin_id=? AND o.state='Spendable'",(action['id'],coin['coin_id'])).fetchone()
                    assert observed and (observed['actor'],observed['pubkey'],observed['amount_sat'])==(actor,coin['pubkey'],coin['amount_sat']),'same scheduled sync must independently verify and adopt each new signed replacement'
                movements=[json.loads(r[0]) for r in store.db.execute('SELECT payload FROM movement_evidence WHERE actor=?',(actor,))]
                assert any(v['id']==candidate['pending_movement_id'] and v['status']=='successful' and set(v['output_vtxos'])==set(candidate['expected_output_coin_ids']) for v in movements)
            assert store.db.execute('SELECT count(*) FROM action').fetchone()[0]==before+2,'one cycle must not hide extra syncs or snapshots'
            return {'result':'PASS','scheduler_cycles':1,'customer_syncs':2,'automatic_confirmation_rule':True,
                'candidates':candidates,'scheduler_tick':tick,'scope':'isolated regtest lifetime432, actual SDK depth1 and margin12; unsafe shorter lifetimes remain held'}
        result=asyncio.run(cycle());(Path(m['out_dir'])/'round-scheduler-result.json').write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result))
    store.verify_event_chain()
finally:store.close()
