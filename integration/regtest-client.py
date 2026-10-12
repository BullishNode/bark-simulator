#!/usr/bin/env python3
"""Isolated fixture controller exercising the actual simulator journal/driver.

Only a trusted Rust fixture launches this tool. It cannot mine or fund a chain;
those events remain separately declared fixture/operator actions. Recovery runs
only after the fixture proves a confirmed rightful payout, in another process
without opening the absent Bark DB.
"""
import asyncio,base64,hashlib,json,os,shutil,subprocess,sys,time,urllib.request
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from simulator.config import Config
from simulator.engine import Engine,initialize
from simulator.store import Store
from simulator.report import generate
from simulator.raw_cases import RAW_CASES

mode=sys.argv[1];manifest=Path(sys.argv[2]);m=json.loads(manifest.read_text())
command=json.loads(sys.argv[3]) if len(sys.argv)>3 else {}
actor=command.get('actor','actor-01')
assert actor in {f'actor-{i:02}' for i in range(1,13)}
assert m['network']=='regtest' and m['core_url'].startswith('http://127.0.0.1:')

def rpc(method,*args):
    credential=Path(m['core_cookie']).read_text().strip()
    body=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':list(args)}).encode()
    request=urllib.request.Request(m['core_url'],body,{'Authorization':'Basic '+base64.b64encode(credential.encode()).decode(),'Content-Type':'application/json'})
    response=json.load(urllib.request.urlopen(request,timeout=90),parse_float=Decimal)
    if response.get('error'):raise RuntimeError('fixture Core RPC failed')
    return response['result']

def config():
    return Config(state_dir=Path(m['state_dir']),wallet_root=Path(m['wallet_root']),
        observer_command=(sys.executable,str(Path(__file__).resolve()),'observer',str(manifest)),
        driver_command=(m['driver'],),expected_genesis=m['genesis'],expected_container='regtest-local-captaind',
        expected_image='sha256:'+m['server_binary_sha256'],expected_server_pubkey=m['server_pubkey'],
        fee_budget_sat=m.get('fee_budget_sat',10000),interval_seconds=1,action_timeout_seconds=120,active=True,network='regtest',
        proof_command=(m['proof'],m['core_url'],m['core_cookie'],m['server_pubkey']))

os.environ['SIM_DRIVER_CONFIG']=m['driver_config']
if mode=='observer':
    before=rpc('getblockchaininfo');genesis=rpc('getblockhash',0)
    request={'operation':'info','expected_server_pubkey':m['server_pubkey'],'action_id':'fixture-info'}
    proc=subprocess.run([m['driver']],input=json.dumps(request),text=True,capture_output=True,check=True,timeout=45)
    info=json.loads(proc.stdout.splitlines()[-1]);assert info['status']=='ok'
    assert info['data']['network']=='regtest'
    after=rpc('getblockchaininfo')
    print(json.dumps({'identity':{'network':'regtest','genesis':genesis,'container':'regtest-local-captaind',
        'image_digest':'sha256:'+hashlib.sha256(Path(m['server_binary']).read_bytes()).hexdigest(),
        'server_pubkey':info['data']['server_pubkey']},'observed_at':time.time(),'height':after['blocks'],
        'tip_hash':after['bestblockhash'],'stable_tip':before['bestblockhash']==after['bestblockhash'],
        'initial_block_download':after['initialblockdownload'],'server_status':{'status':'running'},
        'complete':False,'rounds_confirmed_sat':None,'validation_scope':'isolated fixture; full capital is separately audited'}))
elif mode=='fixture_backup':
    # The explicit fixture saves its private recovery backup while online.
    store=Store(Path(m['state_dir']),'live',m.get('fee_budget_sat',10000))
    try: assert store.online(actor)
    finally: store.close()
    backup=Path(m['wallet_root']).parent/'fixture-recovery-backup.seed'
    assert not backup.exists()
    shutil.copyfile(Path(m['wallet_root'])/actor/'mnemonic',backup)
    backup.chmod(0o600)
    print(json.dumps({'backup_created_while_online':True}))
elif mode in {'verified_recovery','verified_recovery_confirm'}:
    from simulator.chain import ChainReader
    from simulator.model import canonical
    from simulator.operator_scripts import collect as collect_operator
    from simulator.ownership import record_server_page
    from simulator.proof_import import collect as collect_proofs
    from simulator.recovery import RecoveryController
    from simulator.settlements import collect_settlements
    out=Path(m['out_dir'])
    cfg=replace(config(),state_dir=Path(m['state_dir']).parent/'public-payout-oracle',
        proof_bundles=(out/'public-proof-bundle.json',),operator_descriptors=(out/'public-operator-descriptor.json',),
        recovery_command=(m['restore'],m['core_url'],m['core_cookie']),recovery_destination=m['recovery_destination'],
        recovery_seeds=((actor,Path(m['wallet_root']).parent/'fixture-recovery-backup.seed'),),
        recovery_maximum_fee_sat=2000,recovery_timeout_seconds=240,funding_wallet=rpc('listwallets')[0])
    store=Store(cfg.state_dir,'live',cfg.fee_budget_sat)
    initialize(store)
    controller=RecoveryController(store,cfg)
    chain=ChainReader(m['core_url'],m['core_cookie'],m['genesis'])
    async def verify_and_recover():
        if mode=='verified_recovery':
            inventory=json.loads((out/'public-payout-inventory.json').read_text())
            store.bind_target({'network':'regtest','genesis':m['genesis'],'server_pubkey':m['server_pubkey'],
                'container':cfg.expected_container,'image_digest':cfg.expected_image})
            store.set_online(actor,False)
            store.db.execute('UPDATE actor SET details=? WHERE id=?',
                (canonical({'binding':inventory['binding'],'permanent_absence':{'fixture':True}}),actor))
            store.db.execute('INSERT INTO operator_script VALUES (?,?)',
                (inventory['operator_anchor']['script'],canonical(inventory['operator_anchor'])))
            record_server_page(store,{'kind':'settlements','rows':inventory['settlements'],'next':None,'inventory_consistent':False})
            assert store.db.execute('SELECT COUNT(*) FROM owned_coin').fetchone()[0]==0
            await collect_settlements(store,chain)
            assert store.db.execute('SELECT state FROM settlement_check').fetchone()[0]=='pending'
            assert await collect_proofs(store,cfg)==1
            await collect_settlements(store,chain)
            assert store.db.execute('SELECT reason FROM settlement_check').fetchone()[0]=='operator change ownership is unverified'
            await collect_operator(store,cfg,chain)
            await collect_settlements(store,chain)
            assert store.db.execute('SELECT state FROM settlement_check').fetchone()[0]=='amounts_checked'
        deadline=time.monotonic()+240
        while True:
            await controller.tick()
            row=store.db.execute('SELECT * FROM seed_recovery').fetchone()
            if row and row['state'] in ({'broadcast'} if mode=='verified_recovery' else {'confirmed'}):break
            assert time.monotonic()<deadline,'automated recovery did not reach its proven boundary'
            assert row is None or row['state'] not in {'held','prepare_unknown','outcome_unknown'},'automated recovery held for missing or contradictory evidence'
            await asyncio.sleep(0.1)
        assert not store.online(actor)
        assert store.db.execute("SELECT COUNT(*) FROM event WHERE kind IN ('driver_request','ark_transfer_verified','recycle_confirmed')").fetchone()[0]==0
        assert store.db.execute("SELECT COUNT(*) FROM event WHERE kind='seed_recovery_spend'").fetchone()[0]==1
        if mode=='verified_recovery_confirm':
            capital=dict(store.db.execute('SELECT * FROM recovered_capital').fetchone())
            assert capital['recovered_sat']==capital['gross_sat']-capital['fee_sat'] and capital['fee_sat']<=2000
            return {'state':'confirmed','capital':capital,'original_wallet_calls':0,'traffic_credit':0,'recycling_credit':0}
        return json.loads(row['prepared'])
    try:
        result=asyncio.run(verify_and_recover())
        store.verify_event_chain()
        (out/(mode+'.json')).write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result))
    finally:
        asyncio.run(controller.close())
        store.close()
elif mode=='recover':
    # The verifier does not receive a txid/address-index/birthday hint.
    payout=json.loads(Path(m['payout_proof']).read_text())
    tx=rpc('getrawtransaction',payout['txid'],True)
    assert tx.get('confirmations',0)>0 and tx['vout'][payout['vout']]['scriptPubKey']['hex']==payout['spk']
    store=Store(Path(m['state_dir']),'live',m.get('fee_budget_sat',10000))
    try: assert not store.online('actor-01')
    finally: store.close()
    with (Path(m['wallet_root'])/'actor-01/mnemonic').open() as seed:
        proc=subprocess.run([m['restore'],m['core_url'],m['core_cookie'],m['recovery_destination'],'3','10000'],
            stdin=seed,text=True,capture_output=True,timeout=240)
    assert proc.returncode==0,'plain BIP84 recovery failed'
    result=json.loads(proc.stdout)
    assert f"{payout['txid']}:{payout['vout']}" in {c['outpoint'] for c in result['inputs']}
    Path(m['out_dir'],'restore.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
elif mode=='fee_audit':
    from simulator.chain import ChainReader
    from simulator.fees import collect
    cfg=config()
    store=Store(cfg.state_dir,'live',cfg.fee_budget_sat)
    try:
        before=store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]
        chain=ChainReader(m['core_url'],m['core_cookie'],m['genesis'])
        asyncio.run(collect(store,chain,limit=16))
        assert store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]==before
        print(json.dumps([dict(r) for r in store.db.execute("SELECT id,actor_id,operation,actual_fee_sat FROM action WHERE operation IN ('board','offboard_all','refresh','refresh_delegated','pay_invoice') AND state='completed' ORDER BY id")]))
        store.verify_event_chain()
    finally:store.close()
elif mode=='receive_fee_audit':
    from simulator.chain import ChainReader
    from simulator.fees import collect
    cfg=config();store=Store(cfg.state_dir,'live',cfg.fee_budget_sat)
    try:
        asyncio.run(collect(store,ChainReader(m['core_url'],m['core_cookie'],m['genesis']),limit=64))
        rows=store.db.execute("SELECT payload FROM event WHERE kind='client_fee_reconciled' AND json_type(payload,'$.receive_movement_ids')='array' AND json_extract(payload,'$.actor')='actor-02'").fetchall()
        assert len(rows)==1,'actual internal Lightning receive claim not independently accounted once'
        proof=json.loads(rows[0][0]);assert len(proof['claims'])==1
        claim=proof['claims'][0];assert claim['principal_sat']==claim['signed_output_sat']+claim['service_charge_sat']==2000
        assert claim['service_charge_sat']==proof['actual_fee_sat']==0
        store.verify_event_chain();print(json.dumps(proof))
    finally:store.close()
elif mode=='payment_audit':
    from simulator.payments import collect
    cfg=config()
    store=Store(cfg.state_dir,'live',cfg.fee_budget_sat)
    try:
        before=store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]
        asyncio.run(collect(store,cfg.driver_command,cfg.expected_server_pubkey))
        assert store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0]==before
        rows=store.db.execute("SELECT id,result,actual_fee_sat FROM action WHERE operation='pay_invoice' ORDER BY id").fetchall()
        print(json.dumps([{'id':r['id'],'payment':json.loads(r['result'])['data'],
            'actual_fee_sat':r['actual_fee_sat']} for r in rows]))
        store.verify_event_chain()
    finally:store.close()
elif mode=='clock_audit':
    from simulator.campaign import collect_ark_receipts,traffic_ready
    cfg=config();store=Store(cfg.state_dir,'live',cfg.fee_budget_sat)
    try:
        collect_ark_receipts(store)
        before=store.db.execute("SELECT COUNT(*) FROM event WHERE kind='ark_transfer_verified'").fetchone()[0]
        collect_ark_receipts(store)
        after=store.db.execute("SELECT COUNT(*) FROM event WHERE kind='ark_transfer_verified'").fetchone()[0]
        assert before==after==1,'one actual signed recipient receipt must count once'
        first=store.db.execute("SELECT MIN(updated_at) FROM action WHERE operation='send_arkoor'").fetchone()[0]
        store.db.execute("INSERT OR REPLACE INTO meta VALUES ('real_campaign_started',?)",(str(first),))
        assert traffic_ready(store),'both actual native traffic rails must qualify inside their windows'
        row=store.db.execute("SELECT payload FROM event WHERE kind='ark_transfer_verified'").fetchone()
        store.verify_event_chain();print(json.dumps({'ark_receipt':json.loads(row[0]),'receipt_count':after,'both_rails_ready':True}))
    finally:store.close()
elif mode=='scheduled_refresh':
    from simulator.continuous import schedule
    cfg=config();store=Store(cfg.state_dir,'live',cfg.fee_budget_sat)
    try:
        details=json.loads(store.db.execute('SELECT details FROM actor WHERE id=?',(actor,)).fetchone()[0])
        assert details['registered_spendable_sat']==0 and details['needs_refresh_sat']>0
        online={r['id']:r['online'] for r in store.db.execute('SELECT id,online FROM actor')}
        # Fixture-only eligibility isolation; originals are untouched and the
        # exact actor online flags are restored before dispatch.
        with store.transaction():
            store.db.execute('UPDATE actor SET online=0 WHERE id!=?',(actor,))
        try:
            schedule(store,cfg,{'capabilities':{'lightning_configured':False}})
        finally:
            with store.transaction():
                for name,value in online.items():store.db.execute('UPDATE actor SET online=? WHERE id=?',(value,name))
        action=store.db.execute("SELECT * FROM action WHERE actor_id=? AND state='queued'",(actor,)).fetchone()
        assert action and action['operation'] in {'refresh','refresh_delegated'} and action['fee_reservation_sat']==2000
        asyncio.run(Engine(cfg,store).run(once=True))
        action=store.db.execute('SELECT state,result FROM action WHERE id=?',(action['id'],)).fetchone()
        assert action['state']=='completed','zero-spendable actual scheduler refresh failed'
        store.verify_event_chain();print(action['result'])
    finally:store.close()
elif mode in {'renewal_funder_create','renewal_fund','renewal_board'}:
    from simulator import renewal
    class FixtureRpc:
        def call(self,method,*args,root=False):
            credential=Path(m['core_cookie']).read_text().strip()
            url=m['core_url']+('' if root else '/wallet/sim-renewal-funder')
            req=urllib.request.Request(url,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':list(args)}).encode(),
                {'Authorization':'Basic '+base64.b64encode(credential.encode()).decode(),'Content-Type':'application/json'})
            data=json.load(urllib.request.urlopen(req,timeout=90),parse_float=Decimal)
            if data.get('error'):raise RuntimeError('fixture funding Core RPC rejected')
            return data['result']
    funding=FixtureRpc()
    if mode=='renewal_funder_create':
        funding.call('createwallet','sim-renewal-funder',root=True)
        address=funding.call('getnewaddress')
        funding.call('unloadwallet','sim-renewal-funder',root=True)
        print(json.dumps({'address':address}))
    else:
        cfg=replace(config(),board_amount_sat=5000)
        store=Store(cfg.state_dir,'live',cfg.fee_budget_sat)
        try:
            if mode=='renewal_fund':
                funding.call('loadwallet','sim-renewal-funder',root=True)
                txid=command['args']['owner_injection_txid'];tx=funding.call('getrawtransaction',txid,True,root=True)
                owned=[o for o in tx['vout'] if funding.call('getaddressinfo',o['scriptPubKey']['address']).get('ismine')]
                assert len(owned)==1 and int(owned[0]['value']*100000000)==100000 and tx.get('confirmations',0)>0
                o=owned[0];source={'outpoint':txid+':'+str(o['n']),'amount_sat':100000,'script':o['scriptPubKey']['hex']}
                if not store.get_meta('owner_renewal_declaration'):
                    store.event('external_owner_injection_observed',{'txid':txid,'owned_outputs':[source],'allocated_sat':0,'scope':'isolated declared fixture owner deposit, not signet evidence'})
                    renewal.declare(store,{'tranche_id':renewal.TRANCHE,'maximum_principal_sat':80000,'maximum_actor_grant_sat':8000,'maximum_mining_fee_sat':2000,'maximum_batches':1,'sources':[{'txid':txid,'outputs':[source]}]})
                print(json.dumps(renewal.fund(store,funding,cfg)))
            else:
                detail=json.loads(store.db.execute('SELECT details FROM actor WHERE id=?',(actor,)).fetchone()[0])
                assert renewal.queue_board(store,actor,detail,cfg),'confirmed renewal failed to queue'
                asyncio.run(Engine(cfg,store).run(once=True))
                row=store.db.execute('SELECT state,result FROM action WHERE id=?',('owner-renewal-board-'+actor+'-1',)).fetchone()
                assert row['state']=='completed','renewed own source did not board'
                print(row['result'])
            store.verify_event_chain()
        finally:
            store.close()
            if mode=='renewal_fund':funding.call('unloadwallet','sim-renewal-funder',root=True)
elif mode in {'recycle_once','recycle_audit'}:
    from simulator.chain import ChainReader
    from simulator.recycling import collect,plan,report
    cfg=config();store=Store(cfg.state_dir,'live',cfg.fee_budget_sat)
    try:
        asyncio.run(collect(store,ChainReader(m['core_url'],m['core_cookie'],m['genesis']),limit=16))
        if mode=='recycle_once':
            details=json.loads(store.db.execute('SELECT details FROM actor WHERE id=?',(actor,)).fetchone()[0])
            cfg=replace(cfg,board_amount_sat=command.get('args',{}).get('board_cap_sat',4500))
            args=plan(store,actor,details,cfg)
            assert args is not None,'real confirmed exit did not qualify for recycling'
            action_id='fixture-recycle-'+str(store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
            with store.transaction():
                store.queue(action_id,actor,'H35','board',args,2000)
                store._event('recycle_intent',{'actor':actor,'action_id':action_id,'source':args['recycle_source'],
                    'board_amount_sat':args['amount_sat'],'fee_reserve_sat':2000,'new_external_funding_sat':0,
                    'grant_reused':False,'outcome':'pending confirmed input/fee proof'})
            asyncio.run(Engine(cfg,store).run(once=True))
            action=store.db.execute('SELECT state,result FROM action WHERE id=?',(action_id,)).fetchone()
            assert action['state']=='completed','source-linked native board did not complete'
            print(action['result'])
        else:print(json.dumps(report(store)))
        store.verify_event_chain()
    finally:store.close()
else:
    cfg=config();cfg.wallet_root.mkdir(mode=0o700,parents=True,exist_ok=True)
    store=Store(cfg.state_dir,'live',cfg.fee_budget_sat)
    try:
        initialize(store)
        engine=Engine(cfg,store)
        if mode=='receive_absent':
            from simulator.continuous import arm_receive_absence,absence_report
            assert arm_receive_absence(store,actor,command['args']['rail']), 'successful receive lacks independently verified spendable outputs'
            assert not store.online(actor)
            print(json.dumps(absence_report(store)[0]))
        elif mode=='absent':
            assert store.db.execute('SELECT COUNT(*) FROM owned_coin').fetchone()[0]>0, 'no independent signed coin proof before absence'
            assert store.db.execute("SELECT actual_fee_sat FROM action WHERE operation='board'").fetchone()[0] is not None, 'board fee remains unqualified'
            store.set_online(actor,False)
            store.event('fixture_absence_armed',{'actor':actor,'scenario':'H03'})
        else:
            operation=mode
            action_id='fixture-'+mode+'-'+str(store.db.execute('SELECT COUNT(*) FROM action').fetchone()[0])
            store.queue(action_id,
                actor,command.get('scenario',RAW_CASES.get(operation,'H01')),operation,command.get('args',{'amount_sat':10000} if mode=='board' else {}),
                command.get('maximum_fee_sat',2000 if mode in {'board','sync','refresh','refresh_delegated','pay_invoice','offboard_all'} else 0))
            asyncio.run(engine.run(once=True))
            assert store.get_meta('paused') is None, 'simulator oracle reported an incident'
            action=store.db.execute('SELECT * FROM action WHERE id=?',(action_id,)).fetchone()
            expected={'completed','expected_refusal'} if operation in RAW_CASES else {'completed'}
            assert action['state'] in expected,f"fixture driver outcome {action['state']}"
            print(action['result'])
        store.verify_event_chain();generate(store,evaluate=False)
    finally:store.close()
