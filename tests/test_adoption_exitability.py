"""Synthetic admission controls; cryptography/live exitability remain native gates."""
import copy,hashlib,json,sqlite3,tempfile,time,unittest
from pathlib import Path
from simulator import adoption_exitability as x
from simulator.bundle_audit import decode_transaction
from simulator.engine import initialize
from simulator.model import canonical
from simulator.round_adoption import record_input_params
from simulator.store import Store
from tests.test_wallet_projection import Core,transaction

class ExitCore(Core):
    def call(self,method,*args):
        if method=='estimatesmartfee':return {'feerate':'0.00011000'}
        if method=='deriveaddresses':return [args[0]+'/'+str(i) for i in range(args[1][0],args[1][1]+1)]
        if method=='validateaddress':return {'scriptPubKey':self.script(args[0].split('/')[0])}
        return super().call(method,*args)
    def script(self,descriptor):return '0014'+('11' if descriptor=='actor-01' else '22')*20
    def tx(self,txid):return self.call('getrawtransaction',txid,True)

class AdoptionExitabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.wallets=self.root/'wallets';self.wallets.mkdir()
        (self.root/'config').mkdir();config=b'vtxo_exit_margin=12\nhtlc_recv_claim_delta=18\n';(self.root/'config/wallet.toml').write_bytes(config)
        self.s=Store(self.root/'state','synthetic',10000,architecture_profile='two_step_per_key');initialize(self.s);self.core=ExitCore();self.server='02'+'33'*32
        self.d={'id':'adoption-unit','actors':['actor-01','actor-02'],'server_pubkey':self.server,'pins':{},
            'adoption':{'actor':'actor-01','previous_action_ids':[],'input_expiry_height':1048,
                'exitability_policy':{'minimum_original_headroom_blocks':24,'wallet_configuration_sha256':hashlib.sha256(config).hexdigest(),
                    'fee_allocations':{},'original_coin_ids_by_actor':{}}}}
        for n,actor in enumerate(self.d['actors']):
            directory=self.wallets/actor;directory.mkdir();db=sqlite3.connect(directory/'db.sqlite')
            db.executescript('CREATE TABLE bdk_wallet(id INTEGER,descriptor TEXT,change_descriptor TEXT);CREATE TABLE bdk_wallet_locked_outpoints(txid TEXT,vout INTEGER);CREATE TABLE bdk_txouts(txid TEXT,vout INTEGER,value INTEGER,script BLOB);CREATE TABLE bdk_txs(txid TEXT);')
            db.execute('INSERT INTO bdk_wallet VALUES (0,?,NULL)',(actor,));script=self.core.script(actor)
            funding=transaction(['aa'*32+':'+str(n)],[(20000,script)],nonce=n);txid=self.core.add(funding,confirmations=2)
            self.core.coin(txid,0,20000,0,confirmations=2);self.core.mempool_unspent[(txid,0)]['scriptPubKey']['hex']=script
            db.execute('INSERT INTO bdk_txouts VALUES (?,?,?,?)',(txid,0,20000,bytes.fromhex(script)));db.execute('INSERT INTO bdk_txs VALUES (?)',(txid,));db.commit();db.close()
            self.d['adoption']['exitability_policy']['fee_allocations'][actor]={'txid':txid,'vout':0}
            anchor=('44' if n==0 else '55')*32+':0';self.core.coin(anchor[:-2],0,10000,0,confirmations=5)
            first=self.node(anchor,[10000]);second=self.node(first['txid']+':0',[5000,5000]);key=('02' if n==0 else '03')+'66'*32
            self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(key,actor,'mailbox','{}'));self.s.queue('observe-'+actor,actor,'H17','snapshot',{},0)
            ids=[]
            for i in range(2):
                leaf=self.node(second['txid']+':'+str(i),[5000]);path=[copy.deepcopy(first),copy.deepcopy(second),leaf];path[1]['output_index']=i;path[1]['output_amount_sat']=5000
                coin=leaf['txid']+':0';ids.append(coin);signed=canonical({'unit_fixture':coin}).encode().hex();hashed=hashlib.sha256(bytes.fromhex(signed)).hexdigest()
                proof={'id':coin,'user_pubkey':key,'amount_sat':5000,'expiry_height':1048,'server_pubkey':self.server,'signed_path_valid':True,'authorization_path_valid':True,'anchor_confirmations':5,
                    'conditional_steps':0,'path':path,'chain_anchor':anchor,'binding':{'record_signature_valid':True,'key_link_signature_valid':True,'mailbox_pk':'mailbox','spk':script,'seq':1}}
                self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(coin,key,5000,hashed,signed,canonical(proof)))
                self.s.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',(coin,'observe-'+actor,'Spendable',time.time()))
                params={'schema_version':1,'id':coin,'candidate_user_pubkey':key,'amount_sat':5000,'expiry_height':1048,'exit_delta':12,'server_pubkey':self.server,'client_owner_verified':False,'chain_contract_verified':False}
                record_input_params(self.s,signed,params,self.server,'cc'*32)
            self.d['adoption']['exitability_policy']['original_coin_ids_by_actor'][actor]=ids
        self.d['adoption']['input_coin_ids']=self.d['adoption']['exitability_policy']['original_coin_ids_by_actor']['actor-01']
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def node(self,point,amounts):
        raw=bytearray.fromhex(transaction([point],[(a,'5120'+'77'*32) for a in amounts],witness=False));raw[:4]=(3).to_bytes(4,'little');raw[42:46]=bytes(4)
        decoded=decode_transaction(raw.hex(),public_body=True)
        return {'transaction':raw.hex(),'txid':decoded['txid'],'output_index':0,'output_amount_sat':amounts[0],'output_script':'5120'+'77'*32}
    def check(self,height=1000):return x.check(self.s,self.core,self.d,self.wallets,height)
    def test_both_native_known_confirmed_owned_fee_wallets_and_three_stage_paths_are_checked(self):
        proof=self.check();self.assertEqual({3},set(v['maximum_confirmation_stages'] for v in proof['clients'].values()))
        self.assertEqual({4},set(v['unique_parent_count'] for v in proof['clients'].values()));self.assertFalse(proof['confirmation_guarantee'])
        self.assertTrue(all(v['allocation_native_known'] for v in proof['clients'].values()));self.s.verify_event_chain()
    def test_original_twenty_four_block_floor_is_strict(self):
        self.check(height=1023)
        with self.assertRaisesRegex(ValueError,'headroom'):self.check(height=1024)
    def test_actual_locks_sequences_conditions_and_decoded_csv_cannot_be_asserted_away(self):
        row=self.s.db.execute('SELECT * FROM owned_coin LIMIT 1').fetchone();original=json.loads(row['proof'])
        variants=[]
        changed=copy.deepcopy(original);changed['conditional_steps']=1;variants.append(changed)
        for offset in [0,42,-4]:
            changed=copy.deepcopy(original);raw=bytearray.fromhex(changed['path'][0]['transaction']);raw[offset]=1;changed['path'][0]['transaction']=raw.hex();variants.append(changed)
        for changed in variants:
            self.s.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(canonical(changed),row['id']))
            with self.assertRaises(ValueError):self.check()
        self.s.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(row['proof'],row['id']))
        self.s.db.execute("UPDATE round_input_params SET proof=json_set(proof,'$.exit_delta',1)")
        with self.assertRaises(ValueError):self.check()
    def test_unconfirmed_reserved_underfunded_or_foreign_fee_outputs_are_refused(self):
        allocation=self.d['adoption']['exitability_policy']['fee_allocations']['actor-02'];point=(allocation['txid'],0);original=copy.deepcopy(self.core.mempool_unspent[point])
        self.core.mempool_unspent[point]['confirmations']=0
        with self.assertRaisesRegex(ValueError,'fee cash'):self.check()
        self.core.mempool_unspent[point]=original
        db=sqlite3.connect(self.wallets/'actor-02/db.sqlite');db.execute('INSERT INTO bdk_wallet_locked_outpoints VALUES (?,0)',(point[0],));db.commit()
        with self.assertRaisesRegex(ValueError,'fee cash'):self.check()
        db.execute('DELETE FROM bdk_wallet_locked_outpoints');db.commit();db.close()
        self.core.mempool_unspent[point]['scriptPubKey']['hex']='0014'+'ff'*20
        with self.assertRaisesRegex(ValueError,'owned'):self.check()
    def test_missing_native_allocation_adoption_allows_only_the_observation_phase(self):
        db=sqlite3.connect(self.wallets/'actor-02/db.sqlite');db.execute('DELETE FROM bdk_txs');db.execute('DELETE FROM bdk_txouts');db.commit();db.close()
        proof=self.check();self.assertFalse(proof['clients']['actor-02']['allocation_native_known']);self.assertTrue(proof['clients']['actor-01']['allocation_native_known'])
    def test_real_preflight_requires_both_native_known_allocations_and_original_reserved_action(self):
        from simulator import exploratory as e
        from types import SimpleNamespace
        now=time.time();self.d.update(started_at=now-1,deadline=now+600,per_action_fee_sat=500,fee_budget_sat=5500)
        self.d['adoption'].update(input_total_sat=10000,maximum_syncs=6,client_fee_budget_sat=500)
        self.s.db.execute('INSERT INTO meta VALUES (?,?)',(e.KEY,canonical(self.d)));self.s.event('exploratory_operating_scope_declared',self.d)
        self.s.queue('original-delegation','actor-01','H17','refresh_delegated',{'input_vtxo_ids':self.d['adoption']['input_coin_ids']},500)
        db=sqlite3.connect(self.wallets/'actor-02/db.sqlite');txid=self.d['adoption']['exitability_policy']['fee_allocations']['actor-02']['txid'];db.execute('DELETE FROM bdk_txs');db.commit()
        def snapshot():
            self.s.event('exploratory_operating_readiness',{'scope_id':self.d['id'],'financial_pins':self.d['pins'],'height':1000,'tip_hash':self.core.tip,'observed_at':now,
                'ordinary_path_checked':True,'global_complete':False,'adoption_exitability':self.check(),
                'scoped_operator_miner_fees_sat':0,'operator_miner_fees_sat':0,'available_fee_funding_sat':10000,'estimate_warning':False})
            return {'height':1000,'tip_hash':self.core.tip,'exploratory_readiness_sequence':self.s.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]}
        frame=snapshot();self.assertTrue(e.preflight(self.s,SimpleNamespace(),frame,operation='sync',now=now)['allowed'])
        with self.assertRaisesRegex(ValueError,'sync confirmed fee allocations'):
            e.preflight(self.s,SimpleNamespace(),frame,operation='refresh_delegated',maximum_fee_sat=500,now=now,reserved_action_id='original-delegation')
        db.execute('INSERT INTO bdk_txs VALUES (?)',(txid,));db.commit();db.close();frame=snapshot()
        with self.assertRaisesRegex(ValueError,'original reserved'):
            e.preflight(self.s,SimpleNamespace(),frame,operation='refresh_delegated',maximum_fee_sat=500,now=now)
        self.assertTrue(e.preflight(self.s,SimpleNamespace(),frame,operation='refresh_delegated',maximum_fee_sat=500,now=now,reserved_action_id='original-delegation')['allowed'])
    def submitted(self):
        now=time.time();facts=self.check();proof={'scope_id':self.d['id'],'financial_pins':self.d['pins'],'height':1000,'tip_hash':self.core.tip,'observed_at':now-.1,'adoption_exitability':facts,'ordinary_path_checked':True,'global_complete':False}
        self.s.event('exploratory_operating_readiness',proof);seq=self.s.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
        snapshot={'height':1000,'tip_hash':self.core.tip,'exploratory_readiness_sequence':seq};cur=self.s.db.execute('INSERT INTO snapshot VALUES (NULL,?,?)',(now,canonical(snapshot)))
        self.s.queue('original-delegation','actor-01','H17','refresh_delegated',{'input_vtxo_ids':self.d['adoption']['input_coin_ids']},500)
        self.s.event('driver_request',{'action_id':'original-delegation','context':{'height':1000,'tip_hash':self.core.tip,'snapshot_id':cur.lastrowid},'request':{'action_id':'original-delegation','operation':'refresh_delegated','expected_server_pubkey':self.server,'maximum_fee_sat':500,'args':{'input_vtxo_ids':self.d['adoption']['input_coin_ids']}}})
        coins=self.s.db.execute("SELECT c.* FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE k.actor='actor-01' ORDER BY c.id").fetchall()
        self.s.event('driver_evidence',{'action_id':'original-delegation','event':'refresh_proposal','data':{'participation':{'inputs':[c['signed_vtxo'] for c in coins],'outputs':[{'policy':'00'+coins[0]['pubkey'],'amount':10000}]},'committed_fee_sat':0}})
        self.s.db.execute("UPDATE action SET state='completed',result=? WHERE id='original-delegation'",(canonical({'data':{'round_state_id':'actual-unit-state'}}),))
        movement={'subsystem':'bark.round','status':'pending','input_vtxos':self.d['adoption']['input_coin_ids']}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',('actor-01','original-unit-movement',canonical(movement)))
        for coin in coins:self.s.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',(coin['id'],'original-delegation','Locked',now+1))
    def test_dated_strict_admission_allows_only_exact_submitted_locked_input_progression_below_floor(self):
        self.submitted();proof=self.check(height=1030);self.assertEqual('original-delegation',proof['submitted_original_intent']['action_id']);self.s.verify_event_chain()
        self.s.db.execute("UPDATE action SET state='outcome_unknown' WHERE id='original-delegation'")
        with self.assertRaisesRegex(ValueError,'reconcile'):self.check(height=1030)
    def test_unrelated_lock_or_borrowed_presubmit_proof_cannot_allow_progression(self):
        self.submitted();self.s.db.execute('DELETE FROM movement_evidence')
        with self.assertRaisesRegex(ValueError,'pending'):self.check(height=1030)
        self.s.db.execute("UPDATE event SET payload=json_set(payload,'$.scope_id','other') WHERE kind='exploratory_operating_readiness'")
        with self.assertRaisesRegex(ValueError,'admission'):self.check(height=1030)
    def test_actor_two_original_spend_cannot_borrow_actor_one_refresh_permission(self):
        self.submitted();coin=self.d['adoption']['exitability_policy']['original_coin_ids_by_actor']['actor-02'][0]
        self.s.db.execute("UPDATE coin_observation SET state='Spent' WHERE coin_id=?",(coin,))
        with self.assertRaisesRegex(ValueError,'unrelated original client spend'):self.check(height=1030)
    def test_unrelated_new_coin_cannot_borrow_original_refresh_progression(self):
        self.submitted();row=self.s.db.execute('SELECT c.* FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE k.actor=? LIMIT 1',('actor-02',)).fetchone()
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('ee'*32+':0',row['pubkey'],row['amount_sat'],row['signed_hash'],'deadbeef',row['proof']))
        self.s.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',('ee'*32+':0','observe-actor-02','Spendable',time.time()))
        with self.assertRaisesRegex(ValueError,'frozen replacement'):self.check(height=1030)
    def test_exact_signed_replacement_is_observable_but_extra_multiplicity_is_refused(self):
        self.submitted();ids=self.d['adoption']['input_coin_ids'];row=self.s.db.execute('SELECT * FROM owned_coin WHERE id=?',(ids[0],)).fetchone()
        self.s.db.execute("UPDATE coin_observation SET state='Spent' WHERE coin_id IN (?,?)",tuple(ids))
        anchor='88'*32+':0';self.core.coin('88'*32,0,10000,0,confirmations=1);leaf=self.node(anchor,[10000]);coin=leaf['txid']+':0'
        signed=canonical({'unit_replacement':coin}).encode().hex();hashed=hashlib.sha256(bytes.fromhex(signed)).hexdigest();proof=json.loads(row['proof'])
        proof.update(id=coin,amount_sat=10000,expiry_height=1078,path=[leaf],chain_anchor=anchor)
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(coin,row['pubkey'],10000,hashed,signed,canonical(proof)))
        self.s.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',(coin,'original-delegation','Spendable',time.time()+2))
        params={'schema_version':1,'id':coin,'candidate_user_pubkey':row['pubkey'],'amount_sat':10000,'expiry_height':1078,'exit_delta':12,'server_pubkey':self.server,'client_owner_verified':False,'chain_contract_verified':False}
        record_input_params(self.s,signed,params,self.server,'cc'*32)
        self.assertIn(coin,self.check(height=1030)['clients']['actor-01']['coin_ids'])
        duplicate='ff'*32+':0';self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(duplicate,row['pubkey'],10000,'dd'*32,'feed',canonical(proof)))
        self.s.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',(duplicate,'original-delegation','Spendable',time.time()+3))
        with self.assertRaisesRegex(ValueError,'frozen replacement'):self.check(height=1030)

if __name__=='__main__':unittest.main()
