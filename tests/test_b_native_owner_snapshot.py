"""Synthetic public snapshot arithmetic/identity controls; no native qualification."""
import copy
import json
import unittest
from simulator.b_native_owner_snapshot import owner_snapshot,current_resolution_anchors,require_publication_sources
from simulator.ownership import EvidenceGap
from simulator.two_step_normal import digest

PIN='1'*40
H=lambda n:format(n,'064x')

def fixture():
    policy={'urgent_reserve_sat':15000,'ordinary_budget_sat':60000,
        'external_future_reserved_sat':17622,'opening_sha256':H(2)}
    opening={'version':1,'network':'signet','genesis':H(99),'server_pubkey':'02'+H(3),
        'history_prefix_bytes':65,'history_prefix_sha256':H(4),'native_spent_sat':4985,
        'external_spent_sat':3257,'accounting_receipt_sha256':H(5)}
    funding=[{'index':2,'purpose':'round','family_sha256':H(6),'generation':0,
        'unsigned_body_sha256':H(7),'prevouts_sha256':H(8),'txid':H(9),'signed_wtxid':H(10),'ceiling_sat':300},
        {'index':3,'purpose':'pool','family_sha256':H(11),'generation':0,
        'unsigned_body_sha256':H(12),'prevouts_sha256':H(13),'txid':H(14),'signed_wtxid':None,'ceiling_sat':400}]
    urgent=[{'index':1,'ceiling_sat':1000,'source_binding_sha256':H(15),
        'transactions':[{'txid':H(16),'wtxid':H(17)},{'txid':H(18),'wtxid':H(19)}]}]
    snap={'schema':1,'policy_sha256':H(1),'opening_sha256':H(2),'journal_sha256':H(20),
        'journal_device':7,'journal_inode':8,'journal_bytes':2000,'policy':policy,'opening':opening,
        'charged_sat':37564,'remaining_total_sat':22436,'urgent_remaining_sat':14000,
        'discretionary_remaining_sat':8436,'direct_attempt_count':1,'direct_reserved_sat':10000,
        'funding_reserved_sat':700,'round_reserved_sat':300,'pool_reserved_sat':400,
        'urgent_reserved_sat':1000,'funding':funding,'urgent':urgent,
        'resolutions':[{'winner_index':2,'block_height':100,'block_hash':H(21)}]}
    runtime={'product_commit':PIN,'execution_release':{'product_commit':PIN},
        'public_configuration':{'captaind':{'network':'signet','ordinary_fee_policy':copy.deepcopy(policy)},
            'watchmand':{'network':'signet','direct_expiry':{'ordinary_fee_policy':copy.deepcopy(policy)}}},
        'native_budget':{'files':{'ordinary-fee-budget':{'sha256':H(20),'device':7,'inode':8,'bytes':2000},
            'ordinary-fee-policy.json':{'sha256':H(1)},'ordinary-fee-opening.json':{'sha256':H(2)}},
            'lock':{'device':7,'inode':8}}}
    return snap,runtime


def run(s,r):return owner_snapshot(json.dumps(s,separators=(',',':')).encode(),r,expected_product_commit=PIN)


class Chain:
    def __init__(self):self.tip=(101,H(30));self.changed=False;self.calls=0;self.bad={}
    def identity(self):
        self.calls+=1
        return {'blocks':self.tip[0]+int(self.changed and self.calls>1),'bestblockhash':self.tip[1],
            'initialblockdownload':False,'chain':'signet'}
    def call(self,method,*args):
        if method=='getblockhash':return H(99)if args==(0,)else H(21)
        if method=='getrawtransaction':return {'txid':H(9),'hash':H(10),'blockhash':H(21),'confirmations':2,**self.bad}
        raise AssertionError(method)


class SnapshotControls(unittest.TestCase):
    def reject(self,mutate):
        s,r=fixture();mutate(s,r)
        with self.assertRaises((EvidenceGap,ValueError)):run(s,r)
    def test_round_pool_urgent_and_direct_full_ceiling_partition(self):
        s,r=fixture();p=run(s,r)
        self.assertEqual((p['direct_reserved_sat'],p['round_reserved_sat'],p['pool_reserved_sat'],p['urgent_reserved_sat']),
            (10000,300,400,1000))
        self.assertEqual((p['opening_charge_sat'],p['charged_sat'],p['discretionary_remaining_sat']),(25864,37564,8436))
        self.assertIsNone(p['funding'][1]['signed_wtxid'])
        self.assertNotIn('complete',p);self.assertNotIn('qualified',p)
    def test_unbound_urgent_keeps_full_ceiling(self):
        s,r=fixture();s['urgent'][0].update(source_binding_sha256=None,transactions=[])
        self.assertEqual(run(s,r)['urgent_reserved_sat'],1000)
    def test_unsigned_funding_keeps_full_ceiling(self):
        s,r=fixture();s['funding'][0]['signed_wtxid']=None;s['resolutions']=[]
        self.assertEqual(run(s,r)['funding_reserved_sat'],700)
    def test_no_refund_from_resolution(self):
        s,r=fixture();p=run(s,r);s['resolutions']=[]
        self.assertEqual(run(s,r)['charged_sat'],p['charged_sat'])
    def test_actual_cli_final_lf_preserves_projection_and_original_digest(self):
        s,r=fixture();raw=json.dumps(s).encode();p=owner_snapshot(raw+b'\n',r,expected_product_commit=PIN)
        self.assertEqual(p['snapshot_sha256'],digest(raw+b'\n'))
        self.assertEqual(p['charged_sat'],run(s,r)['charged_sat'])
    def test_wrong_native_source(self):self.reject(lambda s,r:r.update(product_commit='2'*40))
    def test_wrong_release_source(self):self.reject(lambda s,r:r['execution_release'].update(product_commit='2'*40))
    def test_extra_ready_flag(self):self.reject(lambda s,r:s.update(ready=True))
    def test_new_unknown_snapshot_schema(self):self.reject(lambda s,r:s.update(schema=2))
    def test_boolean_money(self):self.reject(lambda s,r:s.update(charged_sat=True))
    def test_current_flock_inode(self):self.reject(lambda s,r:r['native_budget']['lock'].update(inode=9))
    def test_snapshot_same_file_hash(self):self.reject(lambda s,r:s.update(journal_sha256=H(31)))
    def test_snapshot_same_file_length(self):self.reject(lambda s,r:s.update(journal_bytes=1999))
    def test_paired_loaded_policy(self):self.reject(lambda s,r:r['public_configuration']['watchmand']['direct_expiry']['ordinary_fee_policy'].update(urgent_reserve_sat=1))
    def test_opening_cannot_be_reset(self):self.reject(lambda s,r:s['opening'].update(native_spent_sat=0))
    def test_missing_funding_attempt_not_hidden_by_category_total(self):self.reject(lambda s,r:s['funding'].pop())
    def test_unknown_funding_purpose(self):self.reject(lambda s,r:s['funding'][0].update(purpose='claim'))
    def test_duplicate_funding_indices(self):self.reject(lambda s,r:s['funding'][1].update(index=2))
    def test_pool_retry_not_allowed(self):self.reject(lambda s,r:s['funding'][1].update(generation=1))
    def test_urgent_member_omission(self):self.reject(lambda s,r:s['urgent'][0].update(transactions=[]))
    def test_unbound_urgent_cannot_claim_signed_package(self):self.reject(lambda s,r:s['urgent'][0].update(source_binding_sha256=None))
    def test_duplicate_urgent_members(self):self.reject(lambda s,r:s['urgent'][0]['transactions'].append(copy.deepcopy(s['urgent'][0]['transactions'][0])))
    def test_resolution_requires_signed_original_round(self):self.reject(lambda s,r:s['resolutions'][0].update(winner_index=3))
    def test_resolution_does_not_erase_charge(self):self.reject(lambda s,r:s.update(charged_sat=37264))
    def test_private_native_projection_is_required_for_new_domains(self):
        s,r=fixture()
        with self.assertRaisesRegex(EvidenceGap,'V79/V80'):require_publication_sources(run(s,r))
        s['funding']=[];s['resolutions']=[];s.update(funding_reserved_sat=0,round_reserved_sat=0,pool_reserved_sat=0,
            charged_sat=36864,remaining_total_sat=23136,discretionary_remaining_sat=9136)
        with self.assertRaisesRegex(EvidenceGap,'nursery/package'):require_publication_sources(run(s,r))
    def test_native_snapshot_byte_bound_and_duplicate_fields(self):
        s,r=fixture()
        for raw in [b'x'*(2*1024*1024+1),b'{"schema":1,"schema":1}']:
            with self.assertRaises((EvidenceGap,ValueError)):owner_snapshot(raw,r,expected_product_commit=PIN)
    def test_native_projection_does_not_export_private_package(self):
        s,r=fixture();s['urgent'][0]['transactions'][0]['raw']='private-preimage-marker'
        with self.assertRaises(EvidenceGap):run(s,r)
    def test_canonical_confirmed_winner_observation(self):
        s,r=fixture();p=run(s,r);c=Chain();actual=current_resolution_anchors(p,c,tip=c.tip)
        self.assertEqual(actual,[{'winner_index':2,'block_height':100,'block_hash':H(21),
            'txid':H(9),'wtxid':H(10),'confirmations':2}]);self.assertNotIn('released_inputs',actual[0])
    def test_mempool_wrong_witness_or_inexact_depth_is_not_confirmed_winner(self):
        s,r=fixture();p=run(s,r)
        for bad in [{'confirmations':0},{'confirmations':1},{'hash':H(22)},{'blockhash':H(22)}]:
            c=Chain();c.bad=bad
            with self.assertRaises(EvidenceGap):current_resolution_anchors(p,c,tip=c.tip)
    def test_reorg_mid_observation_holds(self):
        s,r=fixture();p=run(s,r);c=Chain();c.changed=True
        with self.assertRaisesRegex(EvidenceGap,'tip changed'):current_resolution_anchors(p,c,tip=c.tip)
    def test_resolution_orphan_holds(self):
        s,r=fixture();p=run(s,r);p['resolutions'][0]['block_hash']=H(22);c=Chain()
        with self.assertRaisesRegex(EvidenceGap,'not canonical'):current_resolution_anchors(p,c,tip=c.tip)


class PrivateInputControls(unittest.TestCase):
    """Synthetic original binding only; no actual SQL/native/capture qualification."""
    def inputs(self):
        s,r=fixture();originals={'policy_raw':'private policy fixture','opening_raw':'private opening fixture',
            'journal_raw':'private signed package fixture'}
        for role,snapshot_field,name in [('policy_raw','policy_sha256','ordinary-fee-policy.json'),
                ('opening_raw','opening_sha256','ordinary-fee-opening.json'),
                ('journal_raw','journal_sha256','ordinary-fee-budget')]:
            sha=digest(originals[role].encode());s[snapshot_field]=sha;r['native_budget']['files'][name]['sha256']=sha
            r['native_budget']['files'][name]['bytes']=len(originals[role].encode())
            if role=='journal_raw':s['journal_bytes']=len(originals[role].encode())
        s['policy']['opening_sha256']=s['opening_sha256']
        for service in ('captaind','watchmand'):
            row=r['public_configuration'][service]
            policy=row['ordinary_fee_policy']if service=='captaind'else row['direct_expiry']['ordinary_fee_policy']
            policy['opening_sha256']=s['opening_sha256']
        whole=b'{"kind":"synthetic-whole-frontier"}'
        database={'native_funding_fee_intent':[],'native_funding_fee_input':[],
            'native_funding_fee_resolution':[],'nursery_tx':[]}
        originals['sql_raw']='BEGIN\nSET\nDO\n'+whole.decode()+'\n'+json.dumps(database)+'\nCOMMIT\n'
        files={'b-native-fee-originals.json':json.dumps(originals).encode(),
            'b-native-fee-snapshot.json':json.dumps(s).encode()}
        target={'raw_sql':whole,'auxiliary_originals':files,
            'manifest':{'original_sha256':{'native_sql':digest(whole)},
                'auxiliary_originals':{'b_native_fee_originals':'b-native-fee-originals.json',
                    'b_native_fee_snapshot':'b-native-fee-snapshot.json'},
                'files':{name:{'sha256':digest(raw),'size_bytes':len(raw)}for name,raw in files.items()}}}
        return target,r,{'id':'1'*32,'height':101,'tip_hash':H(30)}
    def prepare(self,t,r,o):
        from simulator.b_private_native_fee_inputs import prepare_native_fee_request
        return prepare_native_fee_request(t,r,expected_product_commit=PIN,expected_tool_commit='2'*40,observation=o)
    def mutate_originals(self,t,edit):
        name='b-native-fee-originals.json';value=json.loads(t['auxiliary_originals'][name]);edit(value)
        raw=json.dumps(value).encode();t['auxiliary_originals'][name]=raw
        t['manifest']['files'][name]={'sha256':digest(raw),'size_bytes':len(raw)}
    def test_exact_private_bytes_and_all_domains_go_to_native_not_public_trace(self):
        t,r,o=self.inputs();request=self.prepare(t,r,o)
        self.assertEqual(request['originals']['journal_raw'],'private signed package fixture')
        self.assertEqual(request['expected']['database_sha256'],digest(request['originals']['database_raw'].encode()))
        self.assertEqual(request['source_observation'],o)
        self.assertEqual(request['sdk_commit'],'2'*40)
        self.assertEqual(r['product_commit'],PIN)
        # Deliberately synthetic empty DB contradicts snapshotfunding: preparation
        # must NOT claim native row equality; actual native verifier must refuse.
        self.assertNotIn('complete',request);self.assertNotIn('qualified',request)
    def test_whole_frontier_original_final_lf_is_preserved_in_hash(self):
        t,r,o=self.inputs();t['raw_sql']+=b'\n'
        t['manifest']['original_sha256']['native_sql']=digest(t['raw_sql'])
        self.assertEqual(self.prepare(t,r,o)['source_observation'],o)
    def test_missing_private_auxiliary_never_becomes_empty_source(self):
        t,r,o=self.inputs();del t['auxiliary_originals']['b-native-fee-originals.json']
        with self.assertRaises(EvidenceGap):self.prepare(t,r,o)
    def test_changed_auxiliary_hash_is_rejected(self):
        t,r,o=self.inputs();t['auxiliary_originals']['b-native-fee-originals.json']+=b' '
        with self.assertRaises(EvidenceGap):self.prepare(t,r,o)
    def test_private_signed_package_must_equal_current_flock_bytes(self):
        t,r,o=self.inputs();self.mutate_originals(t,lambda v:v.update(journal_raw='changed package'))
        with self.assertRaisesRegex(EvidenceGap,'owning file'):self.prepare(t,r,o)
    def test_separately_captured_whole_frontier_is_refused(self):
        t,r,o=self.inputs();self.mutate_originals(t,lambda v:v.update(sql_raw=v['sql_raw'].replace('synthetic-whole-frontier','different-frontier')))
        with self.assertRaisesRegex(EvidenceGap,'whole B frontier'):self.prepare(t,r,o)
    def test_missing_native_input_or_resolution_domain_is_refused(self):
        t,r,o=self.inputs()
        def edit(v):
            lines=v['sql_raw'].splitlines();db=json.loads(lines[4]);del db['native_funding_fee_input']
            lines[4]=json.dumps(db);v['sql_raw']='\n'.join(lines)+'\n'
        self.mutate_originals(t,edit)
        with self.assertRaisesRegex(EvidenceGap,'SQL domains'):self.prepare(t,r,o)
    def test_two_transactions_cannot_be_relabelled_one_cut(self):
        t,r,o=self.inputs();self.mutate_originals(t,lambda v:v.update(sql_raw=v['sql_raw'].replace('\n{"native_funding','\nCOMMIT\nBEGIN\n{"native_funding')))
        with self.assertRaisesRegex(EvidenceGap,'transaction framing'):self.prepare(t,r,o)
    def test_over_native64mib_transport_is_refused_before_partial_parse(self):
        t,r,o=self.inputs();t['auxiliary_originals']['b-native-fee-originals.json']=b'x'*(64*1024*1024+1)
        with self.assertRaisesRegex(EvidenceGap,'hash/size'):self.prepare(t,r,o)
    def test_above_old16mib_original_is_checked_whole_not_truncated(self):
        t,r,o=self.inputs();self.mutate_originals(t,lambda v:v.update(sql_raw='x'*(17*1024*1024)))
        with self.assertRaisesRegex(EvidenceGap,'transaction framing'):self.prepare(t,r,o)
    def test_bad_source_nonce_is_refused(self):
        t,r,o=self.inputs();o['id']='not-a-source-nonce'
        with self.assertRaisesRegex(EvidenceGap,'source observation'):self.prepare(t,r,o)


class NativeReplyControls(unittest.TestCase):
    """Synthetic interface controls; native executable/signature proof NOT_RUN."""
    def proof(self):
        owner,_=fixture();tool='2'*40
        request={'schema':1,'kind':'b-native-fee-source-request','sdk_commit':tool,
            'source_observation':{'id':'1'*32,'height':101,'tip_hash':H(30)},
            'originals':{k:'synthetic original '+k for k in ['policy_raw','opening_raw','journal_raw','database_raw']}}
        def tx(ident,witness,point,value,out,fee,weight=400):
            return {'txid':H(ident),'wtxid':H(witness),'weight_wu':weight,'fee_sat':fee,
                'inputs':[{'outpoint':point,'value_sat':value,'script_pubkey':'5120'+H(50)}],
                'outputs':[{'vout':0,'value_sat':out,'script_pubkey':'5120'+H(50)}]}
        funding=[]
        for pub,point0,amount in [(owner['funding'][0],H(31)+':0',1000),(owner['funding'][1],H(32)+':0',2000)]:
            ident=int(pub['txid'],16);fee=pub['ceiling_sat'];unsigned=tx(ident,ident,point0,amount,amount-fee,fee,200)
            signed=tx(ident,int(pub['signed_wtxid'],16),point0,amount,amount-fee,fee)if pub['signed_wtxid']else None
            funding.append({**{k:pub[k]for k in ['index','purpose','family_sha256','generation','unsigned_body_sha256','prevouts_sha256','ceiling_sat']},
                'attempt_key':H(80+pub['index']),'reservation_native_sha256':H(90+pub['index']),
                'max_fee_rate_sat_kwu':4000,'unsigned':unsigned,'signed':signed,
                'family':{'Round':{'round_seq':123,'pinned_input':point0}}if pub['purpose']=='round'else{'Pool':{'funding_txid':pub['txid']}}})
        txs=[tx(16,17,H(40)+':0',3000,2800,200),tx(18,19,H(16)+':0',2800,2500,300)]
        urgent=[{'index':1,'ceiling_sat':1000,'policy_sha256':H(1),'metadata_binding_sha256':H(15),
            'source_anchors':[H(40)+':0'],'journal_binding_sha256':H(15),'urgent_fee_bound':True,
            'fee_sat':500,'transactions':txs}]
        nursery=[{'txid':t['txid'],'wtxid':t['wtxid'],'weight_wu':t['weight_wu'],'kind':'internal',
            'urgent_fee_bound':i==1,'urgent_metadata_native_sha256':H(15)if i==1 else None}for i,t in enumerate(txs)]
        nursery.append({'txid':H(70),'wtxid':H(71),'weight_wu':400,'kind':'expiry-payout',
            'urgent_fee_bound':False,'urgent_metadata_native_sha256':None})
        raw=json.dumps(request).encode()
        reply={'schema':1,'kind':'b-native-fee-source-proof','sdk_commit':tool,'input_sha256':digest(raw),
            'source_observation':request['source_observation'],
            'original_sha256':{k:digest(v.encode())for k,v in request['originals'].items()},
            'snapshot':{k:v for k,v in owner.items()if k not in {'journal_device','journal_inode'}},
            'direct_reservations':[{'line':1,'ceiling_sat':10000}],
            'funding_rows':funding,'urgent_rows':urgent,'resolutions':owner['resolutions'],
            'nursery_inventory':nursery,'unrelated_nursery_txids':[H(70)]}
        return raw,reply,json.dumps(owner).encode()
    def bind(self,raw,reply,owner):
        from simulator.b_native_fee_reply import bind_native_fee_reply
        return bind_native_fee_reply(raw,json.dumps(reply).encode(),owner,expected_tool_commit='2'*40)
    def reject(self,edit):
        raw,reply,owner=self.proof();edit(reply)
        with self.assertRaises((EvidenceGap,ValueError)):self.bind(raw,reply,owner)
    def test_native_direct_rows_preserve_physical_lines_and_complete_ceiling(self):
        raw,reply,owner=self.proof()
        self.assertEqual(self.bind(raw,reply,owner)['direct_reservations'],[{'line':1,'ceiling_sat':10000}])
        for rows0 in ([],[{'line':1,'ceiling_sat':9999}],[{'line':True,'ceiling_sat':10000}],
                      [{'line':1,'ceiling_sat':5000},{'line':1,'ceiling_sat':5000}]):
            reply['direct_reservations']=rows0
            with self.subTest(rows=rows0),self.assertRaises(EvidenceGap):self.bind(raw,reply,owner)

    def test_every_funding_and_full_urgent_member_retained_without_financial_flags(self):
        raw,reply,owner=self.proof();result=self.bind(raw,reply,owner)
        self.assertEqual(len(result['funding_rows']),2);self.assertEqual(len(result['urgent_rows'][0]['transactions']),2)
        self.assertEqual(result['unrelated_nursery_txids'],[H(70)])
        self.assertEqual(result['publication_inputpoints'],sorted([H(31)+':0',H(32)+':0',H(40)+':0',H(16)+':0']))
        self.assertNotIn('complete',result);self.assertNotIn('qualified',result);self.assertNotIn('ready',result)
    def test_native_identifier_order_is_preserved_without_display_text_sorting(self):
        raw,reply,owner=self.proof()
        reply['urgent_rows'][0]['source_anchors']=['01'+'00'*31+':2','00'*31+'02:10']
        extra=copy.deepcopy(reply['nursery_inventory'][-1]);extra.update(txid=H(69),wtxid=H(72))
        reply['nursery_inventory'].append(extra);reply['unrelated_nursery_txids']=[H(70),H(69)]
        result=self.bind(raw,reply,owner)
        self.assertEqual(result['urgent_rows'][0]['source_anchors'],reply['urgent_rows'][0]['source_anchors'])
        self.assertEqual(result['unrelated_nursery_txids'],[H(70),H(69)])
    def test_duplicate_unrelated_nursery_identity_refuses(self):self.reject(lambda r:r['unrelated_nursery_txids'].append(H(70)))
    def test_unbound_unsigned_old_attempt_cannot_be_omitted(self):self.reject(lambda r:r['funding_rows'].pop())
    def test_current_owner_snapshot_must_equal_all_private_native_projection(self):self.reject(lambda r:r['snapshot'].update(charged_sat=0))
    def test_bool_snapshot_count_is_not_native_integer(self):self.reject(lambda r:r['snapshot'].update(direct_attempt_count=True))
    def test_float_resolution_height_is_not_native_integer(self):self.reject(lambda r:r['resolutions'][0].update(block_height=100.0))
    def test_wrong_actual_tool_source(self):self.reject(lambda r:r.update(sdk_commit='3'*40))
    def test_wrong_request_original_hash(self):self.reject(lambda r:r.update(input_sha256=H(33)))
    def test_changed_private_original_hash(self):self.reject(lambda r:r['original_sha256'].update(journal_raw=H(33)))
    def test_changed_original_funding_prevout_value(self):self.reject(lambda r:r['funding_rows'][0]['signed']['inputs'][0].update(value_sat=999))
    def test_wrong_signed_winner_witness(self):self.reject(lambda r:r['funding_rows'][0]['signed'].update(wtxid=H(33)))
    def test_private_raw_field_never_accepted_in_safe_transaction(self):self.reject(lambda r:r['urgent_rows'][0]['transactions'][0].update(witness='private marker'))
    def test_missing_null_metadata_shared_parent(self):self.reject(lambda r:r['nursery_inventory'].pop(0))
    def test_wrong_shared_parent_metadata(self):self.reject(lambda r:r['nursery_inventory'][0].update(urgent_metadata_native_sha256=H(33)))
    def test_wrong_publication_bound_state(self):self.reject(lambda r:r['nursery_inventory'][1].update(urgent_fee_bound=False))
    def test_unrelated_nursery_rows_not_silently_dropped(self):self.reject(lambda r:r.update(unrelated_nursery_txids=[]))
    def test_resolution_sql_coverage_cannot_be_dropped(self):self.reject(lambda r:r.update(resolutions=[]))
    def test_changed_urgent_member_witness(self):self.reject(lambda r:r['urgent_rows'][0]['transactions'][0].update(wtxid=H(33)))


class PrivateProofLifecycleControls(unittest.TestCase):
    """Actual isolated tiny local subprocesses; NOT native verifier credit."""
    def tool(self,parent,body):
        from pathlib import Path
        binary=Path(parent)/'fixture-tool'
        binary.write_text('#!/usr/bin/python3\n'+body);binary.chmod(0o700)
        return {'command':[str(binary),'native-fee-source-proof'],'sha256':digest(binary.read_bytes()),
            'evidence_directory':str(parent)}
    def test_default_input_bound_stays2mib_but_native_allows_complete_larger_original(self):
        import tempfile
        from simulator.two_step_normal import run_proof,run_native_fee_source_proof
        with tempfile.TemporaryDirectory()as tmp:
            tool=self.tool(tmp,'import sys,json,hashlib\nr=sys.stdin.buffer.read()\nprint(json.dumps({"input_sha256":hashlib.sha256(r).hexdigest()}))\n')
            request={'synthetic_private_original':'x'*(2*1024*1024)}
            with self.assertRaisesRegex(ValueError,'input exceeds'):run_proof(tool,request)
            encoded,reply=run_native_fee_source_proof(tool,request)
            self.assertGreater(len(encoded),2*1024*1024)
            self.assertEqual(json.loads(reply)['input_sha256'],digest(encoded))
    def test_default_output_bound_stays2mib_native_limit_is_separate(self):
        import tempfile
        from simulator.two_step_normal import run_proof,run_native_fee_source_proof
        with tempfile.TemporaryDirectory()as tmp:
            tool=self.tool(tmp,'import json\nprint(json.dumps({"fixture":"x"*(2*1024*1024)}))\n')
            with self.assertRaisesRegex(ValueError,'exceeded bounds'):run_proof(tool,{})
            _,reply=run_native_fee_source_proof(tool,{})
            self.assertGreater(len(reply),2*1024*1024)
    def test_fixed_offline_subcommand_no_rpc_or_config_argument(self):
        from simulator.two_step_normal import run_native_fee_source_proof
        for command in [['/not/executed','rpc'],['/not/executed','native-fee-source-proof','-C','private.toml']]:
            with self.assertRaisesRegex(ValueError,'fixed native fee proof'):run_native_fee_source_proof({'command':command},{})
    def test_actual_refusal_keeps_private_terminal_and_never_becomes_proof(self):
        import tempfile
        from pathlib import Path
        from simulator.two_step_normal import run_native_fee_source_proof
        with tempfile.TemporaryDirectory()as tmp:
            tool=self.tool(tmp,'import sys\nsys.stderr.write("fixture refusal")\nsys.exit(7)\n')
            with self.assertRaisesRegex(ValueError,'native proof refused'):run_native_fee_source_proof(tool,{})
            directory=next(x for x in Path(tmp).iterdir()if x.is_dir())
            self.assertEqual(json.loads((directory/'terminal.json').read_text())['exit'],7)
            self.assertTrue(all(x.stat().st_mode&0o777==0o600 for x in directory.iterdir()))
    def test_changed_executable_refuses_before_private_request_dispatch(self):
        import tempfile
        from pathlib import Path
        from simulator.two_step_normal import run_native_fee_source_proof
        with tempfile.TemporaryDirectory()as tmp:
            tool=self.tool(tmp,'print("{}")\n');Path(tool['command'][0]).write_text('changed')
            with self.assertRaisesRegex(ValueError,'executable identity'):run_native_fee_source_proof(tool,{})
