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
        originals['sql_raw']='BEGIN\nSET\n'+whole.decode()+'\n'+json.dumps(database)+'\nCOMMIT\n'
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
        return prepare_native_fee_request(t,r,expected_product_commit=PIN,observation=o)
    def mutate_originals(self,t,edit):
        name='b-native-fee-originals.json';value=json.loads(t['auxiliary_originals'][name]);edit(value)
        raw=json.dumps(value).encode();t['auxiliary_originals'][name]=raw
        t['manifest']['files'][name]={'sha256':digest(raw),'size_bytes':len(raw)}
    def test_exact_private_bytes_and_all_domains_go_to_native_not_public_trace(self):
        t,r,o=self.inputs();request=self.prepare(t,r,o)
        self.assertEqual(request['originals']['journal_raw'],'private signed package fixture')
        self.assertEqual(request['expected']['database_sha256'],digest(request['originals']['database_raw'].encode()))
        self.assertEqual(request['source_observation'],o)
        # Deliberately synthetic empty DB contradicts snapshotfunding: preparation
        # must NOT claim native row equality; actual native verifier must refuse.
        self.assertNotIn('complete',request);self.assertNotIn('qualified',request)
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
            lines=v['sql_raw'].splitlines();db=json.loads(lines[3]);del db['native_funding_fee_input']
            lines[3]=json.dumps(db);v['sql_raw']='\n'.join(lines)+'\n'
        self.mutate_originals(t,edit)
        with self.assertRaisesRegex(EvidenceGap,'SQL domains'):self.prepare(t,r,o)
    def test_two_transactions_cannot_be_relabelled_one_cut(self):
        t,r,o=self.inputs();self.mutate_originals(t,lambda v:v.update(sql_raw=v['sql_raw'].replace('\n{"native_funding','\nCOMMIT\nBEGIN\n{"native_funding')))
        with self.assertRaisesRegex(EvidenceGap,'transaction framing'):self.prepare(t,r,o)
    def test_bad_source_nonce_is_refused(self):
        t,r,o=self.inputs();o['id']='not-a-source-nonce'
        with self.assertRaisesRegex(EvidenceGap,'source observation'):self.prepare(t,r,o)
