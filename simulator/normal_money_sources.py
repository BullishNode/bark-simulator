"""Confirmed whole-boundary miner/flow projections from authenticated originals.

Caller authenticates source buffers/immutable declarations, then journals these
records transactionally. This module never writes Store or treats a reservation
as payment. No source-completeness or readiness verdict is returned.
"""
import hashlib
import json
import re
import time
from .bundle_audit import decode_transaction
from .model import integer, canonical
from .normal_native_fee import _json, CANDIDATE_FIELDS, URGENT, PATHS

MAX_BYTES=16*1024*1024
MAX_CALLS=512
MAX_ROWS=10000

def _hash(raw):return hashlib.sha256(raw).hexdigest()
def _identifier(value):
    if not isinstance(value,str) or re.fullmatch('[0-9a-f]{64}',value) is None:raise ValueError('canonical source identity required')
    return value

def _wire(value):
    if not isinstance(value,list) or not value or any(type(n) is not int or not 0<=n<=255 for n in value):raise ValueError('native original bytes required')
    raw=bytes(value)
    if len(raw)>4*1024*1024:raise ValueError('native original bound')
    return raw

def _event(store,kind,action_id):
    rows=store.db.execute("SELECT payload FROM event WHERE kind=? AND json_extract(payload,'$.action_id')=?",(kind,action_id)).fetchall()
    if len(rows)!=1:raise ValueError('one original action event required')
    return json.loads(rows[0][0])

class _Core:
    def __init__(self,store,chain,height,tip_hash):
        self.store,self.chain=store,chain;self.height=integer(height,'source height');self.tip=_identifier(tip_hash)
        self.cache={};self.calls=0;self.bytes=0;self.started=time.monotonic();self.hashes={};self.blocks={}
        self.stable()
    def bounded(self):
        if self.calls>MAX_CALLS or self.bytes>MAX_BYTES or time.monotonic()-self.started>60:raise ValueError('confirmed money proof bound')
    def stable(self):
        value=self.chain.identity();self.calls+=1;self.bounded()
        if value['initialblockdownload'] is not False or (value['blocks'],value['bestblockhash'])!=(self.height,self.tip):raise ValueError('money proof Core tip changed')
    def read(self,txid,*,carrier=False):
        txid=_identifier(txid)
        if txid not in self.cache:
            self.calls+=1;self.bounded()
            if carrier:
                # Existing helper verifies fresh trace-bound method/params/typed-5.
                from .two_step_normal import transaction_or_absent
                value=transaction_or_absent(self.store,self.chain,txid)
            else:value=self.chain.tx(txid)
            if value is not None:
                raw=value.get('hex')
                if not isinstance(raw,str):raise ValueError('Core original bytes unavailable')
                decoded=decode_transaction(raw,public_body=True)
                if decoded['txid']!=txid or value.get('txid')!=txid:raise ValueError('Core original txid differs')
                self.bytes+=len(raw)//2;self.bounded();self.hashes[txid]=_hash(bytes.fromhex(raw))
            self.cache[txid]=value
        return self.cache[txid]
    def confirmed(self,txid,*,carrier=False):
        value=self.read(txid,carrier=carrier)
        if value is None:return None
        confirmations=value.get('confirmations',0)
        if type(confirmations) is not int:raise ValueError('Core confirmation count malformed')
        if confirmations<=0:return None
        block=_identifier(value.get('blockhash'));height=self.height-confirmations+1
        if height<0:raise ValueError('Core confirmation height impossible')
        if height not in self.blocks:
            self.calls+=1;self.bounded();self.blocks[height]=self.chain.call('getblockhash',height)
        if self.blocks[height]!=block:raise ValueError('confirmed monetary carrier not on active chain')
        return value
    def price(self,value):
        tx=decode_transaction(value['hex'],public_body=True);inputs=[];seen=set();gross=0
        for entry in tx['inputs']:
            point=entry['outpoint']
            if point in seen:raise ValueError('duplicate monetary input')
            seen.add(point);txid,index=point.rsplit(':',1)
            if txid=='0'*64 and index=='4294967295':raise ValueError('coinbase is not a miner expense')
            original=self.read(txid);parent=decode_transaction(original['hex']);index=int(index)
            if index>=len(parent['outputs']):raise ValueError('monetary parent output absent')
            output=parent['outputs'][index];gross+=output['amount_sat'];inputs.append({'outpoint':point,'amount_sat':output['amount_sat'],'script':output['script']})
        fee=gross-sum(v['amount_sat']for v in tx['outputs'])
        if fee<0:raise ValueError('monetary carrier creates value')
        return {**tx,'inputs':inputs,'fee_sat':fee,'confirmations':value['confirmations'],'blockhash':value['blockhash']}


def _existing(store,kind):
    result={}
    for row in store.db.execute('SELECT payload FROM event WHERE kind=? ORDER BY sequence',(kind,)):
        value=json.loads(row[0]);identifier=value['monetary_id']
        if identifier in result:raise ValueError('existing monetary identity duplicated')
        result[identifier]=value
    return result


def collect_money_sources(store,chain,*,financial_pins,boundary_members,native_tables,native_fee,
        native_source_sha256,native_member_ids,height,tip_hash,funding_intents=(),admitted_funding_sha256=()):
    """Return cost_records/flow_records; caller writes an exact source join later.

    native_tables/native_fee are the already authenticated source cut and the
    actual verify_native_fee_epoch result, not remote-selected classifications.
    No cost/flow sequence is accepted from the transport or chosen here.
    """
    if funding_intents:
        raise ValueError('funding ownership source join unqualified: declarations alone are insufficient')
    store.verify_event_chain();_identifier(native_source_sha256)
    members={v['id']:v for v in boundary_members} if isinstance(boundary_members,list) else dict(boundary_members)
    if set(native_member_ids)!={'rounds','watchman'} or native_member_ids['rounds']==native_member_ids['watchman']:raise ValueError('explicit distinct native fee members required')
    for name in native_member_ids.values():
        if name not in members or members[name]['kind']!='wallet' or members[name]['role']!='operator':raise ValueError('native payer is not original operator wallet')
    policies=native_tables['fee_allowance_policy']
    if len(policies)!=1:raise ValueError('one authenticated native policy row required')
    policy=_json(bytes.fromhex(policies[0]['policy_bytes_hex']));server=policy['server_pubkey']
    backing=[v['id'] for v in members.values() if v['kind']=='ark_backing' and v['role']=='operator' and v['identity']==server]
    if len(backing)!=1:raise ValueError('one original server backing payer required')
    core=_Core(store,chain,height,tip_hash)
    if chain.call('getblockhash',0)!=policy['genesis']:raise ValueError('money proof genesis differs from native policy')
    old_costs=_existing(store,'financial_cost_verified');old_flows=_existing(store,'treasury_flow_verified')
    costs={};flows={};zeros={};pending={};services=[];reused_costs=set();reused_flows=set();evidence={}
    def add_cost(tx,budget,source,reference,action_id=None):
        identifier='miner:'+tx['txid'];fee=tx['fee_sat']
        record={'monetary_id':identifier,'kind':'miner_cost','txid':tx['txid'],'amount_msat':fee*1000,'budget':budget,'source':source,'destination':'miners','financial_pins':financial_pins}
        if action_id is not None:record['action_id']=action_id
        evidence.setdefault(tx['txid'],[]).append(reference)
        if fee==0:
            if identifier in old_costs:raise ValueError('zero fee carrier has existing positive expense')
            zeros[tx['txid']]={'txid':tx['txid'],'fee_sat':0,'raw_sha256':core.hashes[tx['txid']],'blockhash':tx['blockhash'],'budget':budget}
            return
        if identifier in old_costs:
            old=old_costs[identifier]
            if (old.get('kind')!='miner_cost' or old.get('txid')!=tx['txid'] or old.get('amount_msat')!=fee*1000
                    or old.get('budget')!=budget or old.get('source')!=source or old.get('destination')!='miners'):
                raise ValueError('original miner cost payer/destination conflicts; do not rewrite')
            if action_id is not None and old.get('action_id')!=action_id:raise ValueError('original miner action conflicts')
            reused_costs.add(identifier);return
        if identifier in costs and costs[identifier]!=record:raise ValueError('same miner carrier has conflicting payer/class/action')
        costs[identifier]=record
    rows=native_tables['fee_allowance_candidate']
    if not isinstance(rows,list) or len(rows)>MAX_ROWS or sorted(v['id']for v in rows)!=native_fee['candidate_ids']:raise ValueError('verified native reservation membership differs')
    groups={}
    for row in rows:
        raw=bytes.fromhex(row['candidate_bytes_hex']);c=_json(raw)
        if set(c)!=CANDIDATE_FIELDS or c['epoch_id']!=native_fee['epoch_id'] or c['path'] not in PATHS:raise ValueError('native fee candidate identity/class differs')
        signed=_wire(c['raw']);identifier=hashlib.sha256(hashlib.sha256(signed).digest()).digest()[::-1].hex()
        if identifier!=row['id'] or type(row['urgent']) is not bool or row['urgent']!=(c['path'] in URGENT):raise ValueError('native fee reservation wtxid/class differs')
        tx=decode_transaction(signed.hex());groups.setdefault(tx['txid'],[]).append((row,c,signed))
    for txid,variants in groups.items():
        categories={'urgent' if row['urgent'] else 'ordinary'for row,_,_ in variants}
        if len(categories)!=1:raise ValueError('one carrier assigned ordinary and urgent')
        value=core.confirmed(txid,carrier=True)
        if value is None:pending[txid]={'txid':txid,'reason':'signed reservation not independently confirmed','signed_original_sha256':sorted(_hash(v[2])for v in variants),'budget':next(iter(categories))};continue
        matching=[v for v in variants if v[2].hex()==value['hex']]
        if len(matching)!=1:raise ValueError('confirmed Core witness differs from authenticated native carrier')
        row,c,signed=matching[0];tx=core.price(value)
        if tx['fee_sat']!=integer(row['fee_sat'],'native candidate original fee'):raise ValueError('native reservation fee differs from actual parents')
        # Bind each supplied native parent body, not just its claimed value.
        for raw in c['input_parents']:
            parent=_wire(raw);parent_tx=decode_transaction(parent.hex());actual=core.read(parent_tx['txid'])
            if actual['hex']!=parent.hex():raise ValueError('native original parent bytes differ from independent Core')
        payer=backing[0] if c['path'] in {'Sweep','Claim','ProgressParent'} else native_member_ids['watchman' if c['path']=='ProgressChild' else 'rounds']
        add_cost(tx,next(iter(categories)),payer,{'kind':'native_candidate','wtxid':row['id'],'candidate_sha256':_hash(bytes.fromhex(row['candidate_bytes_hex'])),'source_sha256':native_source_sha256})
    for row in native_tables['recovery_receipt']:
        raw=bytes.fromhex(row['transaction_bytes_hex']);txid=decode_transaction(raw.hex())['txid']
        if row['id']!=txid or row['proof_state']!='physical_bound':raise ValueError('recovery receipt identity/state differs')
        value=core.confirmed(txid)
        if value is None or value['hex']!=raw.hex() or value['blockhash']!=row['block_hash'] or height-value['confirmations']+1!=row['block_height']:raise ValueError('recovery Sweep original active confirmation differs')
        tx=core.price(value);add_cost(tx,'ordinary',backing[0],{'kind':'recovery_sweep','receipt_id':row['id'],'signed_raw_sha256':_hash(raw),'source_sha256':native_source_sha256})
    for action in store.db.execute("SELECT * FROM action WHERE operation='board' AND state='completed' ORDER BY id"):
        proposal_rows=store.db.execute("SELECT payload FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')='board_proposal'",(action['id'],)).fetchall()
        if len(proposal_rows)!=1:raise ValueError('one original Board proposal required')
        proposal=json.loads(proposal_rows[0][0])['data'];txid=_identifier(proposal['funding_txid'])
        intent=_event(store,'action_intent',action['id'])
        if intent['actor']!=action['actor_id'] or intent['operation']!='board' or intent['args']!=json.loads(action['args']) or intent['fee_reservation_sat']!=action['fee_reservation_sat']:raise ValueError('Board mutable action differs from original intent')
        if action['actor_id'] not in members or members[action['actor_id']]['role']!='customer':raise ValueError('Board payer not original customer member')
        value=core.confirmed(txid,carrier=True)
        if value is None:pending[txid]={'txid':txid,'reason':'Board proposal not independently confirmed','action_id':action['id']};continue
        tx=core.price(value);unsigned=decode_transaction(proposal['unsigned_funding_tx'],public_body=True)
        if tx['txid']!=unsigned['txid'] or tx['stripped_hex']!=unsigned['stripped_hex']:raise ValueError('Board actual body differs from pre-sign original')
        from .fees import board_fee
        charge=board_fee(store,action,tx)
        if tx['fee_sat']!=proposal['planned_mining_fee_sat'] or charge['service_charge_sat']!=proposal['estimated_service_fee_sat']:raise ValueError('Board actual mining/service differs from original proposal')
        services.append({'action_id':action['id'],'txid':tx['txid'],'coin_id':charge['coin_id'],'amount_msat':charge['service_charge_sat']*1000,'scope':'internal customer-to-operator charge; never miner expense'})
        add_cost(tx,'ordinary',action['actor_id'],{'kind':'client_board','action_id':action['id'],'proposal_sha256':_hash(proposal_rows[0][0].encode())},action['id'])
    core.stable();store.verify_event_chain()
    return {'cost_records':[costs[k]for k in sorted(costs)],'flow_records':[flows[k]for k in sorted(flows)],
        'zero_fee_carriers':zeros,'pending_carriers':pending,'client_service_charges':services,'reused_cost_ids':sorted(reused_costs),'reused_flow_ids':sorted(reused_flows),
        'evidence_hashes':{'native_source_sha256':native_source_sha256,'independent_Core_raw_sha256':core.hashes,'carrier_sources':evidence}}
