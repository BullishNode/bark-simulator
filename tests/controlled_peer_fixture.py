"""Explicit synthetic original references; this is not native or live evidence."""
import hashlib
from unittest.mock import patch
from simulator.model import SIGNET_GENESIS, canonical
from simulator.treasury import KEY
from simulator.controlled_peer_evidence import _derive_external
from simulator.fees import movement_fee, receive_fee
from tests.test_final_campaign import PINS

NODES={'operator':'02'+'5'*64,'fixture_peer':'02'+'6'*64}
INVOICE='synthetic-signed-invoice'
HASH='b'*64

def membership(f):
    if f.store.get_meta(KEY):return
    members=[]
    for alias,identity in NODES.items():
        member={'id':alias,'kind':'lightning_peer','role':alias,'identity':identity,'descriptors':[]}
        with patch('simulator.store.time.time',return_value=99.0):
            f.store.event('treasury_member_verified',{'member':member,'genesis':SIGNET_GENESIS,'financial_pins':PINS})
        sequence=f.store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
        members.append({**member,'verification_sequence':sequence})
    declaration={'id':'synthetic-external','genesis':SIGNET_GENESIS,'pins':PINS,'members':members,'excluded':[]}
    f.store.db.execute('INSERT INTO meta VALUES (?,?)',(KEY,canonical(declaration)))
    with patch('simulator.store.time.time',return_value=99.0):
        f.store.event('treasury_boundary_declared',declaration)

def sources(f,at,direction):
    refs={}
    payer,recipient=('operator','fixture_peer') if direction=='send' else ('fixture_peer','operator')
    digest=hashlib.sha256(INVOICE.encode()).hexdigest()
    for alias in NODES:
        row={'payment_hash':HASH,'invoice_sha256':digest,'invoice_amount_msat':1_000_000,
             'payee':NODES[recipient],'signature_valid':True,'preimage_hash_verified':True,'terminal_at':at}
        fact={'schema_version':1,'node_alias':alias,'node_pubkey':NODES[alias],'network':'signet','node_version':'synthetic',
              'query_started_at':at,'query_completed_at':at,'selection':'exact_hash_without_pagination',
              'payment_hash':HASH,'pay':None,'invoice':None}
        if alias==payer:fact['pay']={**row,'state':'complete','amount_msat':1_000_000,'amount_sent_msat':1_000_003,'number_of_parts':1}
        else:fact['invoice']={**row,'state':'paid','amount_received_msat':1_000_000}
        with patch('simulator.store.time.time',return_value=float(at)):
            f.store.event('controlled_peer_payment_source',{'action_id':'external','fact':fact,'financial_pins':PINS})
        refs[('operator' if alias=='operator' else 'peer')+'_source_sequence']=f.store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
    return refs

def external_send(f,at=103,*,emit=True):
    membership(f)
    data={'payment_hash':HASH,'payment_status_verified':True,'payment_state':'succeeded','committed_fee_sat':0}
    f.action('external','pay_invoice',at=at,data=data,args={'invoice':INVOICE,'amount_sat':1000})
    result=f.event('action_result',{'action_id':'external','state':'completed','result':{'data':data}})
    f.coin('actor-01','send-principal','external',at)
    proposal=f.event('driver_evidence',{'action_id':'external','event':'lightning_proposal','data':{
        'payment_hash':HASH,'amount_sat':1000,'fee_ceiling_sat':0,'input_vtxo_ids':['send-principal']}})
    movement={'id':'external-send','subsystem':'bark.lightning_send','status':'successful','payment_hash':HASH,
              'input_vtxos':['send-principal'],'output_vtxos':[],'offchain_fee_sat':0,'effective_balance_sat':-1000}
    f.store.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',('actor-01',movement['id'],canonical(movement)))
    action=f.store.db.execute("SELECT * FROM action WHERE id='external'").fetchone()
    fee=f.event('client_fee_reconciled',{'action_id':'external',**movement_fee(f.store,action)})
    f.store.db.execute("UPDATE action SET actual_fee_sat=0 WHERE id='external'")
    outcome=f.event('lightning_payment_outcome',{'action_id':'external','payment_hash':HASH,'state':'succeeded','response':{
        'status':'ok','action_id':'payment-status:external','data':{'payment_hash':HASH,'state':'succeeded',
        'success_preimage_hash_valid':True,'read_only':True,'actual_fee_sat':0}}})
    refs={'action_id':'external','payment_hash':HASH,'direction':'send','financial_pins':PINS,
          'native_result_source_sequence':result,'native_fee_source_sequence':fee,'native_proposal_source_sequence':proposal,'native_outcome_source_sequence':outcome,
          **sources(f,at,'send')}
    action=f.store.db.execute("SELECT * FROM action WHERE id='external'").fetchone()
    proof={**refs,**_derive_external(f.store,action,refs)}
    return f.event('controlled_peer_payment_verified',proof) if emit else proof

def external_receive(f,at=103,*,emit=True):
    membership(f)
    f.action('external','invoice',at=at,data={'payment_hash':HASH,'invoice':INVOICE,'estimated_claim_fee_sat':0},args={'amount_sat':1000})
    result=f.event('action_result',{'action_id':'external','state':'completed','result':{'data':{'payment_hash':HASH,'invoice':INVOICE,'estimated_claim_fee_sat':0}}})
    movement={'id':'external-receive','subsystem':'bark.lightning_receive','status':'successful','payment_hash':HASH,
              'input_vtxos':[],'output_vtxos':['received'],'offchain_fee_sat':0,'effective_balance_sat':1000}
    claim_data={'receive_count_before':1,'receive_count_after':0,'before_evidence':{'movements':[]},'evidence':{'movements':[movement]}}
    f.action('claim','sync',at=at,data=claim_data)
    f.coin('actor-01','received','claim',at)
    f.store.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',('actor-01',movement['id'],canonical(movement)))
    claim=f.store.db.execute("SELECT * FROM action WHERE id='claim'").fetchone()
    fee=f.event('client_fee_reconciled',{'action_id':'claim',**receive_fee(f.store,claim)})
    f.store.db.execute("UPDATE action SET actual_fee_sat=0 WHERE id='claim'")
    f.event('action_result',{'action_id':'claim','state':'completed','result':{'data':claim_data}})
    refs={'action_id':'external','payment_hash':HASH,'direction':'receive','financial_pins':PINS,
          'native_result_source_sequence':result,'native_fee_source_sequence':fee,'claim_action_id':'claim',**sources(f,at,'receive')}
    action=f.store.db.execute("SELECT * FROM action WHERE id='external'").fetchone()
    proof={**refs,**_derive_external(f.store,action,refs)}
    return f.event('controlled_peer_payment_verified',proof) if emit else proof
