#!/usr/bin/env python3
"""Independent raw-block audit of the simulator's completed board disappearance slice.

No original wallet is opened. Reconstruct a network-disabled private Core from
raw blocks; inspect actual prevouts/outputs/confirmations and validate public
VTXO signatures with the pinned independent read-only native verifier.
"""
import argparse,datetime,hashlib,importlib.util,json,shutil,sqlite3,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('chain_audit','/home/francis/bark-integration-2026-10-01/scale-stage4/verify-stage4.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

def verify(run,core,proof_binary,evidence):
    pre=json.loads((run/'predeclared.json').read_text());summary=json.loads((run/'summary.json').read_text())
    assert summary['overall']=='PASS' and summary['exit']==0
    test=pre['test'].split('::')[-1]
    assert test in ('simulator_board_absence_restore','simulator_pending_board_absence_restore','simulator_ark_receive_then_disappear','simulator_lightning_receive_then_disappear')
    boundary=json.loads((run/'out/absence-boundary.json').read_text())
    if test=='simulator_pending_board_absence_restore':
        assert boundary['scenario']=='H04' and not boundary['client_registered_before_absence']
        assert 0<boundary['anchor_confirmations']<boundary['required_board_confirmations']
    else:
        assert boundary['scenario']=='H03' and boundary['client_registered_before_absence']
        assert boundary['anchor_confirmations']>=boundary['required_board_confirmations']
    assert a.sha(run/'simulator_vertical.rs')==pre['harness_sha256']
    assert a.sha(run/'run-regtest.py')==pre['runner_sha256']
    assert a.sha(run/'regtest-client.py')==pre['simulator_sources']['integration/regtest-client.py']
    result=summary['result'];p=result['payout'];r=result['seed_restore']
    tx=core.tx(p['txid']);assert tx['confirmations']>0
    out=tx['vout'][p['vout']];assert out['scriptPubKey']['hex']==p['spk']
    assert a.sats(out['value'])==p['amount_sat']>=1000
    assert sum(o['scriptPubKey']['hex']==p['spk'] for o in tx['vout'])==1
    fee=sum(a.sats(core.tx(i['txid'])['vout'][i['vout']]['value']) for i in tx['vin'])-sum(a.sats(o['value']) for o in tx['vout'])
    assert fee==p['tx_fee_sat']==p['recipient_fee_sat']+p['operator_fee_sat']
    assert p['principal_sat']==p['amount_sat']+p['recipient_fee_sat']
    if test in ('simulator_board_absence_restore','simulator_pending_board_absence_restore'):assert p['principal_sat']==10000
    spend=core.tx(result['confirmed_seed_spend']);assert spend['confirmations']>0
    actual_inputs={f"{i['txid']}:{i['vout']}" for i in spend['vin']}
    assert actual_inputs=={i['outpoint'] for i in r['inputs']}
    assert f"{p['txid']}:{p['vout']}" in actual_inputs
    restore_fee=sum(a.sats(core.tx(i['txid'])['vout'][i['vout']]['value']) for i in spend['vin'])-sum(a.sats(o['value']) for o in spend['vout'])
    assert restore_fee==r['fee_sat']
    operations=[]
    for line in (run/'out/client-operations.log').read_text().splitlines():
        try:v=json.loads(line)
        except ValueError:continue
        if v.get('status')=='ok':operations.append(v)
    created=next(o for o in operations if o['action_id'].startswith('fixture-create'))
    assert created['data']['fallback_script']==p['spk']
    parent,coin=next((o,c) for o in operations for c in o['data'].get('evidence',{}).get('coins',[]) if c['id']==p['entitlement_id'])
    binding=parent['data']['evidence'].get('binding')
    fixture=run/'test-data/bark_sdk'/test
    manifest=json.loads((fixture/'sim-fixture.json').read_text())
    argv=[str(proof_binary),f'http://127.0.0.1:{core.port}',str(core.datadir/'regtest/.cookie'),manifest['server_pubkey']]
    request={**coin,'binding':binding} if binding else coin['signed_vtxo']
    validated=subprocess.run(argv,input=json.dumps(request) if binding else request,text=True,capture_output=True,timeout=30,check=True)
    decoded=json.loads(validated.stdout)
    assert decoded['signed_path_valid'] and decoded['id']==p['entitlement_id']
    assert decoded['amount_sat']==coin['amount_sat'] and decoded['user_pubkey']==coin['user_pubkey']
    if binding:
        assert decoded['binding']['record_signature_valid'] and decoded['binding']['key_link_signature_valid']
        assert decoded['binding']['spk']==p['spk']
        wrong={**request,'binding':{**binding,'spk':'0014'+'00'*20}}
        rejected=subprocess.run(argv,input=json.dumps(wrong),text=True,capture_output=True,timeout=30)
        assert rejected.returncode!=0,'verifier accepted an altered destination binding'
    # Negative control: changing the signed coin amount must invalidate proof.
    encoded=bytearray.fromhex(coin['signed_vtxo']);encoded[2]^=1
    bad=subprocess.run(argv,input=encoded.hex(),text=True,capture_output=True,timeout=30)
    assert bad.returncode!=0,'verifier accepted tampered signed amount'
    (evidence/'public-vtxo-proof.json').write_text(json.dumps(decoded,indent=2)+'\n')
    ids=p.get('entitlement_ids',[p['entitlement_id']]);validated_coins=[]
    for coin_id in ids:
        parent,owned=next((o,c) for o in operations for c in o['data'].get('evidence',{}).get('coins',[]) if c['id']==coin_id)
        bound=parent['data']['evidence']['binding']
        checked=subprocess.run(argv,input=json.dumps({**owned,'binding':bound}),text=True,capture_output=True,timeout=30,check=True)
        obj=json.loads(checked.stdout)
        assert obj['signed_path_valid'] and obj['id']==coin_id and obj['amount_sat']==owned['amount_sat']
        assert obj['binding']['record_signature_valid'] and obj['binding']['key_link_signature_valid'] and obj['binding']['spk']==p['spk']
        validated_coins.append(obj)
    assert len(ids)==len(set(ids)) and sum(c['amount_sat'] for c in validated_coins)==p['principal_sat']
    receive_boundary=None
    if result.get('receive_rail'):
        receive_boundary=json.loads((run/'out/receive-absence-boundary.json').read_text())
        assert receive_boundary['rail']==result['receive_rail'] and receive_boundary['online'] is False
        assert receive_boundary['payout_verdict']=='pending'
        assert set(receive_boundary['coin_ids']).issubset(ids)
        fixture=run/'test-data/bark_sdk'/test
        db=sqlite3.connect('file:'+str(fixture/'sim-journal/state.sqlite')+'?mode=ro',uri=True)
        try:
            assert db.execute("SELECT online FROM actor WHERE id='actor-01'").fetchone()[0]==0
            assert db.execute("SELECT count(*) FROM action WHERE actor_id='actor-01' AND created_at>?",(receive_boundary['armed_at'],)).fetchone()[0]==0
            event=db.execute("SELECT count(*) FROM event WHERE kind='receive_then_disappear_armed'").fetchone()[0]
            assert event==1
        finally:db.close()
        payments=[]
        for height in range(core.call('getblockcount')+1):
            block=core.call('getblock',core.call('getblockhash',height),2)
            for transaction in block['tx']:
                for output in transaction['vout']:
                    if output['scriptPubKey']['hex']==p['spk']:
                        payments.append({'txid':transaction['txid'],'vout':output['n'],'amount_sat':a.sats(output['value'])})
        assert payments==[{'txid':p['txid'],'vout':p['vout'],'amount_sat':p['amount_sat']}], 'wrong, additional or duplicate payout to absent owner'
        (evidence/'all-payments-to-absent-owner.json').write_text(json.dumps(payments,indent=2)+'\n')
    (evidence/'all-public-coin-proofs.json').write_text(json.dumps(validated_coins,indent=2)+'\n')
    board_at=next(i for i,o in enumerate(operations) if o['action_id'].startswith('fixture-board'))
    board=operations[board_at]['data']
    assert boundary['coin_id']==p['entitlement_id']
    if test=='simulator_pending_board_absence_restore':
        assert not any(o['action_id'].startswith('fixture-sync') for o in operations[board_at+1:])
        snapshot=next(o['data'] for o in operations[board_at+1:] if o['action_id'].startswith('fixture-snapshot'))
        assert snapshot['balance']['pending_board_sat']>0 and snapshot['balance']['spendable_sat']==0
    funding_txid,funding_index=decoded['chain_anchor'].split(':');funding=core.tx(funding_txid)
    board_mining=sum(a.sats(core.tx(i['txid'])['vout'][i['vout']]['value']) for i in funding['vin'])-sum(a.sats(o['value']) for o in funding['vout'])
    service=a.sats(funding['vout'][int(funding_index)]['value'])-decoded['amount_sat']
    assert service==board['sdk_service_fee_sat']
    return {'overall':'PASS','owners':1,'scenario':boundary['scenario'],'absence_boundary':boundary,'receive_absence_boundary':receive_boundary,'independently_checked_coins':len(validated_coins),'principal_sat':p['principal_sat'],'recipient_net_sat':p['amount_sat'],
        'payout_fee_sat':fee,'restore_fee_sat':restore_fee,'tampered_amount_rejected':True,
        'board_mining_fee_sat':board_mining,'board_service_charge_sat':service,
        'record_and_coin_key_link_verified':binding is not None,'altered_destination_rejected':binding is not None,
        'validation_scope':'raw-chain values, confirmations, destination, seed-recovery spend and signed protocol backing path; automatic settlement discovery and full six-source ownership oracle remain pending'}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('run',type=Path);parser.add_argument('--audit-name',default='independent-audit');args=parser.parse_args();run=args.run.resolve()
    assert args.audit_name.replace('-','').isalnum();evidence=run/args.audit_name;evidence.mkdir(exist_ok=False)
    private=evidence/'core';(private/'regtest').mkdir(parents=True,mode=0o700)
    test=json.loads((run/'predeclared.json').read_text())['test'].split('::')[-1]
    assert test in ('simulator_board_absence_restore','simulator_pending_board_absence_restore','simulator_ark_receive_then_disappear','simulator_lightning_receive_then_disappear')
    blocks=run/'test-data/bark_sdk'/test/'bitcoind/regtest/blocks'
    shutil.copytree(blocks,private/'regtest/blocks')
    executable=Path('/home/francis/bark-integration-2026-10-01/expiry-fallback-evidence/tools/bitcoind-31.0')
    proof=ROOT/'target/debug/vtxo-proof'
    declaration={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'verifier_sha256':a.sha(proof),'auditor_sha256':a.sha(Path(__file__)),'core_sha256':a.sha(executable)}
    (evidence/'predeclared.json').write_text(json.dumps(declaration,indent=2)+'\n')
    try:
        with a.Core(private,executable,evidence) as core:result=verify(run,core,proof,evidence)
    except Exception as e:
        (evidence/'summary.json').write_text(json.dumps({'overall':'FAIL','reason':type(e).__name__+': '+str(e)})+'\n');raise
    (evidence/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
