"""One reconciled native transfer per real block for an admitted phase."""
import json,time
from simulator.model import canonical
from simulator.signet_proof import verify_coin
from simulator.signet_checks import confirmed_backing

def advance(campaign,height):
    prefix=f'traffic-{height}'
    for row in campaign.db.execute("SELECT id FROM action WHERE operation='send' AND id LIKE 'traffic-%-send'"):
        earlier=row[0][:-5]
        if earlier!=prefix and not campaign.db.execute('SELECT 1 FROM result WHERE id=?',(earlier+'-complete',)).fetchone():
            raise RuntimeError('an earlier bounded monetary intent requires reconciliation before new traffic')
    original=campaign.db.execute("SELECT chain FROM action WHERE id='s01-transfer'").fetchone()
    if original and height<=json.loads(original[0])['height']:
        return {'kind':'active_traffic_observation','stage':'WAITING_FOR_NEW_HEIGHT_AFTER_S01','height':height,'amount_sat':5000,'transfer_dispatched':False}
    key=prefix+'-plan'
    old=campaign.db.execute('SELECT payload FROM result WHERE id=?',(key,)).fetchone()
    if old:plan=json.loads(old[0])
    else:
        count=campaign.db.execute("SELECT count(*) FROM action WHERE operation='send' AND id LIKE 'traffic-%-send'").fetchone()[0]
        provenance=json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='phase_upgrade'").fetchone()[0])
        first=provenance['first_traffic_sender'];other='sender' if first=='receiver' else 'receiver'
        sender,receiver=(first,other) if count%2==0 else (other,first)
        plan={'kind':'active_traffic_plan','height':height,'sequence':count,'sender':sender,'receiver':receiver,'amount_sat':5000,'maximum_fee_sat':1000}
        campaign.db.execute('INSERT INTO result VALUES (?,?,?)',(key,time.time(),canonical(plan)))
    done=campaign.db.execute('SELECT payload FROM result WHERE id=?',(prefix+'-complete',)).fetchone()
    if done:return json.loads(done[0])
    sender,receiver=plan['sender'],plan['receiver']
    def native(name,actor,operation,args):
        row=campaign.execute(name,actor,operation,args)
        if row['state']!='acknowledged':raise RuntimeError('original native outcome requires reconciliation')
        return json.loads(row['reply'])
    address=native('traffic-'+receiver+'-address',receiver,'address',{})['address']
    names=[prefix+'-sender-before',prefix+'-sender-after',prefix+'-receiver-before',prefix+'-receiver-after']
    sb=native(names[0],sender,'sync_vtxos',{})
    rb=native(names[2],receiver,'sync_vtxos',{})
    if any(c['state'] not in {'spendable','spent'} for c in sb+rb):
        return {'kind':'active_traffic_observation','stage':'WAITING_FOR_NATIVE_SETTLEMENT','height':height,'amount_sat':5000,'transfer_dispatched':False}
    if sum(c['amount_sat'] for c in sb if c['state']=='spendable')<6000:
        raise RuntimeError('bounded traffic lacks declared amount and fee headroom')
    confirmed_backing(campaign.core,[sb,rb])
    native(prefix+'-send',sender,'send',{'destination':address,'amount_sat':5000})
    sa=native(names[1],sender,'sync_vtxos',{})
    ra=native(names[3],receiver,'sync_vtxos',{})
    checkname=prefix+'-check'
    prior=campaign.db.execute('SELECT payload FROM result WHERE id=?',(checkname,)).fetchone()
    check=json.loads(prior[0]) if prior else campaign.check_transfer(checkname,prefix+'-send',names[0],names[1],names[2],names[3],1000)
    if check.get('arithmetic')!='PASS' or check.get('backing')!='PASS':
        raise RuntimeError('original bounded transfer conservation/backing requires reconciliation')
    proofs=[]
    for actor,snapshot in [(sender,sa),(receiver,ra)]:
        for coin in snapshot:
            if coin['state']=='spendable':
                expected=address if actor==receiver and coin['id'] in check['new_receiver_coins'] else None
                proofs.append(verify_coin(campaign,actor,coin,expected_address=expected))
    if not proofs or any(p.get('status')!='PASS' for p in proofs):
        raise RuntimeError('original bounded transfer signatures require reconciliation')
    value={'kind':'active_traffic_observation','stage':'RECONCILED','height':height,'sequence':plan['sequence'],'sender':sender,'receiver':receiver,'amount_sat':5000,'observed_offchain_fee_sat':check['observed_offchain_fee_sat'],'check':check,'signature_proofs':proofs,'scope':'bounded ordinary native traffic; no fallback, app, Noah or load qualification'}
    campaign.db.execute('INSERT INTO result VALUES (?,?,?)',(prefix+'-complete',time.time(),canonical(value)))
    return value
