"""Read-only independent canonical Core proof, no native wallet operations."""
import json,subprocess,pathlib,decimal,datetime,hashlib,sqlite3
D=decimal.Decimal;b=pathlib.Path('/var/lib/abandon-fresh');cli=['/opt/abandon-fresh/bin/bitcoin-cli','-datadir='+str(b/'core')]
def rpc(m,*a):
 raw=subprocess.check_output(cli+[m]+[str(x) for x in a],text=True).strip()
 return raw if m in {'getblockhash','getbestblockhash'} else json.loads(raw,parse_float=D)
def sat(v):
 x=v*100000000;assert x==x.to_integral_value();return int(x)
def transaction(t):
 x=rpc('getrawtransaction',t,'true');assert x['txid']==t and x.get('confirmations',0)>=6
 block=rpc('getblockheader',x['blockhash']);assert rpc('getblockhash',block['height'])==x['blockhash']
 inputs=[]
 for vin in x['vin']:
  p=rpc('getrawtransaction',vin['txid'],'true')['vout'][vin['vout']]
  inputs.append({'outpoint':vin['txid']+':'+str(vin['vout']),'amount_sat':sat(p['value'])})
 outputs=[{'vout':o['n'],'amount_sat':sat(o['value']),'script':o['scriptPubKey']['hex']} for o in x['vout']]
 return {'txid':t,'height':block['height'],'confirmations':x['confirmations'],'version':x['version'],'vsize':x['vsize'],'inputs':inputs,'outputs':outputs,'miner_fee_sat':sum(i['amount_sat'] for i in inputs)-sum(o['amount_sat'] for o in outputs)}
info=rpc('getblockchaininfo');assert info['chain']=='signet' and not info['initialblockdownload'];assert rpc('getblockhash',0)=='00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6'
destination='tb1qusq7m3xctjl5csfrr5zpfzg0lqsp9q46z5pa5p';destination_spk=rpc('validateaddress',destination)['scriptPubKey']
cases=[('receive','native-ln-receive-v2','20f119e07cbe1f9949f75813ef705671dee4c8ae81fd665317c26ac920a7247a','a3f00c0ef1f037d0d71c105237107fa576b74fc3629d56feb6b02aac7181b94a','43fb70c6396532ce7161cb275986901569045f676947d9a63a508b95e16d64a0',3890,'0014f6cb317634543f8564334d7262a98dd402f066a5',326782),('failed_send','native-ln-failed-send-v2','556ea567cc4a142457c03585af27e8d07a38753aa97c795dc2dc37bf73eb2e2f','02f1a1939c3b50392f662953c8a3cc9e0aa526d3418ccd65d8d429daf0af1d11','0e4f2b223e99f27fef775a84811269e307fb053f7a6d8f67d1e58930f88f6fa7',28670,'0014d1aec760c6412136dd1c5864b60ab2eba31275cc',326787)]
proof={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'method':'Read-only independent Core canonical transactions plus original journal operation counts; no native wallet open or financial action.','height':info['blocks'],'bestblockhash':info['bestblockhash'],'recovery_destination':destination,'recovery_destination_script':destination_spk,'cases':{}}
for name,state,parent,child,recovery,amount,script,birthday in cases:
 p=transaction(parent);f=transaction(child);r=transaction(recovery)
 assert p['version']==3 and p['outputs'][0]['amount_sat']==amount and p['outputs'][0]['script']==script and p['miner_fee_sat']==0
 assert parent+':2' in [i['outpoint'] for i in f['inputs']] and f['miner_fee_sat']==363
 assert parent+':0' in [i['outpoint'] for i in r['inputs']]
 assert len(r['outputs'])==1 and r['outputs'][0]['script']==destination_spk
 db=sqlite3.connect('file:'+str(b/'simulation'/state/'signet.sqlite')+'?mode=ro',uri=True)
 assert db.execute("SELECT count(*) FROM action WHERE state IN ('unknown','dispatched')").fetchone()[0]==0
 counts={op:n for op,n in db.execute("SELECT operation,count(*) FROM action WHERE state='acknowledged' GROUP BY operation")}
 assert counts['restore']==counts['onchain_drain']==1
 restore=json.loads(db.execute("SELECT arguments FROM action WHERE operation='restore'").fetchone()[0]);assert restore=={'birthday_height':birthday,'source_actor':'absent'}
 first=db.execute("SELECT observed,payload FROM result WHERE json_extract(payload,'$.case_verdict')='PASS' ORDER BY observed LIMIT 1").fetchone();original=json.loads(first[1]);assert original['physical_recovery_spend']==recovery
 proof['cases'][name]={'parent':p,'fee_child':f,'recovery':r,'original_seed_birthday':birthday,'operation_counts':counts,'unknown_actions':0,'original_first_pass_observed':first[0],'original_first_pass_recovery_height':original['recovery'][0]['confirmation_height'],'original_first_pass_recovery_confirmations':original['recovery'][0]['chain']['height']-original['recovery'][0]['confirmation_height']+1,'original_first_pass_payload_sha256':hashlib.sha256(first[1].encode()).hexdigest(),'operator_parent_remainder_sat':p['outputs'][1]['amount_sat'],'watchman_miner_fee_cash_sat':f['miner_fee_sat'],'net_subsidy_sat':max(0,f['miner_fee_sat']-p['outputs'][1]['amount_sat']),'scope':'Native BOLT11 only; no Noah/LNURL, reorg or legacy fault qualification.'}
 db.close()
assert rpc('getbestblockhash')==info['bestblockhash'],'chain tip moved; preserve read as nonfinal observation'
path=b/'simulation/native-ln-completed-current-core-proof-20261018.json';data=json.dumps(proof,indent=2)+'\n'
with path.open('x') as out:out.write(data)
path.chmod(0o600)
print('PROOF',str(path),'SHA256',hashlib.sha256(data.encode()).hexdigest());print(data)
