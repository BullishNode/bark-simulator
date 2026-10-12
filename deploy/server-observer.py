#!/usr/bin/env python3
"""Forced SSH command: fixed read-only fallback operations, bounded output.

No arbitrary shell/SQL/path/RPC names accepted. This bridge has no client seed or
mailbox key. Independent chain verification is performed on the simulator host.
"""
import json,os,re,subprocess,sys,time,tomllib
from pathlib import Path
DEPLOY=Path('/home/ubuntu/abandon-signet-fallback/deploy')
CONTAINER='abandon-signet-fallback-fb-captaind-1'
MAX_BYTES=2*1024*1024

def run(argv):
    result=subprocess.run(argv,cwd=DEPLOY,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20,check=True)
    if len(result.stdout)>MAX_BYTES:raise ValueError('bridge output bound exceeded')
    return result.stdout.decode()

def ops(*args):return run([str(DEPLOY/'fallback/ops.sh'),*args])

def request(raw):
    if len(raw)>4096:raise ValueError('request bound exceeded')
    value=json.loads(raw)
    if not isinstance(value,dict):raise ValueError('invalid bridge request')
    if value.get('kind')=='binding_check':
        if set(value)!={'kind','mailboxes','keys'}:raise ValueError('invalid binding request')
        for field,limit in [('mailboxes',2),('keys',32)]:
            items=value[field]
            if not isinstance(items,list) or len(items)>limit or len(set(items))!=len(items):raise ValueError('binding request bound')
            if any(not isinstance(item,str) or not re.fullmatch(r'(02|03)[0-9a-f]{64}',item) for item in items):raise ValueError('invalid public key')
        if not value['mailboxes']:raise ValueError('protected mailbox required')
        return 'binding_check',value
    if set(value)-{'kind','after'}:raise ValueError('invalid bridge request')
    kind=value.get('kind','snapshot');after=value.get('after','')
    if kind not in {'snapshot','settlements','coins','pending','links','records','nursery'}:raise ValueError('unsupported bridge operation')
    if not isinstance(after,str) or not re.fullmatch(r'[a-zA-Z0-9:_-]{0,128}',after):raise ValueError('invalid cursor')
    if kind=='snapshot' and after:raise ValueError('snapshot takes no cursor')
    return kind,after

def page(kind,after):
    # Lexicographic cyclic inventories: the caller restarts from '' after each
    # complete scan. Never assert a complete consistent database snapshot across
    # separate calls, and never use this cursor as a once-only commit watermark.
    tables={
      'settlements':("s.id", "expiry_settlement s", "s.id,s.txid,s.fee_sat,encode(s.spk,'hex') AS spk,s.created_at, (SELECT COUNT(*) FROM expiry_settlement z WHERE z.txid=s.txid) AS tx_settlement_count, "
         "(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT h.spend_state,h.policy_type,h.oor_spent_txid,h.spent_in_round,h.offboarded_in,h.confirmed_height,h.onchain_spent_txid FROM vtxo_history h WHERE h.vtxo_id=s.id AND h.history_created_at=s.created_at) q) AS pre_commit_rows, "
         "EXISTS (SELECT 1 FROM pending_board p WHERE p.vtxo_id=s.id) AS board_reserved, "
         "(SELECT jsonb_build_object('payment_hash',h.payment_hash,'direction',h.direction,'htlc_expiry',h.htlc_expiry,'offchain_resolution',h.offchain_resolution,'chain_resolution',h.chain_resolution, "
         "'collection_recorded',EXISTS (SELECT 1 FROM htlc_settlement z WHERE z.payment_hash=h.payment_hash AND z.created_at<=s.created_at), "
         "'subscription_settled',EXISTS (SELECT 1 FROM lightning_htlc_subscription r WHERE r.payment_hash=h.payment_hash AND r.status='settled')) FROM htlc_vtxo h JOIN vtxo v ON v.id=h.id WHERE v.vtxo_id=s.id) AS htlc"),
      'coins':("v.vtxo_id","vtxo v","v.vtxo_id,v.id,v.expiry,v.spend_state,v.policy_type,encode(v.vtxo,'hex') AS signed_vtxo,v.onchain_spent_txid,v.onchain_spent_height,v.confirmed_height,v.oor_spent_txid,v.spent_in_round,v.offboarded_in"),
      'pending':("p.vtxo_id","pending_board p","p.vtxo_id,p.id,p.expiry,encode(p.vtxo,'hex') AS signed_vtxo"),
      'links':("encode(l.user_pubkey,'hex')","key_link l","encode(l.user_pubkey,'hex') AS user_pubkey,encode(l.mailbox_pk,'hex') AS mailbox_pk,encode(l.sig,'hex') AS sig"),
      'records':("encode(r.mailbox_pk,'hex')","fallback_record r","encode(r.mailbox_pk,'hex') AS mailbox_pk,encode(r.spk,'hex') AS spk,r.seq,encode(r.sig,'hex') AS sig"),
      'nursery':("n.txid","nursery_tx n","n.txid,encode(n.tx,'hex') AS raw_tx,n.kind,n.confirmed_at_height,n.abandoned_at")}
    key,table,columns=tables[kind]
    # Cursor whitelist contains no quotes/operators. All table/column names fixed.
    sql=f"BEGIN READ ONLY; SET LOCAL statement_timeout='8s'; SELECT coalesce(jsonb_agg(t),'[]'::jsonb) FROM (SELECT {columns} FROM {table} WHERE {key} > '{after}' ORDER BY {key} LIMIT 101) t; COMMIT;"
    lines=ops('sql',sql).splitlines()
    arrays=[line for line in lines if line.startswith('[')]
    if len(arrays)!=1:raise ValueError('unrecognized bridge database response')
    rows=json.loads(arrays[0]);more=len(rows)>100;rows=rows[:100]
    field={'settlements':'id','coins':'vtxo_id','pending':'vtxo_id','links':'user_pubkey','records':'mailbox_pk','nursery':'txid'}[kind]
    return {'kind':kind,'rows':rows,'next':rows[-1][field] if more else None,'inventory_consistent':False,
        'validation_scope':'trusted server claims; independently verify chain, backing, signatures and rightful ownership'}

def collect(kind,after):
    if kind=='binding_check':
        def byte_array(items):return 'ARRAY['+','.join("decode('"+item+"','hex')" for item in items)+']::bytea[]'
        mailboxes=byte_array(after['mailboxes']);keys=byte_array(after['keys'])
        sql=("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='8s'; SELECT jsonb_build_object("
            "'records',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT encode(mailbox_pk,'hex') AS mailbox_pk,encode(spk,'hex') AS spk,seq,encode(sig,'hex') AS sig FROM fallback_record WHERE mailbox_pk=ANY("+mailboxes+")) q),"
            "'links',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT encode(user_pubkey,'hex') AS user_pubkey,encode(mailbox_pk,'hex') AS mailbox_pk,encode(sig,'hex') AS sig FROM key_link WHERE user_pubkey=ANY("+keys+")) q)); COMMIT;")
        lines=[line for line in ops('sql',sql).splitlines() if line.startswith('{')]
        if len(lines)!=1:raise ValueError('invalid binding response')
        result=json.loads(lines[0])
        return {'kind':kind,'mailboxes':after['mailboxes'],'keys':after['keys'],**result,'inventory_consistent':True,
            'validation_scope':'one bounded read-only database snapshot of the requested public records and links'}
    if kind!='snapshot':return page(kind,after)
    before=json.loads(ops('cli','getblockchaininfo'))
    image=json.loads(run(['sudo','-n','docker','inspect','--format','{"image_digest":{{json .Image}},"status":{{json .State.Status}},"restarts":{{json .RestartCount}}}',CONTAINER]))
    wallet=json.loads(ops('capt','rpc','wallet'))
    cfg=tomllib.loads((DEPLOY/'state/signet-fallback/captaind.toml').read_text())
    ending=json.loads(ops('cli','getblockchaininfo'))
    return {'kind':kind,'observed_at':time.time(),'height':ending['blocks'],'tip_hash':ending['bestblockhash'],
        'network':ending['chain'],'genesis':ops('cli','getblockhash','0').strip().strip('"'),
        'stable_tip':before['bestblockhash']==ending['bestblockhash'],'initial_block_download':ending['initialblockdownload'],
        'container':CONTAINER,'server_status':image,'wallet':wallet,
        'timings':{key:cfg.get('expiry_payout',{}).get(key) for key in ['enabled','min_payout_sat','grace_blocks','sweep_min_confs']},
        'lightning_configured':bool(cfg.get('cln_array')),'complete':False}

def main():
    kind,after=request(sys.stdin.buffer.read(4097));result=collect(kind,after)
    encoded=json.dumps(result,allow_nan=False)
    if len(encoded.encode())>MAX_BYTES:raise ValueError('serialized response too large')
    print(encoded)
if __name__=='__main__':
    try:main()
    except Exception:
        print('read-only server observation unavailable',file=sys.stderr);sys.exit(1)
