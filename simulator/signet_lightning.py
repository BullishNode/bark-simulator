"""One native BOLT11 receive to an absent recipient, never LNURL evidence.

Only the coordinator's separately admitted/funded profile may execute this path.
REST and payer replies stay private; public projections are explicit allowlists.
An uncertain invoice/payment is held permanently until exact-hash reconciliation.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import time
import tomllib
import urllib.request

from .model import canonical, integer, public_payload
from .signet import Campaign, digest, network_identity
from .signet_phase import _native, _quiescent, _verify_runtime
from .signet_s02 import _confirmed_transaction, _freeze, _save, check_recovery, observe_payout
from .signet_discovery import discover_payouts
from .signet_repair import _fee_child

PROFILE = {'vtxo_lifetime': 32, 'vtxo_exit_delta': 12,
           'pool_lifetime': 32, 'pool_pre_expiry': 12, 'htlc_expiry_delta': 6,
           'sdk_exit_margin': 12, 'sdk_claim_delta': 18,
           'receive_base_fee_sat': 100, 'receive_ppm': 2000}
PRODUCTION_PROFILE = {**PROFILE, 'vtxo_lifetime': 4320, 'vtxo_exit_delta': 144,
                      'pool_lifetime': 432, 'pool_pre_expiry': 144,
                      'htlc_expiry_delta': 40, 'sdk_refresh_expiry_threshold': 144}
POINT = re.compile(r'[0-9a-f]{64}:(0|[1-9][0-9]*)')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,file,code,message,headers,newurl):
        raise ValueError('owned loopback request must not redirect')


def _loopback_open(request,timeout):
    # Do not send authenticated requests to an environment-supplied proxy or
    # forward credentials to a redirect target, even from the local service.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),_NoRedirect())
    return opener.open(request,timeout=timeout)


def _protected(path, limit=512):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('owner-only regular input required')
        raw = stream.read(limit + 1)
    if not 1 <= len(raw) <= limit:
        raise ValueError('bounded protected input required')
    return raw


def _operation(campaign):
    row = campaign.db.execute("SELECT value FROM meta WHERE key='native_bolt11_receive'").fetchone()
    if not row:
        raise ValueError('separately admitted native receive operation required')
    spec = json.loads(row[0])
    profile = spec['profile']
    if profile not in (PROFILE, PRODUCTION_PROFILE):
        raise ValueError('exact admitted native receive profile required')
    production = profile == PRODUCTION_PROFILE
    _verify_runtime(campaign)
    if digest(Path(spec['admission'])) != spec['admission_sha256']:
        raise ValueError('original coordinator admission changed')
    if digest(Path(spec['cln_binary'])) != spec['cln_binary_sha256']:
        raise ValueError('payer binary changed')
    pins=json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0])
    config=tomllib.loads((Path(pins['configuration_directory'])/'captaind.toml').read_text())
    expected = {k:profile[k] for k in ['vtxo_lifetime','vtxo_exit_delta','htlc_expiry_delta']}
    if production:
        expected.update(network='signet', htlc_send_expiry_delta=258, max_htlc_expiry_delta=288,
                        required_board_confirmations=3)
    if ({k:config.get(k) for k in expected} != expected
            or (production and any(type(config.get(k)) is not type(v) for k,v in expected.items()))
            or config.get('vtxopool',{}).get('vtxo_lifetime')!=profile['pool_lifetime']
            or config.get('vtxopool',{}).get('vtxo_pre_expiry')!=profile['pool_pre_expiry']
            or not config.get('vtxopool',{}).get('vtxo_targets')
            or config.get('fees',{}).get('lightning_receive')!={'base_fee_sat':100,'ppm':2000}):
        raise ValueError('actual native receive configuration differs from admitted bounded profile')
    admission=json.loads(Path(spec['admission']).read_text())
    if (admission.get('network')!='signet'
            or not re.fullmatch('0[23][0-9a-f]{64}',admission.get('server_pubkey',''))):
        raise ValueError('actual public Signet server identity receipt required')
    if production and (admission.get('runtime_pins_sha256') != hashlib.sha256(canonical(pins).encode()).hexdigest()
                       or config.get('postgres',{}).get('name') != spec['database']):
        raise ValueError('production admission must bind exact paired runtime pins and database')
    if not campaign.db.execute("SELECT 1 FROM actor WHERE id='absent' AND absent=1").fetchone():
        raise ValueError('recipient absence fence required')
    return spec


def stage(campaign, spec, runtime_pins, registration, source):
    """Import genuine cached registration + original seed, never a wallet DB.

    Admission is a retained coordinator receipt, not a synthetic readiness flag.
    Its runtime/configuration verification and actual funding remain owner work.
    """
    if campaign.db.execute('SELECT 1 FROM actor UNION SELECT 1 FROM action UNION SELECT 1 FROM result').fetchone():
        raise ValueError('new empty campaign required')
    if campaign.db.execute("SELECT 1 FROM meta WHERE key='native_bolt11_receive'").fetchone():
        raise ValueError('operation already staged')
    required = {'profile','amount_sat','max_payment_fee_msat','provider_url','provider_token_file',
                'cln_binary','cln_binary_sha256','cln_directory','payer_pubkey','invoice_payee',
                'recipient_address','recipient_registration_sha256','birthday_height',
                'recovery_destination','admission','admission_sha256','database'}
    if set(spec) != required or spec['profile'] not in (PROFILE, PRODUCTION_PROFILE) or spec['amount_sat'] != 5000:
        raise ValueError('exact bounded native receive profile required')
    if not re.fullmatch(r'http://127\.0\.0\.1:[0-9]+', spec['provider_url']):
        raise ValueError('owned loopback provider required')
    if not re.fullmatch('[a-z_][a-z0-9_]{0,62}',spec['database']):raise ValueError('actual owned database name required')
    for name in ['cln_binary_sha256','recipient_registration_sha256','admission_sha256']:
        if not re.fullmatch('[0-9a-f]{64}',spec[name]):raise ValueError('exact input hashes required')
    for name in ['payer_pubkey','invoice_payee']:
        if not re.fullmatch('0[23][0-9a-f]{64}',spec[name]):raise ValueError('actual compressed LN identity required')
    if (not re.fullmatch('tark1[0-9a-z]+',spec['recipient_address'])
            or registration.get('network') != 'signet'
            or hashlib.sha256(canonical(registration).encode()).hexdigest() != spec['recipient_registration_sha256']):
        raise ValueError('original authenticated native recipient registration required')
    integer(spec['birthday_height'],'original birthday')
    if integer(spec['max_payment_fee_msat'],'payment fee ceiling') > 10000:
        raise ValueError('bounded payment fee ceiling required')
    phrase = _protected(source)
    _protected(spec['provider_token_file'])
    chain = network_identity(campaign.core)
    if spec['birthday_height'] > chain['height']:raise ValueError('original birthday cannot follow funding')
    for address, expected in [(registration['payout_address'],registration['record']['spk']),
                              (spec['recovery_destination'],None)]:
        actual=campaign.core.call('validateaddress',address)
        if actual.get('isvalid') is not True or not actual.get('scriptPubKey') or (expected and actual['scriptPubKey']!=expected):
            raise ValueError('exact registered payout and owned recovery scripts required')
    # Configuration includes private credential-file paths. It stays in the
    # private campaign database and is never a public result projection.
    public_payload(registration)
    campaign.db.execute('BEGIN IMMEDIATE')
    try:
        campaign.db.execute("INSERT INTO meta VALUES ('phase_runtime_pins',?)",(canonical(runtime_pins),))
        campaign.db.execute("INSERT INTO meta VALUES ('native_bolt11_receive',?)",(canonical(spec),))
        campaign.db.execute("INSERT INTO meta VALUES ('native_bolt11_registration',?)",(canonical(registration),))
        campaign.db.execute("INSERT INTO actor VALUES ('absent',1)")
        _operation(campaign)
        campaign._retain_private('s02-recovery-source-absent','source',io.BytesIO(phrase))
        campaign.db.execute('COMMIT')
    except BaseException:
        if campaign.db.in_transaction:campaign.db.execute('ROLLBACK')
        raise
    return _save(campaign,'native-ln-stage',{'kind':'native_BOLT11_receive','stage':'STAGED_NO_INVOICE',
                  'case_verdict':'INCOMPLETE','recipient_wallet_opened':False,'chain':chain,
                  'scope':'Native BOLT11 only; no Noah or LNURL compatibility credit.'})


def _private_call(campaign, intent, kind, argv):
    """Fixed argv only, private bounded stdout/stderr, never opens recipient."""
    environment={k:v for k,v in os.environ.items() if not k.startswith('BARK_')}
    try:
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              env=environment,timeout=150,check=False)
    except subprocess.TimeoutExpired as error:
        campaign._retain_private(intent,kind+'-stdout',io.BytesIO(error.stdout or b''))
        campaign._retain_private(intent,kind+'-stderr',io.BytesIO(error.stderr or b''))
        raise
    campaign._retain_private(intent,kind+'-stdout',io.BytesIO(result.stdout))
    campaign._retain_private(intent,kind+'-stderr',io.BytesIO(result.stderr))
    if result.returncode or len(result.stdout)>4*1024*1024:
        raise ValueError('private subprocess did not return a bounded successful result')
    return json.loads(result.stdout)


def _cln(campaign,spec,intent,kind,*args):
    return _private_call(campaign,intent,kind,[spec['cln_binary'],
        '--lightning-dir='+spec['cln_directory'],'--network=signet',
        '--notifications=none','--json',*args])


def _attempt(campaign,prefix):
    # A failed read can already have retained artifacts. Reserve its sequence
    # before I/O so the next observation never overwrites that failed receipt.
    key='native_ln_attempt:'+prefix
    row=campaign.db.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone()
    number=int(row[0]) if row else 0
    campaign.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',(key,str(number+1)))
    return number


def validate_invoice(decoded, spec, now):
    """CLN26 `decode`, which verifies BOLT11 signature; NOT the LNURL verifier."""
    if (decoded.get('type')!='bolt11 invoice' or decoded.get('valid') is not True
            or decoded.get('currency')!='tbs' or decoded.get('amount_msat')!=spec['amount_sat']*1000
            or decoded.get('payee')!=spec['invoice_payee']
            or not re.fullmatch('[0-9a-f]{64}',decoded.get('payment_hash',''))):
        raise ValueError('valid exact native Signet invoice/payee required')
    created=integer(decoded.get('created_at'),'invoice creation')
    expires=created+integer(decoded.get('expiry'),'invoice expiry',1)
    if created>now+30 or expires<=now+120:
        raise ValueError('invoice must retain bounded payment time')
    return {'payment_hash':decoded['payment_hash'],'payee':decoded['payee'],
            'amount_msat':decoded['amount_msat'],'expires_at':expires,
            'min_final_cltv_expiry':integer(decoded.get('min_final_cltv_expiry'),'actual final CLTV',1)}


def _once(campaign,intent,actor,operation,arguments,dispatch):
    """Persist dispatch BEFORE external effect. Existing unknown never retries."""
    old=campaign.db.execute('SELECT * FROM action WHERE id=?',(intent,)).fetchone()
    if old:
        if (old['actor'],old['operation'],old['arguments'])!=(actor,operation,canonical(arguments)):
            raise ValueError('immutable external action intent changed')
        if old['state']!='acknowledged':raise ValueError('original external outcome requires exact-hash reconciliation')
        return json.loads(old['reply'])
    _quiescent(campaign)
    chain=network_identity(campaign.core);now=time.time()
    campaign.db.execute('BEGIN IMMEDIATE')
    try:
        _quiescent(campaign)
        campaign.db.execute('INSERT OR IGNORE INTO actor(id) VALUES (?)',(actor,))
        campaign.db.execute('INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)',
            (intent,actor,operation,canonical(arguments),'dispatched',now,now,canonical(chain),None,None))
        campaign.db.execute('INSERT INTO action_context VALUES (?,?,?,?,?)',
            (intent,campaign.controller_id,campaign.config['source_commit'],campaign.config['binary_sha256'],campaign.config['product_config_sha256']))
        campaign.db.execute('COMMIT')
    except BaseException:
        if campaign.db.in_transaction:campaign.db.execute('ROLLBACK')
        raise
    try:
        reply=dispatch();public_payload(reply)
        campaign.db.execute("UPDATE action SET state='acknowledged',updated=?,reply=? WHERE id=?",
                            (time.time(),canonical(reply),intent))
        return reply
    except BaseException as error:
        campaign.db.execute("UPDATE action SET state='unknown',updated=?,diagnostic=? WHERE id=?",
                            (time.time(),type(error).__name__,intent))
        raise


def _rest(campaign,spec,intent,method,path,body=None):
    token=_protected(spec['provider_token_file']).decode().strip()
    request=urllib.request.Request(spec['provider_url']+'/api/v1'+path,
        data=canonical(body).encode() if body is not None else None,
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'},method=method)
    with _loopback_open(request,timeout=60) as response:
        raw=response.read(4*1024*1024+1)
        campaign._retain_private(intent,'rest-response',io.BytesIO(raw))
        if response.status!=200 or len(raw)>4*1024*1024:raise ValueError('bounded successful REST reply required')
    return json.loads(raw)


def issue_invoice(campaign):
    spec=_operation(campaign)
    def dispatch():
        payer=_cln(campaign,spec,'native-ln-invoice','payer-getinfo','getinfo')
        if payer.get('id')!=spec['payer_pubkey'] or payer.get('network')!='signet':
            raise ValueError('actual independent payer identity changed')
        reply=_rest(campaign,spec,'native-ln-invoice','POST','/lightning/receives/invoice/for-address',
                    {'address':spec['recipient_address'],'amount_sat':spec['amount_sat'],
                     'description':'Native offline-recipient fallback qualification'})
        invoice=reply['invoice']
        if not isinstance(invoice,str) or len(invoice)>20000:raise ValueError('bounded original invoice required')
        campaign._retain_private('native-ln-invoice','invoice',io.BytesIO(invoice.encode()))
        decoded=_cln(campaign,spec,'native-ln-invoice','decode','decode',invoice)
        return {**validate_invoice(decoded,spec,int(time.time())),
                'invoice_sha256':hashlib.sha256(invoice.encode()).hexdigest(),
                'scope':'Native BOLT11 validity only; plain memo gives no LNURL credit.'}
    return _once(campaign,'native-ln-invoice','ln-provider','native_bolt11_invoice',
                 {'recipient_address':spec['recipient_address'],'amount_sat':spec['amount_sat']},dispatch)


def _invoice(campaign):
    row=campaign.db.execute("SELECT reply FROM action WHERE id='native-ln-invoice' AND state='acknowledged'").fetchone()
    if not row:raise ValueError('acknowledged original invoice required')
    public=json.loads(row[0])
    raw=campaign.db.execute("SELECT * FROM native_artifact WHERE intent='native-ln-invoice' AND kind='invoice'").fetchone()
    if not raw or raw['truncated']:raise ValueError('complete original invoice required')
    invoice=(campaign.root/raw['relative_path']).read_text()
    if hashlib.sha256(invoice.encode()).hexdigest()!=public['invoice_sha256'] or raw['sha256']!=public['invoice_sha256']:
        raise ValueError('original invoice bytes changed')
    return invoice,public


def pay_invoice(campaign):
    spec=_operation(campaign);invoice,public=_invoice(campaign)
    def dispatch():
        decoded=_cln(campaign,spec,'native-ln-payment','decode','decode',invoice)
        verified=validate_invoice(decoded,spec,int(time.time()))
        if verified!={k:public[k] for k in verified}:
            raise ValueError('original invoice identity changed')
        # Refuse an already attempted payment even if this controller lost its
        # own journal. A found attempt must be reconciled, never paid again.
        prior=_cln(campaign,spec,'native-ln-payment','prior','listpays','payment_hash='+public['payment_hash'])
        if prior.get('pays')!=[]:raise ValueError('payer already has this payment hash; reconcile without replay')
        reply=_cln(campaign,spec,'native-ln-payment','xpay','xpay','invstring='+invoice,
                   'maxfee='+str(spec['max_payment_fee_msat'])+'msat','retry_for=30',
                   'label=native-offline-fallback-'+public['payment_hash'])
        preimage=reply.get('payment_preimage')
        if (not isinstance(preimage,str) or not re.fullmatch('[0-9a-f]{64}',preimage)
                or hashlib.sha256(bytes.fromhex(preimage)).hexdigest()!=public['payment_hash']):
            raise ValueError('actual payer success must reveal the exact invoice preimage')
        delivered=integer(reply.get('amount_msat'),'delivered millisatoshis')
        sent=integer(reply.get('amount_sent_msat'),'sent millisatoshis')
        if delivered!=spec['amount_sat']*1000 or not delivered<=sent<=delivered+spec['max_payment_fee_msat']:
            raise ValueError('payment amount/fee differs from original bounded intent')
        return {'payment_hash':public['payment_hash'],'preimage_hash_verified':True,
                'amount_msat':delivered,'amount_sent_msat':sent,'routing_fee_msat':sent-delivered,
                'state':'PAYER_SETTLED_RECIPIENT_CLAIM_NOT_YET_PROVEN'}
    return _once(campaign,'native-ln-payment','ln-payer','native_bolt11_xpay',
                 {'payment_hash':public['payment_hash'],'amount_msat':spec['amount_sat']*1000,
                  'max_fee_msat':spec['max_payment_fee_msat']},dispatch)


def _varint(value):
    raw=bytearray()
    while value>127:raw.append((value&127)|128);value>>=7
    return bytes(raw)+bytes([value])


def public_vtxo(ark_url,coin_id):
    """Exact current proto GetVtxo, gRPC-Web unary; no wallet/registration."""
    if not POINT.fullmatch(coin_id):raise ValueError('public VTXO ID required')
    txid,index=coin_id.split(':');index=int(index)
    if index>0xffffffff:raise ValueError('VTXO output index exceeds u32')
    point=bytes.fromhex(txid)[::-1]+struct.pack('<I',index)
    body=b'\x0a'+_varint(len(point))+point
    request=urllib.request.Request(ark_url+'/bark_server.ArkService/GetVtxo',
        data=b'\0'+struct.pack('>I',len(body))+body,
        headers={'Content-Type':'application/grpc-web+proto','X-Grpc-Web':'1'},method='POST')
    with _loopback_open(request,timeout=30) as response:
        raw=response.read(4*1024*1024+1)
        if response.status!=200 or len(raw)>4*1024*1024:raise ValueError('bounded unary response required')
    frames=[];trailers=b'';pos=0
    while pos<len(raw):
        if pos+5>len(raw):raise ValueError('truncated gRPC frame')
        flag=raw[pos];size=int.from_bytes(raw[pos+1:pos+5],'big');pos+=5
        value=raw[pos:pos+size];pos+=size
        if len(value)!=size:raise ValueError('truncated gRPC body')
        if flag==0:frames.append(value)
        elif flag==128:trailers+=value
        else:raise ValueError('unexpected compressed frame')
    status=dict(line.split(b':',1) for line in trailers.lower().split(b'\r\n') if b':' in line)
    if status.get(b'grpc-status',b'').strip()!=b'0' or len(frames)!=1:raise ValueError('successful unary GetVtxo required')
    body=frames[0]
    if not body or body[0]!=10:raise ValueError('serialized VTXO field required')
    size=0;pos=1
    for shift in range(0,35,7):
        if pos>=len(body):raise ValueError('truncated VTXO length')
        byte=body[pos];pos+=1;size|=(byte&127)<<shift
        if byte<128:break
    else:raise ValueError('oversized VTXO length')
    if size<1 or len(body)-pos!=size:raise ValueError('one complete serialized VTXO required')
    return body[pos:].hex()


def signed_public_coin(campaign,coin_id,*,recipient=False):
    spec=_operation(campaign)
    sequence=_attempt(campaign,'proof')
    intent=f'native-ln-proof-{sequence}'
    serialized=public_vtxo(campaign.config['ark_url'],coin_id)
    campaign._retain_private(intent,'serialized',io.BytesIO(serialized.encode()))
    binary=campaign.config['binary']
    prefix=[binary,'--quiet','--no-logfile','dev','vtxo']
    coin=_private_call(campaign,intent,'decode',prefix+['decode',serialized])
    if coin.get('id')!=coin_id or coin.get('server_pubkey')!=json.loads(Path(spec['admission']).read_text())['server_pubkey']:
        raise ValueError('public serialized coin identity differs from admitted server')
    txid,index=coin['chain_anchor'].split(':');chain=network_identity(campaign.core)
    funding=campaign.core.call('getrawtransaction',txid,False)
    _confirmed_transaction(campaign,txid,chain)
    proof=_private_call(campaign,intent,'verify',prefix+['verify',serialized,funding,
        *(['--address',spec['recipient_address']] if recipient else [])])
    path=proof.get('path_outpoints')
    if (proof.get('verified') is not True or proof.get('anchor_txid')!=txid or proof.get('vtxo')!=coin
            or (recipient and proof.get('address_verified') is not True)
            or not isinstance(path,list) or not path or len(path)>10000
            or any(not isinstance(p,str) or not POINT.fullmatch(p) for p in path)
            or path[0]!=coin['chain_anchor'] or path[-1]!=coin_id or len(set(path))!=len(path)):
        raise ValueError('complete authentic signed lineage required')
    if network_identity(campaign.core)!=chain:raise ValueError('chain changed during public coin proof')
    return _save(campaign,'native-ln-proof',{'kind':'native_ln_signed_public_coin','coin':coin,
                 'path_outpoints':path,'serialized_sha256':hashlib.sha256(bytes.fromhex(serialized)).hexdigest(),
                 'recipient_address_verified':recipient,'chain':chain,'recipient_wallet_opened':False})


def observe_receive(campaign):
    spec=_operation(campaign);_,invoice=_invoice(campaign)
    n=_attempt(campaign,'status')
    raw=_rest(campaign,spec,f'native-ln-status-{n}','GET','/lightning/receives/'+invoice['payment_hash'])
    if raw.get('payment_hash')!=invoice['payment_hash'] or raw.get('amount_sat')!=spec['amount_sat']:
        raise ValueError('provider receive identity changed')
    if raw.get('state') not in ['awaiting-payment','htlcs-ready','preimage-revealed','delivering','settled']:
        raise ValueError('unrecognized actual native receive state')
    # The receive's transient grant list is cleared after settlement. Existing
    # movement metadata retains those public IDs, but ALSO a secret: project
    # only the exact hash and IDs, never arbitrary metadata or raw history.
    history=_rest(campaign,spec,f'native-ln-history-{n}','GET','/wallet/movements')
    if not isinstance(history,list) or len(history)>1000:raise ValueError('bounded provider history required')
    matching=[m for m in history if isinstance(m,dict)
              and isinstance(m.get('metadata'),dict)
              and m['metadata'].get('payment_hash')==invoice['payment_hash']]
    grants=set(raw.get('htlc_vtxo_ids',[]))
    for movement in matching:grants.update(movement['metadata'].get('htlc_vtxos',[]))
    if len(grants)>4 or any(not isinstance(p,str) or not POINT.fullmatch(p) for p in grants):
        raise ValueError('bounded actual receive grant IDs required')
    # No raw preimage/invoice or arbitrary diagnostic ever reaches public rows.
    observation={k:raw[k] for k in ['payment_hash','state','amount_sat','htlc_vtxo_ids','settled_at'] if k in raw}
    observation.update(kind='native_ln_receive_state',htlc_vtxo_ids=sorted(grants),
                       chain=network_identity(campaign.core),case_verdict='INCOMPLETE')
    proofs=[signed_public_coin(campaign,point) for point in observation.get('htlc_vtxo_ids',[])]
    if proofs:
        if any(p['coin']['policy_type'] not in ['server-htlc-receive-v1','server-htlc-receive'] for p in proofs):
            raise ValueError('authentic receive-HTLC grants required')
        # VtxoInfo intentionally has no policy deadline field. Use ONLY the
        # existing administrative field projection approved by the coordinator;
        # ownership still requires the actual signed native paths, below.
        quoted=','.join("'"+point+"'" for point in sorted(grants))
        query=("BEGIN READ ONLY; SELECT coalesce(json_agg(json_build_object("
               "'grant_id',v.vtxo_id,'payment_hash',h.payment_hash,'direction',h.direction,"
               "'htlc_expiry',h.htlc_expiry)), '[]'::json) "
               "FROM htlc_vtxo h JOIN vtxo v ON v.id=h.id WHERE v.vtxo_id IN ("+quoted+"); COMMIT;")
        terms=_private_call(campaign,f'native-ln-status-{n}','grant-deadlines',
            ['sudo','-u','postgres','psql','-X','-qAt','-d',spec['database'],'-c',query])
        if (not isinstance(terms,list) or len(terms)!=len(grants)
                or {r.get('grant_id') for r in terms}!=grants
                or any(set(r)!={'grant_id','payment_hash','direction','htlc_expiry'}
                       or r['payment_hash']!=invoice['payment_hash'] or r['direction']!='outgoing'
                       or type(r['htlc_expiry']) is not int or r['htlc_expiry']<1 for r in terms)):
            raise ValueError('actual public grant/hash/direction/deadline join required')
        observation['grant_terms']=terms
        observation['grant_deadline_schema']='server/src/database/migrations/V63__htlc_vtxo.sql'
        pins=json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0])
        observation['grant_deadline_source']=pins['elf_source']['captaind']
        observation['grant_signed_proofs']=[{'grant_id':p['coin']['id'],'tree_expiry':p['coin']['expiry_height'],
                                           'serialized_sha256':p['serialized_sha256']} for p in proofs]
    return _save(campaign,'native-ln-status',observation)


def freeze_claim(campaign,coin_ids):
    """Accept only signed destination-bound descendants of observed real grants."""
    spec=_operation(campaign)
    old=campaign.db.execute("SELECT value FROM meta WHERE key='s02_absent:absent'").fetchone()
    if old:
        frozen=json.loads(old[0])
        if sorted(coin_ids)!=sorted(c['id'] for c in frozen['coins']):raise ValueError('original frozen claim changed')
        return frozen
    if not 1<=len(coin_ids)<=4 or len(set(coin_ids))!=len(coin_ids):raise ValueError('bounded distinct recipient claim IDs required')
    if not campaign.db.execute("SELECT 1 FROM action WHERE id='native-ln-payment' AND state='acknowledged'").fetchone():
        raise ValueError('actual exact-hash payer settlement required')
    grants={row[0] for row in campaign.db.execute("SELECT DISTINCT value FROM result,json_each(result.payload,'$.htlc_vtxo_ids') WHERE json_extract(result.payload,'$.kind')='native_ln_receive_state'")}
    if not grants:raise ValueError('actual intermediate grant observation still required')
    proofs=[signed_public_coin(campaign,point,recipient=True) for point in coin_ids]
    expected=spec['amount_sat']-100-(spec['amount_sat']*2000+999999)//1000000
    # A signed registered body proves its cryptographic policy/path, not the
    # current spend state. S02 public-path/payout consumers need no state field.
    coins=[dict(p['coin']) for p in proofs]
    if (sum(c['amount_sat'] for c in coins)!=expected
            or any(c['policy_type']!='pubkey' for c in coins)
            or any(not grants.intersection(p['path_outpoints']) for p in proofs)):
        raise ValueError('exact net customer amount and real grant-to-recipient signed lineage required')
    registration=json.loads(campaign.db.execute("SELECT value FROM meta WHERE key='native_bolt11_registration'").fetchone()[0])
    frozen={'kind':'S02_absent_cohort','actor':'absent','registration':registration,'coins':coins,
        'signature_proofs':[{'coin_id':p['coin']['id'],'status':'PASS','path_outpoints':p['path_outpoints']} for p in proofs],
        'chain':network_identity(campaign.core),'case_verdict':'INCOMPLETE',
        'stage':'RECIPIENT_CLAIM_REGISTERED_ABSENT_WAITING_FOR_EXPIRY',
        'ownership_evidence':'Authentic signed public server bodies bound to the original recipient Ark address; not a recipient wallet snapshot.'}
    public_payload(frozen)
    campaign.db.execute("INSERT INTO meta VALUES ('s02_absent:absent',?)",(canonical(frozen),))
    return _save(campaign,'native-ln-frozen',frozen)


def advance_recovery(campaign):
    spec=_operation(campaign);_quiescent(campaign);frozen=_freeze(campaign,'absent')
    production=spec['profile']==PRODUCTION_PROFILE
    discover_payouts(campaign,'absent')
    payouts={}
    for row in campaign.db.execute("SELECT id,payload FROM result WHERE json_extract(payload,'$.kind')='S02_payout_observation' AND json_extract(payload,'$.payout_check')='PASS' ORDER BY observed").fetchall():
        original=json.loads(row['payload']);point=original['outpoint']
        if point in payouts:continue
        txid,index=point.split(':');current=observe_payout(campaign,'absent',txid,int(index),original['coin_ids'])
        if current['payout_check']=='PASS':payouts[point]=(row['id'],current)
    result={'kind':'native_BOLT11_receive_fallback','case_verdict':'INCOMPLETE',
            'scope':'Native Lightning receive only; no Noah/LNURL success.',
            'stage':'WAITING_FOR_RIGHTFUL_FALLBACK'}
    ids=[coin_id for _,p in payouts.values() for coin_id in p['coin_ids']]
    if sorted(ids)!=sorted(c['id'] for c in frozen['coins']):return _save(campaign,'native-ln-recovery',result)
    chain=network_identity(campaign.core)
    if production and any(p['chain']!=chain for _,p in payouts.values()):
        return _save(campaign,'native-ln-recovery',{**result,'stage':'WAITING_FOR_STABLE_CHAIN_VIEW'})
    try:
        fees=[_fee_child(campaign,p,chain) for _,p in payouts.values()]
    except ValueError:
        if production and network_identity(campaign.core)!=chain:
            return _save(campaign,'native-ln-recovery',{**result,'stage':'WAITING_FOR_STABLE_CHAIN_VIEW'})
        raise
    if network_identity(campaign.core)!=chain:
        if production:
            return _save(campaign,'native-ln-recovery',{**result,'stage':'WAITING_FOR_STABLE_CHAIN_VIEW'})
        raise ValueError('chain changed during payout/fee observation')
    if any(f is None for f in fees) or any(p['confirmations']<6 for _,p in payouts.values()) or any(f['confirmations']<6 for f in fees):
        return _save(campaign,'native-ln-recovery',{**result,'stage':'WAITING_FOR_SIX_CONFIRMED_PARENTS_AND_CHILDREN','fee_children':fees})
    restore={'source_actor':'absent','birthday_height':spec['birthday_height']}
    if production:
        restore['wallet_profile']={'vtxo_refresh_expiry_threshold':144,'vtxo_exit_margin':12}
    _native(campaign,'native-ln-seed-restore','restored','restore',restore)
    if not campaign.db.execute("SELECT 1 FROM action WHERE id='native-ln-drain'").fetchone():
        n=campaign.db.execute("SELECT count(*) FROM action WHERE operation='onchain_utxos'").fetchone()[0]
        utxos=_native(campaign,f'native-ln-utxos-{n}','restored','onchain_utxos')
        found={u['outpoint']:u for u in utxos if u['confirmation_height'] is not None}
        if any(point not in found or found[point]['amount_sat']!=p['amount_sat'] for point,(_,p) in payouts.items()):
            return _save(campaign,'native-ln-recovery',{**result,'stage':'WAITING_FOR_SEED_ONLY_DISCOVERY'})
        if network_identity(campaign.core)!=chain:
            if production:
                return _save(campaign,'native-ln-recovery',{**result,'stage':'WAITING_FOR_STABLE_CHAIN_VIEW'})
            raise ValueError('chain changed before single drain')
    _native(campaign,'native-ln-drain','restored','onchain_drain',{'destination':spec['recovery_destination']})
    recovery=[check_recovery(campaign,'absent','restored','native-ln-drain',row,spec['recovery_destination']) for row,_ in payouts.values()]
    current=network_identity(campaign.core)
    complete=all(r['recovery_check']=='PASS' and r['chain']==current for r in recovery)
    if production and complete:
        txid=recovery[0]['spend_txid']
        try:
            transaction,_=_confirmed_transaction(campaign,txid,current)
        except ValueError:
            if network_identity(campaign.core)!=current:
                return _save(campaign,'native-ln-recovery',{**result,'stage':'WAITING_FOR_STABLE_CHAIN_VIEW'})
            raise
        if (chain!=current or network_identity(campaign.core)!=current
                or any(r['spend_txid']!=txid for r in recovery)):
            return _save(campaign,'native-ln-recovery',{**result,'stage':'WAITING_FOR_STABLE_CHAIN_VIEW'})
        if transaction['confirmations']<6:
            return _save(campaign,'native-ln-recovery',{**result,'stage':'WAITING_FOR_SIX_CONFIRMED_RECOVERY',
                'recovery':recovery,'physical_recovery_spend':txid,'confirmations':transaction['confirmations']})
    return _save(campaign,'native-ln-recovery',{**result,'stage':'RECOVERY_CONFIRMED' if complete else 'WAITING_FOR_CONFIRMED_RECOVERY',
        'case_verdict':'PASS' if complete else 'INCOMPLETE','payouts':[p for _,p in payouts.values()],
        'fee_children':fees,'recovery':recovery,'physical_recovery_spend':recovery[0].get('spend_txid'),
        'physical_recovery_fee_sat':recovery[0].get('miner_fee_sat'),
        'accounting_note':'One physical drain/fee, even when several payout inputs are checked.'})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,required=True);parser.add_argument('--config',type=Path,required=True)
    sub=parser.add_subparsers(dest='operation',required=True)
    start=sub.add_parser('stage')
    for name in ['spec','runtime-pins','registration','source']:start.add_argument('--'+name,type=Path,required=True)
    for name in ['invoice','pay','observe','recover']:sub.add_parser(name)
    claim=sub.add_parser('freeze-claim');claim.add_argument('coin_ids',nargs='+')
    args=parser.parse_args();campaign=Campaign(args.state,json.loads(args.config.read_text()))
    try:
        with (campaign.root/'native-ln.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if args.operation=='stage':result=stage(campaign,json.loads(args.spec.read_text()),json.loads(args.runtime_pins.read_text()),json.loads(args.registration.read_text()),args.source)
            elif args.operation=='invoice':result=issue_invoice(campaign)
            elif args.operation=='pay':result=pay_invoice(campaign)
            elif args.operation=='observe':result=observe_receive(campaign)
            elif args.operation=='freeze-claim':result=freeze_claim(campaign,args.coin_ids)
            else:result=advance_recovery(campaign)
            print(canonical(result))
    finally:campaign.close()


if __name__=='__main__':main()
