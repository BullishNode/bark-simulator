"""Bind original private C native bodies to actual admitted offline SDK proofs.

This is cryptographic/source geometry only. Unfinished paths remain explicit,
not zero liability or operator assets. The enclosing typed normal factory owns
current economics, action ancestry, mempool, complete membership and admission.
"""
import hashlib
import os
from pathlib import Path
import stat
import re
from . import c_private_native_body_cut as body
from . import c_private_fee_cut as common
from .bundle_audit import decode_transaction
from .model import SIGNET_GENESIS, integer
from .normal_source_deadline import check as deadline_check
from .two_step_normal import run_proof, strict_json

PROOF_SOURCE='5f744f7f69796826844b1de12f65f7bb6bbd2204'
FIELDS={'schema_version','kind','source_encoding','sdk_commit','input_body_sha256',
 'canonical_reencoding_sha256','canonical_reencoding_equal','funding_txid','raw_funding_sha256',
 'id','point','chain_anchor','amount_sat','expiry_height','exit_delta','server_pubkey','user_pubkey',
 'policy_type','policy_hex','ancestor_ids','path_steps','anchor_only','transitions','unsigned_path_valid',
 'signed_path_valid','all_native_witnesses_present','witnessed_conditional_steps','total_conditional_steps',
 'unresolved','validation_scope'}
SCOPE='Offline exact SDK decoding and supplied-funding path validation only; active chain membership, current economic ownership, retirement, pool ownership, paid status and completeness require independent same-observation proofs. No witness bytes or preimages emitted.'


def _sha(raw):return hashlib.sha256(raw).hexdigest()


def _point(text):
    if not isinstance(text,str)or re.fullmatch('[0-9a-f]{64}:(0|[1-9][0-9]{0,9})',text)is None:
        raise ValueError('canonical native source anchor required')
    txid,index=text.split(':');index=int(index)
    if index>=2**32:raise ValueError('native source output index overflow')
    return txid,index


def _tool(tool,identity,pins,*,expected_source=PROOF_SOURCE,binary_name="native-full-proof"):
    # Only fixed native roles used by the admitted C callers. Neither field is
    # read from an observer request; the qualification binds their exact data.
    if binary_name not in {'native-full-proof','native-fee-audit'}:
        raise ValueError('fixed native proof role required')
    fields={'source_commit','sdk_actual_GIT_HASH','sdk_component_commit','binary_sha256','launcher_sha256','runtime_manifest_sha256','component_inventory','python_sha256'}
    if(not isinstance(identity,dict)or set(identity)!=fields or identity['source_commit']!=expected_source
            or identity['sdk_component_commit']!=pins['sdk_commit']or identity['launcher_sha256']!=tool.get('sha256')
            or not isinstance(tool.get('command'),(list,tuple))or len(tool['command'])!=1):
        raise ValueError('explicit actual native proof source/component/runtime identity required')
    for name,value in identity.items():
        if name=='component_inventory':continue
        size=64 if name.endswith('sha256')else 40
        if not isinstance(value,str)or re.fullmatch('[0-9a-f]{'+str(size)+'}',value)is None:
            raise ValueError('complete native proof identity hash required')
    components=identity['component_inventory']
    modes={binary_name:0o500,'source-identity.json':0o600,'launch':0o500,
      'lib/libc.so.6':0o400,'lib/ld-linux-x86-64.so.2':0o500,'lib/libgcc_s.so.1':0o400}
    if(not isinstance(components,dict)or set(components)!=set(modes)or any(not isinstance(v,dict)for v in components.values())
            or components['launch'].get('sha256')!=identity['launcher_sha256']
            or components[binary_name].get('sha256')!=identity['binary_sha256']):
        raise ValueError('exact qualified native closure components required')
    root=Path(tool['command'][0]).parent
    if not root.is_absolute()or any(p.is_symlink()for p in [root,*root.parents]):raise ValueError('fixed native closure root differs')
    for directory in (root,root/'lib'):
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode)or info.st_uid!=os.getuid()or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('owned0700 native runtime directories required')
    if {p.name for p in root.iterdir()}!={'launch',binary_name,'source-identity.json','lib'}or {p.name for p in (root/'lib').iterdir()}!={'libc.so.6','ld-linux-x86-64.so.2','libgcc_s.so.1'}:
        raise ValueError('native runtime closure contains extra/missing members')
    for name,mode in modes.items():
        entry=components[name]
        if(not isinstance(entry,dict)or set(entry)!={'bytes','sha256','mode'}or type(entry['bytes'])is not int
                or not 0<entry['bytes']<=16*1024*1024 or entry['mode']!=oct(mode)
                or not isinstance(entry['sha256'],str)or re.fullmatch('[0-9a-f]{64}',entry['sha256'])is None):
            raise ValueError('complete exact native runtime component inventory required')
        fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb')as stream:
            before=os.fstat(stream.fileno());raw=stream.read(entry['bytes']+1);after=os.fstat(stream.fileno())
        signature=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        if(not stat.S_ISREG(before.st_mode)or before.st_uid!=os.getuid()or before.st_nlink!=1
                or stat.S_IMODE(before.st_mode)!=mode or len(raw)!=entry['bytes']or _sha(raw)!=entry['sha256']
                or signature(before)!=signature(after)):
            raise ValueError('actual qualified native runtime component differs')
        if name=='source-identity.json':
            source=common._json(raw)
            if(not isinstance(source,dict)or source.get('source')!=identity['source_commit']
                    or source.get('SDK_actual_source')!=identity['sdk_actual_GIT_HASH']
                    or source.get('actual_GIT_HASH')!=identity['sdk_actual_GIT_HASH']
                    or source.get('SDK_component')!=identity['sdk_component_commit']):
                raise ValueError('actual native runtime source/SDK component identity differs')
    python=Path('/usr/bin/python3').resolve()
    if _sha(python.read_bytes())!=identity['python_sha256']:raise ValueError('actual native launcher Python runtime differs')


def bind_path(row,request_raw,response_raw,*,source_table,funding_raw,tool_identity,server_pubkey):
    """Pure binding AFTER actual run_proof; caller retains private raw originals."""
    request=common._json(request_raw);proof=common._json(response_raw)
    metadata=row['metadata'];expected_encoding=body.SOURCE_ENCODINGS[source_table]
    if(not isinstance(request,dict)or set(request)!={'schema_version','kind','source_encoding','body_hex','funding_transaction_hex','expected_server_pubkey'}
            or type(request['schema_version'])is not int or request['schema_version']!=1
            or request['kind']!='native-full-path-request'or request['source_encoding']!=expected_encoding
            or request['body_hex']!=row['body_hex']or request['expected_server_pubkey']!=server_pubkey
            or request['funding_transaction_hex']!=funding_raw.hex()):
        raise ValueError('actual native proof request/source original differs')
    native_body=common._raw(row['body_hex'],body.MAX_BODY_BYTES);funding=decode_transaction(funding_raw.hex())
    if(not isinstance(proof,dict)or set(proof)!=FIELDS or type(proof['schema_version'])is not int or proof['schema_version']!=1
            or proof['kind']!='native-full-path-proof'or proof['source_encoding']!=expected_encoding
            or proof['sdk_commit']!=tool_identity['sdk_actual_GIT_HASH']or proof['validation_scope']!=SCOPE
            or proof['input_body_sha256']!=_sha(native_body)or proof['canonical_reencoding_sha256']!=_sha(native_body)
            or proof['canonical_reencoding_equal']is not True or proof['unsigned_path_valid']is not True
            or proof['raw_funding_sha256']!=_sha(funding_raw)or proof['funding_txid']!=funding['txid']
            or proof['id']!=metadata['vtxo_id']or proof['server_pubkey']!=server_pubkey
            or type(proof['signed_path_valid'])is not bool or type(proof['all_native_witnesses_present'])is not bool
            or proof['total_conditional_steps']is not None
            or proof['unresolved']!=([]if proof['signed_path_valid']else['native_signed_path_not_valid'])):
        raise ValueError('actual native proof output/source/component differs')
    anchor,index=_point(proof['chain_anchor'])
    if anchor!=funding['txid']or index>=len(funding['outputs']):raise ValueError('native proof actual funding anchor differs')
    if (source_table=='coins'and any(proof[k]!=metadata[m]for k,m in [('amount_sat','amount'),('expiry_height','expiry'),('chain_anchor','anchor_point'),('policy_hex','policy'),('policy_type','policy_type')])):
        raise ValueError('native registered body/public metadata differs')
    if source_table=='pending_boards'and(proof['chain_anchor']!=row['anchor_point']or proof['expiry_height']!=metadata['expiry']):
        raise ValueError('native pending original anchor/expiry differs')
    if source_table=='pool'and(proof['amount_sat']!=metadata['amount']or proof['expiry_height']!=metadata['expiry_height']):
        raise ValueError('native pool body/public amount/expiry differs')
    for name in ['amount_sat','expiry_height','exit_delta']:integer(proof[name],'actual native '+name)
    if proof['user_pubkey']is not None and (not isinstance(proof['user_pubkey'],str)or re.fullmatch('(02|03)[0-9a-f]{64}',proof['user_pubkey'])is None):raise ValueError('native compressed owner key differs')
    common._raw(proof['policy_hex'],16384)
    _point(proof['point'])
    steps=integer(proof['path_steps'],'actual native path steps')
    if(steps>1024 or not isinstance(proof['transitions'],list)or len(proof['transitions'])!=steps
            or type(proof['anchor_only'])is not bool or proof['anchor_only']!=(steps==0)
            or not isinstance(proof['ancestor_ids'],list)or len(proof['ancestor_ids'])>1024
            or integer(proof['witnessed_conditional_steps'],'actual witnessed conditional steps')>steps):
        raise ValueError('actual native safe path projection bounds differ')
    # Keep signedfalse/unknown conditional count as observations, never upgrade.
    return {'source_table':source_table,'coin_id':proof['id'],'proof':proof,
      'body_sha256':_sha(native_body),'request_sha256':_sha(request_raw),'response_sha256':_sha(response_raw),
      'funding_raw_sha256':_sha(funding_raw),'signed_path_valid':proof['signed_path_valid'],
      'economic_ownership':'UNRESOLVED_REQUIRES_SAME_RR_CURRENT_SOURCE'}


def collect_paths(loaded,chain,tool,*,tool_identity,observation,server_pubkey):
    """Actual pure verifier per original body, same independent source tip.

    Uses the shared run_proof lifecycle/private evidence/12s sub-bound and its
    unchanged2MiB effective request/output ceilings. No RPC wallet or SDK open.
    Roots are independently acquired canonical active-chain transactions. A
    confirmed funding tx does not mean its output remains unspent/available.
    """
    pins=common._pins(observation['financial_pins']);_tool(tool,tool_identity,pins)
    common._observation({'source_observation':observation},pins,observation['height'],observation['tip_hash'])
    def tip():
        value=chain.identity()
        if(chain.call('getblockhash',0)!=SIGNET_GENESIS or value.get('chain')!='signet'
                or value.get('initialblockdownload')is not False
                or(value['blocks'],value['bestblockhash'])!=(observation['height'],observation['tip_hash'])):
            raise ValueError('independent native proof source tip differs')
    tip();database=loaded['database'];pg=loaded['private_pg'];originals=loaded['originals']
    if(common._json(originals['private-pg.json'])!=pg or loaded['manifest']['financial_pins']!=pins
            or loaded['manifest']['source_observation']!=observation):raise ValueError('native body private source provenance differs')
    context=common._json(originals['cut.json']);body._preflight(context['preflight'])
    body._assemble(pg,{'identity':database['database_identity']},database['rows'],context['preflight'])
    registered={r['metadata']['vtxo_id']:r for r in pg['coins']};fundings={};paths=[];private_proofs=[]
    for table in body.SOURCES:
        for row in pg[table]:
            deadline_check()
            if table=='coins':point=row['metadata']['anchor_point']
            elif table=='pending_boards':point=row['anchor_point']
            else:
                source=registered.get(row['metadata']['vtxo_id'])
                if source is None:raise ValueError('pool source lacks actual registered funding-anchor relationship')
                point=source['metadata']['anchor_point']
            txid,index=_point(point)
            if txid not in fundings:
                native=chain.call('getrawtransaction',txid,True)
                if(not isinstance(native,dict)or native.get('txid')!=txid or type(native.get('confirmations'))is not int or native['confirmations']<1):
                    raise ValueError('actual confirmed independent funding transaction missing')
                raw=common._raw(native['hex'],body.MAX_BODY_BYTES);parsed=decode_transaction(raw.hex())
                if parsed['txid']!=txid:raise ValueError('independent funding original transaction bytes differ')
                fundings[txid]={'raw':raw,'confirmations':native['confirmations'],'blockhash':native.get('blockhash')}
            funding=fundings[txid]['raw']
            request={'schema_version':1,'kind':'native-full-path-request','source_encoding':body.SOURCE_ENCODINGS[table],
              'body_hex':row['body_hex'],'funding_transaction_hex':funding.hex(),'expected_server_pubkey':server_pubkey}
            _tool(tool,tool_identity,pins)
            request_raw,reply_raw=run_proof(tool,request)
            _tool(tool,tool_identity,pins)
            paths.append(bind_path(row,request_raw,reply_raw,source_table=table,funding_raw=funding,
              tool_identity=tool_identity,server_pubkey=server_pubkey))
            private_proofs.append({'source_table':table,'coin_id':row['metadata']['vtxo_id'],'request':request_raw,'response':reply_raw})
    tip();deadline_check()
    return {'kind':'c-native-body-path-auxiliary','source_observation':observation,'financial_pins':pins,
      'paths':paths,'private_proof_originals':private_proofs,
      'funding_originals':fundings,'unresolved_signed_paths':[p['coin_id']for p in paths if not p['signed_path_valid']],
      'current_economic_ownership_complete':False,'complete':False,'qualified':False}
