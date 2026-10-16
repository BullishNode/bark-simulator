"""Explicit OWN A non-target source composition; private originals stay private."""
import asyncio
import hashlib
import json
import os
import re
import signal
import time
from pathlib import Path

from .chain import ChainReader
from .model import SIGNET_GENESIS, btc_to_sat, canonical, integer, timestamp
from .two_step_normal import digest, native_tables, strict_json
from .public_wallet_metadata import wallet_metadata
from .scanned_public_wallets import scan_current


class ConfigCredential:
    """Read only the scoped Core config's two auth fields into local memory."""
    def __init__(self,path):self.path=Path(path)
    def read_text(self):
        path=self.path;meta=path.lstat()
        if (not path.is_absolute() or path.is_symlink() or meta.st_mode&0o077
                or meta.st_uid!=os.getuid() or not 0<meta.st_size<=1024):
            raise ValueError('private owned scoped Core configuration required')
        with path.open('rb') as source:raw=source.read(1025)
        if len(raw)!=meta.st_size:raise ValueError('scoped Core configuration changed')
        fields={}
        for line in raw.decode().splitlines():
            key,separator,value=line.partition('=')
            if (not separator or key not in {'rpcuser','rpcpassword'} or key in fields
                    or not value or any(character.isspace() for character in value) or ':' in value):
                raise ValueError('exact scoped Core user/password fields required')
            fields[key]=value
        if set(fields)!={'rpcuser','rpcpassword'}:raise ValueError('scoped Core authentication incomplete')
        return fields['rpcuser']+':'+fields['rpcpassword']


def private_file(path,maximum):
    path=Path(path);meta=path.lstat()
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or meta.st_mode&0o077 or meta.st_uid!=os.getuid() or not 0<=meta.st_size<=maximum):
        raise ValueError('bounded owned private source original required')
    raw=path.read_bytes()
    if len(raw)!=meta.st_size:raise ValueError('private original changed while reading')
    return raw


def bank_projection(raw,member,chain,*,height,tip_hash,records):
    """Resolve actual bank native results; no pending/coverage flags accepted."""
    info=raw['getwalletinfo'];balances=raw['getbalances']['mine'];listed=raw['listdescriptors']['descriptors']
    if (info.get('scanning') is not False or info.get('descriptors') is not True
            or type(info.get('txcount')) is not int or not 0<=info['txcount']<=2000
            or balances['untrusted_pending']!=0 or balances['immature']!=0
            or len(raw['listtransactions'])>2000 or len(raw['listunspent'])>2000):
        raise ValueError('bank source discovery/pending/immature coverage unresolved')
    if any(type(row.get('confirmations')) is not int or row['confirmations']<1 for row in raw['listtransactions']):
        raise ValueError('bank has unresolved unconfirmed/conflicted transaction history')
    descriptors=[row['desc'] for row in listed]
    if len(set(descriptors))!=len(descriptors) or set(descriptors)!=set(member['descriptors']):
        raise ValueError('bank actual native public descriptor membership differs')
    if raw['listlockunspent']:
        # Retained locked_gettxout originals are not ordinary available cash.
        # A current source resolver must attribute every locked right first.
        raise ValueError('bank locked-output ownership/pending resolver required')
    result={'source_kind':'core_wallet_rpc','network':'signet','height':height,'tip_hash':tip_hash,
        'public_descriptors':member['descriptors'],'pending_transactions':[],
        'reserved_outpoints':[],'discovery_gaps':[],'source_records':records,'utxos':[]}
    seen=set()
    for row in raw['listunspent']:
        if type(row.get('confirmations')) is not int or row['confirmations']<1:
            raise ValueError('bank unconfirmed onchain output requires source resolver')
        address=row['address'];details=raw['getaddressinfo'][address]
        path=details.get('hdkeypath','').split('/')
        if not path or re.fullmatch('[0-9]+',path[-1]) is None:
            raise ValueError('bank current native ordinary derivation child missing')
        child=int(path[-1]);matches=[]
        for index,descriptor in enumerate(member['descriptors']):
            canonical_desc=chain.call('getdescriptorinfo',descriptor)
            if canonical_desc.get('hasprivatekeys') is not False or canonical_desc.get('descriptor')!=descriptor:
                raise ValueError('bank canonical public descriptor required')
            if chain.call('deriveaddresses',descriptor,[child,child])==[address]:matches.append(index)
        point=row['txid']+':'+str(integer(row['vout'],'bank output'))
        if (len(matches)!=1 or point in seen or details.get('scriptPubKey')!=row['scriptPubKey']
                or details.get('ismine') is not True):
            raise ValueError('bank actual output descriptor/derivation ownership differs')
        seen.add(point)
        coin=chain.call('gettxout',row['txid'],row['vout'],False)
        if (coin is None or coin['bestblock']!=tip_hash or coin['confirmations']!=row['confirmations']
                or coin['scriptPubKey']['hex']!=row['scriptPubKey'] or btc_to_sat(coin['value'])!=btc_to_sat(row['amount'])):
            raise ValueError('bank literal output differs from independent current Core')
        result['utxos'].append({'outpoint':point,'amount_sat':btc_to_sat(row['amount']),
            'script':row['scriptPubKey'],'descriptor_index':matches[0],'child_index':child})
    return result


class MemberReader:
    def __init__(self,configuration,store):self.configuration=configuration;self.store=store

    async def read(self,observation,members,target):
        cfg=self.configuration;identifier=observation['id'];start=time.time()
        if re.fullmatch('[0-9a-f]{32}',identifier) is None:raise ValueError('canonical member source nonce required')
        evidence=Path(cfg['evidence_root'])/identifier
        evidence.mkdir(mode=0o700) # exclusive: no replay of a partial observation
        def save(name,raw):
            path=evidence/name
            with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as output:
                output.write(raw);output.flush();os.fsync(output.fileno())
            return digest(raw)
        save('request.json',canonical(observation).encode())
        helper=Path(cfg['helper_command'][-1])
        helper_meta=helper.lstat()
        if (not helper.is_absolute() or helper.is_symlink() or not helper.is_file()
                or helper_meta.st_mode&0o022 or helper_meta.st_uid not in {0,os.getuid()} or not 0<helper_meta.st_size<=65536
                or digest(helper.read_bytes())!=cfg['helper_sha256']):
            raise ValueError('installed bank/fixture helper source differs')
        process=await asyncio.create_subprocess_exec(*cfg['helper_command'],identifier,
            stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,start_new_session=True)
        terminal={'pid':process.pid}
        async def drain(stream,name,bound):
            data=bytearray()
            with os.fdopen(os.open(evidence/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as output:
                while True:
                    part=await stream.read(65536)
                    if not part:break
                    output.write(part[:max(0,bound-len(data))]);data.extend(part)
                    if len(data)>bound:raise ValueError('private member helper output exceeds bound')
                output.flush();os.fsync(output.fileno())
            return bytes(data)
        stdout=asyncio.create_task(drain(process.stdout,'helper.stdout',4096));stderr=asyncio.create_task(drain(process.stderr,'helper.stderr',65536))
        try:
            out,err,_=await asyncio.wait_for(asyncio.gather(stdout,stderr,process.wait()),timeout=95)
            terminal['exit']=process.returncode
            if process.returncode:raise ValueError('literal bank/fixture source refused')
        except BaseException as error:
            terminal['error_type']=type(error).__name__
            if process.returncode is None:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            await process.wait();await asyncio.gather(stdout,stderr,return_exceptions=True);terminal['exit']=process.returncode
            raise
        finally:save('helper.terminal.json',canonical(terminal).encode())
        receipt=strict_json(out);manifest_path=Path(cfg['helper_evidence_root'])/identifier/'manifest.json'
        if receipt['manifest_path']!=str(manifest_path):raise ValueError('member helper selected an unexpected private path')
        raw_manifest=private_file(manifest_path,4*1024*1024)
        if digest(raw_manifest)!=receipt['manifest_sha256']:raise ValueError('member helper original manifest differs')
        manifest=strict_json(raw_manifest);originals={};total=0
        if (manifest['source_observation_id']!=identifier or manifest['unresolved_sources']
                or manifest['source_program_sha256']!=cfg['helper_sha256']
                or (manifest['height'],manifest['tip_hash'])!=(observation['height'],observation['tip_hash'])
                or not start<=timestamp(manifest['started_at'],'member helper start')<=timestamp(manifest['completed_at'],'member helper end')<=time.time()):
            raise ValueError('member helper actual source/time/tip differs')
        from .private_source_package import relative
        for name,record in manifest['files'].items():
            relative(name);raw=private_file(manifest_path.parent/name,2*1024*1024);total+=len(raw)
            if total>40*1024*1024 or record!={'sha256':digest(raw),'size_bytes':len(raw)}:raise ValueError('member source original hash/aggregate bound differs')
            originals[name]=raw
        for role,name in manifest['originals_map'].items():
            if digest(originals[name])!=manifest['original_sha256'][role]:raise ValueError('member original role binding differs')
        core=strict_json(originals[manifest['originals_map']['core']])
        if core['genesis']!=SIGNET_GENESIS or any((frame['chain'],frame['blocks'],frame['bestblockhash'],frame['initialblockdownload'])!=('signet',observation['height'],observation['tip_hash'],False) for frame in (core['before'],core['after'])):
            raise ValueError('member helper chain identity/bracket differs')
        rpc_records=[]
        def capture(frame):
            raw=frame['raw']
            if raw is None:raise ValueError('actual public Core original unavailable')
            sha=save('core-%04d.json'%len(rpc_records),raw);rpc_records.append(sha)
            return {'sha256':sha}
        chain=ChainReader(cfg['chain_url'],cfg['scoped_core_config'],SIGNET_GENESIS,capture=capture,consumer='normal-current-members')
        chain.credential=ConfigCredential(cfg['scoped_core_config'])
        prepared_raw=private_file(cfg['prepared_descriptors'],65536)
        if digest(prepared_raw)!=cfg['prepared_descriptors_sha256']:raise ValueError('immutable pure descriptor provenance differs')
        prepared=strict_json(prepared_raw);metadata={}
        for actor in cfg['actor_member_ids']:
            path=Path(cfg['wallet_root'])/actor/'db.sqlite'
            metadata[actor]=wallet_metadata(path) if path.exists() else {'wallet_database_exists':False}
        save('public-wallet-metadata.json',canonical(metadata).encode())
        frames=scan_current(chain,members,cfg['actor_member_ids'],prepared,metadata,rpc_records)
        bank=cfg['bank_member_id'];fixture=cfg['fixture_member_id'];target_cln=cfg['target_cln_member_id'];backing=cfg['backing_member_id']
        bank_raw=strict_json(originals[manifest['originals_map']['bank']],decimals=True)
        frames[bank]=bank_projection(bank_raw,members[bank],chain,height=observation['height'],tip_hash=observation['tip_hash'],records=[digest(raw_manifest),*rpc_records])
        frames[fixture]=strict_json(originals[manifest['originals_map']['fixture_cln']])
        cln_name=target['manifest']['auxiliary_originals']['target_cln']
        frames[target_cln]=strict_json(target['auxiliary_originals'][cln_name])
        # Core checks current unspent roots. Spent roots retain liabilities and
        # are resolved later by actual native proof + recovery-hold validation.
        tables=native_tables(target['raw_sql'],target['manifest']['original_sha256']['native_sql'])
        roots={}
        from .financial_transition import _current_claims
        for claim in _current_claims(self.store):
            proof=json.loads(self.store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(claim['coin_id'],)).fetchone()['proof'])
            point=proof['chain_anchor'];row=next((row for row in tables['vtxo'] if row['vtxo_id']==point),None)
            if row is None:raise ValueError('native original backing root missing')
            if row['onchain_spent_txid'] is not None:continue
            txid,index=point.rsplit(':',1);coin=chain.call('gettxout',txid,int(index),False)
            if coin is None or coin['bestblock']!=observation['tip_hash']:raise ValueError('current original backing source unavailable')
            roots[point]={'amount_sat':btc_to_sat(coin['value']),'script':coin['scriptPubKey']['hex']}
        frames[backing]={'source_kind':'native_signed_ordinary_backing','roots':roots}
        final=chain.identity()
        if (final['blocks'],final['bestblockhash'],final['initialblockdownload'])!=(observation['height'],observation['tip_hash'],False):raise ValueError('current member source chain changed')
        result={name:{'raw_original':canonical(frame).encode()} for name,frame in frames.items()}
        result[fixture]['raw_original']=originals[manifest['originals_map']['fixture_cln']]
        result[target_cln]['raw_original']=target['auxiliary_originals'][cln_name]
        for name,frame in result.items():frame['source_sha256']=save('member-'+digest(name.encode())+'.json',frame['raw_original'])
        result_manifest={'source_observation_id':identifier,'started_at':start,'completed_at':time.time(),
            'height':observation['height'],'tip_hash':observation['tip_hash'],'source_program_sha256':digest(Path(__file__).read_bytes()),
            'unresolved_sources':[],'original_sha256':{name:frame['source_sha256'] for name,frame in result.items()},
            'helper_manifest_sha256':digest(raw_manifest),'prepared_descriptors_sha256':digest(prepared_raw)}
        encoded=canonical(result_manifest).encode();save('manifest.json',encoded)
        return {'manifest':result_manifest,'raw_manifest':encoded,'manifest_sha256':digest(encoded),'members':result}
