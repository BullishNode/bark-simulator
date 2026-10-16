"""Explicit OWN A non-target source composition; private originals stay private."""
import asyncio
import hashlib
import json
import os
import re
import signal
import stat
import time
from pathlib import Path

from .chain import ChainReader
from .normal_source_deadline import ACTIVE, DeadlineChain, timeout as source_timeout
from .model import SIGNET_GENESIS, btc_to_sat, canonical, integer, timestamp
from .two_step_normal import digest, native_tables, strict_json
from .public_wallet_metadata import wallet_metadata
from .descriptor_checkpoint import current_from_checkpoint


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
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb') as source:
        before=os.fstat(source.fileno())
        identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_mode,value.st_uid)
        if not stat.S_ISREG(before.st_mode) or identity(before)!=identity(meta):
            raise ValueError('private original changed before bounded read')
        raw=source.read(maximum+1)
        after=os.fstat(source.fileno())
        if len(raw)>maximum or len(raw)!=meta.st_size or identity(before)!=identity(after):
            raise ValueError('private original changed while reading')
    return raw


def bank_output_ownership(raw,member,chain,row):
    """Derive one literal bank row from the complete declared public descriptors.

    Historical funding ownership may use this independently of current UTXO
    availability. Its caller must authenticate the original native bank frame
    and independently check the actual output bytes, timing and source chain.
    """
    descriptors=[entry['desc'] for entry in raw['listdescriptors']['descriptors']]
    if len(set(descriptors))!=len(descriptors) or set(descriptors)!=set(member['descriptors']):
        raise ValueError('bank actual native public descriptor membership differs')
    address=row['address'];details=raw['getaddressinfo'][address]
    path=details.get('hdkeypath','').split('/')
    if not path or re.fullmatch('[0-9]+',path[-1]) is None:
        raise ValueError('bank current native ordinary derivation child missing')
    child=int(path[-1])
    if child>=2**31:raise ValueError('ordinary public bank child required')
    matches=[]
    for index,descriptor in enumerate(member['descriptors']):
        actual=chain.call('getdescriptorinfo',descriptor)
        if actual.get('hasprivatekeys') is not False or actual.get('descriptor')!=descriptor:
            raise ValueError('bank canonical public descriptor required')
        if chain.call('deriveaddresses',descriptor,[child,child])==[address]:matches.append(index)
    if len(matches)!=1 or details.get('scriptPubKey')!=row['scriptPubKey'] or details.get('ismine') is not True:
        raise ValueError('bank actual output descriptor/derivation ownership differs')
    return {'outpoint':row['txid']+':'+str(integer(row['vout'],'bank output')),
        'amount_sat':btc_to_sat(row['amount']),'script':row['scriptPubKey'],
        'descriptor_index':matches[0],'child_index':child}


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
        owned=bank_output_ownership(raw,member,chain,row)
        point=owned['outpoint']
        if point in seen:raise ValueError('duplicate bank output')
        seen.add(point)
        coin=chain.call('gettxout',row['txid'],row['vout'],False)
        if (coin is None or coin['bestblock']!=tip_hash or coin['confirmations']!=row['confirmations']
                or coin['scriptPubKey']['hex']!=row['scriptPubKey'] or btc_to_sat(coin['value'])!=btc_to_sat(row['amount'])):
            raise ValueError('bank literal output differs from independent current Core')
        result['utxos'].append(owned)
    return result


class MemberReader:
    def __init__(self,configuration,store, *, native_profile=None):
        self.configuration=configuration;self.store=store
        if native_profile is not None:
            from .b_normal_profile_adapter import require_profile
            require_profile(native_profile)
        self.native_profile=native_profile

    async def read(self,observation,members,target, *, runtime_config=None):
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
            out,err,_=await asyncio.wait_for(asyncio.gather(stdout,stderr,process.wait()),timeout=source_timeout(95))
            terminal['exit']=process.returncode
            if process.returncode:raise ValueError('literal bank/fixture source refused')
        except BaseException as error:
            terminal['error_type']=type(error).__name__
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
        if ACTIVE.get() is not None:chain=DeadlineChain(chain,ACTIVE.get())
        if self.native_profile is None:
            prepared_raw=private_file(cfg['prepared_descriptors'],65536)
            if digest(prepared_raw)!=cfg['prepared_descriptors_sha256']:raise ValueError('immutable pure descriptor provenance differs')
            prepared=strict_json(prepared_raw);metadata={}
            for actor in cfg['actor_member_ids']:
                path=Path(cfg['wallet_root'])/actor/'db.sqlite'
                metadata[actor]=wallet_metadata(path) if path.exists() else {'wallet_database_exists':False}
            save('public-wallet-metadata.json',canonical(metadata).encode())
            frames=current_from_checkpoint(chain,members,cfg['actor_member_ids'],prepared,metadata,rpc_records,
                path=cfg['descriptor_checkpoint'],expected_sha256=cfg['descriptor_checkpoint_sha256'],
                prepared_sha256=cfg['prepared_descriptors_sha256'])
            bank=cfg['bank_member_id'];fixture=cfg['fixture_member_id'];target_cln=cfg['target_cln_member_id'];backing=cfg['backing_member_id']
            bank_raw=strict_json(originals[manifest['originals_map']['bank']],decimals=True)
            frames[bank]=bank_projection(bank_raw,members[bank],chain,height=observation['height'],tip_hash=observation['tip_hash'],records=[digest(raw_manifest),*rpc_records])
            frames[fixture]=strict_json(originals[manifest['originals_map']['fixture_cln']])
            cln_name=target['manifest']['auxiliary_originals']['target_cln']
            frames[target_cln]=strict_json(target['auxiliary_originals'][cln_name])
            # Core checks current unspent roots. Spent roots retain liabilities and
            # are resolved later by actual native proof + recovery-hold validation.
            tables=native_tables(target['raw_sql'],target['manifest']['original_sha256']['native_sql'],
                pending_board_proof_sha256=cfg.get('pending_board_proof_sha256'),
                ordinary_pool_source_sha256=cfg.get('ordinary_pool',{}).get('classifier_sha256'))
            roots={}
            owned_originals=self.store.db.execute('SELECT id,proof FROM owned_coin ORDER BY id').fetchall()
            if len(owned_originals)>10000:raise ValueError('bounded complete original backing roots required')
            for claim in owned_originals:
                proof=json.loads(claim['proof'])
                point=proof['chain_anchor'];row=next((row for row in tables['vtxo'] if row['vtxo_id']==point),None)
                if row is None:raise ValueError('native original backing root missing')
                if row['onchain_spent_txid'] is not None:continue
                txid,index=point.rsplit(':',1);coin=chain.call('gettxout',txid,int(index),True)
                if coin is None or coin['bestblock']!=observation['tip_hash']:raise ValueError('current original backing source unavailable')
                roots[point]={'amount_sat':btc_to_sat(coin['value']),'script':coin['scriptPubKey']['hex']}
            if cfg.get('ordinary_pool')is not None:
                from .normal_pool import source_originals
                pool=strict_json(source_originals(target,cfg['ordinary_pool'])['owning_pool_inventory'])
                if len(pool['candidates'])>256:raise ValueError('bounded actual pool candidates required')
                rows={row['vtxo_id']:row for row in tables['vtxo']}
                for candidate in pool['candidates']:
                    row=rows.get(candidate['id'])
                    if row is None:raise ValueError('pool source missing exact same-cut SQL identity')
                    point=row['anchor_point'];txid,index=point.rsplit(':',1);coin=chain.call('gettxout',txid,int(index),True)
                    if coin is None or coin['bestblock']!=observation['tip_hash']:raise ValueError('pool source backing not currently unspent')
                    roots[point]={'amount_sat':btc_to_sat(coin['value']),'script':coin['scriptPubKey']['hex']}
            frames[backing]={'source_kind':'native_signed_ordinary_backing','roots':roots}
        else:
            frames, b_context = self.native_profile.member_frames(self.store, runtime_config, chain,
                cfg, observation, members, target, originals, manifest, rpc_records)
            prepared_raw=private_file(cfg['prepared_descriptors'],65536)
            fixture = cfg['fixture_member_id']; target_cln = cfg['target_cln_member_id']
            cln_name = target['manifest']['auxiliary_originals']['target_cln']
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
        if self.native_profile is not None:
            result_manifest['b_public_context_sha256']=digest(canonical(b_context).encode())
            save('b-public-metadata-context.json',canonical(b_context).encode())
        encoded=canonical(result_manifest).encode();save('manifest.json',encoded)
        package={'manifest':result_manifest,'raw_manifest':encoded,'manifest_sha256':digest(encoded),'members':result}
        if self.native_profile is not None:package['b_public_context']=b_context
        return package
