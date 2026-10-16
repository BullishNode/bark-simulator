"""Actual C customer/bank sources joined to fresh owning/CLN originals.

Reuse the existing named-bank collector, public SQLite metadata, independent
complete descriptor/mempool source and shared physical-asset reducer. No SDK
wallet opens, create/retry, balance flags, epoch resets or financial admission.
"""
import copy
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import time

from . import c_cohort, c_normal_cln_join as cln_join, c_normal_runtime_source as runtime_source
from .c_normal_source import _context
from .final_campaign import _source_event
from .funding import WalletRpc
from .funding_bank import collect_funding_bank_source, EVENT_KIND as BANK_KIND
from .model import SIGNET_GENESIS, btc_to_sat, canonical, public_payload
from .normal_source_deadline import check as deadline_check, timeout as source_timeout
from .ownership import EvidenceGap
from .public_wallet_metadata import wallet_metadata
from .two_step_normal import module_hash

KIND = 'c_normal_member_sources_joined'


def digest(raw):return hashlib.sha256(raw).hexdigest()


def _credential_identity(binding):
    token = Path(binding.bank.token_file); value = token.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_nlink != 1
            or value.st_mode & 0o077 or not 0 < value.st_size <= 1024):
        raise EvidenceGap('protected original named-bank credential file required')
    return (value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns,value.st_mode,value.st_uid)


@dataclass(frozen=True)
class MemberBinding:
    wallet_root: str
    actor_member_ids: dict
    bank: WalletRpc
    qualification_sequence: int

    def check(self):
        actors = set(self.actor_member_ids) if isinstance(self.actor_member_ids,dict) else set()
        root = Path(self.wallet_root)
        if (actors not in (set(c_cohort.INITIAL), set(c_cohort.INITIAL+c_cohort.RAMP))
                or len(set(self.actor_member_ids.values())) != len(actors)
                or any(not isinstance(v,str) or not v for v in self.actor_member_ids.values())
                or set(self.actor_member_ids.values()) & {'bank','rounds','watchman'}
                or not root.is_absolute() or str(root) != os.path.abspath(root)
                or any(p.is_symlink() for p in [root,*root.parents])
                or type(self.bank) is not WalletRpc or set(self.bank.__dict__) != {'token_file','wallet','capture'}
                or self.bank.capture is not None
                or type(self.qualification_sequence) is not int or self.qualification_sequence < 1):
            raise EvidenceGap('fixed C complete cohort and named bank binding required')
        token = Path(self.bank.token_file)
        if not token.is_absolute() or any(p.is_symlink() for p in [token,*token.parents]):
            raise EvidenceGap('fixed private bank credential path required')
        return {'wallet_root':str(root), 'actor_member_ids':copy.deepcopy(self.actor_member_ids),
            'bank_wallet':self.bank.wallet, 'bank_credential_path_sha256':digest(str(token).encode()),
            'qualification_sequence':self.qualification_sequence}


def history(store, actors):
    """Retained authenticated native creates, never current zero-asset claims."""
    original = c_cohort.historical_initial_identity_sources(store)
    sources = copy.deepcopy(original['sources'])
    if actors == set(c_cohort.INITIAL+c_cohort.RAMP):
        c_cohort.cohort_request(store,'ramp') # original real credited10800 ancestry
        current = c_cohort.enrollment(store,'ramp')
        if current is None or not c_cohort.enrollment_complete(store,'ramp'):
            raise EvidenceGap('actual checked ramp identity closure required')
        for actor,(event,proof) in c_cohort._zero_sources(store,current).items():
            native_event,native = _source_event(store,proof['driver_response_sequence'])
            action = store.db.execute('SELECT fee_reservation_sat FROM action WHERE id=?',(proof['action_id'],)).fetchone()
            if action is None or action[0] != 0:
                raise EvidenceGap('original zero-fee ramp create reservation differs')
            c_cohort._verify_key_sources(store,actor,proof['action_id'],native['response']['data'],proof['financial_pins'],initial_rows=None)
            sources[actor] = {'driver_response_sequence':native_event['sequence'], 'driver_response_hash':native_event['hash'],
                'zero_source_sequence':event['sequence'], 'zero_event_hash':event['hash'], 'create_action_id':proof['action_id']}
        from .c_pilot import retained_links
        retained_links(store,actors=list(c_cohort.RAMP))
    if set(sources) != actors:
        raise EvidenceGap('all actual retained C native identities required')
    return {**original,'actors':sorted(actors),'sources':sources}


def requirement(binding,pins):
    from .confirmed_scan import confirmed_scan
    from .owned_mempool import collect
    from .treasury import _capture_assets
    from .two_step_capture import _public_wallet_rows
    constructor = binding.check()
    constructor.pop('qualification_sequence') # the qualifying event cannot name its own future sequence
    return {'architecture_profile':'direct_per_key','financial_pins':pins,
        'constructor':constructor, 'component_sha256':{
            'producer':digest(Path(__file__).read_bytes()), 'bank':module_hash(collect_funding_bank_source),
            'bank_rpc':module_hash(WalletRpc.call), 'metadata':module_hash(wallet_metadata),
            'confirmed_scan':module_hash(confirmed_scan), 'owned_activity':module_hash(collect),
            'treasury':module_hash(_capture_assets), 'wallet_rows':module_hash(_public_wallet_rows),
            'cohort_history':module_hash(c_cohort.historical_initial_identity_sources),
            'previous_join':module_hash(cln_join.collect)}}


def _bank(store,binding,chain,observation):
    first = store.db.execute('SELECT coalesce(max(sequence),0) FROM event').fetchone()[0]
    sequence = collect_funding_bank_source(store,binding.bank,chain,timeout_seconds=source_timeout(30))
    event,value = _source_event(store,sequence)
    if (type(sequence) is not int or sequence <= first or event['kind'] != BANK_KIND
            or value.get('source_identity',{}).get('wallet_name') != binding.bank.wallet
            or (value.get('height'),value.get('tip_hash')) != (observation['height'],observation['tip_hash'])
            or not observation['started_at'] <= value.get('observed_at',-1) <= value.get('completed_at',-1) <= time.time()
            or value.get('stable_tip') is not True or value.get('complete_source_projection') is not True
            or any(value.get(k) != [] for k in ('pending_transactions','pending_parents','locked_coins','listlockunspent'))
            or value.get('listsinceblock',{}).get('transactions') != []):
        raise EvidenceGap('new complete stable unreserved named bank source required')
    return event,value


def _members(store,boundary,binding):
    from .treasury import _members as members_of
    members = members_of(boundary); actors = set(binding.actor_member_ids)
    wallet_ids = {'bank','rounds','watchman',*binding.actor_member_ids.values()}
    if {k for k,v in members.items() if v['kind']=='wallet'} != wallet_ids:
        raise EvidenceGap('complete exact C wallet membership required')
    for name in wallet_ids:
        member = members[name]; event,proof = _source_event(store,member['verification_sequence'])
        if (event['kind'] != 'treasury_member_verified' or proof.get('financial_pins') != boundary['pins']
                or proof.get('genesis') != SIGNET_GENESIS
                or proof.get('member') != {k:v for k,v in member.items() if k!='verification_sequence'}):
            raise EvidenceGap('original C member verification differs')
        if member['role'] != ('customer' if name in binding.actor_member_ids.values() else 'operator'):
            raise EvidenceGap('declared C bank/operator/customer role must be preserved')
    if members['bank']['identity'] != 'core-wallet:'+binding.bank.wallet:
        raise EvidenceGap('actual declared named bank identity required')
    return members,actors


async def collect(store,config,chain,observation,*,boundary,checked,runtime,cln,binding):
    _context(store,observation); deadline_check()
    if type(binding) is not MemberBinding:raise EvidenceGap('typed complete C member binding required')
    original = canonical(observation); constructor = canonical(binding.check())
    credential = _credential_identity(binding)
    members,actors = _members(store,boundary,binding)
    if (boundary['pins'] != observation['financial_pins'] or boundary['id'] != observation['boundary_id']
            or Path(binding.wallet_root) != config.wallet_root
            or checked.get('kind') != 'c-checked-native-target-source' or checked.get('source_observation') != observation
            or checked.get('loaded',{}).get('manifest',{}).get('source_observation') != observation
            or checked['loaded']['manifest'].get('financial_pins') != observation['financial_pins']):
        raise EvidenceGap('C member observation/boundary/wallet root differs')
    if store.db.execute("SELECT 1 FROM event WHERE kind=? AND json_extract(payload,'$.source_observation.id')=?",(KIND,observation['id'])).fetchone():
        raise EvidenceGap('C member observation already collected')
    event,admitted = _source_event(store,binding.qualification_sequence)
    if event['kind'] != 'c_normal_member_source_qualified' or admitted != requirement(binding,boundary['pins']):
        raise EvidenceGap('actual fixed C member source qualification missing')
    identities = history(store,actors)
    from .identity_bootstrap import _root
    if (Path(identities['wallet_root']) != config.wallet_root or identities['financial_pins'] != boundary['pins']
            or _root(str(config.wallet_root)) != identities['filesystem']):
        raise EvidenceGap('retained native cohort source root or pins differ')
    children = {p.name for p in config.wallet_root.iterdir()}
    if not actors <= children or children - actors - {'supervisor.lock'}:
        raise EvidenceGap('actual private root contains missing or unenumerated customer wallets')
    safe = cln.get('safe',{})
    cln_event,_ = cln_join.owning_join._original(store,safe.get('source_sequence'),cln_join.KIND,safe,observation)
    if (safe.get('runtime_component_sequence') != runtime['safe']['source_sequence']
            or safe.get('runtime_source_sequence') != runtime['safe']['runtime_source_sequence']
            or safe.get('target_original_private_source_references') != checked['original_private_source_references']
            or set(safe.get('inventory_sequences',{})) != {'rounds','watchman',*cln['private_cln_component']['inventory_sequences']}):
        raise EvidenceGap('same observation original C owning/CLN union required')
    runtime_raw = runtime_source._public_file(runtime['safe']['current_startup_path'],runtime['safe']['current_source_sha256'],2*1024*1024)
    current = runtime_source.decode_object(runtime_raw.decode())
    if current != runtime['private_runtime_source']:raise EvidenceGap('actual private runtime source differs')
    first_bank,bank = _bank(store,binding,chain,observation)
    metadata = {}; specs = {}; root = Path(binding.wallet_root); meta_before = {}
    for actor,name in sorted(binding.actor_member_ids.items()):
        directory = root/actor; st = directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.getuid():
            raise EvidenceGap('actual owned private customer directory required')
        value = wallet_metadata(directory/'db.sqlite'); member = members[name]
        native_event,native = _source_event(store,identities['sources'][actor]['driver_response_sequence'])
        descriptors = native.get('response',{}).get('data',{}).get('onchain_inventory',{}).get('descriptors')
        if (native_event['hash'] != identities['sources'][actor]['driver_response_hash']
                or not isinstance(descriptors,list) or len(descriptors) != 1 or descriptors[0].get('keychain') != 'external'
                or member['descriptors'] != [descriptors[0]['descriptor']]
                or value['wallet']['descriptor'] != descriptors[0]['descriptor'] or value['locked_outpoints']
                or not 0 <= value['issued_frontier'] < 1980):
            raise EvidenceGap('current public metadata differs from original native customer')
        metadata[actor] = value; meta_before[actor] = canonical(value)
        specs[value['wallet']['descriptor']] = [0,max(19,value['issued_frontier']+20)]
    for owner in ('rounds','watchman'):
        value = runtime['private_owning_frames'][owner]['source'][owner]
        if members[owner]['descriptors'] != [value['public_descriptor']]:raise EvidenceGap('actual owning descriptor differs')
        specs[value['public_descriptor']] = [0,max(19,value['last_revealed_index']+20)]
    bank_descriptors = bank['listdescriptors']['descriptors']
    if len(bank_descriptors) != len(members['bank']['descriptors']) or [r['desc'] for r in bank_descriptors] != members['bank']['descriptors']:
        raise EvidenceGap('complete original bank descriptor order differs')
    for row in bank_descriptors:
        frontier = row.get('next_index')
        if type(frontier) is not int or not 0 <= frontier < 1980 or not isinstance(row.get('range'),list) or row['range'][0] != 0:
            raise EvidenceGap('actual bounded bank issued descriptor frontier required')
        specs[row['desc']] = [0,max(19,frontier+20)]
    from .confirmed_scan import confirmed_scan
    scripts,ranges,scan,provenance = confirmed_scan(store,config,chain,current,pins=boundary['pins'],
        boundary_id=boundary['id'],members=list(members.values()),specs=specs,tip=(observation['height'],observation['tip_hash']))
    for actor,name in binding.actor_member_ids.items():
        native = metadata[actor]
        selected = {r['child_index']:script for script,r in scripts.items() if r['member_id']==name}
        if (len(native['last_revealed']) != 1
                or native['last_revealed'][0]['last_revealed'] != native['issued_frontier']
                or native['last_revealed'][0]['descriptor_id'] != digest(bytes.fromhex(selected[0]))
                or any(row['spk_index'] in selected and row['script'] != selected[row['spk_index']] for row in native['derived_scripts'])):
            raise EvidenceGap('actual customer descriptor index/cache differs from independent derivation')
    from .owned_mempool import collect as owned_activity,collector_context
    activity = owned_activity(store,chain,set(scripts),time.monotonic(),context=collector_context('c_normal_all_members',
        {**observation,'descriptor_ranges':ranges}))
    rows = {name:[] for name in members}
    for coin in scan['unspents']:
        owner = scripts[coin['scriptPubKey']]; name = owner['member_id']
        txid,index = coin['txid'],coin['vout']; actual = chain.call('gettxout',txid,index,False)
        if (actual is None or actual.get('bestblock') != observation['tip_hash'] or actual.get('confirmations',0)<1
                or actual['scriptPubKey']['hex'] != coin['scriptPubKey'] or btc_to_sat(actual['value']) != btc_to_sat(coin['amount'])):
            raise EvidenceGap('scanned member output differs from independent current Core')
        rows[name].append({'outpoint':txid+':'+str(index),'amount_sat':btc_to_sat(coin['amount']),
            'script':coin['scriptPubKey'],'descriptor_index':owner['descriptor_index'],'child_index':owner['child_index']})
    bank_points = {r['txid']+':'+str(r['vout']):r for r in bank['listunspent']}
    if len(bank_points) != len(bank['listunspent']) or set(bank_points) != {r['outpoint'] for r in rows['bank']}:
        raise EvidenceGap('all native bank coins must match complete independent descriptor scan')
    for row in rows['bank']:
        native = bank_points[row['outpoint']]
        if (native['scriptPubKey'] != row['script'] or btc_to_sat(native['amount']) != row['amount_sat']
                or native.get('safe') is not True or native.get('spendable') is not True or native.get('solvable') is not True):
            raise EvidenceGap('actual controlled safe bank coin differs')
    if (sum(r['amount_sat'] for r in rows['bank']) != btc_to_sat(bank['getbalances']['mine']['trusted'])
            or any(btc_to_sat(bank['getbalances']['mine'][k]) for k in ('untrusted_pending','immature'))):
        raise EvidenceGap('complete actual bank balance differs')
    for owner in ('rounds','watchman'):
        expected = runtime['private_owning_frames'][owner]['source'][owner]['utxos']
        if sorted((r['outpoint'],r['value_sat'],r['script_pubkey']) for r in expected) != sorted((r['outpoint'],r['amount_sat'],r['script']) for r in rows[owner]):
            raise EvidenceGap('full member scan differs from actual owning wallet union')
    last_bank,fresh_bank = _bank(store,binding,chain,observation)
    bank_fields = ('source_identity','getwalletinfo','listdescriptors','listunspent','listlockunspent','listsinceblock',
        'getbalances','locked_coins','pending_transactions','pending_parents')
    if any(bank[k] != fresh_bank[k] for k in bank_fields):raise EvidenceGap('actual bank changed during complete member scan')
    for actor in metadata:
        if canonical(wallet_metadata(root/actor/'db.sqlite')) != meta_before[actor]:raise EvidenceGap('public customer SQLite metadata changed')
    final_activity = owned_activity(store,chain,set(scripts),time.monotonic(),context=collector_context('c_normal_all_members',
        {**observation,'descriptor_ranges':ranges}))
    if (canonical(binding.check()) != constructor or canonical(observation) != original
            or _root(str(config.wallet_root)) != identities['filesystem']
            or _credential_identity(binding) != credential
            or runtime_source._public_file(runtime['safe']['current_startup_path'],runtime['safe']['current_source_sha256'],2*1024*1024) != runtime_raw):
        raise EvidenceGap('C member constructor/runtime changed')
    from .two_step_capture import public_wallet_projection,_public_wallet_rows
    inventories = dict(safe['inventory_sequences']); sources = dict(safe['inventory_source_sequences'])
    for name in ['bank',*binding.actor_member_ids.values()]:
        member = members[name]
        frame = {'source_kind':'core_descriptor_scan','network':'signet','height':observation['height'],
            'tip_hash':observation['tip_hash'],'public_descriptors':member['descriptors'],'pending_transactions':[],
            'reserved_outpoints':[],'discovery_gaps':[],'source_records':[provenance['raw_response_sha256'],first_bank['hash'],last_bank['hash']],
            'utxos':rows[name]}
        projected = (_public_wallet_rows if name=='bank' else public_wallet_projection)(member,frame,
            height=observation['height'],tip_hash=observation['tip_hash'])
        ctx = {'member_id':name,'identity':member['identity'],'financial_pins':boundary['pins'],
            'height':observation['height'],'tip_hash':observation['tip_hash'],'observed_at':time.time()}
        store.event('treasury_native_inventory_source',{**ctx,**frame,'source_scope':'actual public metadata and complete Core source; named bank originals separate'})
        sources[name] = store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        store.event('treasury_inventory',{**ctx,'complete':True,'utxos':projected,'scope':'one actual fully scanned member only'})
        inventories[name] = store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    from .treasury import _capture_assets
    if len(inventories) != len(actors)+5:raise EvidenceGap('exact17/29 wallet and twoCLN inventories required')
    assets = _capture_assets(store,{**boundary,'members':[members[k] for k in inventories]},inventories,chain)
    _context(store,observation);cln_join.owning_join.owning._tip(chain,observation);deadline_check()
    result = {'source_observation':copy.deepcopy(observation),'financial_pins':boundary['pins'],'boundary_id':boundary['id'],
        'height':observation['height'],'tip_hash':observation['tip_hash'],'observed_at':time.time(),
        'cln_join_sequence':cln_event['sequence'],'cln_join_event_hash':cln_event['hash'],
        'bank_original_sequences':[first_bank['sequence'],last_bank['sequence']],
        'bank_original_event_hashes':[first_bank['hash'],last_bank['hash']],
        'confirmed_scan':provenance,'mempool_activity':{'before':activity,'after':final_activity},'metadata':metadata,
        'historical_identity_sources':identities['sources'],'inventory_sequences':inventories,'inventory_source_sequences':sources,
        'actual_member_assets':assets,'qualification_sequence':binding.qualification_sequence,
        'remaining_declared_members':sorted(set(members)-set(inventories)),
        'complete':False,'qualified':False,'financial_readiness':False,
        'scope':'actual17/29 wallet and twoCLN source union only; native backing/liability/joint/urgent fees and final normal admission remain required'}
    public_payload(result);store.event(KIND,result)
    result['source_sequence'] = store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    return {'safe':result,'private_runtime_source':current,'private_confirmed_scripts':scripts,
        'private_checked_target':checked,'private_cln_join':cln}
