"""Original bounded source receipts for a fresh, closed wallet cohort.

Zero assets is a bootstrap prerequisite only. It is neither a treasury inventory
nor permission to fund or dispatch. The bootstrap owner validates the fresh-root,
sole-writer, exact artifact/configuration contract before calling this verifier.
"""
from . import frontier_source
import hashlib
import json
import time

from .model import SIGNET_GENESIS, canonical, public_payload
from .final_campaign import _pins, _source_event
from .process import json_command, public_command_capture
from .trace import normalized

MAX_MEMPOOL_TRANSACTIONS = 4096
MAX_MEMPOOL_SCAN_BYTES = 8 * 1024 * 1024
MAX_MEMPOOL_OUTPUTS = 50000
MAX_SOURCE_SECONDS = 180
MAX_SCAN_SECONDS = 120
MAX_MEMPOOL_PASSES = 8


def _digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


async def collect_closed_source_frames(store, config, chain, *, wallet_actions, bank_source_sequence=None):
    """Capture actual fixed bridge replies and four original native wallet frames.

    ``wallet_actions`` enumerates the bank and three customers by actor/action
    identity; each action must already have completed through the sole Engine.
    This collector does no wallet dispatch and cannot create readiness itself.
    Original facts are preserved even when subsequent closure remains a gap.
    """
    if (chain is None or not config.inventory_command or config.network != 'signet'
            or config.expected_genesis != SIGNET_GENESIS or getattr(store, 'trace', None) is None):
        raise ValueError('actual traced readonly sources and independent signet required')
    count=4 if bank_source_sequence is None else 3
    if not isinstance(wallet_actions, dict) or len(wallet_actions) != count or len(set(wallet_actions.values())) != count:
        raise ValueError('enumerate exactly bank and three customer native actions')
    before=chain.identity()
    if before.get('chain')!='signet' or before.get('initialblockdownload') is not False:
        raise ValueError('independent synchronized signet required')
    bank=None
    if bank_source_sequence is not None:
        if type(bank_source_sequence) is not int or bank_source_sequence<1:raise ValueError('original bank source sequence required')
        bank_event,bank_frame=_source_event(store,bank_source_sequence)
        identity=bank_frame.get('source_identity',{})
        if (bank_event['kind']!='treasury_bank_original_source' or bank_frame.get('schema_version')!=1
                or bank_frame.get('network')!='signet' or bank_frame.get('genesis')!=SIGNET_GENESIS
                or bank_frame.get('read_only') is not True or bank_frame.get('stable_tip') is not True
                or bank_frame.get('complete_source_projection') is not True
                or (bank_frame.get('height'),bank_frame.get('tip_hash'))!=(before['blocks'],before['bestblockhash'])
                or not isinstance(identity,dict) or not identity.get('wallet_name') or not identity.get('descriptors')):
            raise ValueError('original complete named Core bank source differs')
        bank={'source_sequence':bank_source_sequence,'source_event_hash':bank_event['hash'],
            'response_sha256':_digest(bank_frame),'frame':bank_frame}
    native={}
    for actor,action_id in wallet_actions.items():
        action=store.db.execute('SELECT * FROM action WHERE id=?',(action_id,)).fetchone()
        if (action is None or action['actor_id']!=actor or action['operation'] not in {'create','snapshot'}
                or action['state']!='completed'):
            raise ValueError('original completed native wallet observation required')
        sources=store.db.execute("SELECT sequence,hash,payload FROM event WHERE kind='driver_response' AND json_extract(payload,'$.action_id')=?",(action_id,)).fetchall()
        if len(sources)!=1:raise ValueError('unique original native wallet response required')
        source,original=_source_event(store,sources[0]['sequence']);response=original['response']
        if response!=json.loads(action['result']) or response.get('status')!='ok' or response.get('action_id')!=action_id:
            raise ValueError('native wallet observation provenance differs')
        frame=response.get('data',{}).get('onchain_inventory')
        if not isinstance(frame,dict) or frame.get('schema_version')!=1 or frame.get('read_only') is not True or frame.get('network')!='signet':
            raise ValueError('actual public native wallet frame required')
        native[actor]={'action_id':action_id,'source_sequence':source['sequence'],'source_event_hash':source['hash'],
            'response_sha256':_digest(response),'observed_at':action['updated_at'],'frame':frame}
    if (len(canonical(native).encode())>2*1024*1024
            or sum(len(value) for item in native.values() for value in item['frame'].values() if isinstance(value,list))>2000):
        raise ValueError('aggregate native wallet source exceeds byte/row budget')
    replies={}
    sequences={}
    for kind in ('closed_frontier','financial_readiness'):
        request={'kind':kind}
        reply=(await frontier_source.collect(store,config,store.financial_context(),timeout=25)
            if kind=='closed_frontier' and frontier_source.schema(config)==2 else
            await json_command(list(config.inventory_command),request,timeout=25,
            **public_command_capture(store,'closed_cohort.'+kind,request)))
        if kind=='closed_frontier':frontier_source.verify_frame(store,config,reply,store.financial_context())
        public_payload(reply)
        if reply.get('kind')!=kind or reply.get('complete') is not False or reply.get('qualified') is not False:
            raise ValueError('fixed source contract differs; no readiness inferred')
        if kind=='closed_frontier' and (reply.get('database_tables_complete') is not True
                or reply.get('inventory_consistent') is not True or reply.get('read_only') is not True):
            raise ValueError('complete readonly database snapshot unavailable')
        if kind=='financial_readiness' and (reply.get('network')!='signet' or reply.get('genesis')!=SIGNET_GENESIS):
            raise ValueError('actual bridge chain identity differs')
        store.event('closed_cohort_original_source',{'source_kind':kind,'response':reply,'response_sha256':_digest(reply),
            'observed_at':time.time(),'financial_pins':store.financial_context()})
        sequences[kind]=store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
        replies[kind]=reply
    ending=chain.identity();financial=replies['financial_readiness']
    stable=(ending.get('initialblockdownload') is False and financial.get('stable_tip') is True
        and (before['blocks'],before['bestblockhash'])==(ending['blocks'],ending['bestblockhash'])
        ==(financial.get('height'),financial.get('tip_hash')))
    receipt={'kind':'closed_cohort_source_collection','native_wallets':native,'bank_source':bank,'source_sequences':sequences,
        'height':ending['blocks'],'tip_hash':ending['bestblockhash'],'genesis':SIGNET_GENESIS,
        'independent_same_tip':stable,'observed_at':time.time(),'complete':False,'qualified':False,
        'gaps':['authenticate exact bank/customer membership and exhaustive wallet discovery',
            'verify original loaded configuration and same running process',
            'resolve complete database frontier to immutable economic obligations and backing',
            'independently reconcile all retained carrier versions and owning reservations',
            'enforce finite cumulative capital and fee budget through Engine admission'],
        'scope':'original actual source frames only; no monetary completeness or financial admission'}
    public_payload(receipt);store.event('closed_cohort_source_collection',receipt)
    return receipt


def verify_bootstrap_zero_assets(store, config, chain, actor, action_id, *, bootstrap_declaration):
    """Verify actual completed create provenance; never accept a supplied frame.

    The caller must authenticate ``bootstrap_declaration`` through its immutable
    bootstrap gate. This routine returns a receipt for that gate to bind; it
    never changes financial readiness, pause state, or dispatcher authority.
    """
    started = time.monotonic()
    if chain is None or config.network != 'signet' or config.expected_genesis != SIGNET_GENESIS:
        raise ValueError('independent signet source required')
    if getattr(store, 'trace', None) is None:
        raise ValueError('original driver and Core trace capture required')
    public_payload(bootstrap_declaration)
    _pins(bootstrap_declaration['pins'])
    if store.get_meta('zero_principal_identity_bootstrap') != canonical(bootstrap_declaration):
        raise ValueError('immutable bootstrap declaration required')
    declarations = store.db.execute("SELECT sequence FROM event WHERE kind='identity_bootstrap_declared'").fetchall()
    if len(declarations)!=1:raise ValueError('original bootstrap declaration required')
    _,declared=_source_event(store,declarations[0]['sequence'])
    if (declared.get('declaration') != bootstrap_declaration
            or actor not in bootstrap_declaration['actors']):
        raise ValueError('original bootstrap declaration scope differs')
    action = store.db.execute('SELECT * FROM action WHERE id=?', (action_id,)).fetchone()
    if (action is None or action['actor_id'] != actor or action['operation'] != 'create'
            or action['state'] != 'completed' or action['fee_reservation_sat'] != 0
            or action['actual_fee_sat'] != 0):
        raise ValueError('original successful zero-fee create required')
    if store.db.execute('SELECT 1 FROM action WHERE actor_id=? AND id!=?', (actor, action_id)).fetchone():
        raise ValueError('bootstrap actor has another action intent')
    sources = store.db.execute("SELECT sequence,hash,payload FROM event WHERE kind='driver_response' AND json_extract(payload,'$.action_id')=?", (action_id,)).fetchall()
    if len(sources) != 1:
        raise ValueError('unique original create response required')
    source,original = _source_event(store,sources[0]['sequence'])
    response = original['response']
    if (response != json.loads(action['result']) or response.get('action_id') != action_id
            or response.get('status') != 'ok' or response.get('actual_fee_sat') != 0):
        raise ValueError('original create response differs from completed action')
    existing=store.db.execute("SELECT sequence FROM event WHERE kind='identity_bootstrap_zero_assets_verified' AND json_extract(payload,'$.actor')=?",(actor,)).fetchall()
    if existing:
        if len(existing)!=1:raise ValueError('ambiguous repeated bootstrap source proofs')
        _,receipt=_source_event(store,existing[0]['sequence'])
        expected={'actor':actor,'action_id':action_id,'bootstrap_id':bootstrap_declaration['id'],
            'bootstrap_declaration_sha256':_digest(bootstrap_declaration),
            'financial_pins':bootstrap_declaration['pins'],'source_sequence':source['sequence'],
            'driver_response_sequence':source['sequence'],'source_event_hash':source['hash'],
            'response_sha256':_digest(response),'native_response_sha256':_digest(response),
            'complete':True,'zero_assets':True}
        if any(receipt.get(key)!=value for key,value in expected.items()):
            raise ValueError('existing bootstrap source proof context differs')
        # This is an immutable historical bootstrap proof, not a fresh funded
        # wallet inventory. Reconciliation must not append duplicate markers.
        return receipt
    data = response.get('data', {})
    native = data.get('onchain_inventory', {})
    if (native.get('schema_version') != 1 or native.get('network') != 'signet'
            or native.get('read_only') is not True or native.get('complete') is not True
            or any(native.get(key) != [] for key in ('utxos','pending_transactions','pending_parents','unavailable_parent_txids'))):
        raise ValueError('fresh complete empty native onchain graph required')
    descriptors = native.get('descriptors')
    # The pinned SDK uses Wallet::create_single(Bip84 External). Introducing
    # an invented change keychain would make this source incomplete in reality.
    if (not isinstance(descriptors, list) or len(descriptors) != 1
            or descriptors[0].get('keychain') != 'external'):
        raise ValueError('pinned single external wallet descriptor required')
    before = chain.identity()
    if before.get('chain') != 'signet' or before.get('initialblockdownload') is not False:
        raise ValueError('independent synchronized signet required')
    scans, scripts = [], set()
    for row in descriptors:
        # SDK5e load_or_create reserves fallback external0. The existing native
        # create then reveals its one funding address at external1.
        if type(row.get('last_revealed_index')) is not int or row['last_revealed_index'] != 1:
            raise ValueError('fresh wallet derivation frontier differs')
        descriptor = row.get('descriptor')
        if not isinstance(descriptor, str) or not 1 <= len(descriptor) <= 4096:
            raise ValueError('bounded native public descriptor required')
        public_payload({'descriptor': descriptor})
        info = chain.call('getdescriptorinfo', descriptor)
        if (info.get('hasprivatekeys') is not False or info.get('isrange') is not True
                or info.get('issolvable') is not True or info.get('descriptor') != descriptor):
            raise ValueError('canonical public solvable ranged descriptor required')
        addresses = chain.call('deriveaddresses', descriptor, [0,19])
        if not isinstance(addresses, list) or len(addresses) != 20 or len(set(addresses)) != 20:
            raise ValueError('complete fresh descriptor derivation required')
        for address in addresses:
            if time.monotonic() - started > MAX_SOURCE_SECONDS:
                raise ValueError('bootstrap source deadline exceeded')
            checked = chain.call('validateaddress', address)
            if checked.get('isvalid') is not True or not checked.get('scriptPubKey'):
                raise ValueError('independent descriptor script unavailable')
            if checked['scriptPubKey'] in scripts:
                raise ValueError('bootstrap descriptors overlap')
            scripts.add(checked['scriptPubKey'])
        scans.append({'desc': descriptor, 'range': [0,19]})
    if chain.call('scantxoutset','status') is not None:
        raise ValueError('independent descriptor scan already running; hold without starting or aborting')
    scan = chain.call('scantxoutset', 'start', scans, timeout=MAX_SCAN_SECONDS)
    if (scan.get('success') is not True or scan.get('height') != before['blocks']
            or scan.get('bestblock') != before['bestblockhash'] or scan.get('unspents') != []
            or scan.get('total_amount') != 0):
        raise ValueError('independent bootstrap scan is not empty at exact tip')
    def current_mempool():
        items=chain.call('getrawmempool',False)
        if (not isinstance(items,list) or len(items)>MAX_MEMPOOL_TRANSACTIONS
                or any(not isinstance(txid,str) or len(txid)!=64
                    or any(character not in '0123456789abcdef' for character in txid) for txid in items)
                or len(set(items))!=len(items)):
            raise ValueError('complete mempool exceeds bootstrap observation bound')
        return set(items)
    current=current_mempool();checked_txids=set()
    mempool_bytes=mempool_outputs=0
    for passes in range(1,MAX_MEMPOOL_PASSES+1):
        if len(checked_txids|current)>MAX_MEMPOOL_TRANSACTIONS:
            raise ValueError('complete mempool exceeds bootstrap unique transaction bound')
        for txid in sorted(current-checked_txids):
            if time.monotonic() - started > MAX_SOURCE_SECONDS:
                raise ValueError('bootstrap source deadline exceeded')
            transaction = chain.tx(txid)
            mempool_bytes+=len(canonical(normalized(transaction)).encode())
            if mempool_bytes>MAX_MEMPOOL_SCAN_BYTES:
                raise ValueError('complete mempool exceeds bootstrap aggregate byte bound')
            outputs=transaction.get('vout')
            if not isinstance(outputs,list):raise ValueError('complete mempool output inventory required')
            mempool_outputs+=len(outputs)
            if mempool_outputs>MAX_MEMPOOL_OUTPUTS:
                raise ValueError('complete mempool exceeds bootstrap aggregate output bound')
            for output in outputs:
                if (not isinstance(output,dict) or not isinstance(output.get('scriptPubKey'),dict)
                        or not isinstance(output['scriptPubKey'].get('hex'),str)):
                    raise ValueError('complete mempool output script inventory required')
                if output['scriptPubKey']['hex'] in scripts:
                    raise ValueError('bootstrap wallet has unconfirmed assets')
            checked_txids.add(txid)
        current=current_mempool()
        if current<=checked_txids:break
    else:
        raise ValueError('complete mempool did not reach bounded checked fixed point')
    ending = chain.identity()
    if (ending.get('initialblockdownload') is not False
            or (ending['blocks'], ending['bestblockhash']) != (before['blocks'], before['bestblockhash'])):
        raise ValueError('independent chain changed during bootstrap observation')
    if time.monotonic()-started>MAX_SOURCE_SECONDS:raise ValueError('bootstrap source deadline exceeded')
    receipt = {'actor': actor, 'action_id': action_id, 'bootstrap_id': bootstrap_declaration['id'],
        'complete': True, 'zero_assets': True,
        'driver_response_sequence': source['sequence'], 'native_response_sha256': _digest(response),
        'bootstrap_declaration_sha256': _digest(bootstrap_declaration),
        'financial_pins': bootstrap_declaration['pins'], 'source_sequence': source['sequence'],
        'source_event_hash': source['hash'], 'response_sha256': _digest(response),
        'native_inventory_sha256': _digest(native), 'descriptors': descriptors,
        'genesis': SIGNET_GENESIS, 'height': ending['blocks'], 'tip_hash': ending['bestblockhash'],
        'descriptor_range': [0,19], 'mempool_transactions_checked': len(checked_txids),
        'mempool_unique_transactions_checked':len(checked_txids),'mempool_current_transactions':len(current),
        'mempool_current_set_sha256':_digest(sorted(current)),'mempool_fixed_point_passes':passes,
        'mempool_pass_bound':MAX_MEMPOOL_PASSES,
        'mempool_transaction_bound':MAX_MEMPOOL_TRANSACTIONS,'mempool_bytes_checked':mempool_bytes,
        'mempool_byte_bound':MAX_MEMPOOL_SCAN_BYTES,'mempool_outputs_checked':mempool_outputs,
        'mempool_output_bound':MAX_MEMPOOL_OUTPUTS,
        'source_deadline_seconds':MAX_SOURCE_SECONDS,'descriptor_scan_timeout_seconds':MAX_SCAN_SECONDS,
        'confirmed_assets_sat': 0, 'unconfirmed_assets_sat': 0,
        'observed_at': time.time(), 'scope': 'fresh sole-writer bootstrap descriptors only; not financial readiness'}
    store.event('identity_bootstrap_zero_assets_verified', receipt)
    return receipt
