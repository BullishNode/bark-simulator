"""B initial-terminal normal profile parts. No source/flow/readiness writer.

The shared399/A776 full collector has no native-profile seam. build_collector
therefore refuses installation; these checked projections are not readiness.
Only the original three-leaf terminal Board/Arkoor cohort is supported.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import time

from . import b_native_normal_verifier as native
from . import b_normal_runtime_source as runtime_source
from .architecture import DIRECT, profile
from .final_campaign import _source_event
from .model import SIGNET_GENESIS, canonical, integer, btc_to_sat
from .ownership import EvidenceGap
from .two_step_normal import strict_json, native_wallet

RECONCILIATION = (5132, 'treasury_original_opening_reconciled',
    'b56720aa9313abe687339071d5cb25313ddfe4e096d11c4770274a93b427dd75')
INJECTION = (5133, 'treasury_external_injection_source_verified',
    'ab2e742d8d91b517df796432a412939f839d340b8972bdfbc7812c6771353cf1')
FLOW = (5134, 'treasury_flow_verified',
    '5faf67147a419aef4a11eb08e1da93f9ae89d171e9cb88760eb90f37c535f7ba')
RECEIPT = 'a0b610330c50be6f3fb685654776d85fa2a76e441a3762c22a414b9b2bc4f324'
SUCCESSOR = 'bcc3ed30c74d3c3babcee12c70bb7730bd263ccba31d5ff73a84f23b282ad456'
RECEIPT_SCRIPT = '5120f024464df2f4759c165c1675c0cc744503e95eb8f5eff681fdb53ed77f237099'
CUT_HASH = '00000014520d64b4c783aa3216123af13dba97dc348f30a928177793e594618e'
REPLACEMENT = '000000056341d08b82a3ab06f05b5afd846caa45af5f3b4ad3bc023776cbdfdb'
ORPHAN = '0000000418c626cf0411429570e2af8745b1b9567a1dc55488269d1df2ab5012'
COST_SEQUENCES = (234, 600, 2947, 4447)
FLOW_FIELDS = {'id', 'kind', 'source', 'destination', 'amount_msat'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise EvidenceGap(message)


def original_event(store, reference):
    sequence, kind, expected_hash = reference
    event, value = _source_event(store, sequence)
    require((event['kind'], event['hash']) == (kind, expected_hash),
            'B initial profile: original source identity differs')
    return event, value


def ordinary_budget_subset(raw, runtime):
    """Parse the SAME hash-bound private5a ledger; never treat u/p as ordinary.

    Native schema2 aggregate labels cannot distinguish economic authorization.
    Initial scope refuses any urgent reservation/publication before decoding its
    private signed bytes. No witness or raw ledger is returned/journaled.
    """
    require(isinstance(raw, bytes) and len(raw) <= 2*1024*1024,
            'B native budget: actual bounded original bytes required')
    budget = runtime.get('native_budget', {})
    disk = budget.get('disk_budget', {})
    file = budget.get('files', {}).get('ordinary-fee-budget', {})
    require(digest(raw) == file.get('sha256') == disk.get('budget_file_sha256')
            and file.get('bytes') == len(raw),
            'B native budget: same captured file hash/length differs')
    try:
        text = raw.decode('ascii')
    except UnicodeDecodeError as error:
        raise EvidenceGap('B native budget: noncanonical ledger encoding') from error
    require(not text or text.endswith('\n'), 'B native budget: torn ledger append')
    amounts = []
    for line in text.splitlines():
        if line.startswith(('u:', 'p:')):
            raise EvidenceGap('B initial profile: urgent publication/cost source unsupported')
        require(re.fullmatch(r'(?:0|[1-9][0-9]*)', line) is not None,
                'B native budget: unknown/noncanonical reservation')
        amount = int(line)
        require(0 < amount <= 2**64-1, 'B native budget: reservation outside nativeu64')
        amounts.append(amount)
        require(len(amounts) <= 2000 and sum(amounts) <= 2**64-1,
                'B native budget: bounded ordinary subset exceeded')
    require(disk.get('attempt_count') == len(amounts)
            and disk.get('reserved_ceiling_sum_sat') == sum(amounts),
            'B native budget: aggregate includes unproved nonordinary authorization')
    return {'ordinary_attempts': len(amounts), 'ordinary_ceiling_sum_sat': sum(amounts),
            'ordinary_entries_sha256': digest(raw)}


def ordinary_public_subset(runtime):
    """Consume reviewed schema2 runtime projection, never private package bytes.

    Called only after checked_runtime replays the admitted protected producer.
    The initial-terminal profile supports no urgent publication or new prepare.
    """
    budget = runtime.get('native_budget', {})
    ledger = budget.get('public_ledger')
    require(isinstance(ledger,dict) and set(ledger) == {'budget_file_sha256',
        'ordinary_reservations','urgent_reservations','urgent_bindings','record_count'},
        'B native budget: protected schema2 public ledger missing/unknown fields')
    disk = budget['disk_budget']; file = budget['files']['ordinary-fee-budget']
    require(ledger['budget_file_sha256'] == file['sha256'] == disk['budget_file_sha256'],
        'B native budget: public ledger/FLOCK file identity differs')
    for name in ('ordinary_reservations','urgent_reservations','urgent_bindings'):
        require(isinstance(ledger[name],list) and len(ledger[name]) <= 2000,
            'B native budget: bounded public ledger rows required')
    require(not ledger['urgent_reservations'] and not ledger['urgent_bindings'],
        'B initial profile: urgent publication/cost source unsupported')
    rows = ledger['ordinary_reservations']
    require(type(ledger['record_count']) is int and ledger['record_count'] == len(rows),
        'B native budget: public record coverage differs')
    total = 0
    for index,row in enumerate(rows,1):
        require(isinstance(row,dict) and set(row) == {'line','ceiling_sat'}
            and type(row['line']) is int and row['line'] == index
            and type(row['ceiling_sat']) is int and 0 < row['ceiling_sat'] <= 2**64-1,
            'B native budget: ordinary line identity/ceiling differs')
        total += row['ceiling_sat']
        require(total <= 2**64-1,'B native budget: ordinary authorization overflow')
    require(type(disk['attempt_count']) is int and disk['attempt_count'] == len(rows)
        and type(disk['reserved_ceiling_sum_sat']) is int and disk['reserved_ceiling_sum_sat'] == total,
        'B native budget: aggregate is not exact ordinary subset')
    return {'ordinary_attempts':len(rows),'ordinary_ceiling_sum_sat':total,
            'ordinary_entries_sha256':ledger['budget_file_sha256']}


@dataclass(frozen=True)
class RuntimeBuffers:
    expected: bytes
    checkpoint: bytes
    observation: bytes
    protected_receipt: bytes


def checked_runtime(buffers, admission):
    """Recompute the fixed actual producer against admitted raw declarations.

    Raw declaration bytes are mandatory: parsed JSON plus a caller-provided hash
    cannot establish the original protected file's whitespace/content identity.
    """
    require(isinstance(buffers, RuntimeBuffers), 'B runtime: typed raw originals required')
    for value in (buffers.expected, buffers.checkpoint, buffers.observation, buffers.protected_receipt):
        require(isinstance(value, bytes) and len(value) <= 4*1024*1024,
                'B runtime: bounded raw original unavailable')
    producer_hash = digest(Path(runtime_source.__file__).read_bytes())
    require(producer_hash == admission['runtime_producer_sha256']
            and digest(buffers.expected) == admission['runtime_expected_source_sha256']
            and digest(buffers.checkpoint) == admission['runtime_checkpoint_source_sha256'],
            'B runtime: installed producer/protected original identity differs')
    expected, checkpoint, observation, receipt = map(strict_json,
        (buffers.expected, buffers.checkpoint, buffers.observation, buffers.protected_receipt))
    result = runtime_source.verify(expected, checkpoint, observation)
    require(receipt == {**result,
        'operator_expected_source_sha256': admission['runtime_expected_source_sha256'],
        'operator_checkpoint_source_sha256': admission['runtime_checkpoint_source_sha256'],
        'producer_source_sha256': producer_hash},
        'B runtime: protected producer result differs from independent replay')
    # The receipt is computed here. Disk reader candidate flags remain false and
    # retained fee/whole-input reserve checks remain separate native predicates.
    return result


def historical_money(store, chain, old_boundary, new_boundary, scripts, groups, *, historical_costs=None):
    """Authenticate actual5132/5133/5134, without rebooking or changing a pin."""
    require(profile(store) == DIRECT, 'B initial profile requires direct_xpub')
    revent, reconstruction = original_event(store, RECONCILIATION)
    sevent, source = original_event(store, INJECTION)
    fevent, flow = original_event(store, FLOW)
    actual_flows = [row[0] for row in store.db.execute(
        "SELECT sequence FROM event WHERE kind='treasury_flow_verified' ORDER BY sequence")]
    require(actual_flows == [fevent['sequence']], 'B initial profile: unexpected/duplicate treasury flow')
    require(set(flow) == FLOW_FIELDS and flow == {'id':'injection:'+RECEIPT+':0',
        'kind':'injection', 'source':'outside-b-neutral-funding', 'destination':'bank',
        'amount_msat':10000000000}, 'B initial profile: strict original five-field flow differs')
    require(reconstruction['financial_pins'] == source['financial_pins'] == old_boundary['pins']
        and source['original_boundary_id'] == old_boundary['id']
        and source['original_boundary_sha256'] == digest(canonical(old_boundary).encode())
        and reconstruction['id'] == source['opening_reconciliation_id']
        and source['opening_reconciliation_sequence'] == revent['sequence']
        and source['opening_reconciliation_event_hash'] == revent['hash']
        and source['opening_reconciliation_sha256'] == digest(canonical(reconstruction).encode())
        and source['flow_id'] == flow['id'] and source['amount_msat'] == flow['amount_msat']
        and source['outpoint'] == RECEIPT+':0' and source['script'] == RECEIPT_SCRIPT,
        'B initial profile: source/reconciliation/original boundary link differs')
    require(reconstruction['canonical_cut'] == {'height':326473, 'hash':CUT_HASH}
        and reconstruction['original_orphan'] == {'height':326474, 'hash':ORPHAN}
        and chain.call('getblockhash',326473) == CUT_HASH
        and chain.call('getblockhash',326474) == REPLACEMENT,
        'B initial profile: explicit new canonical cut no longer holds')
    require(reconstruction['script_count'] == 611
        and len(reconstruction['original_roots']) == 12
        and all(not b['owned_created'] and not b['owned_consumed']
                for b in reconstruction['block_effects']['blocks']),
        'B initial profile: admitted original footprint reconstruction differs')
    before = chain.identity()
    require(before.get('chain') == 'signet' and before.get('initialblockdownload') is False
        and chain.call('getblockhash', 0) == SIGNET_GENESIS,
        'B initial profile: canonical signet identity unavailable')
    receipt = chain.transaction(RECEIPT); successor = chain.transaction(SUCCESSOR)
    require(receipt['confirmations'] >= 1 and successor['confirmations'] >= 1,
        'B initial profile: original receipt/successor unconfirmed')
    immutable = lambda tx: {key:tx[key] for key in ('txid','inputs','outputs','fee_sat','blockhash')}
    require(immutable(receipt) == source['receipt_transaction']
        and immutable(successor) == source['spent_successor']
        and successor['inputs'] == [{'outpoint':RECEIPT+':0', 'amount_sat':10000000, 'script':RECEIPT_SCRIPT}]
        and source['successor_cost_sequence'] == 4447,
        'B initial profile: canonical physical receipt/successor differs')
    for tx, height in ((receipt, source['receipt_height']), (successor, source['successor_height'])):
        require(type(height) is int and before['blocks']-tx['confirmations']+1 == height
            and chain.call('getblockhash', height) == tx['blockhash'],
            'B initial profile: receipt/successor canonical height differs')
    owner = scripts.get(RECEIPT_SCRIPT)
    require(owner is not None and owner['member_id'] == 'bank'
        and not any(i['script'] in scripts for i in receipt['inputs']),
        'B initial profile: original bank/outside source ownership differs')
    old_bank = [m for m in old_boundary['members'] if m['id'] == 'bank']
    new_bank = [m for m in new_boundary['members'] if m['id'] == 'bank']
    identity_fields = ('id', 'kind', 'role', 'identity', 'descriptors')
    require(len(old_bank) == len(new_bank) == 1 and old_bank[0]['kind'] == 'wallet'
        and all(old_bank[0][key] == new_bank[0][key] for key in identity_fields),
        'B initial profile: original bank identity/descriptors changed')
    costs = native.original_costs(store, chain) if historical_costs is None else historical_costs
    require(tuple(r['sequence'] for r in costs) == COST_SEQUENCES,
        'B initial profile: new/urgent/or missing original cost domain')
    require(all(r['budget'] == 'ordinary' for r in costs),
        'B initial profile: urgent cost domain unsupported')
    payers = native.physical_cost_payers(costs, chain, scripts, groups)
    after = chain.identity()
    require((before['blocks'],before['bestblockhash']) == (after['blocks'],after['bestblockhash'])
        and after.get('initialblockdownload') is False,
        'B initial profile: canonical tip changed during historical join')
    return {'flows':[dict(flow)], 'flow_sequences':[fevent['sequence']],
        'costs':costs, 'cost_payers':payers,
        'source_sequences':[revent['sequence'],sevent['sequence'],fevent['sequence']],
        'scope':'Original received10M once; CLN preexisting capital is not a flow.'}


def preexisting_cln(raw, expected_sha256, members, chain, *, tip, opening_cut, original_scripts):
    """Current two-owned-peer source, with canonical pre-cut physical creation.

    This returns newly observed source facts, never a historical source event or
    an injection. Common member admission and full-boundary/old action history
    still must be authenticated by the collector; this projection is not enough
    to activate readiness on its own.
    """
    from .two_step_capture import cln_projection
    from .financial_components import inspect as inspect_components
    require(isinstance(raw, bytes) and len(raw) <= 128*1024 and digest(raw) == expected_sha256,
            'B CLN: bounded original source/hash required')
    frame = strict_json(raw)
    height, tip_hash = tip
    require(frame['kind'] == 'b_owned_cln_original_projection' and frame['network'] == 'signet'
        and frame['genesis'] == SIGNET_GENESIS
        and (frame['height'],frame['tip_hash']) == tip,
        'B CLN: original fixed source identity/tip differs')
    require(0 <= time.time()-frame['completed_at'] <= 90
        and frame['observed_at'] <= frame['completed_at'], 'B CLN: original source stale')
    peers = {m['identity']:m for m in members if m['kind'] == 'lightning_peer'}
    nodes_by_identity = {v['getinfo']['id']:v for v in frame['nodes'].values()}
    require(len(peers) == len(frame['nodes']) == len(nodes_by_identity) == 2
        and set(nodes_by_identity) == set(peers),
        'B CLN: both distinct declared owned peers required')
    nodes = []
    for identity, member in peers.items():
        native_frame, _, _ = cln_projection(member, nodes_by_identity[identity], height=height)
        nodes.append({'id':member['id'],'source_sha256':digest(canonical(native_frame).encode()),**native_frame})
    facts = inspect_components([], nodes, [], chain, height=height,tip_hash=tip_hash,
        gaps=['Projection only: authenticated capture/member/old-lifecycle closure required'])
    physical = {point:{'amount_sat':v['amount_sat'],'script':v['script']}
                for point,v in facts['wallet_outputs'].items()}
    for point, sides in facts['channels'].items():
        txid,index = point.rsplit(':',1)
        coin = chain.call('gettxout',txid,int(index),False)
        physical[point] = {'amount_sat':btc_to_sat(coin['value']), 'script':coin['scriptPubKey']['hex']}
    creations = []
    for point, output in physical.items():
        require(output['script'] not in original_scripts,
                'B CLN: physical asset overlaps original descriptor boundary')
        txid,index = point.rsplit(':',1); tx = chain.tx(txid)
        creation = height-integer(tx.get('confirmations',0),'CLN creation confirmations',1)+1
        require(tx['txid'] == txid and 1 <= creation <= opening_cut
            and chain.call('getblockhash',creation) == tx['blockhash'],
            'B CLN: physical asset not canonical before explicit opening cut')
        matches = [v for v in tx['vout'] if v['n'] == int(index)]
        require(len(matches) == 1 and btc_to_sat(matches[0]['value']) == output['amount_sat']
            and matches[0]['scriptPubKey']['hex'] == output['script'],
            'B CLN: original physical output differs')
        for include_mempool in (False,True):
            coin = chain.call('gettxout',txid,int(index),include_mempool)
            require(coin is not None and coin.get('confirmations',0) >= 1
                and btc_to_sat(coin['value']) == output['amount_sat']
                and coin['scriptPubKey']['hex'] == output['script'],
                'B CLN: original physical output spent/pending/changed')
        creations.append({'outpoint':point,**output,'creation_height':creation,
                          'creation_blockhash':tx['blockhash']})
    end = chain.identity()
    require((end['blocks'],end['bestblockhash']) == tip and end['initialblockdownload'] is False,
            'B CLN: canonical tip changed during preexisting join')
    return {'raw_source_sha256':expected_sha256,'physical':physical,'creations':creations,
        'current_component':facts,'preexisting_physical_sat':sum(v['amount_sat'] for v in physical.values()),
        'scope':'New observation of pre-cut physical assets; not a historical CLN opening or flow.'}


@dataclass(frozen=True)
class InitialTerminalProfile:
    journey_sequence: int = 874

    def native_projection(self, store, chain, raw, expected_sha256, *, scripts, tip,
                          minimum_confirmations, boundary):
        result = native.captured_direct_source(store, chain, raw, expected_sha256,
            journey_sequence=self.journey_sequence, scripts=scripts, tip=tip,
            minimum_confirmations=minimum_confirmations, boundary=boundary)
        require(not result['pending_liabilities'],
                'B initial profile: original customer liability remains unsettled')
        return result

    def fee_projection(self, runtime, *, costs, groups,
                       accounting_receipt_sha256, watchman_raw, physical, selected_points,
                       chain, server_pubkey):
        subset = ordinary_public_subset(runtime)
        # This initial transition supports the adopted old terminal carrier only.
        # New preparations/failed attempts require continuing-campaign evidence.
        require(subset['ordinary_attempts'] == 0,
                'B initial profile: post-opening native prepare domain unsupported')
        budget = native.require_native_budget_join(runtime, server_pubkey=server_pubkey,
            costs=costs, groups=groups, accounting_receipt_sha256=accounting_receipt_sha256,
            opening_cost_sequences=COST_SEQUENCES)
        watchman = native_wallet(watchman_raw, 'watchman')
        urgent = native.urgent_reserve(watchman, physical, selected_points, chain,
            minimum_sat=budget['urgent_reserve_sat'])
        return {'ordinary_subset':subset, 'native_budget':budget,
                'confirmed_whole_input_urgent_reserve':urgent}


def build_collector(*args, **kwargs):
    """Refuse before readers/Store writes: shared399/A776 is explicitly A-only.

    The common owner must add an explicit typed native projection/reducer seam,
    retain raw_runtime+raw_watchman_inventory+raw budget originals, and keep the
    common nonce/deadline/admission/publication kernel. No architecture remap,
    monkeypatch of shared globals, copied collector or fallback is installed.
    """
    raise EvidenceGap('B full collector seam absent: SourceCapture decode/backing/liabilities; '
        'Collector._produce A-only guard/reducer; raw runtime/watchman/budget return contract')
