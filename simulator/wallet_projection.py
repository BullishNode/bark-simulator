"""Check one owning native wallet frame against Core, without dispatch authority.

This is a supplied-frame projection, not exhaustive wallet discovery, signer
possession, economic availability, or a complete treasury producer. Public
transaction bodies retain txids; stripped bodies alone do not prove signatures.
"""
from __future__ import annotations

import hashlib
import re
import time

from .bundle_audit import decode_transaction
from .final_campaign import _pins
from .model import SIGNET_GENESIS, InvariantError, btc_to_sat, canonical, integer, public_payload, timestamp
from .ownership import EvidenceGap
from .trace import normalized

MAX_ROWS = 2000
MAX_BYTES = 2 * 1024 * 1024
MAX_DERIVATIONS = 2000
MAX_RPC_CALLS = 256
MAX_CORE_BYTES = 16 * 1024 * 1024
MAX_SECONDS = 25
OWNERS = {'rounds': 'rounds_wallet', 'watchman': 'watchman_wallet'}


def _hash(value):
    return hashlib.sha256(canonical(normalized(value)).encode()).hexdigest()


def _hex(value, length, label):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{'+str(length)+'}', value) is None:
        raise ValueError('invalid '+label)
    return value


def _point(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}:(0|[1-9][0-9]{0,9})', value) is None:
        raise ValueError('invalid public outpoint')
    txid, index = value.split(':')
    if int(index) >= 2**32: raise ValueError('outpoint index exceeds uint32')
    return txid, int(index)


def _rows(value, label):
    if not isinstance(value, list) or len(value) > MAX_ROWS:
        raise EvidenceGap('bounded '+label+' source required')
    return value


def _require(value, fields, label):
    if not isinstance(value, dict) or not set(fields) <= value.keys():
        raise EvidenceGap('missing '+label+' fields')


def _fresh(value, now):
    start = timestamp(value['observed_at'], 'source start')
    end = timestamp(value['completed_at'], 'source completion')
    if not start <= end <= now or now-start > 90:
        raise EvidenceGap('owning source is stale or has invalid capture times')


class _Core:
    def __init__(self, chain, started):
        self.chain, self.started = chain, started
        self.observations, self.transactions = [], {}
        self.response_bytes = 0

    def call(self, method, *args):
        # ChainReader has a 12s per-call timeout. Do not begin a call with less
        # than that left in the whole observation budget. No network retry.
        if len(self.observations) >= MAX_RPC_CALLS or time.monotonic()-self.started > MAX_SECONDS-12:
            raise EvidenceGap('wallet projection Core call/time budget exhausted')
        try: result = self.chain.call(method, *args)
        except Exception as error:
            self.observations.append({'method': method, 'params': list(args), 'error': type(error).__name__})
            raise
        encoded = canonical(normalized(result)).encode()
        self.response_bytes += len(encoded)
        self.observations.append({'method': method, 'params': list(args),
            'result_sha256': hashlib.sha256(encoded).hexdigest(), 'result_bytes': len(encoded)})
        if self.response_bytes > MAX_CORE_BYTES:
            raise EvidenceGap('wallet projection Core byte budget exhausted')
        return result

    def identity(self):
        if self.call('getblockhash', 0) != SIGNET_GENESIS:
            raise ValueError('independent Core genesis differs')
        value = self.call('getblockchaininfo')
        _hex(value['bestblockhash'], 64, 'Core tip')
        integer(value['blocks'], 'Core height')
        if value.get('chain') != 'signet' or value.get('initialblockdownload') is not False:
            raise EvidenceGap('independent signet Core is not synchronized')
        return value

    def tx(self, txid, *, optional=False):
        if txid in self.transactions: return self.transactions[txid]
        try: value = self.call('getrawtransaction', txid, True)
        except EvidenceGap: raise
        except (ValueError, OSError):
            if optional:
                self.transactions[txid] = None
                return None
            raise EvidenceGap('independent raw transaction unavailable: '+txid) from None
        if not isinstance(value['hex'], str) or len(value['hex']) > MAX_BYTES*2:
            raise EvidenceGap('independent raw transaction exceeds slice bound')
        decoded = decode_transaction(value['hex'], public_body=True)
        confirmations = value.get('confirmations', 0)
        if type(confirmations) is not int or confirmations < 0:
            raise EvidenceGap('conflicted or unknown Core transaction position')
        if decoded['txid'] != txid or value.get('txid') != txid:
            raise InvariantError('independent raw transaction identity differs')
        if value.get('weight', decoded['weight']) != decoded['weight']:
            raise InvariantError('Core reported weight differs from actual raw bytes')
        for output, reported in zip(decoded['outputs'], value['vout']):
            if (reported['n'] != output['vout'] or btc_to_sat(reported['value']) != output['amount_sat']
                    or reported['scriptPubKey']['hex'] != output['script']):
                raise InvariantError('Core decoded output differs from raw bytes')
        if len(value['vout']) != len(decoded['outputs']):
            raise InvariantError('Core raw output count differs')
        result = {'decoded': decoded, 'reported': value}
        self.transactions[txid] = result
        return result


def _transactions(rows):
    result = {}
    for row in _rows(rows, 'native transaction'):
        _require(row, ('txid', 'transaction_body', 'signed_weight_wu', 'encoding'), 'native transaction')
        txid = _hex(row['txid'], 64, 'native transaction id')
        if txid in result: raise InvariantError('duplicate native transaction')
        if row.get('encoding') != 'bitcoin-stripped-body-v1':
            raise EvidenceGap('native public transaction body encoding unsupported')
        body = row['transaction_body']
        if not isinstance(body, str) or len(body) > MAX_BYTES*2:
            raise EvidenceGap('native transaction body exceeds bound')
        decoded = decode_transaction(body, public_body=True)
        if decoded['txid'] != txid or decoded['witness_redacted'] or decoded['stripped_hex'] != body:
            raise InvariantError('native stripped body does not bind its txid')
        if any(decoded['input_script_sig_sizes']):
            raise EvidenceGap('native public body has nonempty scriptSig')
        weight = integer(row['signed_weight_wu'], 'native signed weight', 1)
        if not decoded['weight'] <= weight <= 4_000_000:
            raise InvariantError('native signed weight is impossible')
        points = [row['outpoint'] for row in decoded['inputs']]
        if len(set(points)) != len(points): raise InvariantError('native transaction repeats an input')
        result[txid] = {'row': row, 'decoded': decoded}
    return result


def _eligibility(row, locks, height):
    _require(row, ('value_sat', 'coinbase', 'mature', 'trusted', 'reserved', 'transaction_eligible',
        'confirmed_fee_eligible', 'confirmed_height_upper_bound', 'confirmations'), 'native eligibility')
    integer(row['value_sat'], 'native UTXO value')
    for key in ('coinbase', 'mature', 'trusted', 'reserved', 'transaction_eligible', 'confirmed_fee_eligible'):
        if type(row[key]) is not bool: raise ValueError('native eligibility flag must be boolean')
    if row['reserved'] != (row['outpoint'] in locks): raise InvariantError('native row and reservation set differ')
    position = row['confirmed_height_upper_bound']
    confs = integer(row['confirmations'], 'native confirmations')
    if position is None:
        if confs != 0 or any(row.get(key) is not None for key in ('confirmation_block_hash', 'confirmation_time', 'confirming_descendant_txid')):
            raise InvariantError('unconfirmed native position has confirmed facts')
    elif integer(position, 'native confirmation height') > height or confs != height-position+1:
        raise InvariantError('native confirmed position differs from its tip')
    else:
        _hex(row['confirmation_block_hash'], 64, 'native confirmation block')
        integer(row['confirmation_time'], 'native confirmation time')
        if row.get('confirming_descendant_txid') is not None:
            _hex(row['confirming_descendant_txid'], 64, 'confirming descendant')
        if row.get('unconfirmed_first_seen') is not None or row.get('unconfirmed_last_seen') is not None:
            raise InvariantError('confirmed native position retains unconfirmed timestamps')
    mature = not row['coinbase'] or confs >= 100
    eligible = row['trusted'] and mature and not row['reserved']
    if row['mature'] != mature or row['transaction_eligible'] != eligible or row['confirmed_fee_eligible'] != (eligible and position is not None):
        raise InvariantError('native eligibility flags are internally inconsistent')
    return position, confs


def reduce_wallet_projection(member, facts, chain, financial_pins, *, owner, now=None):
    """Return replayable supplied-frame evidence; never emit a readiness event.

    The caller must preserve the original bridge/trace frame before using this
    result. Pins bind capture context; they do not prove a loaded runtime or a
    private signer owns a descriptor. No wallet or producer complete flag grants
    exhaustive asset coverage. Missing parents/ownership remain explicit gaps.
    """
    started = time.monotonic()
    now = time.time() if now is None else timestamp(now, 'observation time')
    _pins(financial_pins)
    public_payload(facts); public_payload(member)
    _require(facts, ('schema_version', 'kind', 'network', 'genesis', 'architecture_profile', 'financial_pins',
        'source_identity', 'observed_at', 'completed_at', 'sources', 'height', 'tip_hash', 'source_gaps'), 'financial fact envelope')
    _require(member, ('id', 'identity', 'kind', 'descriptors'), 'wallet member')
    if (owner not in OWNERS or member.get('kind') != 'wallet'
            or any(not isinstance(member.get(key), str) or not 1 <= len(member[key]) <= 128 for key in ('id', 'identity'))):
        raise ValueError('explicit owning wallet member required')
    if (facts.get('schema_version'), facts.get('kind'), facts.get('network'), facts.get('genesis')) != (1, 'financial_facts', 'signet', SIGNET_GENESIS):
        raise ValueError('versioned owned signet financial facts required')
    from .architecture import PROFILES
    if facts.get('architecture_profile') not in PROFILES or facts.get('financial_pins') != financial_pins:
        raise ValueError('financial fact profile/pin context differs')
    identity = facts['source_identity']
    _require(identity, ('product_commit', 'schema_sha256', 'bridge_sha256', 'daemon_binary_hashes'), 'source identity')
    if identity.get('product_commit') != financial_pins['product_commit'] or identity.get('schema_sha256') != financial_pins['schema_sha256']:
        raise ValueError('native product/schema binding differs')
    _hex(identity['bridge_sha256'], 64, 'bridge hash')
    if not isinstance(identity['daemon_binary_hashes'], dict): raise EvidenceGap('daemon hash map missing')
    for value in identity['daemon_binary_hashes'].values(): _hex(value, 64, 'daemon binary hash')
    if set(identity['daemon_binary_hashes']) != {'captaind', 'watchmand'}:
        raise EvidenceGap('both daemon binary source bindings required')
    _fresh(facts, now)
    _require(facts['sources'], (OWNERS[owner],), 'owning source')
    frame = facts['sources'][OWNERS[owner]]
    _require(frame, ('owner', 'observed_at', 'completed_at', 'source'), 'owning capture')
    if frame.get('owner') != owner: raise ValueError('owning frame alias differs')
    _fresh(frame, now)
    if not facts['observed_at'] <= frame['observed_at'] <= frame['completed_at'] <= facts['completed_at']:
        raise EvidenceGap('native frame times are outside the original envelope')
    response = frame['source']
    _require(response, (owner,), 'owning native response')
    native = response[owner]
    other = 'watchman' if owner == 'rounds' else 'rounds'
    if response.get(other) is not None or not isinstance(native, dict):
        raise ValueError('frame must contain only the owning daemon wallet')
    _require(native, ('wallet', 'network', 'public_descriptor', 'tip_height', 'tip_hash', 'min_trusted_confirmations',
        'utxos', 'reserved_outpoints', 'last_revealed_index', 'pending_transaction_scope',
        'pending_transactions', 'pending_parents', 'unavailable_parent_txids'), 'native wallet')
    if len(canonical(response).encode()) > MAX_BYTES:
        raise EvidenceGap('owning wallet JSON exceeds byte bound')
    if native.get('wallet') != owner or native.get('network') != 'signet':
        raise ValueError('native owning wallet/network differs')
    if native.get('pending_transaction_scope') != 'canonical_wallet_graph_only':
        raise EvidenceGap('canonical pending transaction scope required')
    if member.get('descriptors') != [native['public_descriptor']]:
        raise ValueError('declared descriptor differs from owning frame')
    rows = _rows(native['utxos'], 'native UTXO')
    locks = _rows(native['reserved_outpoints'], 'native reservation')
    for point in locks: _point(point)
    if len(set(locks)) != len(locks): raise InvariantError('duplicate native reservation')
    locks = set(locks)
    pending = _transactions(native['pending_transactions'])
    parents = _transactions(native['pending_parents'])
    parent_ids = {_point(row['outpoint'])[0] for tx in pending.values() for row in tx['decoded']['inputs']}
    if parents.keys()-parent_ids: raise InvariantError('native parent is not used by any supplied pending body')
    for txid in pending.keys() & parents.keys():
        if pending[txid]['row'] != parents[txid]['row']:
            raise InvariantError('pending and parent bodies conflict')
    unavailable = _rows(native['unavailable_parent_txids'], 'missing parent')
    for txid in unavailable: _hex(txid, 64, 'missing parent id')
    if len(set(unavailable)) != len(unavailable): raise InvariantError('duplicate missing parent id')
    if set(unavailable)-parent_ids: raise InvariantError('unavailable parent is not used by a pending body')
    if set(unavailable) & parents.keys(): raise InvariantError('parent is both present and unavailable')
    if sum(len(value) for value in (rows, locks, pending, parents, unavailable)) > MAX_ROWS:
        raise EvidenceGap('native wallet aggregate row budget exceeded')
    core = _Core(chain, started)
    tip = core.identity(); height = tip['blocks']; blockhash = tip['bestblockhash']
    if (native['tip_height'], native['tip_hash']) != (height, blockhash) or (facts['height'], facts['tip_hash']) != (height, blockhash):
        raise EvidenceGap('native/source/independent Core tips differ')
    descriptor = native['public_descriptor']
    details = core.call('getdescriptorinfo', descriptor)
    if details.get('hasprivatekeys') is not False or details.get('descriptor') != descriptor or details.get('isrange') is not True:
        raise ValueError('canonical ranged public descriptor required')
    minimum = integer(native['min_trusted_confirmations'], 'native trust depth')
    high = native['last_revealed_index']
    if high is not None: integer(high, 'native last revealed index')
    for row in rows:
        _require(row, ('outpoint', 'derivation_index', 'keychain', 'script_pubkey'), 'native UTXO')
        child = integer(row['derivation_index'], 'native derivation child')
        high = child if high is None else max(high, child)
    if high is not None and high >= MAX_DERIVATIONS:
        raise EvidenceGap('descriptor range exceeds this bounded reducer slice')
    addresses = [] if high is None else core.call('deriveaddresses', descriptor, [0, high])
    if len(addresses) != (0 if high is None else high+1) or len(set(addresses)) != len(addresses):
        raise InvariantError('independent descriptor derivation range differs')
    by_address = {address: index for index, address in enumerate(addresses)}
    scripts = {}; gaps = set(); confirmed = {}; candidates = {}; observed = set(); pending_inputs = {}

    def script_at(child):
        if child not in scripts:
            data = core.call('validateaddress', addresses[child])
            if data.get('isvalid') is not True: raise InvariantError('derived descriptor address invalid')
            script = data['scriptPubKey']
            if not isinstance(script, str) or re.fullmatch('(?:[0-9a-f]{2}){1,10000}', script) is None:
                raise InvariantError('derived public script invalid')
            scripts[child] = script
        return scripts[child]

    def output_at(tx, index):
        if index >= len(tx['decoded']['outputs']): raise InvariantError('outpoint exceeds actual raw transaction')
        return tx['decoded']['outputs'][index]

    def confirmed_coin(point, output, child, origin):
        txid, index = _point(point)
        coin = core.call('gettxout', txid, index, False)
        if coin is None: return None
        confs = integer(coin['confirmations'], 'Core confirmations', 1)
        if coin.get('bestblock') != blockhash or confs > height+1:
            raise EvidenceGap('Core UTXO position is not at observed tip')
        if btc_to_sat(coin['value']) != output['amount_sat'] or coin['scriptPubKey']['hex'] != output['script']:
            raise InvariantError('confirmed UTXO differs from exact raw prevout')
        coinbase = core.transactions[txid]['decoded']['inputs'] == [{'outpoint': '0'*64+':4294967295'}]
        if type(coin.get('coinbase')) is not bool or coin['coinbase'] != coinbase:
            raise InvariantError('Core UTXO coinbase flag differs from raw transaction')
        if script_at(child) != output['script']: raise InvariantError('prevout does not derive from declared wallet')
        asset = {'outpoint': point, 'amount_sat': output['amount_sat'], 'script': output['script'],
                 'descriptor_index': 0, 'child_index': child, 'confirmations': confs, 'origins': [origin]}
        if point in confirmed:
            prior = confirmed[point]
            if any(prior[key] != asset[key] for key in ('amount_sat', 'script', 'child_index', 'confirmations')):
                raise InvariantError('same confirmed asset has conflicting facts')
            prior['origins'] = sorted(set(prior['origins']+[origin]))
        else: confirmed[point] = asset
        return coin

    for txid, tx in pending.items():
        actual = core.tx(txid, optional=True)
        if actual:
            if actual['decoded']['stripped_hex'] != tx['row']['transaction_body'] or actual['decoded']['weight'] != tx['row']['signed_weight_wu']:
                raise InvariantError('native pending body/weight differs from actual Core bytes')
            if actual['reported'].get('confirmations', 0) > 0: gaps.add('native_pending_already_confirmed:'+txid)
        for entry in tx['decoded']['inputs']:
            point = entry['outpoint']; parent_id, index = _point(point)
            pending_inputs.setdefault(point, []).append(txid)
            actual_parent = core.tx(parent_id, optional=True)
            parent = parents.get(parent_id) or pending.get(parent_id)
            if parent is None and actual_parent is None:
                gaps.add('pending_parent_unavailable:'+parent_id); continue
            if parent and actual_parent and parent['decoded']['stripped_hex'] != actual_parent['decoded']['stripped_hex']:
                raise InvariantError('native parent body differs from Core raw bytes')
            if parent and actual_parent and parent['row']['signed_weight_wu'] != actual_parent['decoded']['weight']:
                raise InvariantError('native parent weight differs from Core raw bytes')
            if actual_parent is None:
                gaps.add('independent_parent_raw_unavailable:'+parent_id); continue
            output = output_at(actual_parent, index)
            reported = actual_parent['reported']['vout'][index]['scriptPubKey']
            address = reported.get('address')
            child = by_address.get(address)
            if child is None:
                gaps.add('pending_prevout_not_attributed_in_descriptor_window:'+point); continue
            coin = confirmed_coin(point, output, child, 'pending_input:'+txid)
            if coin is None and actual_parent['reported'].get('confirmations', 0) > 0:
                gaps.add('confirmed_pending_prevout_consumed:'+point)

    for row in rows:
        point = row['outpoint']; txid, index = _point(point)
        if point in observed: raise InvariantError('duplicate native UTXO')
        observed.add(point)
        child = row['derivation_index']
        position, confs = _eligibility(row, locks, height)
        if position is None and txid not in pending:
            gaps.add('native_unconfirmed_utxo_without_pending_body:'+point)
        if row.get('keychain') != 'external': raise EvidenceGap('native internal keychain needs its own declared descriptor')
        if script_at(child) != row['script_pubkey']: raise InvariantError('native UTXO derivation differs')
        actual = core.tx(txid, optional=True)
        if actual is None:
            if txid in pending:
                output = output_at(pending[txid], index)
                if output['script'] != row['script_pubkey'] or output['amount_sat'] != row['value_sat']:
                    raise InvariantError('native pending output differs from its transaction body')
                continue
            gaps.add('native_utxo_raw_unavailable:'+point); continue
        output = output_at(actual, index)
        if output['script'] != row['script_pubkey'] or output['amount_sat'] != row['value_sat']:
            raise InvariantError('native UTXO differs from Core raw prevout')
        coin = confirmed_coin(point, output, child, 'native_utxo')
        if coin is None:
            if position is not None: gaps.add('native_confirmed_utxo_missing_at_tip:'+point)
            continue
        if position is None:
            gaps.add('native_unconfirmed_utxo_already_confirmed:'+point); continue
        if core.call('getblockhash', position) != row['confirmation_block_hash'] or coin['confirmations'] < confs:
            raise InvariantError('native confirmation bound differs from independent chain')
        coinbase = actual['decoded']['inputs'] == [{'outpoint': '0'*64+':4294967295'}]
        if row['coinbase'] != coinbase or (row['trusted'] and confs < minimum):
            raise InvariantError('native coinbase/trust differs from confirmed source')
        mempool_coin = core.call('gettxout', txid, index, True)
        if mempool_coin is not None:
            if (mempool_coin.get('bestblock') != blockhash or btc_to_sat(mempool_coin['value']) != output['amount_sat']
                    or mempool_coin['scriptPubKey']['hex'] != output['script']
                    or mempool_coin.get('confirmations') != coin['confirmations'] or mempool_coin.get('coinbase') != coin['coinbase']):
                raise InvariantError('mempool-aware UTXO differs from exact prevout')
        elif point not in pending_inputs:
            gaps.add('mempool_spend_not_in_supplied_pending_graph:'+point)
        if row['confirmed_fee_eligible'] and mempool_coin is not None and point not in pending_inputs:
            candidates[point] = confirmed[point]
    for point, spenders in pending_inputs.items():
        if len(spenders) > 1: gaps.add('conflicting_pending_spends:'+point)
        candidates.pop(point, None)
    for point in confirmed:
        txid, _ = _point(point)
        if txid in pending and any(row['outpoint'] in confirmed for row in pending[txid]['decoded']['inputs']):
            raise InvariantError('pending change and its confirmed input cannot both be tip assets')
    for point in locks-observed-pending_inputs.keys(): gaps.add('reserved_outpoint_not_in_supplied_graph:'+point)
    for parent_id in unavailable:
        if core.transactions.get(parent_id) is None: gaps.add('native_parent_unresolved:'+parent_id)
    end = core.identity()
    if (end['blocks'], end['bestblockhash']) != (height, blockhash):
        raise EvidenceGap('independent Core tip changed during wallet projection')
    result = {'schema_version': 1, 'kind': 'wallet_projection_evidence', 'owner': owner,
        'member_id': member['id'], 'declared_identity': member['identity'], 'financial_pins': financial_pins,
        'architecture_profile': facts['architecture_profile'], 'genesis': SIGNET_GENESIS, 'network': 'signet',
        'height': height, 'tip_hash': blockhash, 'observed_at': min(facts['observed_at'], frame['observed_at']),
        'completed_at': now+time.monotonic()-core.started,
        'source_envelope_sha256': _hash(facts), 'native_frame_sha256': _hash(response), 'source_identity': identity,
        'public_descriptor': descriptor, 'descriptor_sha256': _hash(descriptor), 'derivation_window': [0, high],
        'confirmed_tip_utxos': sorted(confirmed.values(), key=lambda row: row['outpoint']),
        'known_confirmed_tip_sat': sum(row['amount_sat'] for row in confirmed.values()),
        'native_fee_candidates': sorted(candidates), 'native_reserved_outpoints': sorted(locks),
        'pending_spenders': {key: sorted(value) for key, value in sorted(pending_inputs.items())},
        'projection_complete': not gaps, 'projection_gaps': sorted(gaps),
        'source_gaps': facts.get('source_gaps', []), 'core_observations': core.observations,
        'core_budget_used': {'rpc_calls': len(core.observations), 'response_bytes': core.response_bytes},
        'coverage': {'supplied_frame_only': True, 'exhaustive_wallet_discovery': False,
            'native_source_qualified': False, 'economic_unreserved_funding': False,
            'other_treasury_members_verified': False, 'operating_readiness': False},
        'remaining_requirements': ['independent exhaustive descriptor/UTXO coverage and signer source qualification',
            'durable nursery/round/history reconciliation', 'stopped-wallet preclosure public descriptors',
            'Ark backing and full CLN onchain/channel ownership', 'actual miner/router cost components',
            'customer principal, continuing liabilities and EP06 retained-minimum obligations']}
    public_payload(result)
    elapsed = time.monotonic()-started
    completed = now+elapsed
    _fresh(facts, completed); _fresh(frame, completed)
    if elapsed > MAX_SECONDS:
        raise EvidenceGap('wallet projection total time budget exhausted')
    result['completed_at'] = completed
    return result
