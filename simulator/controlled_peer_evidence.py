"""Exact-hash read-only Lightning facts and original-reference verification.

Private CLN replies are checked in memory and projected before capture. The
observer never creates an invoice, pays, claims, retries or opens a wallet.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time

from .model import SIGNET_GENESIS, canonical, integer, public_payload, timestamp
from .ownership import EvidenceGap

ALIASES = {'operator', 'fixture_peer'}
SOURCE_KIND = 'controlled_peer_payment_source'


def _hash(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('exact public payment hash required')
    return value


def _msat(value):
    if isinstance(value, str) and re.fullmatch('[0-9]+msat', value):
        value = int(value[:-4])
    return integer(value, 'exact native millisatoshis')


def _witness(row, payment_hash):
    values = [row[k] for k in ('preimage', 'payment_preimage') if k in row]
    if not values:
        raise EvidenceGap('terminal native payment lacks its private hash witness')
    for value in values:
        raw = bytes.fromhex(_hash(value)) if isinstance(value, str) else value
        if not isinstance(raw, bytes) or len(raw) != 32 or hashlib.sha256(raw).hexdigest() != payment_hash:
            raise ValueError('native private payment witness differs from selected hash')
    return True


def _one(response, key, payment_hash):
    rows = response.get(key)
    if not isinstance(rows, list) or len(rows) > 1:
        raise EvidenceGap('exact-hash aggregate is missing or ambiguous')
    if not rows:
        return None
    row = rows[0]
    if row.get('payment_hash') != payment_hash:
        raise ValueError('selected native reply has another payment hash')
    return row


def _hold_invoice(response, payment_hash):
    """Private Hold.List JSON adapter; inspect every part before projection."""
    row = _one(response, 'invoices', payment_hash)
    if row is None:return None
    if row.get('state') not in {0, 1, 2, 3}:
        raise ValueError('actual hold invoice enum required')
    parts = row.get('htlcs')
    if not isinstance(parts, list) or len(parts) > 1024:
        raise EvidenceGap('complete bounded hold parts required')
    identities = set();received = 0
    for part in parts:
        identity = (part['channel_id'], integer(part['id'], 'hold part identity'))
        if identity in identities:raise ValueError('hold part counted twice')
        identities.add(identity)
        state = part.get('state')
        if state in {0, 1}:raise EvidenceGap('hold payment still has an unsettled part')
        if state not in {2, 3}:raise ValueError('actual hold part enum required')
        if state == 2:received += _msat(part['msat'])
    public_row = {'payment_hash': payment_hash, 'bolt11': row['invoice'],
                  'status': 'paid' if row['state'] == 2 else 'unpaid'}
    if row['state'] == 2:
        if not received:raise EvidenceGap('paid hold invoice has no paid parts')
        _witness(row, payment_hash)  # Private check occurs before any capture.
        public_row.update(payment_preimage=row['preimage'], amount_received_msat=received,
                          paid_at=row['settled_at'])
    return public_row


class SelectedClnReader:
    """A bound owned transport accepts only these internal fixed read methods.

    rpc(alias, method, params) is an authenticated, declared local/bridge reader.
    It MUST NOT attach raw stdout/stderr callbacks: replies may contain secrets.
    Production declarations come from the conserved treasury; explicit regtest
    declarations are reader qualification only and cannot earn signet credit.
    """
    def __init__(self, rpc, *, node_ids, network, hold_list=None, clock=time.time):
        if set(node_ids) != ALIASES or len(set(node_ids.values())) != 2:
            raise ValueError('declare two distinct controlled node identities')
        if any(re.fullmatch('(02|03)[0-9a-f]{64}', p) is None for p in node_ids.values()):
            raise ValueError('controlled compressed node identities required')
        if network not in {'signet', 'regtest'}:
            raise ValueError('owned qualification network required')
        self.rpc, self.node_ids, self.network, self.clock = rpc, dict(node_ids), network, clock
        self.hold_list = hold_list

    async def read(self, alias, payment_hash):
        async with asyncio.timeout(25):
            return await self._read(alias, payment_hash)

    async def _read(self, alias, payment_hash):
        if alias not in ALIASES:
            raise ValueError('fixed controlled node alias required')
        _hash(payment_hash)
        started = timestamp(self.clock(), 'native query start')
        info = await self.rpc(alias, 'getinfo', {})
        if info.get('id') != self.node_ids[alias] or info.get('network') != self.network:
            raise ValueError('actual controlled node identity/network differs')
        if info.get('warning_bitcoind_sync') or info.get('warning_lightningd_sync'):
            raise EvidenceGap('controlled node is not synchronized')
        # Never pass start/limit/status: CLN combines all payment parts here.
        pays = await self.rpc(alias, 'listpays', {'payment_hash': payment_hash})
        invoices = await self.rpc(alias, 'listinvoices', {'payment_hash': payment_hash})
        pay, invoice = _one(pays, 'pays', payment_hash), _one(invoices, 'invoices', payment_hash)
        if self.hold_list is not None:
            hold_invoice = _hold_invoice(await self.hold_list(alias, payment_hash), payment_hash)
            if hold_invoice is not None:
                if invoice is not None and (invoice.get('bolt11'), invoice.get('status')) != (hold_invoice['bolt11'], hold_invoice['status']):
                    raise EvidenceGap('core and hold invoice snapshots disagree')
                invoice = hold_invoice
        if pay is None and invoice is None:
            raise EvidenceGap('selected core-CLN hash absent; hold-plugin facts may be required')
        public = {'schema_version': 1, 'node_alias': alias, 'node_pubkey': info['id'],
                  'network': self.network, 'node_version': info.get('version'),
                  'query_started_at': started, 'payment_hash': payment_hash,
                  'selection': 'exact_hash_without_pagination', 'pay': None, 'invoice': None}
        for row, kind in ((pay, 'pay'), (invoice, 'invoice')):
            if row is None:
                continue
            bolt11 = row.get('bolt11')
            if not isinstance(bolt11, str) or not 1 <= len(bolt11) <= 16000:
                raise EvidenceGap('selected native row lacks original bounded BOLT11')
            decoded = await self.rpc(alias, 'decode', {'string': bolt11})
            if (decoded.get('type') != 'bolt11 invoice' or decoded.get('valid') is not True
                    or decoded.get('payment_hash') != payment_hash):
                raise ValueError('native signed invoice decoder differs from selected hash')
            expected_currency = {'regtest': 'bcrt', 'signet': 'tbs'}[self.network]
            if decoded.get('currency') != expected_currency:
                raise ValueError('signed invoice currency differs from declared chain')
            fact = {'payment_hash': payment_hash, 'invoice_sha256': hashlib.sha256(bolt11.encode()).hexdigest(),
                    'invoice_amount_msat': _msat(decoded['amount_msat']), 'payee': decoded['payee'],
                    'signature_valid': True, 'state': row.get('status'), 'preimage_hash_verified': False}
            if kind == 'invoice' and fact['payee'] != info['id']:
                raise ValueError('selected invoice belongs to another node identity')
            terminal = row.get('status') == ('complete' if kind == 'pay' else 'paid')
            if terminal:
                fact['preimage_hash_verified'] = _witness(row, payment_hash)
                if kind == 'pay':
                    fact.update(amount_msat=_msat(row['amount_msat']), amount_sent_msat=_msat(row['amount_sent_msat']),
                                terminal_at=timestamp(row['completed_at'], 'native payment completion'),
                                number_of_parts=integer(row.get('number_of_parts', 1), 'aggregate parts', 1))
                    if row.get('destination') != fact['payee'] or fact['amount_sent_msat'] < fact['amount_msat']:
                        raise ValueError('actual payer destination/amount differs')
                else:
                    fact.update(amount_received_msat=_msat(row['amount_received_msat']),
                                terminal_at=timestamp(row['paid_at'], 'native invoice payment'))
            public[kind] = fact
        ending = await self.rpc(alias, 'getinfo', {})
        if (ending.get('id'), ending.get('network'), ending.get('version')) != (info['id'], self.network, info.get('version')):
            raise EvidenceGap('controlled node identity changed during selected read')
        public['query_completed_at'] = timestamp(self.clock(), 'native query finish')
        if public['query_completed_at'] < started:
            raise EvidenceGap('clock moved backwards during selected read')
        public_payload(public)  # Only the explicit public projection reaches callers.
        if len(canonical(public).encode()) > 65536:
            raise EvidenceGap('selected public native evidence exceeds whole-frame bound')
        return public


def _event(store, sequence, kind, pins):
    from .final_campaign import _source_event
    event, proof = _source_event(store, sequence)
    if event['kind'] != kind or proof.get('financial_pins') != pins:
        raise ValueError('original external source kind/pins differ')
    return event, proof


def _unique(store, kind, action_id):
    rows = store.db.execute("SELECT sequence FROM event WHERE kind=? AND json_extract(payload,'$.action_id')=?",
                            (kind, action_id)).fetchall()
    if len(rows) != 1:
        raise ValueError('original external native reference missing or ambiguous: ' + kind)
    return rows[0][0]


def _derive_external(store, action, proof):
    """Re-derive a summary from original facts; booleans are never referents."""
    from .final_campaign import _action_pins, _recipient_pins, _source_event
    from .treasury import boundary
    from .fees import movement_fee, receive_fee
    pins = proof['financial_pins']
    direction = proof.get('direction')
    expected_operation = {'send': 'pay_invoice', 'receive': 'invoice'}.get(direction)
    if action['operation'] != expected_operation or store.actor_namespace(action['actor_id']) != 'ordinary':
        raise ValueError('external direction differs from original native user action')
    _action_pins(store, action['id'], pins)
    declared = boundary(store)
    declaration_events = store.db.execute("SELECT sequence FROM event WHERE kind='treasury_boundary_declared'").fetchall()
    if len(declaration_events) != 1:
        raise ValueError('original treasury declaration missing or ambiguous')
    declaration_event, original_declaration = _source_event(store, declaration_events[0][0])
    if original_declaration != declared or declaration_event['observed_at'] > action['created_at']:
        raise ValueError('original treasury declaration was not sealed before action')
    if declared['pins'] != pins:
        raise ValueError('external controlled membership pins differ')
    nodes = {}
    for role in ALIASES:
        members = [m for m in declared['members'] if m['kind'] == 'lightning_peer' and m['role'] == role]
        if len(members) != 1:
            raise ValueError('unique original controlled node membership required')
        member = members[0]
        member_event, original = _source_event(store, member['verification_sequence'])
        if (member_event['kind'] != 'treasury_member_verified' or original.get('genesis') != SIGNET_GENESIS
                or original.get('member') != {k: v for k, v in member.items() if k != 'verification_sequence'} or original.get('financial_pins') != pins):
            raise ValueError('original controlled node identity evidence differs')
        nodes[role] = member['identity']
    sources = []
    for field, alias in (('operator_source_sequence', 'operator'), ('peer_source_sequence', 'fixture_peer')):
        event, source = _event(store, proof[field], SOURCE_KIND, pins)
        fact = source['fact']
        start = timestamp(fact['query_started_at'], 'original controlled query start')
        end = timestamp(fact['query_completed_at'], 'original controlled query end')
        if (source.get('action_id') != action['id'] or start > end or end > event['observed_at']
                or start < action['created_at']):
            raise ValueError('original controlled query action/time differs')
        if (fact.get('schema_version') != 1 or fact.get('node_alias') != alias or fact.get('node_pubkey') != nodes[alias]
                or fact.get('network') != 'signet' or fact.get('selection') != 'exact_hash_without_pagination'
                or fact.get('payment_hash') != proof['payment_hash']):
            raise ValueError('original selected controlled source differs')
        sources.append((event, fact))
    payer_index, receiver_index = (0, 1) if direction == 'send' else (1, 0)
    payer = sources[payer_index][1]['pay']; receiver = sources[receiver_index][1]['invoice']
    if (not payer or not receiver or payer.get('state') != 'complete' or receiver.get('state') != 'paid'
            or payer.get('preimage_hash_verified') is not True or receiver.get('preimage_hash_verified') is not True
            or payer.get('signature_valid') is not True or receiver.get('signature_valid') is not True):
        raise ValueError('both original terminal controlled outcomes required')
    data = json.loads(action['result'])['data']; args = json.loads(action['args'])
    invoice = args.get('invoice') if direction == 'send' else data.get('invoice')
    if not isinstance(invoice, str) or not invoice:
        raise ValueError('original native invoice missing')
    digest = hashlib.sha256(invoice.encode()).hexdigest()
    amount = integer(args['amount_sat'], 'original native principal', 1) * 1000
    receiver_id = sources[receiver_index][1]['node_pubkey']
    if (payer.get('invoice_sha256') != digest or receiver.get('invoice_sha256') != digest
            or payer.get('payee') != receiver_id or receiver.get('payee') != receiver_id
            or payer.get('invoice_amount_msat') != amount or receiver.get('invoice_amount_msat') != amount
            or payer.get('amount_msat') != amount or receiver.get('amount_received_msat') != amount):
        raise ValueError('original invoice/payee/amount differs; overpayment needs separate accounting')
    if data.get('payment_hash') != proof['payment_hash']:
        raise ValueError('original native hash differs')
    result_event, original_result = _source_event(store, proof['native_result_source_sequence'])
    original_data = original_result.get('result', {}).get('data', {})
    if (result_event['kind'] != 'action_result' or original_result.get('action_id') != action['id']
            or original_result.get('state') != 'completed' or original_data.get('payment_hash') != proof['payment_hash']
            or result_event['observed_at'] < action['created_at']
            or any(result_event['observed_at'] > source['query_started_at'] for _, source in sources)):
        raise ValueError('original native invoice/payment result differs')
    if direction == 'receive' and (original_data.get('invoice') != invoice
            or original_data.get('estimated_claim_fee_sat') != data.get('estimated_claim_fee_sat')):
        raise ValueError('original native invoice/quote cannot be rewritten')
    fee_sequence = proof['native_fee_source_sequence']
    _, fees = _event(store, fee_sequence, 'client_fee_reconciled', pins)
    native_action = action
    claim_sequences = []
    if direction == 'send':
        _, proposal = _event(store, proof['native_proposal_source_sequence'], 'driver_evidence', pins)
        if (proposal.get('action_id') != action['id'] or proposal.get('event') != 'lightning_proposal'
                or proposal.get('data', {}).get('payment_hash') != proof['payment_hash']):
            raise ValueError('original native frozen payment proposal differs')
        _, outcome = _event(store, proof['native_outcome_source_sequence'], 'lightning_payment_outcome', pins)
        response = outcome.get('response', {})
        status = response.get('data', {})
        if (outcome.get('action_id') != action['id'] or outcome.get('payment_hash') != proof['payment_hash']
                or outcome.get('state') != 'succeeded' or status.get('payment_hash') != proof['payment_hash']
                or status.get('state') != 'succeeded' or status.get('success_preimage_hash_valid') is not True
                or status.get('read_only') is not True or status.get('actual_fee_sat') != 0
                or response.get('status') != 'ok' or response.get('action_id') != 'payment-status:' + action['id']):
            raise ValueError('original native payer outcome differs')
        expected_fee = movement_fee(store, action)
        _recipient_pins(store, action['actor_id'], expected_fee['input_coin_ids'], pins)
        if expected_fee['output_coin_ids']:
            _recipient_pins(store, action['actor_id'], expected_fee['output_coin_ids'], pins)
    else:
        native_action = store.db.execute('SELECT * FROM action WHERE id=?', (proof['claim_action_id'],)).fetchone()
        if (native_action is None or native_action['operation'] not in {'sync', 'claim_lightning'} or native_action['state'] != 'completed'
                or native_action['actor_id'] != action['actor_id']):
            raise ValueError('rightful original native claim action required; custody is insufficient')
        _action_pins(store, native_action['id'], pins)
        if native_action['created_at'] < action['created_at']:
            raise ValueError('native claim predates its original invoice')
        expected_fee = receive_fee(store, native_action)
        claims = [c for c in expected_fee['claims'] if c['payment_hash'] == proof['payment_hash'] and c['invoice_action_id'] == action['id']]
        if len(claims) != 1:
            raise ValueError('unique original invoice/claim linkage required')
        _recipient_pins(store, action['actor_id'], claims[0]['output_coin_ids'], pins)
        for coin_id in claims[0]['output_coin_ids']:
            if store.db.execute("SELECT 1 FROM coin_observation WHERE coin_id=? AND action_id=? AND state='Spendable'",
                                (coin_id, native_action['id'])).fetchone() is None:
                raise ValueError('original claim lacks its signed spendable recipient observation')
        claim_sequences = [fee_sequence]
    if {k: v for k, v in fees.items() if k != 'financial_pins'} != {'action_id': native_action['id'], **expected_fee}:
        raise ValueError('original independently signed native cost proof differs')
    if native_action['actual_fee_sat'] != expected_fee['actual_fee_sat']:
        raise ValueError('native cost is not independently reconciled')
    sent = integer(payer['amount_sent_msat'], 'actual payer amount', amount)
    terminal_at = max(timestamp(payer['terminal_at'], 'payer terminal'), timestamp(receiver['terminal_at'], 'receiver terminal'))
    if direction == 'receive':
        result_event, result = _source_event(store, _unique(store, 'action_result', native_action['id']))
        if result.get('state') != 'completed' or result.get('result') != json.loads(native_action['result']):
            raise ValueError('original native claim completion differs')
        terminal_at = max(terminal_at, result_event['observed_at'])
    if terminal_at < int(action['created_at']) or any(terminal_at > e['observed_at'] for e, _ in sources):
        raise ValueError('external terminal time cannot be imported or refreshed')
    expected = {'action_id': action['id'], 'payment_hash': proof['payment_hash'], 'direction': direction,
                'peer_pubkey': nodes['fixture_peer'], 'state': 'succeeded', 'peer_outcome_checked': True,
                'amount_msat': amount, 'amount_sent_msat': sent, 'amount_received_msat': amount,
                'router_fee_msat': sent - amount, 'native_customer_fee_sat': expected_fee['actual_fee_sat'],
                'claim_source_sequences': claim_sequences,
                'verified_at': terminal_at, 'invoice_sha256': digest, 'financial_pins': pins}
    return expected


def verify_referenced_external(store, action, proof):
    expected = _derive_external(store, action, proof)
    if any(proof.get(k) != v for k, v in expected.items()):
        raise ValueError('external summary differs from original referenced evidence')
    return expected['verified_at']


async def collect_controlled_peer_payments(store, config, selected_hash_reader, limit=2):
    """Collect original terminal hashes only; no invoice/payment/claim dispatch."""
    integer(limit, 'controlled peer observation batch', 1)
    if limit > 2:
        raise ValueError('controlled peer batch exceeds bound')
    cursor = store.get_meta('controlled_peer_cursor') or ''
    query = """SELECT a.* FROM action a JOIN actor r ON r.id=a.actor_id
        WHERE operation IN ('pay_invoice','invoice') AND state='completed'
        AND r.role NOT IN ('noah','noah-phone','noah-payer','noah-forwarder') AND a.id {} ? ORDER BY a.id LIMIT ?"""
    rows = store.db.execute(query.format('>'), (cursor, limit)).fetchall()
    if len(rows) < limit:
        rows += store.db.execute(query.format('<='), (cursor, limit-len(rows))).fetchall()
    emitted = 0
    for action in rows[:limit]:
        try:
            pins = store.financial_context()
            if pins is None:
                raise EvidenceGap('original controlled observation financial context missing')
            direction = 'send' if action['operation'] == 'pay_invoice' else 'receive'
            payment_hash = _hash(json.loads(action['result'])['data']['payment_hash'])
            previous = store.db.execute("""SELECT sequence FROM event WHERE kind='controlled_peer_payment_verified'
                AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.payment_hash')=?
                AND json_extract(payload,'$.direction')=?""", (action['id'], payment_hash, direction)).fetchall()
            if previous:
                if len(previous) != 1:
                    raise ValueError('controlled payment already has ambiguous original proof')
                from .final_campaign import _source_event
                _, original = _source_event(store, previous[0][0])
                verify_referenced_external(store, action, original)
                continue
            refs = {'action_id': action['id'], 'payment_hash': payment_hash, 'direction': direction, 'financial_pins': pins,
                    'native_result_source_sequence': _unique(store, 'action_result', action['id'])}
            if direction == 'send':
                refs['native_fee_source_sequence'] = _unique(store, 'client_fee_reconciled', action['id'])
                refs['native_outcome_source_sequence'] = _unique(store, 'lightning_payment_outcome', action['id'])
                proposals = store.db.execute("""SELECT sequence FROM event WHERE kind='driver_evidence'
                    AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')='lightning_proposal'""", (action['id'],)).fetchall()
                if len(proposals) != 1:
                    raise EvidenceGap('unique original native proposal missing')
                refs['native_proposal_source_sequence'] = proposals[0][0]
            else:
                claims = store.db.execute("""SELECT sequence,payload FROM event WHERE kind='client_fee_reconciled'
                    AND json_extract(payload,'$.actor')=?""", (action['actor_id'],)).fetchall()
                matches = [(r['sequence'], json.loads(r['payload'])) for r in claims
                           if any(c.get('invoice_action_id') == action['id'] and c.get('payment_hash') == payment_hash
                                  for c in json.loads(r['payload']).get('claims', []))]
                if len(matches) != 1:
                    raise EvidenceGap('unique original signed native claim missing; custody is insufficient')
                refs['native_fee_source_sequence'], claim = matches[0]
                refs['claim_action_id'] = claim['action_id']
            facts = await asyncio.gather(*(selected_hash_reader.read(alias, payment_hash) for alias in ('operator', 'fixture_peer')))
            if store.financial_context() != pins:
                raise EvidenceGap('financial observation context changed during controlled query')
            # Financial context is frozen before the private native queries, not
            # taken from a later snapshot to re-label existing facts.
            for alias, fact in zip(('operator', 'fixture_peer'), facts):
                public_payload(fact)
                with store.transaction():
                    store._event(SOURCE_KIND, {'action_id': action['id'], 'financial_pins': pins, 'fact': fact})
                    refs[('operator' if alias == 'operator' else 'peer') + '_source_sequence'] = store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]
            proof = {**refs, **_derive_external(store, action, refs)}
            public_payload(proof)
            with store.transaction():
                if store.db.execute("""SELECT 1 FROM event WHERE kind='controlled_peer_payment_verified'
                    AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.payment_hash')=?
                    AND json_extract(payload,'$.direction')=?""", (action['id'], payment_hash, direction)).fetchone():
                    raise ValueError('controlled proof already emitted during collection')
                store._event('controlled_peer_payment_verified', proof)
            emitted += 1
        except (EvidenceGap, ValueError, KeyError, TypeError, TimeoutError, OSError) as error:
            store.event('controlled_peer_payment_pending', {'action_id': action['id'], 'reason': type(error).__name__, 'monetary_retry': False})
        finally:
            store.db.execute("INSERT OR REPLACE INTO meta VALUES ('controlled_peer_cursor',?)", (action['id'],))
    return emitted
