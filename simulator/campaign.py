"""Persisted client ramp, driven only by verified live-campaign health.

No wall-clock catch-up on restart: setup, pauses, unavailable observations and
process downtime contribute zero. Creation/funding remain journaled operations;
adding actor rows never transfers money or retries an uncertain action.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict

from .model import canonical, integer
from .store import Store
from .ownership import proof_matches_profile
from .architecture import DIRECT_PER_KEY,profile

TRAFFIC_WINDOW_SECONDS = 600
LIGHTNING_WINDOW_SECONDS = 3600
QUALIFIED_COUNTER = "qualified_campaign_active_seconds"


def _signed_coin(store, coin_id, actor):
    row = store.db.execute("""SELECT c.*,k.actor,k.mailbox FROM owned_coin c
        JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?""", (coin_id,)).fetchone()
    if row is None or row['actor'] != actor:
        return None
    proof = json.loads(row['proof'])
    bound = proof.get('binding', {})
    origin={'user_pubkey':row['pubkey'],'key_link_attestation':bound.get('key_link_attestation')} if profile(store)==DIRECT_PER_KEY else {
        'user_pubkey':row['pubkey'],'child_index':bound.get('child_index'),'blinded_mailbox_id':bound.get('blinded_mailbox_id')}
    if (proof.get('signed_path_valid') is not True or proof.get('anchor_confirmations', 0) < 1
            or not proof_matches_profile(store,proof,origin)
            or bound.get('mailbox_pk') != row['mailbox']
            or (proof.get('id'), proof.get('user_pubkey'), proof.get('amount_sat'))
                != (row['id'], row['pubkey'], row['amount_sat'])):
        return None
    return row, proof


def _receipt_origin(proof, inputs):
    """A receipt's signed path must branch directly from the frozen send inputs.

    The SDK exposes sender change IDs, not recipient IDs. Its public verifier
    exposes the actual signed transaction path. Match that path to the frozen
    inputs, then require single-input continuations preserving the receipt's
    value to its signed leaf. This also works when the sender has no change.
    Matching the amount or an arbitrary ancestor alone is insufficient.
    """
    path = proof.get('path', [])
    amount = proof['amount_sat']
    for index, step in enumerate(path):
        parents = step.get('inputs', [])
        if (not parents or len(parents) != len(set(parents))
                or not set(parents).issubset(inputs) or step.get('output_amount_sat') != amount):
            continue
        previous = str(step['txid']) + ':' + str(step['output_index'])
        for continuation in path[index + 1:]:
            if (continuation.get('inputs') != [previous]
                    or continuation.get('output_amount_sat') != amount):
                break
            previous = str(continuation['txid']) + ':' + str(continuation['output_index'])
        else:
            if previous == proof['id']:
                return {'input_coin_ids': parents, 'branch_txid': step['txid'],
                        'branch_output': str(step['txid']) + ':' + str(step['output_index'])}
    return None


def collect_ark_receipts(store: Store, now: float | None = None):
    """Credit a frozen send once from already collected public receipt proofs.

    Never open a wallet or synthesize recipient evidence from submission. Use
    the original completed observation time, so retrying an archived proof does
    not manufacture fresh traffic. Ambiguous frozen inputs or receipt assignment
    stay unqualified; the collector cannot authorize a payment retry.
    """
    now = time.time() if now is None else now
    credits = [json.loads(r[0]) for r in store.db.execute(
        "SELECT payload FROM event WHERE kind='ark_transfer_verified'")]
    credited = {c['action_id'] for c in credits}
    claimed = {(c.get('recipient_actor'), c.get('receipt_movement_id')) for c in credits}
    proposals = {}
    input_claims = {}
    for row in store.db.execute("""SELECT payload FROM event WHERE kind='driver_evidence'
            AND json_extract(payload,'$.event')='arkoor_request'"""):
        payload = json.loads(row[0]); identity = payload['action_id']
        proposal = payload['data']
        proposals.setdefault(identity, []).append(proposal)
        for coin in proposal.get('input_vtxo_ids', []):
            input_claims.setdefault(coin, set()).add(identity)
    sends = store.db.execute("""SELECT * FROM action WHERE operation='send_arkoor'
        AND state='completed' AND updated_at<=? ORDER BY updated_at,id""", (now,)).fetchall()
    for action in sends:
        if action['id'] in credited or len(proposals.get(action['id'], [])) != 1:
            continue
        args = json.loads(action['args']); data = json.loads(action['result']).get('data', {})
        recipient = args.get('recipient_actor'); proposal = proposals[action['id']][0]
        if recipient is None:
            # Older fixture/pilot sends froze an address without an actor label.
            # An exact address with one prior advertising actor is unambiguous;
            # never infer the recipient from a receive amount or current details.
            recipients = {r[0] for r in store.db.execute("""SELECT actor_id FROM action
                WHERE operation='address' AND state='completed' AND updated_at<=?
                AND json_extract(result,'$.data.address')=?""",
                (action['updated_at'], args.get('destination')))}
            if len(recipients) == 1:
                recipient = next(iter(recipients))
        inputs = proposal.get('input_vtxo_ids', [])
        amount = args.get('amount_sat')
        if (not recipient or recipient == action['actor_id'] or type(amount) is not int or amount <= 0
                or proposal.get('destination') != args.get('destination')
                or proposal.get('amount_sat') != amount or data.get('amount_sat') != amount
                or data.get('submitted') != 'send_arkoor' or not inputs
                or len(inputs) != len(set(inputs))
                or any(input_claims[coin] != {action['id']} for coin in inputs)
                or any(_signed_coin(store, coin, action['actor_id']) is None for coin in inputs)):
            continue
        sender_movements = [m for m in data.get('evidence', {}).get('movements', [])
            if (m.get('subsystem') == 'bark.arkoor' and m.get('status') == 'successful'
                and sorted(m.get('input_vtxos', [])) == sorted(inputs)
                and m.get('effective_balance_sat') == -amount and m.get('offchain_fee_sat') == 0)]
        if len(sender_movements) != 1:
            continue
        address_rows = store.db.execute("""SELECT result FROM action WHERE actor_id=?
            AND operation='address' AND state='completed' AND updated_at<=?
            AND json_extract(result,'$.data.address')=?""",
            (recipient, action['updated_at'], args['destination'])).fetchall()
        keys = {json.loads(r[0]).get('data', {}).get('user_pubkey') for r in address_rows}
        if len(keys) != 1 or None in keys:
            continue
        key = next(iter(keys))
        candidates = []
        for row in store.db.execute('SELECT payload FROM movement_evidence WHERE actor=?', (recipient,)):
            movement = json.loads(row[0]); ids = movement.get('output_vtxos', [])
            if (movement.get('subsystem') != 'bark.arkoor' or movement.get('status') != 'successful'
                    or movement.get('input_vtxos') != [] or not ids or len(ids) != len(set(ids))
                    or movement.get('effective_balance_sat') != amount or movement.get('offchain_fee_sat') != 0
                    or (recipient, movement['id']) in claimed):
                continue
            receipts = []; observed_times = []
            for coin_id in ids:
                signed = _signed_coin(store, coin_id, recipient)
                if signed is None or signed[0]['pubkey'] != key:
                    break
                coin, proof = signed
                origin = _receipt_origin(proof, set(inputs))
                if origin is None:
                    break
                observed = store.db.execute("""SELECT MIN(a.updated_at) FROM coin_observation o
                    JOIN action a ON a.id=o.action_id WHERE o.coin_id=? AND a.actor_id=?
                    AND a.state='completed' AND a.operation IN ('snapshot','sync','board','send_arkoor','refresh','refresh_delegated','offboard_all','invoice','pay_invoice') AND a.updated_at>=? AND a.updated_at<=?""",
                    (coin_id, recipient, action['updated_at'], now)).fetchone()[0]
                if observed is None:
                    break
                receipts.append({'coin_id': coin_id, 'amount_sat': coin['amount_sat'], **origin})
                observed_times.append(observed)
            else:
                if sum(r['amount_sat'] for r in receipts) == amount:
                    candidates.append((movement, receipts, max(observed_times)))
        if len(candidates) != 1:
            continue
        movement, receipts, observed_at = candidates[0]
        store.event('ark_transfer_verified', {'action_id': action['id'],
            'sender_actor': action['actor_id'], 'recipient_actor': recipient,
            'sender_movement_id': sender_movements[0]['id'], 'receipt_movement_id': movement['id'],
            'destination': args['destination'], 'recipient_pubkey': key, 'amount_sat': amount,
            'input_coin_ids': inputs, 'receipts': receipts, 'verified_at': observed_at,
            'absent_wallet_opened': False,
            'scope': 'signed recipient outputs and transaction paths linked to a unique frozen send'})
        credited.add(action['id']); claimed.add((recipient, movement['id']))


def traffic_ready(store: Store, now: float | None = None, financial_pins=None) -> bool:
    """Both verified customer rails must remain inside their own recent windows."""
    if store.get_meta('final_financial_epoch') is not None:
        from . import final_campaign
        try:
            return final_campaign.traffic_ready(store, time.time() if now is None else now, financial_pins)
        except (ValueError, KeyError):
            return False
    started = store.get_meta("real_campaign_started")
    if started is None:
        return False
    now = time.time() if now is None else now
    started = float(started)
    ark = store.db.execute("""SELECT MAX(json_extract(e.payload,'$.verified_at'))
        FROM event e JOIN action a ON a.id=json_extract(e.payload,'$.action_id')
        WHERE e.kind='ark_transfer_verified' AND a.operation='send_arkoor' AND a.state='completed'
        AND a.updated_at>=? AND a.updated_at<=?
        AND json_extract(e.payload,'$.verified_at')>=?
        AND json_extract(e.payload,'$.verified_at')<=?""", (started, now, started, now)).fetchone()[0]
    lightning = store.db.execute("""SELECT MAX(updated_at) FROM action
        WHERE operation='pay_invoice' AND state='completed' AND updated_at>=? AND updated_at<=?
        AND json_extract(result,'$.data.paid')=1
        AND json_extract(result,'$.data.payment_status_verified')=1
        AND json_extract(result,'$.data.payment_state')='succeeded'""", (started, now)).fetchone()[0]
    return (ark is not None and lightning is not None
            and 0 <= now - ark <= TRAFFIC_WINDOW_SECONDS
            and 0 <= now - lightning <= LIGHTNING_WINDOW_SECONDS)


@dataclass(frozen=True)
class RampPlan:
    initial_clients: int = 12
    added_clients: int = 12
    after_active_seconds: int = 10800
    funding_per_added_client_sat: int = 8000

    def validate(self):
        for key, value in asdict(self).items():
            integer(value, key, 1)
        if self.initial_clients + self.added_clients > 99:
            raise ValueError("driver supports actor-01 through actor-99")


class CampaignClock:
    def __init__(self, store: Store, plan: RampPlan, maximum_gap_seconds: int = 180, clock=time.monotonic):
        plan.validate()
        integer(maximum_gap_seconds, "maximum observation gap", 1)
        self.store, self.plan, self.clock = store, plan, clock
        self.maximum_gap = maximum_gap_seconds
        self.previous_time = None
        self.previous_healthy = False
        self.financial_epoch = store.get_meta('final_financial_epoch')
        encoded = canonical(asdict(plan))
        with store.transaction():
            existing = store.get_meta("ramp_plan")
            if existing is not None and existing != encoded:
                raise ValueError("ramp plan/funding are immutable for this campaign")
            if existing is None:
                store.db.execute("INSERT INTO meta VALUES ('ramp_plan',?)", (encoded,))
                store.db.execute("INSERT OR IGNORE INTO meta VALUES ('campaign_active_seconds','0')")
                store._event("ramp_declared", {**asdict(plan), "added_funding_budget_sat":plan.added_clients * plan.funding_per_added_client_sat,
                    "recent_transfer_window_seconds":TRAFFIC_WINDOW_SECONDS,
                    "required_initial_successful_rails":["ark","lightning"]})
            if store.get_meta(QUALIFIED_COUNTER) is None:
                legacy = store.get_meta("campaign_active_seconds") or "0"
                store.db.execute("INSERT OR IGNORE INTO meta VALUES ('legacy_clock_seconds',?)", (legacy,))
                store.db.execute("INSERT INTO meta VALUES (?,'0')", (QUALIFIED_COUNTER,))
                store._event("qualified_clock_migrated", {"legacy_clock_seconds":float(store.get_meta("legacy_clock_seconds")),
                    "qualified_clock_seconds":0, "ark_window_seconds":TRAFFIC_WINDOW_SECONDS,
                    "lightning_window_seconds":LIGHTNING_WINDOW_SECONDS,
                    "ark_requires_signed_recipient_receipt":True, "legacy_history_preserved":True})

    def tick(self, *, healthy: bool, real_campaign_started: bool, financial_pins=None):
        now = self.clock()
        current_epoch = self.store.get_meta('final_financial_epoch')
        if current_epoch != self.financial_epoch:
            self.previous_time, self.previous_healthy = None, False
            self.financial_epoch = current_epoch
        eligible = healthy and real_campaign_started and not self.store.get_meta("paused")
        if self.store.get_meta('final_financial_epoch') is not None:
            from . import final_campaign
            try:
                eligible = eligible and final_campaign.pins_match(self.store, financial_pins)
            except (ValueError, KeyError):
                eligible = False
        delta = 0
        if self.previous_time is not None and self.previous_healthy and eligible:
            elapsed = now - self.previous_time
            if 0 <= elapsed <= self.maximum_gap:
                delta = elapsed
        self.previous_time, self.previous_healthy = now, eligible
        with self.store.transaction():
            accumulated = float(self.store.get_meta(QUALIFIED_COUNTER)) + delta
            self.store.db.execute("UPDATE meta SET value=? WHERE key=?", (repr(accumulated), QUALIFIED_COUNTER))
            if delta:
                self.store._event("qualified_campaign_active_interval", {"seconds":delta, "total_seconds":accumulated})
            if eligible and accumulated >= self.plan.after_active_seconds and not self.store.get_meta("ramp_applied"):
                expected = {f"actor-{i:02}" for i in range(1, self.plan.initial_clients + 1)}
                actual = {r[0] for r in self.store.db.execute("SELECT id FROM actor") if self.store.actor_namespace(r[0])=='ordinary'}
                if any(self.store.actor_held(actor) for actor in expected):return accumulated
                if actual != expected:
                    raise ValueError("unexpected pre-ramp cohort; no automatic overwrite")
                actors = []
                for index in range(self.plan.initial_clients + 1, self.plan.initial_clients + self.plan.added_clients + 1):
                    actor = f"actor-{index:02}"
                    details = {"cohort":"ramp", "declared_initial_funding_sat":self.plan.funding_per_added_client_sat}
                    self.store.db.execute("INSERT INTO actor VALUES (?,?,1,?)", (actor,"additional realistic client",canonical(details)))
                    actors.append(actor)
                self.store.db.execute("INSERT INTO meta VALUES ('ramp_applied','true')")
                self.store._event("client_ramp_applied", {"actors":actors,"total_clients":len(expected)+len(actors),
                    "active_seconds":accumulated,"funding_budget_sat":self.plan.added_clients*self.plan.funding_per_added_client_sat,
                    "funding_dispatched":False})
        return accumulated
