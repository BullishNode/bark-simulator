"""Advance a positively recorded exit intent without repeating its start.

The original action owns the complete fee budget. Each new confirmed chain tip
permits at most one explicit continuation. Unknown signatures, transport gaps,
and missing intents stay held; permanently absent wallets are never opened.
"""
from __future__ import annotations

import asyncio
import json
import time

from .model import InvariantError, canonical, public_payload
from .ownership import record_candidates, record_verified, verify_client_evidence
from .process import json_command, public_command_capture


def _authorize(store, action):
    from .unknown_outcomes import _coins, _intent
    _intent(store, action)
    args = json.loads(action['args'])
    if args.get('phase', 'start') != 'start':
        return None
    rows = store.db.execute("""SELECT payload FROM event WHERE kind='driver_evidence'
        AND json_extract(payload,'$.action_id')=?
        AND json_extract(payload,'$.event')='exit_proposal'
        AND json_extract(payload,'$.data.stage')='start'""", (action['id'],)).fetchall()
    if len(rows) != 1:
        return None
    proposal = json.loads(rows[0][0])['data']
    ids = args.get('input_vtxo_ids')
    if (proposal.get('input_vtxo_ids') != ids
            or proposal.get('fee_cap_sat') != action['fee_reservation_sat']
            or proposal.get('fee_funding_outpoint') != args.get('fee_funding_outpoint')
            or type(args.get('fee_rate_sat_per_vb')) is not int
            or args['fee_rate_sat_per_vb'] <= 0
            or proposal.get('fee_rate_kwu') != args['fee_rate_sat_per_vb'] * 250
            or proposal.get('no_automatic_fee_bumps') is not True):
        raise InvariantError('exit continuation differs from the original frozen authorization')
    coins = _coins(store, ids, action['actor_id'])
    if proposal.get('signed_vtxos') != [coin['signed_vtxo'] for coin, _ in coins]:
        raise InvariantError('exit continuation changed its original signed inputs')
    return args


async def collect(store, config, chain, limit=1):
    if not config.active or chain is None or store.get_meta('paused'):
        return
    rows = store.db.execute("""SELECT a.* FROM action a JOIN actor u ON u.id=a.actor_id
        WHERE a.operation='exit' AND a.state='outcome_unknown' AND u.online=1
        ORDER BY a.id""").fetchall()
    after = store.get_meta('exit_continuation_cursor') or ''
    rows = [r for r in rows if r['id'] > after] + [r for r in rows if r['id'] <= after]
    for row in rows[:limit]:
        action = dict(row)
        try:
            actor = store.db.execute('SELECT details FROM actor WHERE id=?', (action['actor_id'],)).fetchone()
            if (action['actor_id'] in {'actor-03','actor-09','actor-10'}
                    or json.loads(actor[0]).get('permanent_absence')):
                continue
            args = _authorize(store, action)
            if args is None:
                continue
            tip = await asyncio.to_thread(chain.identity)
            if tip.get('initialblockdownload') is not False:
                continue
            height, block = tip.get('blocks'), tip.get('bestblockhash')
            if type(height) is not int or height < 0 or not isinstance(block, str) or len(block) != 64:
                raise ValueError('exit continuation needs an independently observed chain tip')
            fence = canonical({'height': height, 'blockhash': block})
            key = 'exit_continuation_tip:' + action['id']
            if store.get_meta(key) == fence:
                continue
            request = {'operation': 'exit', 'action_id': action['id'],
                'actor_dir': str(config.wallet_root / action['actor_id']),
                'expected_server_pubkey': config.expected_server_pubkey,
                'maximum_fee_sat': action['fee_reservation_sat'], 'args': {**args, 'phase': 'advance'}}
            frames = []

            def progress(event):
                public_payload(event)
                if event.get('action_id') != action['id'] or event.get('operation') != 'exit':
                    raise InvariantError('exit continuation evidence has another native identity')
                reference = store.trace_capture('driver.event', event, actor=action['actor_id'], action_id=action['id'])
                name = event.get('event')
                if name in {'client_evidence_before','client_evidence_after'}:
                    if event.get('data', {}).get('fresh') is True:
                        frames.append(event['data']['evidence'])
                    if reference is not None:
                        event = {**event, 'data': {'fresh': event.get('data', {}).get('fresh'), 'trace_ref': reference}}
                store.event('driver_evidence', event)

            # Persist the per-tip fence before launching the known lifecycle.
            # A lost reply consumes this attempt; it cannot immediately retry.
            with store.transaction():
                store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, fence))
                store._event('exit_continuation_intent', {'action_id': action['id'], 'actor': action['actor_id'],
                    'request': request, 'chain_tip': {'height': height, 'blockhash': block},
                    'additional_fee_reservation_sat': 0, 'original_action_unchanged': True})
            started = time.monotonic()
            response = await json_command(list(config.driver_command), request,
                timeout=config.action_timeout_seconds, on_event=progress,
                **public_command_capture(store, 'exit.advance', request, actor=action['actor_id'], action_id=action['id']))
            public_payload(response)
            if response.get('action_id') != action['id'] or response.get('status') == 'incident':
                raise InvariantError('exit continuation response contradicts the original action')
            store.event('driver_response', {'action_id': action['id'], 'response': response,
                'phase': 'advance', 'duration_ms': round((time.monotonic() - started) * 1000)})
            for evidence in frames:
                data = {'evidence': evidence}
                record_candidates(store, action['actor_id'], action['id'], data)
                checked = await verify_client_evidence(store, action['actor_id'], 'exit', data, config.proof_command)
                record_verified(store, action['actor_id'], action['id'], checked)
            # Confirmation and cost are resolved by the public collector. A
            # native acknowledgement never updates the original action here.
        except InvariantError:
            raise
        except Exception as error:
            store.event('exit_continuation_held', {'action_id': action['id'], 'reason': type(error).__name__,
                'original_reservation_retained': True, 'start_retried': False})
        finally:
            store.db.execute("INSERT OR REPLACE INTO meta VALUES ('exit_continuation_cursor',?)", (action['id'],))
