"""One declared pair of fixture node grants and one private signet channel.

Run while the campaign supervisor is stopped. Native Core/CLN wallets retain
their keys. Persist an opening fence before fundchannel; an ambiguous result
is reconciled from CLN and Core, never retried as a second channel.
"""
import argparse
from decimal import Decimal
import json
import os
from pathlib import Path
import subprocess
import time
import tomllib

from .engine import Lease
from .funding import WalletRpc
from .model import SIGNET_GENESIS, btc_to_sat, canonical
from .store import Store

IDS = {
    'internal': '034da4217abfc8bc9395997753d5dcbb81c3e16ccb0090b9d088e3fef2ef1eef36',
    'external': '03c58a086487703c4da754623353a3b2ea313af4065902bc3335d552e818fdc312',
}
PLAN = {'node_grants_sat': {'internal': 85000, 'external': 5000},
        'grant_fee_cap_sat': 3000, 'channel_amount_sat': 50000,
        'initial_peer_allocation_msat': 25000000, 'channel_feerate': '3000perkb',
        'classification': 'declared fixture operator/peer capital; not revenue',
        'external_peer_allocation': 'owned test peer allocation, separate from operator equity'}


class Nodes:
    def call(self, node, method, **params):
        if node not in IDS or method not in {'getinfo', 'newaddr', 'listfunds', 'listpeerchannels', 'fundchannel'}:
            raise ValueError('unsupported fixture node operation')
        command = ['sudo', '-n', 'docker', 'exec', f'abandon-simulation-lightning-{node}-1',
                   'lightning-cli', '--network=signet', '--lightning-dir=/data/.lightning', '-k', method]
        command += [f'{k}={json.dumps(v, separators=(",", ":"))}' for k,v in params.items()]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=180, check=True)
        value = json.loads(completed.stdout)
        if 'error' in value:
            raise ValueError('fixture node operation refused')
        return value


def save(store, value, kind):
    with store.transaction():
        store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',
                         ('fixture_lightning_setup', canonical(value)))
        store._event(kind, value)


def load(store):
    value = store.get_meta('fixture_lightning_setup')
    return json.loads(value) if value else {'plan': PLAN, 'state': 'declared'}


def identity(core, nodes):
    if core.call('getblockhash', 0, root=True) != SIGNET_GENESIS:
        raise ValueError('fixture funding chain mismatch')
    chain = core.call('getblockchaininfo', root=True)
    if chain['initialblockdownload']:
        raise ValueError('wait for independent Core sync')
    for node, expected in IDS.items():
        info = nodes.call(node, 'getinfo')
        if info['id'] != expected or info['network'] != 'signet' or info['blockheight'] != chain['blocks']:
            raise ValueError('fixture node identity or tip mismatch')
    return chain


def fund_nodes(store, core, nodes):
    identity(core, nodes)
    state = load(store)
    if state['plan'] != PLAN:
        raise ValueError('immutable Lightning plan changed')
    if state['state'] in {'grant_broadcasting', 'grant_unknown', 'grant_broadcast', 'grant_confirmed',
                          'opening', 'opening_unknown', 'channel_found', 'ready'}:
        tx = core.call('getrawtransaction', state['grant_txid'], True, root=True)
        if tx.get('confirmations', 0) > 0 and state['state'].startswith('grant_'):
            state['state'] = 'grant_confirmed'
            save(store, state, 'fixture_lightning_grants_confirmed')
        return state
    if state['state'] == 'declared':
        if any(nodes.call(n, 'listpeerchannels')['channels'] for n in IDS):
            raise ValueError('existing channel requires explicit attribution before grants')
        opening = btc_to_sat(core.call('getbalances')['mine']['trusted'])
        if opening < sum(PLAN['node_grants_sat'].values()) + PLAN['grant_fee_cap_sat']:
            raise ValueError('no confirmed fixture capital for declared node grants')
        state.update(state='grant_intent', opening_fixture_wallet_sat=opening,
                     addresses={n: nodes.call(n, 'newaddr', addresstype='bech32')['bech32'] for n in IDS})
        if len(set(state['addresses'].values())) != 2 or any(not a.startswith('tb1q') for a in state['addresses'].values()):
            raise ValueError('fixture node destination mismatch')
        save(store, state, 'fixture_lightning_grants_declared')
    if state['state'] == 'grant_intent':
        outputs = [{state['addresses'][n]: str(Decimal(amount)/100000000)}
                   for n, amount in PLAN['node_grants_sat'].items()]
        psbt = core.call('walletcreatefundedpsbt', [], outputs, 0,
                         {'fee_rate':'3', 'lockUnspents':False, 'add_inputs':True})
        fee = btc_to_sat(psbt['fee'])
        if fee > PLAN['grant_fee_cap_sat']:
            raise ValueError('node grant fee exceeds declared cap; no broadcast')
        signed = core.call('walletprocesspsbt', psbt['psbt'])
        final = core.call('finalizepsbt', signed['psbt'])
        if final.get('complete') is not True:
            raise ValueError('node grant signing incomplete')
        tx = core.call('decoderawtransaction', final['hex'], root=True)
        expected = {state['addresses'][n]: v for n,v in PLAN['node_grants_sat'].items()}
        seen = set()
        change = 0
        for output in tx['vout']:
            address = output['scriptPubKey'].get('address')
            if address in expected:
                if address in seen or btc_to_sat(output['value']) != expected[address]:
                    raise ValueError('node grant output mismatch')
                seen.add(address)
            else:
                if not address or not core.call('getaddressinfo', address)['ismine']:
                    raise ValueError('node grant change not owned')
                change += 1
        if seen != set(expected) or change > 1:
            raise ValueError('node grant recipients differ from declaration')
        state.update(state='grant_prepared', grant_txid=tx['txid'], grant_raw=final['hex'], grant_fee_sat=fee)
        save(store, state, 'fixture_lightning_grants_prepared')
    if state['state'] != 'grant_prepared':
        raise ValueError('unsupported node grant state')
    state['state'] = 'grant_broadcasting'
    save(store, state, 'fixture_lightning_grants_broadcast_intent')
    try:
        actual = core.call('sendrawtransaction', state['grant_raw'], root=True)
        if actual != state['grant_txid']:
            raise ValueError('node grant broadcast id differs')
        state['state'] = 'grant_broadcast'
    except Exception:
        state['state'] = 'grant_unknown'
    save(store, state, 'fixture_lightning_grants_result')
    return state


def open_channel(store, core, nodes):
    identity(core, nodes)
    state = load(store)
    if state['plan'] != PLAN:
        raise ValueError('immutable Lightning plan changed')
    if state['state'] != 'grant_confirmed':
        return check_channel(store, core, nodes)
    if any(nodes.call(n, 'listpeerchannels')['channels'] for n in IDS):
        raise ValueError('unexpected pre-existing channel; opening refused')
    funds = nodes.call('internal', 'listfunds')['outputs']
    grant = core.call('getrawtransaction', state['grant_txid'], True, root=True)
    if grant.get('confirmations', 0) < 1:
        raise ValueError('node grants no longer confirmed')
    matches = [o for o in funds if o['txid'] == state['grant_txid'] and o['status'] == 'confirmed'
               and o.get('address') == state['addresses']['internal']]
    if len(matches) != 1 or matches[0]['amount_msat'] != PLAN['node_grants_sat']['internal']*1000:
        raise ValueError('internal node has no unique confirmed declared grant')
    state.update(state='opening', opening_intent_at=time.time(),
                 opening_utxo=f"{state['grant_txid']}:{matches[0]['output']}")
    # A durable once-only fence precedes the actual RPC, including a lost reply.
    save(store, state, 'fixture_lightning_channel_opening_intent')
    try:
        reply = nodes.call('internal', 'fundchannel', id=IDS['external'],
                           amount=PLAN['channel_amount_sat'], announce=False, minconf=1,
                           push_msat=PLAN['initial_peer_allocation_msat'],
                           feerate=PLAN['channel_feerate'], utxos=[state['opening_utxo']])
        state.update(state='channel_found', channel_id=reply['channel_id'],
                     channel_txid=reply['txid'], channel_outnum=reply['outnum'], channel_raw=reply['tx'])
    except Exception:
        state['state'] = 'opening_unknown'
    save(store, state, 'fixture_lightning_channel_opening_result')
    return check_channel(store, core, nodes)


def check_channel(store, core, nodes):
    identity(core, nodes)
    state = load(store)
    if state['plan'] != PLAN or state['state'] not in {'opening', 'opening_unknown', 'channel_found', 'ready'}:
        raise ValueError('channel not opened under declared plan')
    channels = nodes.call('internal', 'listpeerchannels')['channels']
    if len(channels) != 1 or channels[0]['peer_id'] != IDS['external']:
        raise ValueError('no unique declared channel; do not retry opening')
    channel = channels[0]
    txid = channel.get('funding_txid')
    if not txid:
        return state
    if state.get('channel_txid') not in {None, txid}:
        raise ValueError('channel funding identity changed')
    tx = core.call('getrawtransaction', txid, True, root=True)
    inputs = [f"{i['txid']}:{i['vout']}" for i in tx['vin']]
    if inputs != [state['opening_utxo']]:
        raise ValueError('channel uses undeclared funds')
    if btc_to_sat(tx['vout'][channel['funding_outnum']]['value']) != PLAN['channel_amount_sat']:
        raise ValueError('channel funding output differs from plan')
    fee = PLAN['node_grants_sat']['internal'] - sum(btc_to_sat(o['value']) for o in tx['vout'])
    if fee <= 0:
        raise ValueError('invalid channel funding conservation')
    peer = nodes.call('external', 'listpeerchannels')['channels']
    ready = (len(peer) == 1 and peer[0]['peer_id'] == IDS['internal']
             and peer[0]['funding_txid'] == txid and peer[0]['channel_id'] == channel['channel_id']
             and channel['state'] == peer[0]['state'] == 'CHANNELD_NORMAL'
             and tx.get('confirmations',0) > 0
             and all(c.get('spendable_msat',0) >= 3000000 and c.get('receivable_msat',0) >= 3000000
                     for c in [channel,peer[0]]))
    state.update(state='ready' if ready else 'channel_found', channel_txid=txid,
                 channel_id=channel['channel_id'], channel_outnum=channel['funding_outnum'],
                 channel_fee_sat=fee, channel_confirmations=tx.get('confirmations',0))
    save(store, state, 'fixture_lightning_channel_reconciled')
    return state


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('phase', choices=['fund', 'open', 'check'])
    args = parser.parse_args()
    config = tomllib.loads(args.config.read_text())
    with Lease(Path(config['runtime']['state_dir'])):
        store = Store(Path(config['runtime']['state_dir']), 'live', config['runtime']['fee_budget_sat'])
        try:
            if store.get_meta('paused'):
                raise ValueError('campaign paused; no infrastructure mutation')
            core = WalletRpc(config['funding']['credential_file'], config['funding']['wallet'])
            value = {'fund': fund_nodes, 'open': open_channel, 'check': check_channel}[args.phase](store, core, Nodes())
            # Raw txs stay in the private journal, not CLI output.
            print(json.dumps({k:v for k,v in value.items() if not k.endswith('_raw')}))
        finally:
            store.close()


if __name__ == '__main__':
    main()
