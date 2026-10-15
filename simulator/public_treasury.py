"""Shared public cash and physical-frontier arithmetic; no wallet or admission."""
from .model import InvariantError,btc_to_sat
from .ownership import EvidenceGap


def match_scanned_cash(scan,expected):
    """Match every complete scan row, without filtering unknown owned outputs."""
    observed={};total=0
    for coin in scan['unspents']:
        point=coin['txid']+':'+str(coin['vout']);amount=btc_to_sat(coin['amount']);total+=amount
        if point in observed or point not in expected or (amount,coin['scriptPubKey'])!=(expected[point]['amount_sat'],expected[point]['script']):
            raise ValueError('cash source has extra/missing/changed asset')
        observed[point]=expected[point]
    if len(observed)>2000 or set(observed)!=set(expected) or total!=btc_to_sat(scan['total_amount']):
        raise ValueError('complete cash footprint differs')
    return observed


def check_named_bank(bank,wallet_name,observed,tip):
    """The existing exact named-bank source must cover its whole current cash."""
    expected={point:coin for point,coin in observed.items() if coin['member_id']=='bank'}
    points={row['txid']+':'+str(row['vout']):row for row in bank['listunspent']}
    if (bank['source_identity']['wallet_name']!=wallet_name or (bank['height'],bank['tip_hash'])!=tip
            or len(points)!=len(bank['listunspent']) or set(points)!=set(expected)
            or any(bank.get(key)!=[] for key in ('pending_transactions','pending_parents','locked_coins','listlockunspent'))
            or btc_to_sat(bank['getbalances']['mine']['trusted'])!=sum(coin['amount_sat'] for coin in expected.values())
            or btc_to_sat(bank['getbalances']['mine']['untrusted_pending'])!=0):raise ValueError('actual complete bank closing source differs')
    for point,coin in points.items():
        if (btc_to_sat(coin['amount'])!=expected[point]['amount_sat'] or coin['scriptPubKey']!=expected[point]['script']
                or coin.get('spendable') is not True or coin.get('safe') is not True):raise ValueError('actual bank control differs')


def confirmed_frontier(opening,transactions,scripts):
    """Replace proved physical inputs by confirmed successors once, never both."""
    frontier={point:dict(coin) for point,coin in opening.items()};consumed=set();fees=0
    if len(frontier)>2000:raise ValueError('whole physical frontier exceeds bound')
    for tx in transactions:
        if tx.get('confirmations',0)<1:raise EvidenceGap('unconfirmed successor is not confirmed physical capital')
        points=[coin['outpoint'] for coin in tx['inputs']]
        if len(set(points))!=len(points) or consumed.intersection(points):raise InvariantError('physical root consumed more than once')
        if not set(points)<=set(frontier):raise EvidenceGap('confirmed spender has no accounted physical predecessor')
        for coin in tx['inputs']:
            prior=frontier[coin['outpoint']]
            if (coin['amount_sat'],coin['script'])!=(prior['amount_sat'],prior['script']):raise InvariantError('actual spent physical predecessor differs')
        for point in points:del frontier[point]
        consumed.update(points)
        for coin in tx['outputs']:
            point=tx['txid']+':'+str(coin['vout']);owner=scripts.get(coin['script'])
            if point in frontier or point in consumed:raise InvariantError('physical root and successor counted twice')
            if owner is None:raise EvidenceGap('confirmed successor owning public descriptor is unproved')
            frontier[point]={**owner,'amount_sat':coin['amount_sat'],'script':coin['script']}
        if len(frontier)>2000:raise ValueError('whole physical successor frontier exceeds bound')
        fees+=tx['fee_sat']
    if sum(coin['amount_sat'] for coin in opening.values())-fees!=sum(coin['amount_sat'] for coin in frontier.values()):
        raise InvariantError('confirmed physical frontier does not conserve capital and actual miner fees')
    return frontier
