"""Join an actual descriptor-range scan to the existing native wallet projection.

A matching cut proves only the explicitly measured public derivation range. It
cannot prove signer possession, customer attribution, global pending coverage,
fee affordability or completeness of the rest of the treasury.
"""
import time
from datetime import datetime

from .model import SIGNET_GENESIS, InvariantError, btc_to_sat, canonical, integer, public_payload, timestamp
from .ownership import EvidenceGap
from .trace import normalized
from .wallet_projection import OWNERS, _Core, _hash, _point, reduce_wallet_projection

MAX_RANGE = 2000


def reduce_declared_wallet_range(member, facts, capture, chain, financial_pins, *, owner, now=None):
    """Return scope-limited evidence, retaining the full projection and its gaps.

    `capture` is an original bounded scan receipt, retained before this call.
    `facts` must embed its exact native before-frame, not a later balance label.
    Independent Core rechecks scripts, all returned coins and the common tip.
    No scan is started by this reducer, and no store/readiness event is emitted.
    """
    now = time.time() if now is None else timestamp(now, 'observation time')
    if len(canonical(normalized(capture)).encode()) > 8*1024*1024:
        raise EvidenceGap('declared-range capture exceeds byte bound')
    public_payload(capture)
    if capture.get('kind') != 'declared_wallet_range_source' or owner not in OWNERS:
        raise ValueError('original declared-range source required')
    start = datetime.fromisoformat(capture['observed_at']).timestamp()
    end = datetime.fromisoformat(capture['completed_at']).timestamp()
    if not start <= end <= now or now-start > 90:
        raise EvidenceGap('declared-range source is stale')
    bounds = capture['range']
    if (not isinstance(bounds, list) or len(bounds) != 2 or bounds[0] != 0
            or type(bounds[1]) is not int or not 0 <= bounds[1] < MAX_RANGE):
        raise ValueError('explicit bounded public derivation range required')
    high = bounds[1]
    packets = [capture['native_before'], capture['native_after']]
    field = 'rounds_inventory' if owner == 'rounds' else 'watchman_inventory'
    response = packets[0][field]['data']
    native = response[owner]
    if facts['sources'][OWNERS[owner]]['source'] != response:
        raise InvariantError('projection does not preserve the original scan owning frame')
    for packet in packets:
        if packet.get('genesis') != SIGNET_GENESIS or packet.get('network') != 'signet' or packet.get('stable_tip') is not True:
            raise EvidenceGap('original native capture is not stable signet')
        if packet[field]['data'] != response:
            raise EvidenceGap('owning wallet changed across the scan')
        if packet.get('container_runtime_stable') is not True:
            raise EvidenceGap('owning runtime changed across capture')
        expected = facts['source_identity']['daemon_binary_hashes']
        if any(packet['binary_sha256'].get(name) != value for name, value in expected.items()):
            raise InvariantError('actual daemon bytes differ from projection source')
        if packet['config_sha256'] != financial_pins['configuration_sha256']:
            raise InvariantError('actual configuration differs from financial pins')
    if any(packets[0].get(k) != packets[1].get(k) for k in ('source_key','config_sha256','binary_sha256')):
        raise EvidenceGap('actual source identity changed during the scan')
    revealed = native['last_revealed_index']
    if revealed is not None and integer(revealed, 'native issued index') > high:
        raise EvidenceGap('native issuance exceeds the measured range')
    if any(integer(row['derivation_index'], 'native child') > high for row in native['utxos']):
        raise EvidenceGap('native coin exceeds the measured range')
    projection = reduce_wallet_projection(member, facts, chain, financial_pins, owner=owner, now=now)
    core = _Core(chain, time.monotonic())
    tip = core.identity()
    cut = (tip['blocks'], tip['bestblockhash'])
    if cut != (projection['height'], projection['tip_hash']) or capture.get('stable_tip') is not True:
        raise EvidenceGap('projection and range cut differ')
    for boundary in [capture['core_before'], capture['core_after'], *[
            packet[name] for packet in packets for name in ('core_before','core_after')]]:
        if (boundary['blocks'], boundary['bestblockhash'], boundary['initialblockdownload']) != (*cut, False):
            raise EvidenceGap('native, scan and independent Core cuts differ')
    scan = capture['scan']
    if (scan.get('success') is not True or (scan['height'], scan['bestblock']) != cut
            or not isinstance(scan['unspents'], list) or len(scan['unspents']) > 2000):
        raise EvidenceGap('complete bounded original scan result required')
    descriptors = [packets[0][name]['data'][wallet]['public_descriptor']
        for name, wallet in [('rounds_inventory','rounds'),('watchman_inventory','watchman')]]
    starts = [request for request in capture['requests']
        if request['method'] == 'scantxoutset' and request['params'][0] == 'start']
    if len(starts) != 1 or starts[0]['params'] != ['start', [{'desc':d,'range':bounds} for d in descriptors]]:
        raise InvariantError('scan was not the exact one declared two-wallet operation')
    scripts = {}
    for descriptor in descriptors:
        details = core.call('getdescriptorinfo', descriptor)
        if details.get('hasprivatekeys') is not False or details.get('descriptor') != descriptor:
            raise ValueError('actual canonical public scan descriptor required')
        addresses = core.call('deriveaddresses', descriptor, bounds)
        if len(addresses) != high+1:
            raise InvariantError('measured descriptor range is incomplete')
        for index, address in enumerate(addresses):
            details = core.call('validateaddress', address)
            if details.get('isvalid') is not True:
                raise InvariantError('independent derived address invalid')
            script = details['scriptPubKey']
            if script in scripts:
                raise InvariantError('two declared wallets overlap physical scripts')
            scripts[script] = (descriptor, index)
    if capture['native_before']['recovery_reserve'] is not None:
        recovery_script = capture['native_before']['recovery_reserve']['sweep_spk']
        if recovery_script not in scripts or scripts[recovery_script][0] != descriptors[0]:
            raise EvidenceGap('explicitly configured recovery issuance is outside the measured rounds range')
    if btc_to_sat(scan['total_amount']) != sum(btc_to_sat(row['amount']) for row in scan['unspents']):
        raise InvariantError('scan total differs from its original output rows')
    discovered = {}; all_points = set()
    for row in scan['unspents']:
        point = row['txid']+':'+str(row['vout']); txid, index = _point(point)
        if point in all_points:
            raise InvariantError('scan repeats a physical output')
        all_points.add(point)
        script = row['scriptPubKey']
        if script not in scripts:
            raise InvariantError('scan returned a script outside its requested descriptor range')
        descriptor, child = scripts[script]
        coin = core.call('gettxout', txid, index, False)
        amount = btc_to_sat(row['amount'])
        if (coin is None or coin.get('bestblock') != cut[1] or coin.get('confirmations',0) < 1
                or coin['scriptPubKey']['hex'] != script or btc_to_sat(coin['value']) != amount
                or row['height'] > cut[0] or coin['confirmations'] != cut[0]-row['height']+1):
            raise InvariantError('original scan coin differs from independent confirmed-tip output')
        if descriptor == member['descriptors'][0]:
            discovered[point] = {'amount_sat':amount,'script':script,'child_index':child}
    projected = {row['outpoint']:{k:row[k] for k in ('amount_sat','script','child_index')}
        for row in projection['confirmed_tip_utxos']}
    if discovered != projected:
        raise EvidenceGap('owning projection omits or adds a confirmed output in the measured range')
    end_tip = core.identity()
    if (end_tip['blocks'], end_tip['bestblockhash']) != cut:
        raise EvidenceGap('independent Core changed during range reconciliation')
    result = {'kind':'declared_wallet_range_evidence','schema_version':1,
        'member_id':member['id'],'owner':owner,'financial_pins':financial_pins,
        'height':cut[0],'tip_hash':cut[1],'derivation_range':bounds,
        'range_source_sha256':_hash(capture),'native_frame_sha256':_hash(response),
        'projection':projection,'declared_range_matches':True,
        'discovered_confirmed_sat':sum(row['amount_sat'] for row in discovered.values()),
        'confirmed_outpoints':sorted(discovered),'core_observations':core.observations,
        'global_complete':False,'operating_readiness':False,
        'remaining_gaps':sorted(set(capture['remaining_gaps']+projection['projection_gaps'])),
        'scope':'Exact measured descriptor range only; no signer, economic, global-pending or treasury readiness verdict'}
    public_payload(result)
    return result
