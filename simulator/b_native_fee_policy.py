"""Consume the protected literal B5a loaded fee policy, never guessed path caps.

The caller must first authenticate/replay the protected original runtime package.
This is a policy projection only: no cash, current fee estimate, publication,
whole-input reserve, readiness or dispatch proof is established here.
"""
import hashlib
import re

from .model import canonical
from .ownership import EvidenceGap

PRODUCT = '5a6702018bedc37d4d27cec1205abe828ea14ee5'
# Exact canonical POLICY_SOURCE_SHA256 map in reviewed protected producer b44:
# e6263857238031321315e4a4585ab25bce158fb510f2d09c7114c7bad911140e.
SOURCE_MAP_SHA256 = '327a97677d056eddd892cdb343987c3b9e340ed2212c2836fb0424f6cf486910'
PATHS = {'round','pool','sweep','payout','claim','progression'}
MAX_MONEY = 21_000_000 * 100_000_000


def _need(value, field):
    if not value: raise EvidenceGap('B loaded native policy: '+field)


def _number(value, field, *, minimum=0, maximum=2**64-1):
    _need(type(value) is int and minimum <= value <= maximum, field)
    return value


def _rate(value, field):
    if value is None: return None
    # One kvB = four kwu. These are integer rates, never sat/vB floats.
    return 4*_number(value,field,minimum=1,maximum=(2**64-1)//4)


def loaded_native_fee_policy(runtime, *, network):
    """Derive direct rate/amount constraints from actual hash-bound public fields.

    The native5a Round/Pool paths lack pre-promise cumulative reservations;
    their configured estimator ceilings are reported as facts only. They cannot
    receive a supported financial path ceiling here. CLN ppm is not a fixed
    satoshi limit and urgent publication proof is separate. None stays absent.
    """
    disk = runtime.get('native_budget',{}).get('disk_budget')
    _need(type(disk) is dict and type(disk.get('schema_version')) is int
        and disk['schema_version'] == 2, 'locked schema2 fee policy absent')
    return _loaded_policy(runtime, network=network, product=PRODUCT,
        source_map_sha256=SOURCE_MAP_SHA256, locked_policy=disk)


FINAL_PRODUCT = '15e4fd7085802ba5f7b1d9a2c87aab7277d5a7e4'
FINAL_SOURCE_MAP_SHA256 = 'f9e7f6cbcaafc07be37c34d9b9033be3dacfbe0d1f2f0335dcbd600f483698d9'


def loaded_final_native_fee_policy(runtime, *, network):
    """Literal final15e policy; actual native owner supplies the locked policy.

    This establishes configured caps, never publication/input/cash coverage.
    Unknown paths remain unsupported until their independent joins are added.
    """
    from .b_final_native_profile import checked_owner
    checked_owner(runtime)
    return _loaded_policy(runtime, network=network, product=FINAL_PRODUCT,
        source_map_sha256=FINAL_SOURCE_MAP_SHA256,
        locked_policy=runtime['native_budget']['owner_snapshot']['policy'])


def _loaded_policy(runtime, *, network, product, source_map_sha256, locked_policy):
    """One exact public configuration decoder for the two reviewed versions."""
    _need(network in {'signet','regtest'}, 'unsupported expected network')
    _need(type(runtime) is dict and runtime.get('product_commit') == product
        and runtime.get('execution_release',{}).get('product_commit') == product,
        'exact reviewed5a runtime source required')
    public = runtime.get('public_configuration')
    _need(type(public) is dict and set(public) == {'schema_version','product_commit',
        'config_sha256','policy_source_sha256','captaind','watchmand'}
        and type(public['schema_version']) is int and public['schema_version'] == 1
        and public['product_commit'] == product, 'literal protected policy schema/source absent')
    source_map = public['policy_source_sha256']
    _need(type(source_map) is dict and hashlib.sha256(canonical(source_map).encode()).hexdigest()
          == source_map_sha256, 'reviewed native policy semantics source differs')
    hashes = public['config_sha256']; daemons = runtime.get('daemons')
    _need(type(hashes) is dict and set(hashes) == {'captaind','watchmand'}
        and type(daemons) is dict, 'paired loaded config hashes absent')
    for service in ('captaind','watchmand'):
        _need(type(hashes[service]) is str and re.fullmatch('[0-9a-f]{64}',hashes[service])
            and daemons.get(service,{}).get('config_sha256') == hashes[service]
            and daemons[service].get('public_configuration') == public[service],
            'same loaded config projection/hash differs '+service)
    cap,watch = public['captaind'],public['watchmand']
    _need(type(cap) is dict and set(cap) == {'network','fee_estimator_max_sat_kwu',
        'vtxo_lifetime','vtxo_exit_delta','htlc_expiry_delta','htlc_send_expiry_delta',
        'direct_expiry','legacy_expiry_payout_enabled','ln_max_fee_ppm',
        'ordinary_fee_policy','vtxopool'} and type(watch) is dict
        and set(watch) == {'network','fee_estimator_max_sat_kwu','direct_expiry'},
        'literal captaind/watchmand policy fields differ')
    _need(cap['network'] == network == watch['network'], 'loaded native networks differ')
    for field in ('vtxo_lifetime','vtxo_exit_delta','htlc_expiry_delta','htlc_send_expiry_delta'):
        _number(cap[field],field,maximum=2**32-1)
    direct = watch.get('direct_expiry'); cap_direct = cap.get('direct_expiry')
    _need(type(direct) is dict and set(direct) == {'max_miner_fee_sat','ordinary_fee_policy'}
        and type(cap_direct) is dict and set(cap_direct) == {'enabled','grace_blocks'}
        and type(cap_direct.get('enabled')) is bool
        and type(cap.get('legacy_expiry_payout_enabled')) is bool, 'literal direct configuration absent')
    policy = cap.get('ordinary_fee_policy')
    fields = {'ordinary_budget_sat','urgent_reserve_sat','external_future_reserved_sat','opening_sha256'}
    _need(type(policy) is dict and set(policy) == fields
        and direct.get('ordinary_fee_policy') == policy
        and all(locked_policy.get(k) == v for k,v in policy.items()), 'paired loaded/locked ordinary policy differs')
    allowance = _number(policy['ordinary_budget_sat'],'lifetime allowance',minimum=1,maximum=MAX_MONEY)
    _number(policy['urgent_reserve_sat'],'urgent sublimit',minimum=1,maximum=allowance)
    _number(policy['external_future_reserved_sat'],'external future partition',maximum=allowance)
    _need(type(policy['opening_sha256']) is str
        and re.fullmatch('[0-9a-f]{64}',policy['opening_sha256'])
        and policy['opening_sha256'] != '0'*64, 'original adopted opening source absent')
    cap_rate = _rate(cap.get('fee_estimator_max_sat_kwu'),'captaind configured rate')
    watch_rate = _rate(watch.get('fee_estimator_max_sat_kwu'),'watchmand configured rate')
    maximum = _number(direct.get('max_miner_fee_sat'),'direct miner ceiling',minimum=1,maximum=MAX_MONEY)
    grace = _number(cap_direct.get('grace_blocks'),'direct grace blocks',maximum=2**32-1)
    ppm = _number(cap.get('ln_max_fee_ppm'),'CLN proportional maximum')
    pool = cap.get('vtxopool')
    _need(type(pool) is dict and set(pool) == {'targets','vtxo_lifetime','vtxo_pre_expiry',
        'vtxo_target_issue_threshold','max_vtxo_exit_depth'}
        and type(pool.get('targets')) is list and len(pool['targets']) <= 10000,
          'literal configured pool targets absent')
    for field in ('vtxo_lifetime','vtxo_pre_expiry','vtxo_target_issue_threshold'):
        _number(pool[field],'pool '+field,maximum=2**32-1)
    _number(pool['max_vtxo_exit_depth'],'pool exit depth',maximum=65535)
    for target in pool['targets']:
        _need(type(target) is dict and set(target) == {'amount_sat','count'}, 'literal pool target fields')
        _number(target['amount_sat'],'pool target amount',maximum=MAX_MONEY)
        _number(target['count'],'pool target count')
    limits = {path:None for path in PATHS}
    direct_enabled = cap_direct['enabled'] and not cap['legacy_expiry_payout_enabled']
    if cap_direct['enabled']:
        _need(not cap['legacy_expiry_payout_enabled'], 'direct and legacy producers both enabled')
        _need(watch_rate is not None, 'enabled direct requires configured watch fee cap')
    if direct_enabled:
        limits.update(sweep=watch_rate,payout=watch_rate)
    return {'fee_ceilings_sat_kvb':limits, 'direct_carrier_max_miner_fee_sat':maximum,
        'configured_estimator_ceilings_sat_kvb':{'captaind':cap_rate,'watchmand':watch_rate},
        'ordinary_fee_policy':dict(policy), 'direct_grace_blocks':grace,
        'configured_pool_targets':[dict(t)for t in pool['targets']], 'ln_max_fee_ppm':ppm,
        'unsupported_paths':{'round':'native5a lacks pre-promise lifetime reservation',
            'pool':'native5a lacks pre-promise lifetime reservation',
            'claim':'urgent signed publication/input/chain proof required',
            'progression':'urgent signed publication/input/chain proof required'}}
