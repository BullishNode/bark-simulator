"""Ordinary-only continuing schema2 signed-version/ceiling/urgent-cash joins."""
from . import b_native_normal_verifier as native
from .b_native_fee_partition import partition_native_fee_authorizations
from .b_native_fee_policy import loaded_native_fee_policy
from .b_initial_normal_profile import COST_SEQUENCES
from .model import integer
from .ownership import EvidenceGap
from .two_step_normal import native_wallet


def ordinary_fee_facts(runtime,*,versions,costs,groups,accounting_receipt_sha256,
                       watchman_raw,physical,chain,server_pubkey,wallet_context):
    partition=partition_native_fee_authorizations(runtime)
    if partition['urgent_attempts']or partition['urgent_bindings']:
        raise EvidenceGap('B continuing ordinary: urgent private publication/input proof unavailable')
    policy=loaded_native_fee_policy(runtime,network='signet')
    maximum=runtime['public_configuration']['watchmand']['direct_expiry']['max_miner_fee_sat']
    pending=retained_ceiling_exposure(runtime,partition,versions,maximum,
        runtime['public_configuration']['watchmand']['fee_estimator_max_sat_kwu'])
    budget=native.require_native_budget_join(runtime,server_pubkey=server_pubkey,costs=costs,
        groups=groups,accounting_receipt_sha256=accounting_receipt_sha256,
        opening_cost_sequences=COST_SEQUENCES,retained_versions=versions['versions'])
    from .b_pending_wallet import owning_projection
    watch=native_wallet(watchman_raw,'watchman')
    owning_projection(wallet_context['member'],watch,scripts=wallet_context['scripts'],
        scan=wallet_context['scan'],versions=versions,chain=chain,tip=wallet_context['tip'])
    urgent=native.urgent_reserve(watch,physical,
        set(versions['selected_fee_outpoints']),chain,minimum_sat=budget['urgent_reserve_sat'],retained_versions=versions)
    return {'ordinary_subset':partition,'native_budget':budget,
        'confirmed_whole_input_urgent_reserve':urgent,'retained_version_states':versions['states'],
        'pending_native_fee_exposure_msat':{'ordinary':pending,'urgent':0},'loaded_policy':policy}


def retained_ceiling_exposure(runtime,partition,versions,maximum,max_rate_sat_kwu):
    """Source-ordered uniform whole ceilings; failed/unpublished holds remain.

    Native5a reserves the loaded maximum before every direct preparation. The
    decimal grammar has no tx binding, so no invented attempt/tx mapping is
    emitted. Every retained version consumes one conservative full reservation;
    absent/failed attempts keep consuming theirs even without a history txid.
    """
    rate=integer(max_rate_sat_kwu,'actual loaded direct rate ceiling',1)
    rows=partition['ordinary_attempts'];history=runtime['native_budget']['history']['txids']
    prefix=runtime['native_budget']['disk_budget']['history_prefix_bytes']//65
    following=history[prefix:]
    if (any(row['ceiling_sat']!=maximum for row in rows)or len(following)>len(rows)
            or set(history)!=set(versions['versions'])):
        raise EvidenceGap('B continuing ordinary: complete retained set/whole prepare ceilings differ')
    confirmed=0
    for txid in following:
        tx=versions['versions'][txid];fee=integer(tx['fee_sat'],'retained miner fee')
        if fee>maximum:raise EvidenceGap('B continuing ordinary: retained version exceeds exact prepare ceiling')
        weight=integer(versions['signed_weight_wu'].get(txid),'actual signed candidate weight',1)
        # Exact native CarrierLimits max_fee_rate.fee_wu(tx.weight()), with
        # integer ceiling; original opening predates this loaded policy.
        if fee>(rate*weight+999)//1000:
            raise EvidenceGap('B continuing ordinary: retained version exceeds loaded signed-weight rate ceiling')
        state=versions['states'].get(txid)
        if state not in {'mempool','confirmed','replaced'}:
            raise EvidenceGap('B continuing ordinary: unknown retained current disposition')
        if state=='confirmed':confirmed+=fee
    reserved=partition['ordinary_reserved_sat']
    if confirmed>reserved:raise EvidenceGap('B continuing ordinary: confirmed fees exceed native reservations')
    return (reserved-confirmed)*1000
