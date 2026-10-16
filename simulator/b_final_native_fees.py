"""Final native owner/retained ordinary fees using existing money/wallet checks.

Funding/urgent arithmetic alone never authorizes their inputs or costs. Until
those independent path joins are implemented, nonempty such domains HOLD.
"""
from .b_final_native_profile import checked_owner
from .b_native_fee_policy import loaded_final_native_fee_policy
from .b_continuing_native_fees import retained_direct_exposure
from .b_native_normal_verifier import retained_fee_accounting,urgent_reserve
from .b_initial_normal_profile import COST_SEQUENCES
from .b_pending_wallet import owning_projection
from .model import SIGNET_GENESIS
from .ownership import EvidenceGap
from .two_step_normal import native_wallet


def final_ordinary_fee_facts(runtime,*,native_fee_source,versions,costs,groups,
        accounting_receipt_sha256,watchman_raw,physical,chain,server_pubkey,wallet_context):
    partition=checked_owner(runtime)
    proof=native_fee_source['reply']
    if native_fee_source['partition']!=partition:
        raise EvidenceGap('B final fees: same captured owner partition changed')
    if partition['funding'] or partition['resolutions'] or proof['funding_rows']:
        raise EvidenceGap('B final fees: funding reservations require current owning input/family/Core joins')
    if partition['urgent'] or proof['urgent_rows']:
        raise EvidenceGap('B final fees: urgent publications require authenticated source-path/Core/ownership joins')
    require_ordinary_nursery(proof,versions,chain)
    opening=runtime['native_budget']['owner_snapshot']['opening']
    policy=runtime['native_budget']['owner_snapshot']['policy']
    if (partition['network']!='signet' or partition['genesis']!=SIGNET_GENESIS
            or partition['server_pubkey']!=server_pubkey):
        raise EvidenceGap('B final fees: actual native chain/server differs')
    # These rows come from the fixed native codec over the exact private
    # journal, including failed/unpublished preparations; never infer them from
    # an aggregate count/sum or parse the journal again in Python.
    rows=proof.get('direct_reservations')
    if (type(rows) is not list or len(rows)!=partition['direct_attempt_count']
            or any(type(r) is not dict or set(r)!={'line','ceiling_sat'} for r in rows)
            or sum(r['ceiling_sat']for r in rows)!=partition['direct_reserved_sat']):
        raise EvidenceGap('B final fees: complete individual direct reservations missing from native proof ABI')
    loaded=loaded_final_native_fee_policy(runtime,network='signet')
    budget=retained_fee_accounting(runtime['native_budget'],
        history_prefix_bytes=opening['history_prefix_bytes'],history_prefix_sha256=opening['history_prefix_sha256'],
        opening_accounting_receipt_sha256=opening['accounting_receipt_sha256'],
        opening_native_spent_sat=opening['native_spent_sat'],opening_external_spent_sat=opening['external_spent_sat'],
        external_future_reserved_sat=policy['external_future_reserved_sat'],
        ordinary_budget_sat=policy['ordinary_budget_sat'],urgent_reserve_sat=policy['urgent_reserve_sat'],
        reserved_ceiling_sum_sat=partition['direct_reserved_sat'],attempt_count=partition['direct_attempt_count'],
        accounting_receipt_sha256=accounting_receipt_sha256,costs=costs,groups=groups,
        opening_cost_sequences=COST_SEQUENCES,retained_versions=versions['versions'])
    watch_policy=runtime['public_configuration']['watchmand']
    pending=retained_direct_exposure(runtime['native_budget']['history']['txids'],
        history_prefix_bytes=opening['history_prefix_bytes'],ordinary_attempts=rows,
        ordinary_reserved_sat=partition['direct_reserved_sat'],versions=versions,
        maximum=watch_policy['direct_expiry']['max_miner_fee_sat'],
        max_rate_sat_kwu=watch_policy['fee_estimator_max_sat_kwu'])
    watch=native_wallet(watchman_raw,'watchman')
    owning_projection(wallet_context['member'],watch,scripts=wallet_context['scripts'],
        scan=wallet_context['scan'],versions=versions,chain=chain,tip=wallet_context['tip'])
    urgent=urgent_reserve(watch,physical,set(versions['selected_fee_outpoints']),chain,
        minimum_sat=budget['urgent_reserve_sat'],retained_versions=versions)
    return {'ordinary_subset':partition,'native_budget':budget,
        'confirmed_whole_input_urgent_reserve':urgent,'retained_version_states':versions['states'],
        'pending_native_fee_exposure_msat':{'ordinary':pending,'urgent':0},'loaded_policy':loaded}


def require_ordinary_nursery(proof,versions,chain):
    """Retain exact ordinary nursery history, without urgent/source aliases.

    The existing direct verifier already checks allocation/physical inputs,
    signed original rights, current Core body/fee, and replacement disposition.
    Bind each same-RR private nursery member to that exact retained version and
    independently observed witness identity/weight; never drop unknown rows.
    """
    inventory=proof['nursery_inventory'];ids={r['txid']for r in inventory}
    if len(ids)!=len(inventory)or set(proof['unrelated_nursery_txids'])!=ids:
        raise EvidenceGap('B final fees: complete whole nursery membership differs')
    for row in inventory:
        ident=row['txid']
        if (row['kind']!='expiry-payout' or row['urgent_fee_bound'] is not False
                or row['urgent_metadata_native_sha256'] is not None or ident not in versions['versions']):
            raise EvidenceGap('B final fees: nonordinary whole nursery source remains unsupported')
        actual=chain.tx(ident)
        if (actual.get('txid')!=ident or actual.get('hash')!=row['wtxid']
                or type(actual.get('weight')) is not int or actual['weight']!=row['weight_wu']
                or actual['weight']!=versions['signed_weight_wu'].get(ident)):
            raise EvidenceGap('B final fees: retained nursery native/current Core witness identity differs')
