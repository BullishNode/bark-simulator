"""Fixed B private RR fee cut; private producer source proposal only.

No SQL execution, credentials, target selection or public bridge operation is
provided here. The installed root-owned private capturer must bind these exact
query bytes, preserve full stdout and enforce ON_ERROR_STOP/transport bounds.
Raw nursery/package bytes may contain secrets and must NEVER enter public trace.
"""
import hashlib

PUBLIC_OBSERVER_SOURCE_SHA256 = '388a431f45d296ff9006521337431da888ab3847b7c04ec0106c014120ae205f'
PUBLIC_QUERY_PREIMAGE_SHA256 = 'd8ef7abe1faf065608bed9bbb7d5b17223b714d573ffa07b2aaa653ecfd0955f'
# Exact27-table public projection from reviewed claimant_sql(closed=True).
# Keep original table/key/column/order/sentinel limits; no C/A SQL aliases.
PRIMARY_FRAME_SQL = "jsonb_build_object('snapshot',pg_current_snapshot()::text,'observed_at',transaction_timestamp(),'rows',jsonb_build_object('coins',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT vtxo_id,amount,expiry,spend_state,policy_type,encode(policy,'hex') AS policy,anchor_point,vtxo_txid,oor_spent_txid,spent_in_round,offboarded_in,frontier_at,confirmed_height,onchain_spent_height,onchain_spent_txid FROM vtxo WHERE true ORDER BY vtxo_id LIMIT 2001) q),'pending_boards',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT vtxo_id,expiry FROM pending_board WHERE true ORDER BY vtxo_id LIMIT 2001) q),'links',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT encode(user_pubkey,'hex') AS user_pubkey,encode(mailbox_pk,'hex') AS mailbox_pk,child_index FROM key_link WHERE true ORDER BY user_pubkey LIMIT 2001) q),'records',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT encode(mailbox_pk,'hex') AS mailbox_pk,encode(spk,'hex') AS spk,encode(account_xpub,'hex') AS account_xpub,encode(mailbox_sig,'hex') AS mailbox_sig,encode(account_sig,'hex') AS account_sig FROM fallback_record WHERE true ORDER BY mailbox_pk LIMIT 2001) q),'pool',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT id,vtxo_id,expiry_height,amount FROM vtxo_pool WHERE true ORDER BY id LIMIT 2001) q),'lightning_nodes',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT id,encode(pubkey,'hex') AS pubkey FROM lightning_node WHERE true ORDER BY id LIMIT 2001) q),'htlcs',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT h.id,h.payment_hash,h.htlc_expiry,h.direction,h.offchain_resolution,h.chain_resolution,h.chain_resolution_height,EXISTS (SELECT 1 FROM htlc_settlement s WHERE s.payment_hash=h.payment_hash) AS collection_recorded FROM htlc_vtxo h WHERE true ORDER BY h.id LIMIT 2001) q),'receives',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT s.id,s.lightning_node_id,s.payment_hash,s.status,s.lowest_incoming_htlc_expiry,s.accepted_at,s.final_amount_msat,s.receiver_mailbox_id FROM lightning_htlc_subscription s WHERE true ORDER BY s.id LIMIT 2001) q),'payments',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT p.id,p.lightning_node_id,p.payment_hash,p.status,p.amount_msat,p.final_amount_msat,p.sender_mailbox_id,p.lightning_htlc_subscription_id,p.block_height,p.user_fee_sat,p.invoice_expires_at FROM lightning_payment_attempt p WHERE true ORDER BY p.id LIMIT 2001) q),'participations',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT p.id,p.round_id,p.created_at,p.forfeited_at,p.scheduled_height,(p.unlock_preimage IS NOT NULL) AS unlock_available FROM round_participation p WHERE true ORDER BY p.id LIMIT 2001) q),'participation_inputs',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT i.participation_id,i.vtxo_id,(i.signed_forfeit_tx IS NOT NULL) AS forfeit_signed FROM round_part_input i WHERE true ORDER BY i.participation_id,i.vtxo_id LIMIT 2001) q),'participation_outputs',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT o.participation_id,encode(o.policy,'hex') AS policy,o.amount,o.unblinded_mailbox_id FROM round_part_output o WHERE true ORDER BY o.participation_id,o.policy,o.amount LIMIT 2001) q),'journal_allocations',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT id,freeze_set,encode(owner_pubkey,'hex') AS owner_pubkey,encode(spk,'hex') AS spk,disposition,gross_sat,fee_sat,payout_sat,forfeited_sat,source,retirement_ids,frozen_at FROM expiry_allocation WHERE true ORDER BY id LIMIT 2001) q),'journal_carriers',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT txid,generation,backing_ids,fee_inputs,miner_fee_sat,funding_subsidy_sat,created_at,confirmed_height,confirmed_block FROM expiry_carrier WHERE true ORDER BY generation LIMIT 2001) q),'journal_mappings',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT txid,allocation_id,vout FROM expiry_carrier_allocation WHERE true ORDER BY txid,allocation_id LIMIT 2001) q),'journal_records',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT encode(mailbox_pk,'hex') AS mailbox_pk,encode(spk,'hex') AS spk,encode(account_xpub,'hex') AS account_xpub,encode(mailbox_sig,'hex') AS mailbox_sig,encode(account_sig,'hex') AS account_sig FROM fallback_record WHERE true ORDER BY mailbox_pk LIMIT 2001) q),'journal_links',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT encode(user_pubkey,'hex') AS user_pubkey,encode(mailbox_pk,'hex') AS mailbox_pk,child_index FROM key_link WHERE true ORDER BY user_pubkey LIMIT 2001) q),'nursery',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT id,txid,confirm_target_height,confirmed_at_height,abandoned_at,created_at,updated_at,kind FROM nursery_tx WHERE true ORDER BY id LIMIT 2001) q),'rounds',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT id,seq,funding_txid,expiry,swept_at,created_at FROM public.round WHERE true ORDER BY id LIMIT 2001) q)))"

PRIVATE_TABLES = {
    'native_funding_fee_intent': ('native_funding_fee_intent', 'attempt_key',
        "attempt_key,reservation,encode(signed_tx,'hex') AS signed_tx_hex"),
    'native_funding_fee_input': ('native_funding_fee_input', 'outpoint,attempt_key',
        'outpoint,attempt_key'),
    'native_funding_fee_resolution': ('native_funding_fee_resolution', 'winner_index',
        'winner_index,proof'),
    'nursery_tx': ('nursery_tx', 'id',
        "txid,encode(tx,'hex') AS tx_hex,kind::text AS kind,urgent_fee_attempt,urgent_fee_bound"),
}

# Bound the WHOLE private set before selecting raw bytes. No prefix LIMIT,
# active-only filter, metadata-only parent omission or error suppression.
PRIVATE_BOUND_SQL = """DO $b_native_fee_cut$ BEGIN
IF (SELECT count(*)>4096 FROM native_funding_fee_intent)
OR (SELECT count(*)>10000 FROM native_funding_fee_input)
OR (SELECT count(*)>4096 FROM native_funding_fee_resolution)
OR (SELECT count(*)>10000 FROM nursery_tx)
OR (SELECT coalesce(sum(octet_length(reservation::text)+coalesce(octet_length(signed_tx),0)),0)
    FROM native_funding_fee_intent)
 + (SELECT coalesce(sum(octet_length(outpoint)+octet_length(attempt_key)),0) FROM native_funding_fee_input)
 + (SELECT coalesce(sum(octet_length(proof::text)),0) FROM native_funding_fee_resolution)
 + (SELECT coalesce(sum(octet_length(tx)+coalesce(octet_length(urgent_fee_attempt::text),0)),0) FROM nursery_tx)
 > 16777216
THEN RAISE EXCEPTION 'bounded complete native fee source unavailable'; END IF;
END $b_native_fee_cut$;"""


def sql():
    """One no-argument fixed RR transaction, yielding two original JSON lines.

    SELECT1 is the existing public closed-frontier object directly in SQL, so
    the exact emitted first JSON bytes are target.raw_sql. SELECT2 is the full
    private native validator input. Both share pg_current_snapshot(), and the
    private native codec verifies all retained packages/NULL parent members.
    """
    fields=[]
    for name,(table,key,columns) in PRIVATE_TABLES.items():
        fields.append("'"+name+"',(SELECT coalesce(jsonb_agg(q),'[]'::jsonb) FROM (SELECT "+
            columns+" FROM "+table+" ORDER BY "+key+") q)")
    public="("+PRIMARY_FRAME_SQL+" || jsonb_build_object('kind','closed_frontier'," + \
        "'schema_version',1,'fallback_protocol',3,'read_only',current_setting('transaction_read_only')='on'," + \
        "'inventory_consistent',current_setting('transaction_isolation')='repeatable read'," + \
        "'database_tables_complete',true,'row_limit_total',2000,'complete',false,'qualified',false))"
    return "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='8s'; " + \
        PRIVATE_BOUND_SQL+" SELECT "+public+"; SELECT jsonb_build_object("+','.join(fields)+"); COMMIT;"


def query_sha256():
    return hashlib.sha256(sql().encode()).hexdigest()
