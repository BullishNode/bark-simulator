-- ROOT REVIEW/INSTALL ONLY. C worker has NOT executed this SQL.
-- Run only in the isolated C database trackc after product migrations.
-- Review existing grants/memberships first; these additive grants cannot revoke old private access.
-- Requires matching C observer public-presence-view patch; original9358 producer still references private base columns.
BEGIN;
CREATE OR REPLACE VIEW public.track_c_observer_round_participation
WITH (security_barrier = true, security_invoker = false) AS
SELECT id, round_id, created_at, forfeited_at, scheduled_height,
       (unlock_preimage IS NOT NULL) AS unlock_available
FROM public.round_participation;
ALTER VIEW public.track_c_observer_round_participation OWNER TO trackcserver;
CREATE OR REPLACE VIEW public.track_c_observer_round_part_input
WITH (security_barrier = true, security_invoker = false) AS
SELECT participation_id, vtxo_id, (signed_forfeit_tx IS NOT NULL) AS forfeit_signed
FROM public.round_part_input;
ALTER VIEW public.track_c_observer_round_part_input OWNER TO trackcserver;
REVOKE ALL ON public.track_c_observer_round_participation, public.track_c_observer_round_part_input FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO trackcobserver;
GRANT SELECT (id, freeze_set, owner_pubkey, spk, disposition, gross_sat, fee_sat, payout_sat, forfeited_sat, source, retirement_ids, frozen_at) ON TABLE public."expiry_allocation" TO trackcobserver;
GRANT SELECT (txid, generation, backing_ids, fee_inputs, miner_fee_sat, funding_subsidy_sat, created_at, confirmed_height, confirmed_block) ON TABLE public."expiry_carrier" TO trackcobserver;
GRANT SELECT (txid, allocation_id, vout) ON TABLE public."expiry_carrier_allocation" TO trackcobserver;
GRANT SELECT (mailbox_pk, spk, mailbox_sig) ON TABLE public."fallback_record" TO trackcobserver;
GRANT SELECT (payment_hash) ON TABLE public."htlc_settlement" TO trackcobserver;
GRANT SELECT (id, payment_hash, htlc_expiry, direction, offchain_resolution, chain_resolution, chain_resolution_height) ON TABLE public."htlc_vtxo" TO trackcobserver;
GRANT SELECT (user_pubkey, mailbox_pk, sig, recovery_index) ON TABLE public."key_link" TO trackcobserver;
GRANT SELECT (id, lightning_node_id, payment_hash, status, lowest_incoming_htlc_expiry, accepted_at, final_amount_msat, receiver_mailbox_id) ON TABLE public."lightning_htlc_subscription" TO trackcobserver;
GRANT SELECT (id, pubkey) ON TABLE public."lightning_node" TO trackcobserver;
GRANT SELECT (id, lightning_node_id, payment_hash, status, amount_msat, final_amount_msat, sender_mailbox_id, lightning_htlc_subscription_id, block_height, user_fee_sat, invoice_expires_at) ON TABLE public."lightning_payment_attempt" TO trackcobserver;
GRANT SELECT (lightning_payment_attempt_id, vtxo_id) ON TABLE public."lightning_payment_attempt_htlc_vtxo" TO trackcobserver;
GRANT SELECT (id, txid, confirm_target_height, confirmed_at_height, abandoned_at, created_at, updated_at, kind) ON TABLE public."nursery_tx" TO trackcobserver;
GRANT SELECT (id, vtxo_id, expiry) ON TABLE public."pending_board" TO trackcobserver;
GRANT SELECT (id, seq, funding_txid, expiry, swept_at, created_at) ON TABLE public."round" TO trackcobserver;
GRANT SELECT (participation_id, policy, amount, unblinded_mailbox_id) ON TABLE public."round_part_output" TO trackcobserver;
GRANT SELECT (id, vtxo_id, amount, expiry, spend_state, policy_type, policy, anchor_point, vtxo_txid, oor_spent_txid, spent_in_round, offboarded_in, frontier_at, confirmed_height, onchain_spent_height, onchain_spent_txid, lightning_htlc_subscription_id) ON TABLE public."vtxo" TO trackcobserver;
GRANT SELECT (id, vtxo_id, expiry_height, amount, spent_at) ON TABLE public."vtxo_pool" TO trackcobserver;
GRANT SELECT (id, round_id, created_at, forfeited_at, scheduled_height, unlock_available) ON TABLE public.track_c_observer_round_participation TO trackcobserver;
GRANT SELECT (participation_id, vtxo_id, forfeit_signed) ON TABLE public.track_c_observer_round_part_input TO trackcobserver;
ALTER ROLE trackcobserver IN DATABASE trackc SET search_path = pg_catalog, public, pg_temp;
COMMIT;
-- Final source/schema receipt must identify these views and the exact deployed observer hash.
-- No grants above authorize unlock_preimage, signed_forfeit_tx, source_evidence, encoded VTXO, raw transaction or witnesses.
