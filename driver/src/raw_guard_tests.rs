#[path="raw_guard.rs"] mod raw_guard;
use raw_guard::classify;
#[test] fn generic_invalid_argument_is_not_target_guard() {
 assert_eq!(classify("D14","RequestArkoorCosign","InvalidArgument","invalid nonce","key"),"other");
 assert_eq!(classify("D14","RequestArkoorCosign","Unavailable","missing fallback link or wallet record for coin key key; call SetFallback before creating coins","key"),"other");
}
#[test] fn missing_key_guard_binds_exact_rpc_scenario_and_output_key() {
 let msg="missing fallback link or wallet record for coin key key; call SetFallback before creating coins";
 assert_eq!(classify("D14","RequestArkoorCosign","InvalidArgument",msg,"key"),"missing_fallback");
 assert_eq!(classify("D14","SubmitPayment","InvalidArgument",msg,"key"),"other");
 assert_eq!(classify("D14","RequestArkoorCosign","InvalidArgument",msg,"another"),"other");
}
#[test] fn paid_and_pending_refund_have_distinct_predicates() {
 assert_eq!(classify("D29","RequestLightningPayHtlcRevocation","InvalidArgument","invoice has already been paid",""),"paid_refund");
 assert_eq!(classify("D30","RequestLightningPayHtlcRevocation","InvalidArgument","This lightning payment is not eligible for revocation yet",""),"pending_refund");
 assert_eq!(classify("D29","RequestLightningPayHtlcRevocation","InvalidArgument","This lightning payment is not eligible for revocation yet",""),"other");
}
#[test] fn collected_expiry_and_held_expiry_are_not_equivalent() {
 assert_eq!(classify("D35","PrepareLightningReceiveClaim","InvalidArgument","requested HTLC recv expiry 4294967295 is above 326184",""),"collected_expiry_cap");
 assert_eq!(classify("D35","PrepareLightningReceiveClaim","InvalidArgument","requested HTLC recv expiry is excessively high",""),"other");
}
#[test] fn claim_replay_success_is_candidate_not_a_refusal() {
 assert_eq!(classify("D31","ClaimLightningReceive","Ok","",""),"replay_candidate");
 assert_eq!(classify("D32","ClaimLightningReceive","InvalidArgument","preimage doesn't match payment hash",""),"wrong_preimage");
 assert_eq!(classify("D31","ClaimLightningReceive","InvalidArgument","preimage doesn't match payment hash",""),"other");
}
