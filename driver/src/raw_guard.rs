//! Pinned protocol response predicates. Transport/generic failures earn no credit.
pub fn classify(scenario: &str, rpc: &str, code: &str, message: &str, key: &str) -> &'static str {
    let expected = match scenario {
        "D13" => "SubmitPayment",
        "D14" | "D21" => "RequestArkoorCosign",
        "D15" | "D35" => "PrepareLightningReceiveClaim",
        "D16" => "RequestLightningPayHtlcCosign",
        "D22" | "D23" | "D25" => "RegisterVtxoTransactions",
        "D29" | "D30" => "RequestLightningPayHtlcRevocation",
        "D31" | "D32" => "ClaimLightningReceive",
        _ => return "other",
    };
    if rpc != expected {
        return "other";
    }
    if code == "Ok" {
        return if matches!(scenario, "D22" | "D31") {
            "replay_candidate"
        } else {
            "unexpected_acceptance"
        };
    }
    if code != "InvalidArgument" {
        return "other";
    }
    match scenario {
        "D13" | "D14" | "D15" | "D16"
            if !key.is_empty()
                && message.contains("missing fallback link or wallet record")
                && message.contains(&format!("coin key {key};")) =>
        {
            "missing_fallback"
        }
        "D21"
            if message.ends_with("VTXO already committed to an expiry settlement")
                || message.contains("is not spendable (state: spent)") =>
        {
            "settled"
        }
        "D23" | "D25"
            if message.contains("invalid vtxo:")
                || message.contains("vtxo validation failed")
                || message.contains("is not fully signed") =>
        {
            "invalid_chain"
        }
        "D29"
            if message.contains("invoice has already been paid")
                || message.contains("This lightning payment has completed") =>
        {
            "paid_refund"
        }
        "D30"
            if message.contains("This lightning payment is not eligible for revocation yet")
                || message.contains("cannot revoke: the payment can still be claimed") =>
        {
            "pending_refund"
        }
        "D32" if message.contains("preimage doesn't match payment hash") => "wrong_preimage",
        "D35"
            if message.contains("requested HTLC recv expiry ")
                && message.contains(" is above ") =>
        {
            "collected_expiry_cap"
        }
        _ => "other",
    }
}
