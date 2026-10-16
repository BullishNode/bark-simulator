use bitcoin::hashes::{Hash,sha256};
use bitcoin::secp256k1::{Message,Secp256k1,SecretKey};
use lightning_invoice::{Currency,InvoiceBuilder,PaymentSecret};
use noah_public_proof::{InvoicePolicy,validate_invoice,validate_login_signature};
use std::io::Write;
use std::process::{Command,Stdio};
use std::time::Duration;

fn invoice(description_hash:bool)->String {
    invoice_with_currency(description_hash,Currency::Signet)
}

fn invoice_with_currency(description_hash:bool,currency:Currency)->String {
    let key=SecretKey::from_slice(&[42;32]).unwrap();
    let builder=InvoiceBuilder::new(currency)
        .amount_milli_satoshis(5_000_000)
        .payment_hash(sha256::Hash::hash(b"fixture payment hash, no monetary value"))
        .duration_since_epoch(Duration::from_secs(1000))
        .expiry_time(Duration::from_secs(600))
        .payment_secret(PaymentSecret([7;32])).min_final_cltv_expiry_delta(18);
    let signed=if description_hash {
        builder.description_hash(sha256::Hash::hash(b"[[\"text/plain\",\"recipient\"]]"))
            .build_signed(|message|Secp256k1::new().sign_ecdsa_recoverable(message,&key)).unwrap()
    }else{
        builder.description("Paying satoshis to recipient".into())
            .build_signed(|message|Secp256k1::new().sign_ecdsa_recoverable(message,&key)).unwrap()
    };
    signed.to_string()
}

fn policy()->InvoicePolicy {
    InvoicePolicy {invoice:invoice(true),amount_msat:5_000_000,metadata:"[[\"text/plain\",\"recipient\"]]".into(),network:"signet".into(),now:1100}
}

#[test]
fn validates_a_genuinely_signed_metadata_invoice_offline(){
    let proof=validate_invoice(&policy()).unwrap();
    assert_eq!(proof["amount_msat"],5_000_000);assert_eq!(proof["expires_at"],1600);
    assert_eq!(proof["signature_checked"],true);assert_eq!(proof["network"],"signet");
}

#[test]
fn pinned_plain_description_is_a_compatibility_failure(){
    let mut request=policy();request.invoice=invoice(false);
    assert!(validate_invoice(&request).unwrap_err().to_string().contains("metadata"));
}

#[test]
fn rejects_changed_metadata_amount_network_expiry_and_future_issue(){
    for variant in 0..5 {
        let mut request=policy();match variant {
            0=>request.metadata.push(' '),1=>request.amount_msat+=1,
            2=>request.network="regtest".into(),3=>request.now=1600,
            _=>request.now=950,
        };
        assert!(validate_invoice(&request).is_err());
    }
}

#[test]
fn rejects_mutated_signature_or_unsigned_text(){
    let mut request=policy();request.invoice="not an invoice".into();assert!(validate_invoice(&request).is_err());
    request=policy();let last=request.invoice.pop().unwrap();request.invoice.push(if last=='q' {'p'} else {'q'});
    assert!(validate_invoice(&request).is_err());
}

#[test]
fn signet_policy_accepts_signed_tb_and_tbs_but_retains_metadata_amount_and_expiry(){
    for currency in [Currency::BitcoinTestnet,Currency::Signet] {
        let mut request=policy();request.invoice=invoice_with_currency(true,currency);
        let proof=validate_invoice(&request).unwrap();
        assert_eq!(proof["network"],"signet");assert_eq!(proof["signature_checked"],true);
        for variant in 0..4 {
            let mut changed=InvoicePolicy {invoice:request.invoice.clone(),amount_msat:request.amount_msat,
                metadata:request.metadata.clone(),network:request.network.clone(),now:request.now};
            match variant {
                0=>changed.metadata.push(' '),1=>changed.amount_msat+=1,
                2=>changed.now=1600,_=>changed.network="regtest".into(),
            };
            assert!(validate_invoice(&changed).is_err());
        }
    }
}

#[test]
fn regtest_policy_accepts_regtest_but_refuses_simnet_network_alias(){
    let mut request=policy();request.network="regtest".into();
    request.invoice=invoice_with_currency(true,Currency::Regtest);
    assert!(validate_invoice(&request).is_ok());
    request.invoice=invoice_with_currency(true,Currency::Simnet);
    assert!(validate_invoice(&request).is_err());
}

#[test]
fn signet_policy_refuses_signed_mainnet_regtest_and_simnet_currencies(){
    for currency in [Currency::Bitcoin,Currency::Regtest,Currency::Simnet] {
        let mut request=policy();request.invoice=invoice_with_currency(true,currency);
        assert!(validate_invoice(&request).is_err());
    }
}

#[test]
fn actual_offline_cli_preserves_currency_metadata_and_policy_boundaries(){
    for (network,currency,metadata_valid,accepted) in [
        ("signet",Currency::BitcoinTestnet,true,true),
        ("signet",Currency::Signet,true,true),
        ("regtest",Currency::Regtest,true,true),
        ("regtest",Currency::Simnet,true,false),
        ("signet",Currency::Bitcoin,true,false),
        ("signet",Currency::BitcoinTestnet,false,false),
    ] {
        let mut request=policy();request.network=network.into();
        request.invoice=invoice_with_currency(true,currency);
        if !metadata_valid {request.metadata.push(' ');}
        let body=serde_json::json!({"invoice":request.invoice,"amount_msat":request.amount_msat,
            "metadata":request.metadata,"network":request.network,"now":request.now});
        let mut child=Command::new(env!("CARGO_BIN_EXE_noah-public-proof"))
            .env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().unwrap();
        child.stdin.take().unwrap().write_all(serde_json::to_vec(&body).unwrap().as_slice()).unwrap();
        let output=child.wait_with_output().unwrap();
        assert_eq!(output.status.success(),accepted);
        if accepted {
            let proof:serde_json::Value=serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(proof["signature_checked"],true);assert_eq!(proof["network"],network);
            assert_eq!(proof["amount_msat"],5_000_000);assert_eq!(proof["expires_at"],1600);
            assert_eq!(proof.as_object().unwrap().len(),8);
        } else {assert!(output.stdout.is_empty());}
    }
}

#[test]
fn noah_login_is_bitcoin_message_ecdsa_der_not_lnurl_raw_or_ark_schnorr(){
    let secp=Secp256k1::new();let key=SecretKey::from_slice(&[42;32]).unwrap();
    let public=key.public_key(&secp);let challenge=format!("{}_1000","ab".repeat(32));
    let digest=bitcoin::sign_message::signed_msg_hash(&challenge);
    let signed=secp.sign_ecdsa(&Message::from_digest(digest.to_byte_array()),&key);
    assert!(validate_login_signature(&challenge,&signed.to_string(),&public.to_string()).is_ok());
    assert!(validate_login_signature(&(challenge.clone()+"0"),&signed.to_string(),&public.to_string()).is_err());
    let raw=Message::from_digest([0xab;32]);let incorrect=secp.sign_ecdsa(&raw,&key);
    assert!(validate_login_signature(&challenge,&incorrect.to_string(),&public.to_string()).is_err());
}
