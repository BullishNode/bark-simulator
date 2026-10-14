//! Public signature/commitment proof, with no encoded full VTXO or secret witness.
use anyhow::{Context, Result, ensure, bail};
use ark::{ProtocolEncoding, Vtxo, SECP, vtxo::{Bare, Full}};
use bitcoin::{Transaction, OutPoint, ScriptBuf, Witness};
use bitcoin::consensus::{serialize, deserialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr, XOnlyPublicKey};
use bitcoin::sighash::{SighashCache, Prevouts, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Projection { format: String, bare_vtxo: String, path: Vec<Step> }
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step { transaction: String, output_index: usize, authorization: Authorization }
#[derive(Serialize, Deserialize)]
#[serde(tag="kind", deny_unknown_fields)]
enum Authorization {
    Key { signature: String },
    HashLock { signature: String, script: String, control_block: String },
}

fn hex(bytes:&[u8])->String { bytes.iter().map(|b|format!("{b:02x}")).collect() }
fn decode(raw:&str)->Result<Vec<u8>> {
    ensure!(raw.len()<=4*1024*1024 && raw.len()%2==0 && raw.is_ascii(),"bounded proof hex required");
    (0..raw.len()).step_by(2).map(|i|u8::from_str_radix(&raw[i..i+2],16).map_err(Into::into)).collect()
}

/// Validate the safe representation before public emission, without claiming
/// funding, signature or hashlock-satisfaction verification.
pub fn validate_projection(encoded: &[u8]) -> Result<()> {
    ensure!(encoded.len()<=2*1024*1024, "public projection exceeds bound");
    let p: Projection=serde_json::from_slice(encoded)?;
    ensure!(p.format=="ark-public-authorization-v1" && p.path.len()<=1024,"unsupported public proof format");
    Vtxo::<Bare>::deserialize(&decode(&p.bare_vtxo)?)?;
    for step in p.path {
        let tx:Transaction=deserialize(&decode(&step.transaction)?)?;
        ensure!(tx.input.len()==1 && tx.input[0].witness.is_empty() && tx.input[0].script_sig.is_empty(),"encoded private witness refused");
        ensure!(step.output_index<tx.output.len(),"public selected output absent");
        match step.authorization {
            Authorization::Key{signature}=>ensure!(decode(&signature)?.len()==64,"signature encoding invalid"),
            Authorization::HashLock{signature,script,control_block}=>{
                ensure!(decode(&signature)?.len()==64,"signature encoding invalid");
                hashlock_key(&decode(&script)?)?;
                ControlBlock::decode(&decode(&control_block)?)?;
            },
        }
    }
    Ok(())
}

pub fn encode(coin:&Vtxo<Full>)->Result<Vec<u8>> {
    let mut path=Vec::new();
    for item in coin.transactions() {
        ensure!(path.len()<1024 && item.tx.input.len()==1,"bounded single-input Ark path required");
        let witness=item.tx.input[0].witness.iter().collect::<Vec<_>>();
        let authorization=match witness.as_slice() {
            [signature] if signature.len()==64=>Authorization::Key {signature:hex(signature)},
            [signature, secret, script, control] if signature.len()==64 && secret.len()==32=>{
                // The secret is deliberately not copied into the projection.
                // Independent verification proves signature authority, not the
                // undisclosed hashlock's satisfaction or current spend arbitration.
                hashlock_key(script)?;
                Authorization::HashLock {signature:hex(signature),script:hex(script),control_block:hex(control)}
            },
            _=>bail!("unsupported or unfinished witness cannot become public ownership proof"),
        };
        let mut tx=item.tx;
        tx.input[0].witness=Witness::default();
        path.push(Step {transaction:hex(&serialize(&tx)),output_index:item.output_idx,authorization});
    }
    let result=serde_json::to_vec(&Projection {format:"ark-public-authorization-v1".into(),
        bare_vtxo:hex(&coin.to_bare().serialize()),path})?;
    ensure!(result.len()<=2*1024*1024,"public projection exceeds bound");
    Ok(result)
}

// Accept only the two pinned hArk unlock clauses. No arbitrary script execution
// or caller-supplied signing key is substituted for the committed script.
fn hashlock_key(script:&[u8])->Result<XOnlyPublicKey> {
    let tail=if script.len()==61 && script[..6]==[0x82,0x01,0x20,0x88,0xa9,0x14] {&script[26..]}
        else if script.len()==57 && script[..2]==[0xa9,0x14] {&script[22..]}
        else {bail!("unsupported hashlock script")};
    ensure!(tail.len()==35 && tail[0]==0x88 && tail[1]==0x20 && tail[34]==0xac,"invalid hashlock clause");
    Ok(XOnlyPublicKey::from_slice(&tail[2..34])?)
}

pub struct Verified {
    pub coin: Vtxo<Bare>,
    pub path: Vec<Value>,
    pub ancestor_ids: Vec<String>,
    pub conditional_steps: usize,
}

pub fn verify(encoded:&[u8], funding:&Transaction)->Result<Verified> {
    ensure!(encoded.len()<=2*1024*1024,"public projection exceeds bound");
    let projection:Projection=serde_json::from_slice(encoded)?;
    ensure!(projection.format=="ark-public-authorization-v1" && projection.path.len()<=1024,"unsupported public proof format");
    let coin=Vtxo::<Bare>::deserialize(&decode(&projection.bare_vtxo)?)?;
    ensure!(coin.chain_anchor().txid==funding.compute_txid(),"public proof anchor identity differs");
    let mut point=coin.chain_anchor();
    let mut previous=funding.output.get(point.vout as usize).context("public anchor output absent")?.clone();
    let mut path=Vec::new();
    let mut ancestor_ids=vec![point.to_string()];
    let mut conditional_steps=0;
    for step in projection.path {
        let tx:Transaction=deserialize(&decode(&step.transaction)?)?;
        ensure!(tx.input.len()==1 && tx.input[0].previous_output==point && tx.input[0].witness.is_empty()
            && tx.input[0].script_sig.is_empty(),"public path discontinuity or encoded witness");
        let next=tx.output.get(step.output_index).context("public selected output absent")?;
        let total=tx.output.iter().try_fold(0u64,|s,o|s.checked_add(o.value.to_sat())).context("public path amount overflow")?;
        ensure!(total<=previous.value.to_sat() && previous.script_pubkey.is_p2tr(),"public path creates value or has unsupported funding");
        let output_key=XOnlyPublicKey::from_slice(&previous.script_pubkey.as_bytes()[2..])?;
        let prevouts=[previous.clone()];
        let (signature, sighash, key)=match step.authorization {
            Authorization::Key {signature}=>{
                let hash=SighashCache::new(&tx).taproot_key_spend_signature_hash(0,&Prevouts::All(&prevouts),TapSighashType::Default)?;
                (signature,hash,output_key)
            },
            Authorization::HashLock {signature,script,control_block}=>{
                let script=ScriptBuf::from(decode(&script)?);
                let key=hashlock_key(script.as_bytes())?;
                let control=ControlBlock::decode(&decode(&control_block)?)?;
                ensure!(control.leaf_version==LeafVersion::TapScript && control.verify_taproot_commitment(&SECP,output_key,&script),"hashlock script is not committed by actual prior output");
                let hash=SighashCache::new(&tx).taproot_script_spend_signature_hash(0,&Prevouts::All(&prevouts),TapLeafHash::from_script(&script,LeafVersion::TapScript),TapSighashType::Default)?;
                conditional_steps+=1;
                (signature,hash,key)
            },
        };
        let signature=decode(&signature)?;
        ensure!(signature.len()==64,"only the pinned default signature type is supported");
        SECP.verify_schnorr(&schnorr::Signature::from_slice(&signature)?,&bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array()),&key)
            .context("public path signature invalid")?;
        let txid=tx.compute_txid();
        path.push(json!({"txid":txid.to_string(),"output_index":step.output_index,
            "inputs":[point.to_string()],"transaction":step.transaction,
            "outputs":tx.output.iter().enumerate().map(|(vout,o)|json!({"vout":vout,"value_sat":o.value.to_sat(),"script_pubkey":o.script_pubkey.to_hex_string()})).collect::<Vec<_>>(),"output_amount_sat":next.value.to_sat(),"output_script":next.script_pubkey.to_hex_string()}));
        point=OutPoint::new(txid,u32::try_from(step.output_index)?);
        previous=next.clone();
        ancestor_ids.push(point.to_string());
    }
    ensure!(point==coin.point() && previous==coin.txout(),"public terminal does not match exact policy/value/identity");
    Ok(Verified {coin,path,ancestor_ids,conditional_steps})
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, Sequence, TxIn, TxOut, absolute, transaction};
    use bitcoin::secp256k1::{Keypair, SecretKey};
    use bitcoin_ext::{BlockHeight, BlockDelta};
    use ark::vtxo::policy::VtxoPolicy;

    fn fixture(hashlock:bool)->(Projection,Transaction) {
        let signer=Keypair::from_secret_key(&SECP,&SecretKey::from_slice(&[7;32]).unwrap());
        let server=Keypair::from_secret_key(&SECP,&SecretKey::from_slice(&[8;32]).unwrap());
        let key=signer.x_only_public_key().0;
        let secret=[0xab;32];
        let script=ark::scripts::hash_and_sign(bitcoin::hashes::sha256::Hash::hash(&secret),key);
        let info=bitcoin::taproot::TaprootBuilder::new().add_leaf(0,script.clone()).unwrap().finalize(&SECP,key).unwrap();
        let input_script=if hashlock {ScriptBuf::new_p2tr_tweaked(info.output_key())}
            else {ScriptBuf::new_p2tr(&SECP,key,None)};
        let funding=Transaction {version:transaction::Version::TWO,lock_time:absolute::LockTime::ZERO,
            input:vec![],output:vec![TxOut {value:Amount::from_sat(20_000),script_pubkey:input_script}]};
        let anchor=OutPoint::new(funding.compute_txid(),0);
        let mut bare=Vtxo::<Bare>::new(anchor,VtxoPolicy::new_pubkey(signer.public_key()),Amount::from_sat(19_000),
            BlockHeight::new(144),server.public_key(),BlockDelta::new(12),anchor);
        let mut tx=Transaction {version:transaction::Version::TWO,lock_time:absolute::LockTime::ZERO,
            input:vec![TxIn {previous_output:anchor,script_sig:ScriptBuf::new(),sequence:Sequence::MAX,witness:Witness::default()}],
            output:vec![bare.txout()]};
        let prevouts=[funding.output[0].clone()];
        let hash=if hashlock {SighashCache::new(&tx).taproot_script_spend_signature_hash(0,&Prevouts::All(&prevouts),
            TapLeafHash::from_script(&script,LeafVersion::TapScript),TapSighashType::Default).unwrap()}
            else {SighashCache::new(&tx).taproot_key_spend_signature_hash(0,&Prevouts::All(&prevouts),TapSighashType::Default).unwrap()};
        let signing=if hashlock {signer} else {
            use bitcoin::key::TapTweak;
            signer.tap_tweak(&SECP,None).to_inner()
        };
        let signature=SECP.sign_schnorr_no_aux_rand(&bitcoin::secp256k1::Message::from_digest(hash.to_byte_array()),&signing);
        let authorization=if hashlock {Authorization::HashLock {signature:hex(&signature.serialize()),
            script:hex(script.as_bytes()),control_block:hex(&info.control_block(&(script,LeafVersion::TapScript)).unwrap().serialize())}}
            else {Authorization::Key {signature:hex(&signature.serialize())}};
        bare=Vtxo::<Bare>::new(OutPoint::new(tx.compute_txid(),0),bare.policy().clone(),bare.amount(),bare.expiry_height(),
            bare.server_pubkey(),bare.exit_delta(),anchor);
        tx.input[0].witness=Witness::default();
        (Projection {format:"ark-public-authorization-v1".into(),bare_vtxo:hex(&bare.serialize()),
            path:vec![Step {transaction:hex(&serialize(&tx)),output_index:0,authorization}]},funding)
    }
    #[test]
    fn public_signature_paths_verify_without_secrets() {
        for conditional in [false,true] {
            let (p,f)=fixture(conditional);let bytes=serde_json::to_vec(&p).unwrap();
            assert!(!String::from_utf8(bytes.clone()).unwrap().contains(&hex(&[0xab;32])));
            let proof=verify(&bytes,&f).unwrap();
            assert_eq!(proof.coin.amount(),Amount::from_sat(19_000));
            assert_eq!(proof.conditional_steps,usize::from(conditional));
        }
    }
    #[test]
    fn altered_signatures_and_funding_are_refused() {
        let (mut p,f)=fixture(false);
        if let Authorization::Key {signature}=&mut p.path[0].authorization {*signature=hex(&[1;64]);}
        assert!(verify(&serde_json::to_vec(&p).unwrap(),&f).is_err());
        let (p,mut f)=fixture(true);f.output[0].value=Amount::from_sat(20_001);
        assert!(verify(&serde_json::to_vec(&p).unwrap(),&f).is_err());
    }
    #[test]
    fn injected_witness_and_private_fields_are_refused() {
        let (mut p,f)=fixture(true);
        let mut tx:Transaction=deserialize(&decode(&p.path[0].transaction).unwrap()).unwrap();
        tx.input[0].witness=Witness::from_slice(&[&[0xab;32]]);
        p.path[0].transaction=hex(&serialize(&tx));
        assert!(verify(&serde_json::to_vec(&p).unwrap(),&f).is_err());
        let (p,f)=fixture(true);let mut v=serde_json::to_value(p).unwrap();v["preimage"]=json!("forbidden");
        assert!(verify(&serde_json::to_vec(&v).unwrap(),&f).is_err());
    }
}
