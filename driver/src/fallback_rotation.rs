//! Rotate only an explicitly owned destination, once under frozen source terms.
use super::{Request,evidence,hex,native_intent};
use anyhow::{Context,Result,ensure};
use ark::{ProtocolEncoding,attestations::FallbackRecordAttestation};
use bark::Wallet;
use bitcoin::{Address,Network,ScriptBuf,constants::ChainHash};
use serde_json::{Value,json};
use server_rpc::protos::{self,ark_service_client::ArkServiceClient};
use std::{path::Path,str::FromStr};
use tonic::transport::Channel;
fn decode_record(bytes:&[u8],network:Network,mailbox:bitcoin::secp256k1::PublicKey)->Result<(ScriptBuf,u64)>{
 ensure!((73..=114).contains(&bytes.len()),"fallback record length differs");let split=bytes.len()-72;
 let spk=ScriptBuf::from_bytes(bytes[..split].to_vec());let seq=u64::from_le_bytes(bytes[split..split+8].try_into()?);
 ensure!(seq<=i64::MAX as u64,"fallback sequence overflow");
 FallbackRecordAttestation::deserialize(&bytes[split+8..])?.verify(ChainHash::using_genesis_block_const(network),&spk,seq,mailbox)?;
 Ok((spk,seq))
}
async fn server_record(wallet:&Wallet,rpc:&mut ArkServiceClient<Channel>,network:Network)->Result<(ScriptBuf,u64,Vec<u8>)>{
 let mailbox=wallet.mailbox_keypair().public_key();
 let bytes=rpc.set_fallback(protos::SetFallbackRequest{mailbox_pk:mailbox.serialize().to_vec(),record:None,key_links:vec![]}).await?.into_inner().record;
 let (script,seq)=decode_record(&bytes,network,mailbox)?;Ok((script,seq,bytes))
}
pub(super) async fn execute(wallet:&Wallet,rpc:&mut ArkServiceClient<Channel>,path:&Path,req:&Request,network:Network)->Result<Value>{
 ensure!(req.maximum_fee_sat==0,"fallback rotation spends no capital and needs zero fee reserve");
 let phase=req.args["phase"].as_str().unwrap_or("start");ensure!(matches!(phase,"start"|"inspect"),"fallback rotation phase differs");
 let old_script=ScriptBuf::from_hex(req.args["previous_fallback_script"].as_str().context("frozen previous fallback script required")?)?;
 let old_seq=req.args["previous_fallback_seq"].as_u64().context("frozen previous fallback sequence required")?;
 let destination=Address::from_str(req.args["destination"].as_str().context("explicit owned rotation destination required")?)?.require_network(network)?;
 let target=destination.script_pubkey();ensure!(target!=old_script,"fallback rotation must change destination");
 ensure!(wallet.onchain().context("missing owned onchain wallet")?.read().await.is_mine(&target).await?,"rotation destination must be this actor's wallet");
 let existing=native_intent::load(path,req)?;
 let mut intent=match existing {
  Some(intent)=>{ensure!(phase=="inspect","fallback rotation already attempted; inspect original terms only");intent},
  None=>{
   ensure!(phase=="start","no frozen fallback rotation exists");
   let local=wallet.fallback_destination().await?;
   let (server_script,server_seq,raw)=server_record(wallet,rpc,network).await?;
   ensure!(local.spk==old_script && local.seq==old_seq && server_script==old_script && server_seq==old_seq,"previous fallback is not the exact confirmed wallet/server record");
   let proposal=json!({"previous_fallback_script":hex(old_script.as_bytes()),"previous_fallback_seq":old_seq,
    "previous_server_record":hex(&raw),"destination":destination.to_string(),"destination_script":hex(target.as_bytes()),"onchain_ownership_checked":true});
   evidence(req,"fallback_rotation_proposal",proposal.clone())?;
   let intent=native_intent::freeze(req,proposal);native_intent::persist(path,req,&intent)?;
   wallet.set_fallback_destination(target.clone()).await?;intent
  }
 };
 let local=wallet.fallback_destination().await?;
 let (server_script,server_seq,raw)=server_record(wallet,rpc,network).await?;
 ensure!(local.spk==target && local.seq>old_seq && server_script==target && server_seq==local.seq,"rotation remains unresolved or another record superseded its exact destination");
 let result=json!({"fallback_script":hex(target.as_bytes()),"fallback_seq":local.seq,"server_record":hex(&raw),
  "onchain_ownership_checked":true,"exact_server_record_match":true,"actual_fee_sat":0,
  "note":"record rotation checked; expiry payout ownership and chain settlement are separate outcomes"});
 intent.state="completed".into();intent.result=Some(result.clone());native_intent::persist(path,req,&intent)?;Ok(result)
}
#[cfg(test)] mod tests{use super::*;use bitcoin::secp256k1::{Keypair,SecretKey};
 #[test] fn wrong_chain_signature_and_record_tampering_cannot_confirm_rotation(){
  let secret=SecretKey::from_slice(&[42;32]).unwrap();let key=Keypair::from_secret_key(&ark::SECP,&secret);
  let script=ScriptBuf::from_hex(&format!("0014{}","11".repeat(20))).unwrap();let seq=17u64;
  let mut record=script.as_bytes().to_vec();record.extend(seq.to_le_bytes());record.extend(FallbackRecordAttestation::new(ChainHash::SIGNET,&script,seq,&key).serialize());
  assert_eq!(decode_record(&record,Network::Signet,key.public_key()).unwrap(),(script,seq));
  assert!(decode_record(&record,Network::Regtest,key.public_key()).is_err());record[2]^=1;assert!(decode_record(&record,Network::Signet,key.public_key()).is_err());
  assert!(decode_record(&record[..5],Network::Signet,key.public_key()).is_err());
 }
}
