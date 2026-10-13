//! An explicitly scheduled delegated refresh; no retry on uncertain submission.
use super::{Request,evidence,hex,native_intent};
use anyhow::{Context,Result,ensure};
use ark::{ProtocolEncoding,VtxoId};
use bark::{Wallet,subsystem::RoundMovement};
use serde_json::{Value,json};
use std::{collections::HashSet,path::Path,str::FromStr};
fn safe_height(tip:u32,height:u32,expiries:&[u32],confirmations:u32,margin:u32)->Result<()> {
 ensure!(!expiries.is_empty() && confirmations>0 && margin>0 && height>tip,"future schedule and preserved margins required");
 let boundary=height.checked_add(confirmations).and_then(|h|h.checked_add(margin)).context("schedule margin overflow")?;
 ensure!(expiries.iter().all(|expiry|boundary<*expiry),"scheduled refresh consumes input exitability margin");Ok(())
}
pub(super) async fn execute(wallet:&Wallet,path:&Path,req:&Request)->Result<Value>{
 let phase=req.args["phase"].as_str().unwrap_or("start");ensure!(matches!(phase,"start"|"inspect"),"scheduled refresh phase differs");
 if let Some(intent)=native_intent::load(path,req)? {
  ensure!(phase=="inspect","scheduled refresh already attempted; inspect original intent only");
  return Ok(json!({"action_id":intent.action_id,"scheduled_height":intent.args["scheduled_height"],"state":intent.state,
   "proposal":intent.proposal,"result":intent.result,"actual_fee_sat":Value::Null,"read_only":true,
   "note":"no delegated resubmission; reconcile the original entitlement and independent signed outputs"}));
 }
 ensure!(phase=="start","no scheduled refresh intent exists");
 let height:u32=req.args["scheduled_height"].as_u64().context("explicit scheduled height required")?.try_into()?;
 let rows=req.args["input_vtxo_ids"].as_array().context("exact scheduled inputs required")?;
 ensure!(!rows.is_empty() && rows.len()<=16,"scheduled refresh requires 1–16 explicit inputs");
 let mut seen=HashSet::new();let mut inputs=Vec::new();let mut signed=Vec::new();let mut expiries=Vec::new();
 for id in rows {
  let id=VtxoId::from_str(id.as_str().context("invalid scheduled input")?)?;ensure!(seen.insert(id),"duplicate scheduled inputs");
  let coin=wallet.get_vtxo_by_id(id).await?;
  ensure!(coin.state.kind()==bark::vtxo::VtxoStateKind::Spendable,"scheduled input is locked or unavailable");
  let full=wallet.get_full_vtxo(id).await?;full.check_standard()?;wallet.validate_vtxo(&full).await?;
  ensure!(wallet.pubkey_keypair(&full.user_pubkey()).await?.is_some(),"scheduled input is not owned");
  expiries.push(full.expiry_height().to_u32());signed.push(hex(&full.serialize()));inputs.push(coin);
 }
 let tip=wallet.chain().tip().await?.to_u32();safe_height(tip,height,&expiries,wallet.config().round_tx_required_confirmations.to_u32(),wallet.config().vtxo_exit_margin.to_u32())?;
 let participation=wallet.build_scheduled_refresh_participation(inputs,height.into()).await?.context("no scheduled inputs")?;
 let fee=participation.total_in().context("scheduled input overflow")?.checked_sub(participation.total_out().context("scheduled output overflow")?).context("scheduled refresh creates value")?.to_sat();
 if fee>req.maximum_fee_sat{return Ok(json!({"blocked":true,"reason":"scheduled refresh fee exceeds immutable reserve","actual_fee_sat":0}));}
 let proposal=json!({"participation":participation,"committed_fee_sat":fee,"scheduled_height":height,"input_vtxo_ids":rows,
  "signed_input_vtxos":signed,"tip":tip,"round_tx_required_confirmations":wallet.config().round_tx_required_confirmations.to_u32(),
  "vtxo_exit_margin":wallet.config().vtxo_exit_margin.to_u32()});
 evidence(req,"refresh_proposal",proposal.clone())?;
 let mut intent=native_intent::freeze(req,proposal);native_intent::persist(path,req,&intent)?;
 let state=wallet.join_delegated_round(participation,Some(RoundMovement::Refresh),Some(height.into())).await?;
 let result=json!({"round_state_id":state.id().to_string(),"scheduled_height":height,"committed_fee_sat":fee,
  "actual_fee_sat":Value::Null,"note":"submitted delegated entitlement; independent signed replacements and fees required"});
 intent.state="submitted".into();intent.result=Some(result.clone());native_intent::persist(path,req,&intent)?;Ok(result)
}
#[cfg(test)] mod tests{use super::*;
 #[test] fn future_schedule_never_uses_the_confirmation_or_exit_margin(){assert!(safe_height(100,105,&[140,145],3,6).is_ok());
  for h in [100,131,132,u32::MAX]{assert!(safe_height(100,h,&[140],3,6).is_err());}
  assert!(safe_height(100,105,&[],3,6).is_err());assert!(safe_height(100,105,&[140],0,6).is_err());assert!(safe_height(100,105,&[140],3,0).is_err());
 }
}
