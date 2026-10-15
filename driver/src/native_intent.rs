//! Once-only public operation terms, durably frozen before signing/submission.
use anyhow::{Result,ensure};
use bitcoin::hashes::{Hash,sha256};
use serde::{Deserialize,Serialize};
use serde_json::Value;
use std::{fs,io::Write,os::unix::fs::{OpenOptionsExt,PermissionsExt},path::{Path,PathBuf}};
use super::Request;

#[derive(Deserialize,Serialize)]
pub(super) struct Intent {pub action_id:String,pub operation:String,pub server_pubkey:String,pub args:Value,
 pub fee_cap_sat:u64,pub state:String,pub proposal:Value,pub result:Option<Value>}
fn path(root:&Path,req:&Request)->PathBuf {root.join(format!("sim-native-{}.json",sha256::Hash::hash(req.action_id.as_bytes())))}
pub(super) fn load(root:&Path,req:&Request)->Result<Option<Intent>> {
 let file=path(root,req);let m=match fs::symlink_metadata(&file){Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None),Err(e)=>return Err(e.into()),Ok(m)=>m};
 ensure!(m.is_file() && !m.file_type().is_symlink() && m.permissions().mode()&0o077==0,"native intent must be private and regular");
 ensure!(m.len()<=1024*1024,"native intent exceeds bound");let intent:Intent=serde_json::from_slice(&fs::read(file)?)?;
 ensure!(intent.action_id==req.action_id && intent.operation==req.operation && intent.server_pubkey==req.expected_server_pubkey
    && intent.args==terms(req) && intent.fee_cap_sat==req.maximum_fee_sat,"native frozen operation terms changed");
 Ok(Some(intent))
}
fn terms(req:&Request)->Value {let mut args=req.args.clone();if let Some(args)=args.as_object_mut(){args.remove("phase");}args}
pub(super) fn freeze(req:&Request,proposal:Value)->Intent {Intent{action_id:req.action_id.clone(),operation:req.operation.clone(),server_pubkey:req.expected_server_pubkey.clone(),args:terms(req),fee_cap_sat:req.maximum_fee_sat,state:"outcome_unknown".into(),proposal,result:None}}
pub(super) fn persist(root:&Path,req:&Request,intent:&Intent)->Result<()> {
 let file=path(root,req);let tmp=file.with_extension(format!("{}.tmp",std::process::id()));
 let mut writer=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
 writer.write_all(&serde_json::to_vec(intent)?)?;writer.sync_all()?;fs::rename(tmp,file)?;fs::File::open(root)?.sync_all()?;Ok(())
}
fn holds_wallet(intent:&Intent)->bool {
 matches!(intent.operation.as_str(),"fallback_record_check"|"fallback_rotate"|"refresh_scheduled") && intent.state!="completed"
}
fn conflicts(intent:&Intent,req:&Request)->bool {
 if !holds_wallet(intent) || req.operation=="snapshot" {return false;}
 // A generic sync can rebuild/redelegate SDK round states. Only the exact
 // original inspection is admitted until independent reconciliation closes it.
 !(req.operation==intent.operation && req.action_id==intent.action_id
   && req.expected_server_pubkey==intent.server_pubkey && req.maximum_fee_sat==intent.fee_cap_sat
   && terms(req)==intent.args && req.args.get("phase").and_then(Value::as_str)==Some("inspect"))
}
fn read_intents(root:&Path)->Result<Vec<Intent>> {
 let mut intents=Vec::new();
 for entry in fs::read_dir(root)? {let entry=entry?;let name=entry.file_name();let name=name.to_string_lossy();
  if name.starts_with("sim-native-") && name.ends_with(".json"){
   let m=fs::symlink_metadata(entry.path())?;ensure!(m.is_file() && !m.file_type().is_symlink() && m.permissions().mode()&0o077==0 && m.len()<=1024*1024,"unsafe native intent");
   intents.push(serde_json::from_slice(&fs::read(entry.path())?)?);
  }
 }Ok(intents)
}
#[cfg(test)] fn has_unresolved_intent(root:&Path)->Result<bool>{Ok(read_intents(root)?.iter().any(holds_wallet))}
pub(super) fn conflicting_wallet_intent(root:&Path,req:&Request)->Result<Option<String>> {
 for intent in read_intents(root)? {
  if conflicts(&intent,req) {return Ok(Some(intent.action_id));}
 }Ok(None)
}
#[cfg(test)] mod tests{
 use super::*;use serde_json::json;
 #[test] fn unresolved_two_step_rotation_fences_wallet_after_reload_until_exact_inspection_completes(){
  let root=std::env::temp_dir().join(format!("sim-native-a-rotation-hold-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
  fs::create_dir(&root).unwrap();fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
  let original=Request{operation:"fallback_rotate".into(),action_id:"lost-rotation-reply".into(),actor_dir:None,expected_server_pubkey:"server".into(),
   args:json!({"phase":"start","previous_fallback_script":"00140000000000000000000000000000000000000000","previous_fallback_seq":7,"destination":"owned-destination"}),maximum_fee_sat:0};
  let mut intent=freeze(&original,json!({"destination_script":"00141111111111111111111111111111111111111111"}));
  persist(&root,&original,&intent).unwrap(); // durable uncertainty survives losing the process/reply
  let mut request=Request{operation:"sync".into(),action_id:"new-sync".into(),actor_dir:None,expected_server_pubkey:"server".into(),args:json!({}),maximum_fee_sat:0};
  assert_eq!(conflicting_wallet_intent(&root,&request).unwrap().as_deref(),Some("lost-rotation-reply"));
  request.operation="snapshot".into();assert!(conflicting_wallet_intent(&root,&request).unwrap().is_none());
  request.operation=original.operation.clone();request.action_id=original.action_id.clone();request.args=original.args.clone();
  assert!(conflicting_wallet_intent(&root,&request).unwrap().is_some(),"start cannot replay the rotation");
  request.args["phase"]=json!("inspect");assert!(conflicting_wallet_intent(&root,&request).unwrap().is_none());
  request.args["destination"]=json!("other-destination");assert!(conflicting_wallet_intent(&root,&request).unwrap().is_some());
  request.args=original.args.clone();request.args["phase"]=json!("inspect");request.expected_server_pubkey="other-server".into();
  assert!(conflicting_wallet_intent(&root,&request).unwrap().is_some());
  request.expected_server_pubkey=original.expected_server_pubkey.clone();request.maximum_fee_sat=1;
  assert!(conflicting_wallet_intent(&root,&request).unwrap().is_some());
  intent.state="completed".into();persist(&root,&original,&intent).unwrap();
  assert!(conflicting_wallet_intent(&root,&request).unwrap().is_none());
  fs::remove_dir_all(root).unwrap();
 }
 #[test] fn submitted_scheduled_refresh_keeps_a_restart_safe_wallet_hold(){
  let root=std::env::temp_dir().join(format!("sim-native-scheduled-hold-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
  fs::create_dir(&root).unwrap();fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
  let req=Request{operation:"refresh_scheduled".into(),action_id:"original-schedule".into(),actor_dir:None,expected_server_pubkey:"server".into(),
   args:json!({"phase":"start","input_vtxo_ids":["coin"],"scheduled_height":123}),maximum_fee_sat:100};
  let mut intent=freeze(&req,json!({"committed_fee_sat":12}));intent.state="submitted".into();persist(&root,&req,&intent).unwrap();
  let held=has_unresolved_intent(&root).unwrap();fs::remove_dir_all(&root).unwrap();
  assert!(held,"an ACKed scheduled refresh must retain its exact-input wallet hold across restart");
 }
 #[test] fn a_new_action_cannot_supersede_frozen_scheduled_inputs_or_rotation(){
  for operation in ["refresh_scheduled","fallback_record_check"] {
   let mut original=Request{operation:operation.into(),action_id:"original".into(),actor_dir:None,expected_server_pubkey:"server".into(),
    args:json!({"phase":"start","input_vtxo_ids":["coin"],"scheduled_height":123}),maximum_fee_sat:100};
   let mut intent=freeze(&original,json!({}));intent.state="submitted".into();
   assert!(conflicts(&intent,&original)); // start cannot replay even its original ID
   original.args["phase"]=json!("inspect");assert!(!conflicts(&intent,&original));
   original.action_id="different".into();assert!(conflicts(&intent,&original));
   original.action_id="original".into();original.maximum_fee_sat=101;assert!(conflicts(&intent,&original));
   original.maximum_fee_sat=100;original.args["scheduled_height"]=json!(124);assert!(conflicts(&intent,&original));
   for mutation in ["refresh_scheduled","refresh_delegated","refresh","send_arkoor","offboard_all","exit","sync","fallback_record_check"] {
    original.operation=mutation.into();original.args["phase"]=json!("start");assert!(conflicts(&intent,&original),"{mutation} must preserve {operation}");
   }
   original.operation="snapshot".into();assert!(!conflicts(&intent,&original));
   original.operation="sync".into();intent.state="outcome_unknown".into();assert!(conflicts(&intent,&original));
   intent.state="completed".into();assert!(!conflicts(&intent,&original));
  }
 }
 #[test] fn terms_do_not_change_under_inspection_but_cap_source_and_inputs_do(){
  let req=Request{operation:"refresh_scheduled".into(),action_id:"original".into(),actor_dir:None,expected_server_pubkey:"server".into(),
   args:json!({"phase":"start","input_vtxo_ids":["coin"],"scheduled_height":123}),maximum_fee_sat:100};
  let intent=freeze(&req,json!({"committed_fee_sat":12}));assert_eq!(intent.state,"outcome_unknown");
  let mut inspect=req;inspect.args["phase"]=json!("inspect");assert_eq!(terms(&inspect),intent.args);
  inspect.args["input_vtxo_ids"]=json!(["another"]);assert_ne!(terms(&inspect),intent.args);
 }
}
