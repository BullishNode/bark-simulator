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
pub(super) fn has_unresolved_rotation(root:&Path)->Result<bool>{
 for entry in fs::read_dir(root)? {let entry=entry?;let name=entry.file_name();let name=name.to_string_lossy();
  if name.starts_with("sim-native-") && name.ends_with(".json"){
   let m=fs::symlink_metadata(entry.path())?;ensure!(m.is_file() && !m.file_type().is_symlink() && m.permissions().mode()&0o077==0 && m.len()<=1024*1024,"unsafe native intent");
   let intent:Intent=serde_json::from_slice(&fs::read(entry.path())?)?;
   if intent.operation=="fallback_rotate" && intent.state!="completed" {return Ok(true);}
  }
 }Ok(false)
}
#[cfg(test)] mod tests{
 use super::*;use serde_json::json;
 #[test] fn submitted_scheduled_refresh_keeps_a_restart_safe_wallet_hold(){
  let root=std::env::temp_dir().join(format!("sim-native-scheduled-hold-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
  fs::create_dir(&root).unwrap();fs::set_permissions(&root,fs::Permissions::from_mode(0o700)).unwrap();
  let req=Request{operation:"refresh_scheduled".into(),action_id:"original-schedule".into(),actor_dir:None,expected_server_pubkey:"server".into(),
   args:json!({"phase":"start","input_vtxo_ids":["coin"],"scheduled_height":123}),maximum_fee_sat:100};
  let mut intent=freeze(&req,json!({"committed_fee_sat":12}));intent.state="submitted".into();persist(&root,&req,&intent).unwrap();
  let held=has_unresolved_rotation(&root).unwrap();fs::remove_dir_all(&root).unwrap();
  assert!(held,"an ACKed scheduled refresh must retain its exact-input wallet hold across restart");
 }
 #[test] fn terms_do_not_change_under_inspection_but_cap_source_and_inputs_do(){
  let req=Request{operation:"refresh_scheduled".into(),action_id:"original".into(),actor_dir:None,expected_server_pubkey:"server".into(),
   args:json!({"phase":"start","input_vtxo_ids":["coin"],"scheduled_height":123}),maximum_fee_sat:100};
  let intent=freeze(&req,json!({"committed_fee_sat":12}));assert_eq!(intent.state,"outcome_unknown");
  let mut inspect=req;inspect.args["phase"]=json!("inspect");assert_eq!(terms(&inspect),intent.args);
  inspect.args["input_vtxo_ids"]=json!(["another"]);assert_ne!(terms(&inspect),intent.args);
 }
}
