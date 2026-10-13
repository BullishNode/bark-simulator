//! Private stdin/stdout only. Never register this executable as the public driver.
#[path="../noah.rs"] mod noah;
use anyhow::{Context,Result,ensure};
use bark::{Config,OpenWalletArgs,Wallet,WalletSeed,onchain::OnchainWallet,persist::sqlite::SqliteClient};
use bitcoin::Network;
use serde::Deserialize;
use serde_json::{Value,json};
use std::{collections::BTreeMap,fs,io::{self,Read},os::unix::fs::{OpenOptionsExt,PermissionsExt},path::{Path,PathBuf},str::FromStr,sync::Arc};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateConfig {ark_endpoint:String,wallet_config:PathBuf,private_phone_root:PathBuf,phones:BTreeMap<String,PathBuf>,sdk_commit:String}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {protocol:String,operation:String,actor:String,action_id:String,wallet_path:PathBuf,k1:String,expiry_unix:i64,
 expected_sdk_commit:String,expected_server_pubkey:String,expected_ark_address:String,expected_fallback_script:String,
 expected_auth_pubkey:String,expected_mailbox_id:String}
fn private_regular(path:&Path)->Result<()> {
 let m=fs::symlink_metadata(path)?;ensure!(m.is_file() && !m.file_type().is_symlink() && m.permissions().mode()&0o077==0,"phone data must be private regular files");Ok(())
}
fn validate(cfg:&PrivateConfig,req:&Request)->Result<()> {
 ensure!(req.protocol=="noah-private-v1" && req.operation=="enrollment_material","private enrollment protocol differs");
 ensure!(cfg.sdk_commit==noah::SDK_COMMIT && req.expected_sdk_commit==noah::SDK_COMMIT,"independently qualified SDK pin differs");
 let index=req.actor.strip_prefix("actor-").and_then(|s|s.parse::<u16>().ok()).context("native phone actor required")?;
 ensure!((41..=999).contains(&index) && req.actor==format!("actor-{index:02}"),"fresh reserved phone actor required");
 ensure!(!req.action_id.is_empty() && req.action_id.len()<=100 && req.action_id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_'),"explicit private setup id required");
 ensure!(cfg.private_phone_root.is_absolute() && req.wallet_path.is_absolute() && req.wallet_path.parent()==Some(cfg.private_phone_root.as_path())
    && req.wallet_path.file_name().and_then(|p|p.to_str())==Some(req.actor.as_str()) && cfg.phones.get(&req.actor)==Some(&req.wallet_path),"phone wallet differs from explicit declaration");
 for p in req.wallet_path.ancestors(){ensure!(!fs::symlink_metadata(p)?.file_type().is_symlink(),"aliased phone path");}
 let m=fs::symlink_metadata(&req.wallet_path)?;ensure!(m.is_dir() && m.permissions().mode()&0o077==0,"phone directory must be private");
 private_regular(&req.wallet_path.join("mnemonic"))?;private_regular(&req.wallet_path.join("db.sqlite"))?;
 Ok(())
}
async fn execute(cfg:PrivateConfig,req:Request)->Result<Value> {
 validate(&cfg,&req)?;
 let lock=fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600).open(req.wallet_path.join("sim-driver.lock"))?;
 lock.try_lock().context("another controller owns this phone")?;
 let mnemonic=bip39::Mnemonic::from_str(fs::read_to_string(req.wallet_path.join("mnemonic"))?.trim())?;
 let mut config=Config::load(Network::Signet,&cfg.wallet_config)?;
 ensure!(config.server_address==cfg.ark_endpoint,"private phone endpoint differs");config.daemon_manual_sync=true;
 let db=Arc::new(SqliteClient::open(req.wallet_path.join("db.sqlite"))?);
 let onchain=OnchainWallet::load_or_create(Network::Signet,mnemonic.to_seed(""),db.clone()).await?;
 let wallet=Wallet::open(Network::Signet,WalletSeed::new_from_mnemonic(Network::Signet,&mnemonic),config,
   OpenWalletArgs{run_daemon:false,datadir:Some(req.wallet_path),persister:Some(db),onchain:Some(Arc::new(tokio::sync::RwLock::new(onchain))),
   create_if_not_exists:false,skip_recovery:true,..Default::default()}).await?;
 let material=noah::enrollment_material(&wallet,&req.k1,req.expiry_unix,&req.expected_server_pubkey,
   &req.expected_ark_address,&req.expected_fallback_script,&req.expected_auth_pubkey,&req.expected_mailbox_id).await?;
 Ok(json!({"protocol":req.protocol,"operation":req.operation,"actor":req.actor,"action_id":req.action_id,"material":material}))
}
#[tokio::main]
async fn main(){
 // No logging initialization: all grants, DER signatures and diagnostics belong
 // exclusively in the controller's protected, hash-bound transport artifacts.
 let result=async {
  let mut input=String::new();io::stdin().take(65537).read_to_string(&mut input)?;ensure!(input.len()<=65536,"private request exceeds bound");
  let path=std::env::var("SIM_NOAH_PRIVATE_CONFIG").context("private helper config required")?;private_regular(Path::new(&path))?;
  let cfg:PrivateConfig=serde_json::from_slice(&fs::read(path)?)?;let req:Request=serde_json::from_str(&input)?;
  execute(cfg,req).await
 }.await;
 match result {Ok(value)=>println!("{value}"),Err(_)=>{eprintln!("private enrollment unresolved; protected evidence required");std::process::exit(2);}}
}

#[cfg(test)]
mod tests {
 use super::*;
 fn fixture()->(PathBuf,PrivateConfig,Request){
  let root=std::env::temp_dir().join(format!("noah-private-boundary-{}-{}",std::process::id(),bitcoin::secp256k1::rand::random::<u64>()));
  let path=root.join("actor-41");fs::create_dir_all(&path).unwrap();fs::set_permissions(&path,fs::Permissions::from_mode(0o700)).unwrap();
  for name in ["mnemonic","db.sqlite"]{let file=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path.join(name)).unwrap();drop(file);}
  let cfg=PrivateConfig{ark_endpoint:"https://owned.example".into(),wallet_config:root.join("config"),private_phone_root:root.clone(),
    phones:BTreeMap::from([("actor-41".into(),path.clone())]),sdk_commit:noah::SDK_COMMIT.into()};
  let req=Request{protocol:"noah-private-v1".into(),operation:"enrollment_material".into(),actor:"actor-41".into(),action_id:"setup-1".into(),
    wallet_path:path,k1:String::new(),expiry_unix:1500,expected_sdk_commit:noah::SDK_COMMIT.into(),expected_server_pubkey:String::new(),
    expected_ark_address:String::new(),expected_fallback_script:String::new(),expected_auth_pubkey:String::new(),expected_mailbox_id:String::new()};
  (root,cfg,req)
 }
 #[test]
 fn native_boundary_rejects_original_actor_drift_sdk_drift_and_undeclared_phone(){
  let (root,mut cfg,mut req)=fixture();assert!(validate(&cfg,&req).is_ok());
  req.actor="actor-09".into();assert!(validate(&cfg,&req).is_err());req.actor="actor-41".into();
  req.expected_sdk_commit="d47".into();assert!(validate(&cfg,&req).is_err());req.expected_sdk_commit=noah::SDK_COMMIT.into();
  cfg.phones.clear();assert!(validate(&cfg,&req).is_err());fs::remove_dir_all(root).unwrap();
 }
 #[test]
 fn native_boundary_rejects_aliases_and_unprotected_seed_files(){
  let (root,cfg,req)=fixture();fs::set_permissions(req.wallet_path.join("mnemonic"),fs::Permissions::from_mode(0o644)).unwrap();
  assert!(validate(&cfg,&req).is_err());fs::set_permissions(req.wallet_path.join("mnemonic"),fs::Permissions::from_mode(0o600)).unwrap();
  fs::remove_file(req.wallet_path.join("db.sqlite")).unwrap();std::os::unix::fs::symlink(req.wallet_path.join("mnemonic"),req.wallet_path.join("db.sqlite")).unwrap();
  assert!(validate(&cfg,&req).is_err());fs::remove_dir_all(root).unwrap();
 }
}
