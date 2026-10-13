mod exit;
mod board_quote;
mod native_intent;
mod fallback_rotation;
mod scheduled_refresh;
mod raw_guard;
#[cfg(test)]
mod raw_guard_tests;
mod raw_protocol;
mod phase_protocol;
mod phase_transport;
mod phase_round;
mod phase_offboard;
mod phase_delegated;
mod phase_replay;
mod phase_lightning;
mod phase_exit;

use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};
use ark::attestations::{FallbackRecordAttestation, KeyLinkAttestation};
use ark::lightning::Bolt11InvoiceExt;
use ark::{ProtocolEncoding, SECP};
use bark::actions::{
    DriveMode,
    offboard::{Offboard, OffboardKind, Progress as OffboardProgress},
};
use bark::onchain::OnchainWallet;
use bark::persist::BarkPersister;
use bark::persist::sqlite::SqliteClient;
use bark::subsystem::RoundMovement;
use bark::{Config, OpenWalletArgs, Wallet, WalletSeed};
use bitcoin::constants::ChainHash;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Keypair, PublicKey, rand};
use bitcoin::{Address, Amount, FeeRate, Network};
use serde::Deserialize;
use serde_json::{Value, json};
use server_rpc::RequestExt;
use server_rpc::protos::{self, ark_service_client::ArkServiceClient};
use tonic::transport::Endpoint;

#[derive(Debug)]
struct InvariantFailure(&'static str);

impl std::fmt::Display for InvariantFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for InvariantFailure {}

#[derive(Deserialize)]
struct DriverConfig {
    ark_endpoint: String,
    wallet_config: PathBuf,
    wallet_root: PathBuf,
    #[serde(default = "signet")]
    network: String,
}

fn signet() -> String {
    "signet".into()
}

fn allowed_network(name: &str, endpoint: &str) -> Result<Network> {
    let network = Network::from_str(name)?;
    ensure!(
        matches!(network, Network::Signet | Network::Regtest),
        "only signet/regtest are allowed"
    );
    if network == Network::Regtest {
        ensure!(
            endpoint.starts_with("http://127.0.0.1:") || endpoint.starts_with("http://[::1]:"),
            "regtest must use an isolated local endpoint"
        );
    }
    Ok(network)
}

async fn fallback_binding(wallet: &Wallet) -> Result<Value> {
    let record = wallet.fallback_destination().await?;
    let mailbox = wallet.mailbox_keypair();
    let chain = ChainHash::using_genesis_block_const(wallet.network().await?);
    let onchain = wallet.onchain().context("missing onchain wallet")?;
    ensure!(
        onchain.read().await.is_mine(&record.spk).await?,
        "fallback script is not owned by this client"
    );
    Ok(
        json!({"mailbox_pk":mailbox.public_key().to_string(),"spk":hex(record.spk.as_bytes()),
        "seq":record.seq,"record_attestation":hex(&FallbackRecordAttestation::new(chain,&record.spk,record.seq,&mailbox).serialize()),
        "onchain_ownership_checked":true}),
    )
}

async fn coin_evidence(wallet: &Wallet) -> Result<Value> {
    let coins = wallet.all_vtxos().await?;
    ensure!(
        coins.len() <= 1024,
        "actor evidence exceeds bounded inventory; incremental collection required"
    );
    let binding = fallback_binding(wallet).await?;
    let mailbox = wallet.mailbox_keypair().public_key();
    let mut public = Vec::new();
    for coin in &coins {
        let full = wallet.get_full_vtxo(coin.id()).await?;
        let (_, key) = wallet
            .pubkey_keypair(&full.user_pubkey())
            .await?
            .context("owned coin key absent")?;
        public.push(json!({"id":full.id().to_string(), "amount_sat":full.amount().to_sat(),
            "user_pubkey":full.user_pubkey().to_string(), "expiry_height":full.expiry_height().to_u32(),
            "state":coin.state.kind().to_string(), "signed_vtxo":hex(&full.serialize()),
            "key_link_attestation":hex(&KeyLinkAttestation::new(mailbox,&key).serialize())}));
    }
    let movements = wallet.history().await?;
    ensure!(
        movements.len() <= 1024,
        "actor movement evidence exceeds bounded inventory"
    );
    let movements = movements.iter().map(|m| json!({"id":m.id.to_string(), "status":m.status.to_string(),
        "input_vtxos":m.input_vtxos.iter().map(|id|id.to_string()).collect::<Vec<_>>(),
        "output_vtxos":m.output_vtxos.iter().map(|id|id.to_string()).collect::<Vec<_>>(),
        "offchain_fee_sat":m.offchain_fee.to_sat(), "effective_balance_sat":m.effective_balance.to_sat(),
        "subsystem":m.subsystem.name,"payment_hash":m.lightning_invoice().map(|i|i.payment_hash().to_string())})).collect::<Vec<_>>();
    Ok(json!({"coins":public,"movements":movements,"binding":binding}))
}

fn receive_sync_selection(fees: &[u64], maximum_fee_sat: u64, start: usize) -> Result<Vec<usize>> {
    let _total = fees.iter().try_fold(0u64, |total, fee| total.checked_add(*fee))
        .context("receive fee overflow")?;
    ensure!((fees.is_empty() && start == 0) || start < fees.len(), "invalid receive poll start");
    let mut used=0u64;
    let mut selected=Vec::new();
    for offset in 0..fees.len() {
        let index=(start+offset)%fees.len();
        let fee=fees[index];
        if selected.len()==32 { break; }
        if fee<=maximum_fee_sat-used {
            used+=fee;
            selected.push(index);
        }
    }
    Ok(selected)
}

fn receive_sync_start(hashes: &[String], args: &Value) -> Result<usize> {
    if let Some(target)=args.get("receive_payment_hash") {
        let target=target.as_str().context("target receive hash must be a string")?;
        ensure!(target.len()==64 && target.bytes().all(|c|c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "target receive hash must be lowercase hex");
        return hashes.iter().position(|h|h==target).context("target checkpoint is not pending");
    }
    let Some(hint) = args.get("receive_sync_start_after") else { return Ok(0); };
    let hint=hint.as_str().context("receive poll cursor must be a payment hash")?;
    ensure!(hint.len()==64 && hint.bytes().all(|c|c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "receive poll cursor must be a lowercase payment hash");
    // A completed claim can remove the cursor from the pending list. Restart
    // at the first remaining original checkpoint; never create an invoice.
    Ok(hashes.iter().position(|h|h==hint).map(|i|(i+1)%hashes.len()).unwrap_or(0))
}

fn cancellation_is_terminal(was_awaiting: bool, checkpoint_removed: bool, status: protos::LightningReceiveStatus) -> bool {
    was_awaiting && checkpoint_removed && status==protos::LightningReceiveStatus::Canceled
}

fn lightning_fee_ceiling(schedule: &ark::fees::FeeSchedule, amount: Amount) -> Result<Amount> {
    schedule.validate()?;
    schedule
        .lightning_send
        .calculate(
            amount,
            [ark::fees::VtxoFeeInfo {
                amount,
                expiry_blocks: u32::MAX,
            }],
        )
        .context("lightning fee ceiling overflow")
}

#[derive(Deserialize)]
struct Request {
    operation: String,
    #[serde(default)]
    action_id: String,
    actor_dir: Option<PathBuf>,
    expected_server_pubkey: String,
    #[serde(default)]
    args: Value,
    #[serde(default)]
    maximum_fee_sat: u64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn verify_exit_budget(frozen:u64,requested:u64,reserved:&[u64],next:u64)->Result<()> {
    ensure!(frozen>0 && frozen==requested,"exit fee cap changed");
    let used=reserved.iter().try_fold(0u64,|sum,fee|sum.checked_add(*fee)).context("exit fee sum overflow")?;
    ensure!(used.checked_add(next).context("exit fee sum overflow")?<=frozen,"exit fee cap exhausted");Ok(())
}

fn verify_recycle_input(psbt:&bitcoin::Psbt,source:&Value)->Result<()> {
    let outpoint=bitcoin::OutPoint::from_str(source["outpoint"].as_str().context("missing recycle outpoint")?)?;
    let script=bitcoin::ScriptBuf::from_hex(source["script"].as_str().context("missing recycle script")?)?;
    let amount=source["amount_sat"].as_u64().context("missing recycle amount")?;
    ensure!(psbt.unsigned_tx.input.len()==1 && psbt.unsigned_tx.input[0].previous_output==outpoint,
        "recycle board must spend precisely its declared receipt");
    let utxo=psbt.inputs[0].witness_utxo.as_ref().context("recycle input lacks witness UTXO")?;
    ensure!(utxo.value.to_sat()==amount && utxo.script_pubkey==script,"recycle PSBT differs from frozen receipt");
    Ok(())
}

fn public_payment_status(
    hash: sha256::Hash,
    status: protos::LightningPaymentStatus,
) -> Result<Value> {
    use protos::lightning_payment_status::PaymentStatus;
    let state = match status.payment_status.context("payment status absent")? {
        PaymentStatus::Pending(_) => "pending",
        PaymentStatus::Failed(_) => "failed",
        PaymentStatus::Success(success) => {
            ensure!(
                success.preimage.len() == 32 && sha256::Hash::hash(&success.preimage) == hash,
                InvariantFailure("successful payment has an invalid preimage")
            );
            "succeeded"
        }
    };
    Ok(json!({"payment_hash":hash.to_string(),"state":state,
        "success_preimage_hash_valid":state=="succeeded","actual_fee_sat":0,
        "read_only":true,
        "scope":"existing server status RPC; verified preimage hash, not a client-wallet mutation"}))
}

fn amount(args: &Value) -> Result<Amount> {
    let sats = args["amount_sat"]
        .as_u64()
        .context("amount_sat must be an unsigned integer")?;
    ensure!(sats > 0, "zero amount");
    Ok(Amount::from_sat(sats))
}

fn record_bytes(chain: ChainHash, spk: &bitcoin::ScriptBuf, seq: u64, key: &Keypair) -> Vec<u8> {
    let mut bytes = spk.as_bytes().to_vec();
    bytes.extend(seq.to_le_bytes());
    bytes.extend(FallbackRecordAttestation::new(chain, spk, seq, key).serialize());
    bytes
}

fn evidence(req: &Request, event: &str, data: Value) -> Result<()> {
    let value = json!({"kind":"driver_event", "action_id":req.action_id,
                      "event":event, "operation":req.operation, "data":data});
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{value}")?;
    stdout.flush()?;
    Ok(())
}

async fn observed_wallet_operation<F, C, CF, E>(operation:F, mut capture:C, mut emit:E) -> Result<Value>
where F:std::future::Future<Output=Result<Value>>,
      C:FnMut()->CF, CF:std::future::Future<Output=Result<Value>>,
      E:FnMut(&str,Value)->Result<()> {
    let captured=capture().await;
    let emitted=match captured {
        Ok(evidence)=>emit("client_evidence_before",json!({"evidence":evidence,"fresh":true})),
        Err(_)=>Err(anyhow::anyhow!("capture failed")),
    };
    if emitted.is_err() {
        let _=emit("client_evidence_gap",json!({"phase":"before","reason":"capture_or_emission_failed"}));
    }
    let result=operation.await;
    let captured=capture().await;
    let emitted=match captured {
        Ok(evidence)=>emit("client_evidence_after",json!({"evidence":evidence,"fresh":true})),
        Err(_)=>Err(anyhow::anyhow!("capture failed")),
    };
    if emitted.is_err() {
        let _=emit("client_evidence_gap",json!({"phase":"after","reason":"capture_or_emission_failed"}));
    }
    result
}

async fn execute(cfg: DriverConfig, req: &Request) -> Result<Value> {
    let network = allowed_network(&cfg.network, &cfg.ark_endpoint)?;
    let chain_hash = ChainHash::using_genesis_block(network);
    let channel = Endpoint::from_shared(cfg.ark_endpoint.clone())?
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .connect()
        .await?;
    let mut rpc = ArkServiceClient::new(channel.clone());
    let info = rpc.get_ark_info(protos::Empty {}).await?.into_inner();
    ensure!(
        info.network == network.to_string(),
        "server network mismatch"
    );
    ensure!(
        hex(&info.server_pubkey) == req.expected_server_pubkey,
        "server identity mismatch"
    );
    if req.operation == "info" {
        return Ok(
            json!({"network": info.network, "server_pubkey": hex(&info.server_pubkey),
                         "round_interval_secs": info.round_interval_secs,
                         "vtxo_lifetime": info.vtxo_lifetime,
                         "required_board_confirmations": info.required_board_confirmations}),
        );
    }
    if req.operation == "fallback_record_query" {
        let mailbox = PublicKey::from_str(
            req.args["mailbox_pk"]
                .as_str()
                .context("public mailbox required")?,
        )?;
        let response = rpc
            .set_fallback(protos::SetFallbackRequest {
                mailbox_pk: mailbox.serialize().to_vec(),
                record: None,
                key_links: vec![],
            })
            .await
            .map_err(|status| {
                let _ = evidence(
                    req,
                    "fallback_query_failed",
                    json!({"code":format!("{:?}",status.code())}),
                );
                status
            })?
            .into_inner();
        return Ok(
            json!({"mailbox_pk":mailbox.to_string(),"serialized":hex(&response.record),
            "actual_fee_sat":0,"read_only":true}),
        );
    }
    if req.operation == "lightning_receive_status" {
        let hash=sha256::Hash::from_str(req.args["payment_hash"].as_str().context("payment hash required")?)?;
        let response=rpc.check_lightning_receive(protos::CheckLightningReceiveRequest {
            hash:hash.to_byte_array().to_vec(),wait:false,
        }).await?.into_inner();
        let status=protos::LightningReceiveStatus::try_from(response.status)?;
        return Ok(json!({"payment_hash":hash.to_string(),"state":format!("{:?}",status),
            "read_only":true,"actual_fee_sat":0}));
    }
    if req.operation == "lightning_payment_status" {
        let hash = sha256::Hash::from_str(
            req.args["payment_hash"]
                .as_str()
                .context("payment hash required")?,
        )?;
        let status = rpc
            .check_lightning_payment(protos::CheckLightningPaymentRequest {
                hash: hash.to_byte_array().to_vec(),
                wait: false,
            })
            .await?
            .into_inner();
        return public_payment_status(hash, status);
    }
    let path = req.actor_dir.as_ref().context("actor_dir required")?;
    let root = cfg
        .wallet_root
        .canonicalize()
        .context("wallet root must already exist")?;
    ensure!(
        path.parent()
            .context("actor directory has no parent")?
            .canonicalize()?
            == root,
        "actor must be directly beneath wallet root"
    );
    let actor = path
        .file_name()
        .context("actor name missing")?
        .to_str()
        .context("actor name must be UTF-8")?;
    actor_index(actor)?;
    ensure!(!path.is_symlink(), "symlink actor directory");
    if req.operation.starts_with("raw_protocol_") || req.operation.starts_with("phase_execute_") || matches!(req.operation.as_str(),"fallback_rotate"|"phase_register_saved") {
        ensure!(!matches!(actor,"actor-03"|"actor-09"|"actor-10"),"original permanently absent wallet must stay closed");
        ensure!(network==Network::Signet,"declared protocol trials require signet");
    }

    let mnemonic_file = path.join("mnemonic");
    if req.operation == "create" {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let _actor_lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path.join("sim-driver.lock"))?;
    _actor_lock
        .try_lock()
        .context("another driver owns this actor")?;
    if let Some(original_action_id)=native_intent::conflicting_wallet_intent(path,req)? {
        return Ok(json!({"blocked":true,"reason":"frozen native intent requires exact independent reconciliation",
            "original_action_id":original_action_id,"actual_fee_sat":0,"wallet_opened":false}));
    }
    if req.operation=="phase_register_saved" {
        ensure!(req.args["phase_intent"]["context"]["courier_actor"]==actor,"delayed registration must use its declared online courier");
        return phase_protocol::register_saved(&mut rpc,req,&path.join("private-phases"),network).await;
    }
    if req.operation == "create" {
        if !mnemonic_file.exists() {
            let mnemonic = bip39::Mnemonic::generate(12)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&mnemonic_file)?;
            file.write_all(mnemonic.to_string().as_bytes())?;
            file.sync_all()?;
        }
    }
    let metadata = fs::symlink_metadata(&mnemonic_file)?;
    ensure!(
        !metadata.file_type().is_symlink() && metadata.permissions().mode() & 0o077 == 0,
        "mnemonic must be private, not symlinked"
    );
    let mnemonic = bip39::Mnemonic::from_str(fs::read_to_string(&mnemonic_file)?.trim())?;
    let mut config = Config::load(network, &cfg.wallet_config)?;
    ensure!(
        config.server_address == cfg.ark_endpoint,
        "wallet config endpoint differs from pinned endpoint"
    );
    let phase_round_invocation=if matches!(req.operation.as_str(),"phase_execute_d18"|"phase_execute_d19") {
        let invocation=phase_round::setup(channel.clone(),req,&path.join("private-phases")).await?;
        if invocation.is_none(){return Ok(json!({"phase_unknown":true,"actual_fee_sat":Value::Null,"reason":"existing once-only phase fence; no SDK restart/re-sign/retry"}));}
        config.server_address=invocation.as_ref().unwrap().transport.endpoint.clone();
        invocation
    }else{None};
    config.daemon_manual_sync = true;
    let db = Arc::new(SqliteClient::open(path.join("db.sqlite"))?);
    fs::set_permissions(path.join("db.sqlite"), fs::Permissions::from_mode(0o600))?;
    let mut onchain_wallet =
        OnchainWallet::load_or_create(network, mnemonic.to_seed(""), db.clone()).await?;
    if req.operation == "create" && !path.join("birthday-height").exists() {
        let chain = bark::chain::ChainSource::new(config.chain_source()?, network, None).await?;
        let height = chain.tip().await?;
        onchain_wallet
            .initial_wallet_scan(&chain, Some(height))
            .await?;
        fs::write(path.join("birthday-height"), height.to_string())?;
    }
    let onchain = Arc::new(tokio::sync::RwLock::new(onchain_wallet));
    let wallet = Wallet::open(
        network,
        WalletSeed::new_from_mnemonic(network, &mnemonic),
        config,
        OpenWalletArgs {
            run_daemon: false,
            datadir: Some(path.clone()),
            persister: Some(db.clone()),
            onchain: Some(onchain),
            create_if_not_exists: req.operation == "create",
            skip_recovery: true,
            ..Default::default()
        },
    )
    .await?;
    evidence(
        req,
        "wallet_opened",
        json!({"actor":actor, "network":network.to_string(), "daemon":false}),
    )?;
    evidence(req,"wallet_runtime_parameters",json!({
        "actor":actor,"round_tx_required_confirmations":wallet.config().round_tx_required_confirmations.to_u32(),
        "vtxo_exit_margin":wallet.config().vtxo_exit_margin.to_u32(),
        "daemon_manual_sync":wallet.config().daemon_manual_sync,"run_daemon":false
    }))?;
    ensure!(
        wallet
            .require_ark_info()
            .await?
            .server_pubkey
            .serialize()
            .to_vec()
            == info.server_pubkey,
        "wallet server identity mismatch"
    );
    observed_wallet_operation(async {
    if exit::has_unfinished_intent(path)? && !matches!(req.operation.as_str(),"exit"|"snapshot") {
        return Ok(json!({"blocked":true,"reason":"original exit intent owns this wallet; only explicit same-intent continuation or snapshot allowed","actual_fee_sat":0}));
    }
    match req.operation.as_str() {
        "phase_execute_d17"=>phase_protocol::race_arkoor(&wallet,&mut rpc,req,&path.join("private-phases"),actor).await,
        "phase_execute_d18"|"phase_execute_d19"=>phase_round::execute(&wallet,&mut rpc,req,phase_round_invocation.as_ref().context("missing one-process round transport")?,actor).await,
        operation if operation.starts_with("raw_protocol_")=>raw_protocol::execute(&wallet,&db,&mut rpc,req,path,actor).await,

        "exit" => exit::execute(&wallet,&mut rpc,path,req,network).await,
        "fallback_rotate" => fallback_rotation::execute(&wallet,&mut rpc,path,req,network).await,
        "refresh_scheduled" => scheduled_refresh::execute(&wallet,path,req).await,
        "create" => {
            let fallback = wallet.fallback_destination().await?;
            let onchain = wallet.onchain().context("missing onchain wallet")?;
            let receive = onchain.write().await.address().await?;
            Ok(
                json!({"funding_address": receive.to_string(), "fallback_script": hex(fallback.spk.as_bytes()), "fallback_seq": fallback.seq,"binding":fallback_binding(&wallet).await?}),
            )
        }
        "snapshot" => {
            let balance = bark_json::cli::Balance::from(wallet.balance().await?);
            let vtxos = wallet
                .all_vtxos()
                .await?
                .iter()
                .map(bark_json::primitives::WalletVtxoInfo::from)
                .collect::<Vec<_>>();
            let fallback = wallet.fallback_destination().await?;
            let onchain = wallet.onchain().context("missing onchain wallet")?;
            let guard = onchain.read().await;
            let bdk = (&*guard as &dyn std::any::Any)
                .downcast_ref::<OnchainWallet>()
                .context("not a BDK wallet")?;
            let onchain_balance = bark_json::cli::onchain::OnchainBalance::from(bdk.balance());
            drop(guard);
            Ok(
                json!({"balance": balance, "onchain": onchain_balance, "vtxos": vtxos, "fallback_script": hex(fallback.spk.as_bytes()), "fallback_seq": fallback.seq, "evidence":coin_evidence(&wallet).await?}),
            )
        }
        "sync" | "claim_lightning" => {
            if req.operation=="claim_lightning" {ensure!(req.args.get("receive_payment_hash").is_some(),"original claim hash required");}
            let mut receive_ceiling = 0u64;
            let pending_receives = wallet.pending_lightning_receives().await?;
            let receive_count_before = pending_receives.len();
            let receive_payment_hashes_before = pending_receives.iter()
                .map(|recv| recv.payment_hash.to_string()).collect::<Vec<_>>();
            let mut receive_fees=Vec::new();
            for recv in &pending_receives {
                let q = wallet
                    .estimate_lightning_receive_fee(recv.invoice.get_payment_amount(None)?)
                    .await?;
                receive_ceiling = receive_ceiling
                    .checked_add(q.fee.to_sat())
                    .context("receive fee overflow")?;
                receive_fees.push(q.fee.to_sat());
            }
            let start=receive_sync_start(&receive_payment_hashes_before,&req.args)?;
            let targeted=req.args.get("receive_payment_hash").is_some();
            let selected=if targeted {
                if receive_fees[start]<=req.maximum_fee_sat {vec![start]} else {vec![]}
            } else {receive_sync_selection(&receive_fees,req.maximum_fee_sat,start)?};
            let bounded_receive_sync=targeted || selected.len()!=pending_receives.len();
            if !pending_receives.is_empty() && selected.is_empty() {
                return Ok(
                    json!({"blocked":true,"reason":"pending receive fees exceed this sync reserve"}),
                );
            }
            let selected_hashes=selected.iter().map(|i|pending_receives[*i].payment_hash.to_string()).collect::<Vec<_>>();
            let selected_fee_ceiling=selected.iter().map(|i|receive_fees[*i]).sum::<u64>();
            let before = coin_evidence(&wallet).await?;
            evidence(req, "sync_before", before.clone())?;
            evidence(req,"receive_sync_plan",json!({"bounded_receive_sync":bounded_receive_sync,
                "receive_sync_start_after":req.args.get("receive_sync_start_after"),
                "selected_payment_hashes":selected_hashes,"selected_fee_ceiling_sat":selected_fee_ceiling,
                "all_pending_fee_ceiling_sat":receive_ceiling,"maximum_fee_sat":req.maximum_fee_sat}))?;
            let mut canceled=Vec::new();
            let mut target_terminal=false;
            for index in selected {
                let recv=&pending_receives[index];
                let was_awaiting=matches!(recv.progress,bark::actions::lightning::receive::Progress::AwaitingPayment);
                let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(180);
                loop {
                    match wallet.try_claim_lightning_receive(recv.payment_hash,false).await {
                        Ok(bark::actions::lightning::receive::LightningReceiveState::Settled(_))=>{
                            target_terminal=true;break;
                        },
                        Ok(_)=>{},
                        Err(error)=>{
                            // SDK8f reports cancellation through anyhow. Never interpret
                            // its text as terminal evidence: verify the typed server state
                            // and removal of an originally money-free checkpoint.
                            let status=rpc.check_lightning_receive(protos::CheckLightningReceiveRequest {
                                hash:recv.payment_hash.to_byte_array().to_vec(),wait:false,
                            }).await?.into_inner();
                            let status=protos::LightningReceiveStatus::try_from(status.status)?;
                            let removed=wallet.lightning_receive_checkpoint(recv.payment_hash).await?.is_none();
                            if cancellation_is_terminal(was_awaiting,removed,status) {
                                canceled.push(recv.payment_hash.to_string());
                                evidence(req,"receive_canceled",json!({"payment_hash":recv.payment_hash.to_string(),
                                    "server_status":"canceled","checkpoint_before":"AwaitingPayment",
                                    "checkpoint_removed":true,"actual_fee_sat":Value::Null}))?;
                                target_terminal=true;break;
                            }
                            return Err(error);
                        },
                    }
                    if !targeted || tokio::time::Instant::now()+std::time::Duration::from_secs(20)>deadline {break;}
                    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                }
            }
            if !bounded_receive_sync {wallet.sync().await;}
            // A short-lived adapter has no daemon driving unfinished rounds.
            // Lightweight sync only handles completed rounds' confirmations;
            // reuse the SDK's maintenance progression for existing intents.
            if req.operation!="claim_lightning" {
                wallet.progress_pending_rounds(None).await?;
                wallet.sync_onchain().await?;
            }
            let pending_after = wallet.pending_lightning_receives().await?;
            let receive_count_after = pending_after.len();
            let receive_payment_hashes_after = pending_after.iter()
                .map(|recv| recv.payment_hash.to_string()).collect::<Vec<_>>();
            // Sync creates a new fee obligation only for newly claimed receives.
            // Advancing existing boards/rounds/sends/offboards is accounted to
            // their original persisted action, never charged a second time here.
            let no_new_receive = receive_count_before == 0 && receive_count_after == 0;
            Ok(
                json!({"requested": "sync", "note": "SDK sync can log partial failures; inspect snapshot/status before declaring convergence",
                    "receive_count_before":receive_count_before,"receive_count_after":receive_count_after,
                    "receive_payment_hashes_before":receive_payment_hashes_before,
                    "receive_payment_hashes_after":receive_payment_hashes_after,
                    "bounded_receive_sync":bounded_receive_sync,
                    "receive_canceled_payment_hashes":canceled,"target_receive_terminal":target_terminal,
                    "selected_receive_payment_hashes":selected_hashes,
                    "selected_receive_fee_ceiling_sat":selected_fee_ceiling,
                    "all_pending_receive_fee_ceiling_sat":receive_ceiling,
                    "actual_fee_sat":if no_new_receive {json!(0)} else {Value::Null},
                    "fee_scope":"new receive fees require signed claim reconciliation; costs of existing persisted actions remain on those actions",
                    "before_evidence":before,"evidence":coin_evidence(&wallet).await?}),
            )
        }
        "address" => {
            let address = wallet.new_address().await?;
            let pk = address.policy().user_pubkey();
            let (_, key) = wallet
                .pubkey_keypair(&pk)
                .await?
                .context("advertised address key absent")?;
            let mailbox = wallet.mailbox_keypair().public_key();
            Ok(
                json!({"address":address.to_string(),"user_pubkey":pk.to_string(),
                "key_link_attestation":hex(&KeyLinkAttestation::new(mailbox,&key).serialize()),"binding":fallback_binding(&wallet).await?}),
            )
        }
        "send_arkoor" => {
            let destination = ark::Address::from_str(
                req.args["destination"]
                    .as_str()
                    .context("destination required")?,
            )?;
            let estimate = wallet
                .estimate_arkoor_payment_fee(amount(&req.args)?)
                .await?;
            if estimate.fee.to_sat() > req.maximum_fee_sat {
                return Ok(
                    json!({"blocked": true, "reason": "arkoor fee exceeds declared reserve"}),
                );
            }
            evidence(
                req,
                "arkoor_request",
                json!({"destination":destination.to_string(),
                "amount_sat":amount(&req.args)?.to_sat(), "estimated_fee_sat":estimate.fee.to_sat(),
                "input_vtxo_ids":estimate.vtxos_spent.iter().map(|id| id.to_string()).collect::<Vec<_>>()}),
            )?;
            wallet
                .send_arkoor_payment(&destination, amount(&req.args)?)
                .await?;
            Ok(
                json!({"submitted": "send_arkoor", "amount_sat": amount(&req.args)?.to_sat(),
                      "estimated_fee_sat": estimate.fee.to_sat(), "actual_fee_sat":0,
                      "fee_basis":"pinned SDK arkoor has no offchain or onchain fee", "evidence":coin_evidence(&wallet).await?}),
            )
        }
        "invoice" => {
            let quote = wallet
                .estimate_lightning_receive_fee(amount(&req.args)?)
                .await?;
            if quote.fee.to_sat() > req.maximum_fee_sat || quote.net_amount < Amount::from_sat(330)
            {
                return Ok(
                    json!({"blocked":true,"reason":"receive claim fee exceeds reserve or net is dust"}),
                );
            }
            let invoice = wallet
                .bolt11_invoice(
                    amount(&req.args)?,
                    Some("abandon-ship simulator".into()),
                    None,
                )
                .await?;
            Ok(
                json!({"invoice": invoice.to_string(),"payment_hash":invoice.payment_hash().to_string(),"estimated_claim_fee_sat":quote.fee.to_sat(),"actual_fee_sat":0}),
            )
        }
        "board" => {
            wallet.sync_onchain().await?;
            evidence(req,"board_fee_estimate_requested",json!({"source":"SDK chain backend",
                "regular_confirmation_target":3,"same_process":true,"fallback_allowed":false,
                "new_funding_intent_prepared":false}))?;
            let fee_rate=board_quote::regular(wallet.chain()).await?;
            evidence(req,"board_fee_quote",json!({"source":"SDK chain backend",
                "regular_confirmation_target":3,"fee_rate_sat_per_kwu":fee_rate.to_sat_per_kwu(),
                "same_process":true,"used_fallback":false,"new_funding_intent_prepared":false}))?;
            let (key, _) = wallet.derive_store_next_keypair().await?;
            let (destination, expiry) = wallet.board_funding_address(&key).await?;
            let autosize=req.args["recycle_autosize"].as_bool()==Some(true);
            ensure!(!autosize || req.args.get("recycle_source").is_some(), "autosize requires a frozen own receipt");
            let destination_script=destination.script_pubkey();

            let onchain = wallet.onchain().context("missing onchain wallet")?;
            let mut guard = onchain.write().await;
            let psbt = if let Some(source) = req.args.get("recycle_source") {
                let outpoint = bitcoin::OutPoint::from_str(source["outpoint"].as_str().context("missing recycle outpoint")?)?;
                let script = bitcoin::ScriptBuf::from_hex(source["script"].as_str().context("missing recycle script")?)?;
                let value = source["amount_sat"].as_u64().context("missing recycle value")?;
                ensure!(guard.is_mine(&script).await?, "recycle source is not this actor's wallet");
                let bdk = (&mut *guard as &mut dyn std::any::Any).downcast_mut::<OnchainWallet>().context("recycling requires native BDK wallet")?;
                let source_utxo = bdk.list_unspent().into_iter().find(|u|u.outpoint==outpoint).context("recycle source is not unspent")?;
                ensure!(matches!(source_utxo.chain_position,bdk_wallet::chain::ChainPosition::Confirmed{..}), "recycle source is not confirmed");
                ensure!(source_utxo.txout.value.to_sat()==value && source_utxo.txout.script_pubkey==script, "recycle source differs from frozen receipt");
                let mut builder = bdk.build_tx();
                builder.ordering(bdk_wallet::TxOrdering::Untouched).add_utxo(outpoint)?.manually_selected_only()
                    .fee_rate(fee_rate);
                if autosize {
                    let cap=req.args["board_cap_sat"].as_u64().context("invalid board cap")?;
                    ensure!(cap>0, "zero board cap");
                    if value<=cap {
                        // Only the selected receipt can fund this drain output.
                        // Service cost is quoted below against the exact output.
                        builder.drain_wallet().drain_to(destination_script.clone());
                    } else {
                        builder.add_recipient(destination_script.clone(),Amount::from_sat(cap));
                    }
                } else {
                    builder.add_recipient(destination_script.clone(),amount(&req.args)?);
                }
                let psbt=match builder.finish() {
                    Ok(psbt)=>psbt,
                    Err(error) if autosize=>return Ok(json!({"blocked":true,"reason":"source cannot fund an unsigned recycle board at the current fee rate",
                        "preparation_error":error.to_string(),"actual_fee_sat":0,"no_sign_no_broadcast":true})),
                    Err(error)=>return Err(error.into()),
                };
                verify_recycle_input(&psbt,source)?;
                psbt
            } else {
                guard.prepare_tx(&[(destination, amount(&req.args)?)], fee_rate).await?
            };
            let outputs=psbt.unsigned_tx.output.iter().filter(|o|o.script_pubkey==destination_script).collect::<Vec<_>>();
            ensure!(outputs.len()==1, "board funding output is ambiguous");
            let funded=outputs[0].value;
            if autosize {
                ensure!(funded.to_sat()<=req.args["board_cap_sat"].as_u64().context("invalid board cap")?, "prepared board exceeds cap");
            } else {
                ensure!(funded==amount(&req.args)?, "prepared board differs from request");
            }
            let estimate=wallet.estimate_board_offchain_fee(funded).await?;
            if let Some(minimum)=req.args.get("minimum_ark_amount_sat") {
                let minimum=minimum.as_u64().context("invalid minimum Ark principal")?;
                if funded.to_sat().checked_sub(estimate.fee.to_sat()).unwrap_or(0)<minimum {
                    return Ok(json!({"blocked":true,"reason":"recycle board would create below-minimum Ark principal","actual_fee_sat":0,"no_sign_no_broadcast":true}));
                }
            }
            let mining_fee = psbt.fee()?.to_sat();
            let total_fee = mining_fee
                .checked_add(estimate.fee.to_sat())
                .context("fee overflow")?;
            if total_fee > req.maximum_fee_sat {
                return Ok(
                    json!({"blocked": true, "reason": "board fee exceeds declared reserve", "estimated_fee_sat": total_fee}),
                );
            }
            evidence(
                req,
                "board_proposal",
                json!({"funding_txid":psbt.unsigned_tx.compute_txid().to_string(),
                "unsigned_funding_tx":hex(&bitcoin::consensus::serialize(&psbt.unsigned_tx)),
                "amount_sat":funded.to_sat(), "planned_mining_fee_sat":mining_fee,"recycle_autosize":autosize,
                "estimated_service_fee_sat":estimate.fee.to_sat(), "expiry_height":expiry.to_u32()}),
            )?;
            let signed = guard.finish_psbt(psbt).await?;
            drop(guard);
            let board = wallet.board_psbt(signed, key, expiry).await?;
            let service_fee = funded
                .checked_sub(board.amount)
                .context("board amount exceeds funded amount")?
                .to_sat();
            let fallback = wallet.fallback_destination().await?;
            Ok(json!({"board": board, "planned_mining_fee_sat": mining_fee,
                      "sdk_service_fee_sat": service_fee,
                      "fallback_script": hex(fallback.spk.as_bytes()), "expiry_height": expiry.to_u32(),
                      "evidence":coin_evidence(&wallet).await?, "note": "SDK checkpoint accepted; broadcast/mining cost requires independent chain evidence"}))
        }
        "refresh" | "refresh_delegated" => {
            let inputs = wallet.spendable_vtxos().await?;
            let Some(participation) = wallet.build_refresh_participation(inputs).await? else {
                return Ok(json!({"no_inputs":true, "actual_fee_sat":0}));
            };
            let fee = participation
                .total_in()
                .context("refresh input overflow")?
                .checked_sub(
                    participation
                        .total_out()
                        .context("refresh output overflow")?,
                )
                .context("refresh creates money")?
                .to_sat();
            if fee > req.maximum_fee_sat {
                return Ok(json!({"blocked":true,"reason":"refresh fee exceeds reserve"}));
            }
            evidence(
                req,
                "refresh_proposal",
                json!({"participation":participation,"committed_fee_sat":fee}),
            )?;
            let id = if req.operation == "refresh_delegated" {
                wallet
                    .join_next_round_delegated(participation, Some(RoundMovement::Refresh))
                    .await?
                    .id()
            } else {
                let state = wallet
                    .join_next_round(participation, Some(RoundMovement::Refresh))
                    .await?;
                let id = state.id();
                drop(state.unlock());
                wallet.participate_ongoing_rounds().await?;
                id
            };
            Ok(
                json!({"round_state_id":id.to_string(), "committed_fee_sat":fee,
                      "actual_fee_sat":Value::Null,"evidence":coin_evidence(&wallet).await?,
                      "note":"intent submitted; independent round outcome and fee reconciliation required"}),
            )
        }
        "pay_invoice" => {
            let invoice: ark::lightning::Invoice = req.args["invoice"]
                .as_str()
                .context("invoice required")?
                .parse()?;
            ensure!(invoice.network() == network, "invoice network mismatch");
            invoice.check_signature()?;
            let send_amount = invoice.get_payment_amount(Some(amount(&req.args)?))?;
            let ceiling =
                lightning_fee_ceiling(&wallet.require_ark_info().await?.fees, send_amount)?;
            if ceiling.to_sat() > req.maximum_fee_sat {
                return Ok(
                    json!({"blocked":true,"reason":"worst-case SDK lightning fee exceeds reserve"}),
                );
            }
            let quote = wallet.estimate_lightning_send_fee(send_amount).await?;
            ensure!(
                !quote.vtxos_spent.is_empty(),
                "no lightning inputs available"
            );
            evidence(
                req,
                "lightning_proposal",
                json!({"payment_hash":invoice.payment_hash().to_string(),
                "amount_sat":send_amount.to_sat(),"fee_ceiling_sat":ceiling.to_sat(),
                "input_vtxo_ids":quote.vtxos_spent.iter().map(|id|id.to_string()).collect::<Vec<_>>()}),
            )?;
            let hash = invoice.payment_hash();
            let invoice = wallet
                .pay_lightning_invoice(invoice, Some(send_amount), false)
                .await?;
            let pending = wallet.lightning_send_checkpoint(hash).await?;
            if let Some(ref send) = pending {
                ensure!(
                    send.fee <= ceiling,
                    InvariantFailure("lightning fee exceeded bound")
                );
            }
            Ok(
                json!({"payment_hash":invoice.payment_hash().to_string(),"initiated":true,
                "paid":wallet.is_invoice_paid(hash).await?, "committed_fee_sat":pending.as_ref().map(|s|s.fee.to_sat()),
                "actual_fee_sat":Value::Null, "evidence":coin_evidence(&wallet).await?,
                "note":"initiation is not settlement; receiver and node evidence must reconcile"}),
            )
        }
        "offboard_all" => {
            // Reuse the SDK's public persisted action/executor. Freeze the fee and
            // output before any forfeit, instead of re-quoting inside offboard_all.
            let onchain = wallet.onchain().context("missing onchain wallet")?;
            let destination = if let Some(address) = req.args["destination"].as_str() {
                let address = address
                    .parse::<Address<bitcoin::address::NetworkUnchecked>>()?
                    .require_network(network)?;
                ensure!(
                    onchain
                        .read()
                        .await
                        .is_mine(&address.script_pubkey())
                        .await?,
                    "offboard destination must be this actor's wallet"
                );
                address
            } else {
                onchain.write().await.address().await?
            };
            let inputs = wallet.spendable_vtxos().await?;
            ensure!(!inputs.is_empty(), "no offboard inputs");
            let ark = wallet.require_ark_info().await?;
            ensure!(
                inputs.len() <= ark.max_offboard_inputs,
                "too many offboard inputs"
            );
            let ids = inputs.iter().map(|v| v.id()).collect::<Vec<_>>();
            ensure!(
                ids.iter().collect::<std::collections::HashSet<_>>().len() == ids.len(),
                "duplicate offboard inputs"
            );
            let rate = rpc
                .get_offboard_fee_rate(protos::Empty {})
                .await?
                .into_inner();
            let rate = FeeRate::from_sat_per_kwu(rate.sat_vkb / 4);
            let tip = wallet.chain().tip().await?;
            let gross = inputs
                .iter()
                .try_fold(Amount::ZERO, |a, v| a.checked_add(v.amount()))
                .context("offboard input overflow")?;
            let fee = ark
                .fees
                .offboard
                .calculate(
                    &destination.script_pubkey(),
                    gross,
                    rate,
                    inputs
                        .iter()
                        .map(|v| ark::fees::VtxoFeeInfo::from_vtxo_and_tip(v, tip)),
                )
                .context("offboard fee overflow")?;
            if fee.to_sat() > req.maximum_fee_sat {
                return Ok(json!({"blocked":true,"reason":"offboard fee exceeds reserve"}));
            }
            let net = ark::fees::validate_and_subtract_fee_min_dust(
                gross,
                fee,
                destination.script_pubkey().minimal_non_dust(),
            )?;
            let action = Offboard {
                id: hex(&rand::random::<[u8; 16]>()),
                destination: destination.clone().into_unchecked(),
                onchain_output_amount: net,
                committed_fee: fee,
                committed_fee_rate: rate,
                kind: OffboardKind::OffboardWhole {
                    input_vtxo_ids: ids.clone(),
                },
                progress: OffboardProgress::Start,
            };
            evidence(
                req,
                "offboard_proposal",
                json!({"action_id":action.id,"destination":destination.to_string(),
                "destination_script":hex(destination.script_pubkey().as_bytes()),
                "input_vtxo_ids":ids.iter().map(|id|id.to_string()).collect::<Vec<_>>(),"net_sat":net.to_sat(),"committed_fee_sat":fee.to_sat()}),
            )?;
            db.upsert_wallet_action_checkpoint(&action.id, &action.clone().into())
                .await?;
            let id = action.id.clone();
            wallet
                .drive_action(action, DriveMode::UntilParkOrDone)
                .await?;
            let checkpoint = wallet
                .offboard_checkpoint(&id)
                .await?
                .context("offboard checkpoint vanished")?;
            let txid = match checkpoint.progress {
                OffboardProgress::AwaitingConfirmations { offboard_txid, .. } => {
                    Some(offboard_txid.to_string())
                }
                _ => None,
            };
            Ok(
                json!({"offboard_action_id":id,"txid":txid,"destination":destination.to_string(),
                "destination_script":hex(destination.script_pubkey().as_bytes()),
                "committed_fee_sat":fee.to_sat(),"actual_fee_sat":Value::Null,"evidence":coin_evidence(&wallet).await?,
                "note":"await chain confirmation; pending checkpoints are not automatically retried by supervisor"}),
            )
        }
        operation if operation.starts_with("raw_") => {
            let fallback = wallet.fallback_destination().await?;
            evidence(
                req,
                "raw_local_binding_ready",
                json!({"seq":fallback.seq,"spk":hex(fallback.spk.as_bytes())}),
            )?;
            let mailbox = wallet.mailbox_keypair();
            let target_mailbox = if operation == "raw_foreign_record" {
                let target = PublicKey::from_str(
                    req.args["victim_mailbox_pk"]
                        .as_str()
                        .context("public victim mailbox required")?,
                )?;
                ensure!(
                    target != mailbox.public_key(),
                    "victim must be another wallet"
                );
                target
            } else {
                mailbox.public_key()
            };
            let request = |record, key_links| protos::SetFallbackRequest {
                mailbox_pk: target_mailbox.serialize().to_vec(),
                record,
                key_links,
            };
            let before = rpc
                .set_fallback(request(None, vec![]))
                .await.map_err(|status| {
                    let _ = evidence(req,"raw_baseline_query_failed",json!({"mailbox_pk":target_mailbox.to_string(),"code":format!("{:?}",status.code())}));
                    status
                })?
                .into_inner()
                .record;
            evidence(
                req,
                "raw_baseline_read",
                json!({"mailbox_pk":target_mailbox.to_string(),"serialized":hex(&before)}),
            )?;
            let protected_record =
                json!({"mailbox_pk":target_mailbox.to_string(),"serialized":hex(&before)});
            let mut record = record_bytes(chain_hash, &fallback.spk, fallback.seq, &mailbox);
            let mut links = vec![];
            let reject = match operation {
                "raw_board_unlinked" => {
                    let key = Keypair::new(&SECP, &mut rand::thread_rng());
                    let (_, nonce) = ark::musig::nonce_pair(&key);
                    let body = protos::BoardCosignRequest {
                        amount: 100_000,
                        utxo: bitcoin::OutPoint::null().serialize(),
                        expiry_height: 1,
                        user_pubkey: key.public_key().serialize().to_vec(),
                        pub_nonce: nonce.serialize().to_vec(),
                        funding_tx: bitcoin::consensus::serialize(&bitcoin::Transaction {
                            version: bitcoin::transaction::Version::TWO,
                            lock_time: bitcoin::absolute::LockTime::ZERO,
                            input: vec![],
                            output: vec![],
                        }),
                    };
                    evidence(
                        req,
                        "raw_board_request",
                        json!({"user_pubkey":key.public_key().to_string(),
                        "amount_sat":body.amount,"unsigned_funding_hex":hex(&body.funding_tx),
                        "pver":server_rpc::MAX_PROTOCOL_VERSION,"no_funding_broadcast":true}),
                    )?;
                    let mut body = tonic::Request::new(body);
                    body.set_pver(server_rpc::MAX_PROTOCOL_VERSION);
                    let response = rpc.request_board_cosign(body).await;
                    evidence(
                        req,
                        "raw_board_response",
                        json!({"code":response.as_ref().err().map(|s|format!("{:?}",s.code())),
                        "missing_fallback_guard":response.as_ref().err().is_some_and(|s|s.message().contains("missing fallback link or wallet record"))}),
                    )?;
                    match response {
                        Err(s)
                            if s.code() == tonic::Code::InvalidArgument
                                && s.message()
                                    .contains("missing fallback link or wallet record") => {}
                        Err(_) => {
                            bail!("board was not refused by the expected missing-fallback guard")
                        }
                        Ok(_) => {
                            return Err(
                                InvariantFailure("unlinked board request was accepted").into()
                            );
                        }
                    }
                    let after = rpc
                        .set_fallback(request(None, vec![]))
                        .await?
                        .into_inner()
                        .record;
                    ensure!(
                        after == before,
                        InvariantFailure("unlinked board request changed wallet record")
                    );
                    return Ok(
                        json!({"expected_refusal":true,"binding_unchanged":true,"no_funding_broadcast":true,
                        "protected_record":protected_record,
                        "refusal_stage":"missing fallback link or wallet record","attempted_key_pubkeys":[key.public_key().to_string()]}),
                    );
                }
                "raw_relink" => {
                    let (key, _) = wallet.derive_store_next_keypair().await?;
                    let alternate = Keypair::new(&SECP, &mut rand::thread_rng());
                    let mut link = key.public_key().serialize().to_vec();
                    link.extend(KeyLinkAttestation::new(alternate.public_key(), &key).serialize());
                    let body = protos::SetFallbackRequest {
                        mailbox_pk: alternate.public_key().serialize().to_vec(),
                        record: Some(record_bytes(
                            chain_hash,
                            &fallback.spk,
                            fallback.seq,
                            &alternate,
                        )),
                        key_links: vec![link],
                    };
                    evidence(
                        req,
                        "raw_relink_request",
                        json!({"user_pubkey":key.public_key().to_string(),
                        "original_mailbox_pk":mailbox.public_key().to_string(),"alternate_mailbox_pk":alternate.public_key().to_string(),
                        "destination_script":hex(fallback.spk.as_bytes())}),
                    )?;
                    rpc.set_fallback(body).await?;
                    let after = rpc
                        .set_fallback(request(None, vec![]))
                        .await?
                        .into_inner()
                        .record;
                    ensure!(
                        after == before,
                        InvariantFailure("relink changed original wallet record")
                    );
                    return Ok(
                        json!({"binding_unchanged":true,"key_link_immutability_pending":true,
                        "protected_record":protected_record,
                        "user_pubkey":key.public_key().to_string(),"original_mailbox_pk":mailbox.public_key().to_string(),
                        "alternate_mailbox_pk":alternate.public_key().to_string(),
                        "scope":"RPC accepted a valid alternate link; independent server mapping check still required"}),
                    );
                }
                "raw_foreign_record" => {
                    ensure!(!before.is_empty(), "victim record must already exist");
                    true
                }
                "raw_record_tamper" => {
                    record[2] ^= 1;
                    true
                }
                "raw_sequence_tamper" => {
                    let offset = record.len() - 72;
                    record[offset] ^= 1;
                    true
                }
                "raw_wrong_chain" => {
                    record = record_bytes(
                        if network == Network::Signet {
                            ChainHash::REGTEST
                        } else {
                            ChainHash::SIGNET
                        },
                        &fallback.spk,
                        fallback.seq,
                        &mailbox,
                    );
                    true
                }
                "raw_stale_record" | "raw_equal_sequence" => {
                    let mut spk = fallback.spk.as_bytes().to_vec();
                    spk[2] ^= 1;
                    let spk = bitcoin::ScriptBuf::from_bytes(spk);
                    let seq = if operation == "raw_stale_record" {
                        fallback.seq.saturating_sub(1)
                    } else {
                        fallback.seq
                    };
                    record = record_bytes(chain_hash, &spk, seq, &mailbox);
                    false
                }
                "raw_invalid_link" | "raw_mailbox_tamper" | "raw_key_replay" | "raw_mixed_link" => {
                    let key = Keypair::new(&SECP, &mut rand::thread_rng());
                    let other = Keypair::new(&SECP, &mut rand::thread_rng());
                    let public_key = if operation == "raw_invalid_link" {
                        let target = PublicKey::from_str(
                            req.args["victim_pubkey"]
                                .as_str()
                                .context("public victim coin key required")?,
                        )?;
                        ensure!(
                            target != key.public_key(),
                            "victim key must differ from signer"
                        );
                        target
                    } else if operation == "raw_key_replay" {
                        other.public_key()
                    } else {
                        key.public_key()
                    };
                    let signed_mailbox =
                        if operation == "raw_mailbox_tamper" || operation == "raw_mixed_link" {
                            other.public_key()
                        } else {
                            mailbox.public_key()
                        };
                    let mut link = public_key.serialize().to_vec();
                    link.extend(KeyLinkAttestation::new(signed_mailbox, &key).serialize());
                    links.push(link);
                    if operation == "raw_mixed_link" {
                        record = record_bytes(
                            chain_hash,
                            &fallback.spk,
                            fallback.seq.checked_add(1).context("sequence exhausted")?,
                            &mailbox,
                        );
                        let valid = Keypair::new(&SECP, &mut rand::thread_rng());
                        let mut valid_link = valid.public_key().serialize().to_vec();
                        valid_link.extend(
                            KeyLinkAttestation::new(mailbox.public_key(), &valid).serialize(),
                        );
                        links.insert(0, valid_link);
                    }
                    true
                }
                "raw_malformed" => {
                    match req.args["variant"].as_u64().unwrap_or(0) % 3 {
                        0 => {
                            record.truncate(record.len() - 1);
                        }
                        1 => {
                            links.push(vec![0; 96]);
                        }
                        _ => {
                            record = vec![0; 115];
                        }
                    }
                    true
                }
                "raw_bounded_queries" => {
                    for index in 0..8 {
                        let value = rpc
                            .set_fallback(request(None, vec![]))
                            .await?
                            .into_inner()
                            .record;
                        evidence(
                            req,
                            "raw_query",
                            json!({"index":index,"record":hex(&value)}),
                        )?;
                        ensure!(
                            value == before,
                            InvariantFailure("bounded query changed stored binding")
                        );
                    }
                    return Ok(
                        json!({"binding_unchanged":true,"bounded_queries":8,"actual_fee_sat":0,"protected_record":protected_record}),
                    );
                }
                _ => bail!("unsupported raw scenario"),
            };
            evidence(
                req,
                "raw_request",
                json!({"rpc":"SetFallback", "mailbox_pk":hex(&target_mailbox.serialize()),
                "record":hex(&record), "key_links":links.iter().map(|link| hex(link)).collect::<Vec<_>>(),
                "record_before":hex(&before)}),
            )?;
            let attempted_keys = links
                .iter()
                .filter(|l| l.len() == 97)
                .map(|l| hex(&l[..33]))
                .collect::<Vec<_>>();
            let result = rpc.set_fallback(request(Some(record), links)).await;
            evidence(
                req,
                "raw_response",
                json!({"rpc":"SetFallback", "code":result.as_ref().err().map(|status| format!("{:?}",status.code())).unwrap_or("Ok".into()),
                "record_returned":result.as_ref().ok().map(|response| hex(&response.get_ref().record))}),
            )?;
            if reject {
                match result {
                    Err(status) if status.code() == tonic::Code::InvalidArgument => {}
                    Err(_) => bail!("unexpected RPC refusal class"),
                    Ok(_) => return Err(InvariantFailure("invalid request was accepted").into()),
                }
            } else {
                ensure!(
                    result?.into_inner().record == before,
                    InvariantFailure("stale/equal record changed stored binding")
                );
            }
            let after = rpc
                .set_fallback(request(None, vec![]))
                .await?
                .into_inner()
                .record;
            evidence(
                req,
                "raw_binding_after",
                json!({"record_after":hex(&after)}),
            )?;
            ensure!(
                after == before,
                InvariantFailure("negative request changed stored record")
            );
            Ok(
                json!({"expected_refusal": reject, "binding_unchanged": true, "operation": operation,
                    "protected_record":protected_record,
                    "attempted_key_pubkeys":attempted_keys}),
            )
        }
        _ => bail!("unsupported operation"),
    }
    }, ||coin_evidence(&wallet), |name,data|evidence(req,name,data)).await
}

fn response_status(data:&Value)->&'static str {
    if data["probe_unknown"].as_bool()==Some(true) || data["phase_unknown"].as_bool()==Some(true) {"error"}
    else if data["blocked"].as_bool()==Some(true) {"blocked"}
    else if data["expected_refusal"].as_bool()==Some(true) {"expected_refusal"}
    else {"ok"}
}

fn actor_index(actor:&str)->Result<u16> {
    let index=actor.strip_prefix("actor-").and_then(|s|s.parse::<u16>().ok())
        .context("invalid actor directory")?;
    ensure!((1..=999).contains(&index) && actor==format!("actor-{index:02}"),"invalid actor directory");
    Ok(index)
}

fn response_fee(operation:&str,data:&Value)->Value {
    if response_status(data)=="error" {return Value::Null;}
    data.get("actual_fee_sat").cloned().unwrap_or_else(|| {
        if data["blocked"].as_bool()==Some(true)
            || matches!(operation,"create"|"snapshot"|"address"|"invoice")
            || (operation.starts_with("raw_") && !operation.starts_with("raw_protocol_")) {json!(0)}
        else {Value::Null}
    })
}

#[cfg(test)]
mod response_tests {
    use super::*;
    #[test]
    fn native_actor_names_cover_two_hundred_new_phones_without_aliases() {
        for index in 41..=240 {assert_eq!(actor_index(&format!("actor-{index:02}")).unwrap(),index);}
        for name in ["actor-00","actor-041","actor-1000","noah-phone-41","actor-41/../09"] {
            assert!(actor_index(name).is_err());
        }
    }
    #[test]
    fn saved_private_fence_is_unknown_even_with_blocked_flag_and_claimed_zero_fee() {
        for flag in ["probe_unknown","phase_unknown"] {
            let mut data=json!({"blocked":true,"actual_fee_sat":0});
            data[flag]=json!(true);
            assert_eq!(response_status(&data),"error");
            assert!(response_fee("raw_protocol_d13",&data).is_null());
            assert!(response_fee("phase_execute_d17",&data).is_null());
        }
    }
    #[test]
    fn new_money_adapters_cannot_default_a_missing_fee_to_zero() {
        for operation in ["raw_protocol_d13","phase_execute_d17","phase_register_saved"] {
            assert!(response_fee(operation,&json!({})).is_null());
        }
        assert_eq!(response_fee("snapshot",&json!({})),json!(0));
        assert_eq!(response_fee("raw_protocol_d13",&json!({"actual_fee_sat":0})),json!(0));
    }
}

#[tokio::main]
async fn main() {
    if std::env::var("BARK_SIM_LOG").as_deref() == Ok("debug") {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).try_init();
    }
    let mut input = String::new();
    let result = (|| -> Result<(DriverConfig, Request)> {
        io::stdin()
            .take(256 * 1024 + 1)
            .read_to_string(&mut input)?;
        ensure!(input.len() <= 256 * 1024, "request too large");
        let path = std::env::var("SIM_DRIVER_CONFIG").context("SIM_DRIVER_CONFIG required")?;
        Ok((
            serde_json::from_str(&fs::read_to_string(path)?)?,
            serde_json::from_str(&input)?,
        ))
    })();
    match result {
        Ok((cfg, req)) => match execute(cfg, &req).await {
            Ok(data) => {
                let status=response_status(&data);
                let actual_fee=response_fee(req.operation.as_str(),&data);
                println!(
                    "{}",
                    json!({"action_id": req.action_id, "status": status, "data": data, "actual_fee_sat": actual_fee})
                );
            }
            Err(error) => {
                let status = if error.is::<InvariantFailure>() {
                    "incident"
                } else {
                    "error"
                };
                println!(
                    "{}",
                    json!({"action_id": req.action_id, "status": status,
                    "reason": if status == "incident" { "protocol invariant violated; preserve evidence and pause" }
                              else { "driver operation failed; outcome must be reconciled" }})
                );
            }
        },
        Err(_) => {
            eprintln!("invalid request or driver configuration");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[tokio::test]
    async fn operation_evidence_observes_fresh_before_and_after_without_replacing_errors() {
        use std::cell::{Cell,RefCell};
        let current=Cell::new(7);
        let events=RefCell::new(Vec::new());
        let operation=async {current.set(8);bail!("original operation failure")};
        let result=observed_wallet_operation(operation,
            ||async {Ok(json!({"coins":[current.get()]}))},
            |name,value|{events.borrow_mut().push((name.to_owned(),value));Ok(())}).await;
        assert_eq!(result.unwrap_err().to_string(),"original operation failure");
        let events=events.borrow();
        assert_eq!(events.len(),2,"wallet operation has no fresh evidence boundaries");
        assert_eq!(events[0].0,"client_evidence_before");
        assert_eq!(events[0].1["evidence"]["coins"],json!([7]));
        assert_eq!(events[1].0,"client_evidence_after");
        assert_eq!(events[1].1["evidence"]["coins"],json!([8]));
    }

    #[tokio::test]
    async fn observation_failure_cannot_replace_a_successful_operation() {
        let result=observed_wallet_operation(async {Ok(json!({"accepted":true}))},
            ||async {bail!("capture failed")},|_,_|bail!("journal unavailable")).await;
        assert_eq!(result.unwrap()["accepted"],true);
    }


    #[tokio::test]
    async fn missing_before_capture_records_a_gap_and_still_attempts_fresh_after() {
        use std::cell::{Cell,RefCell};
        let count=Cell::new(0);
        let events=RefCell::new(Vec::new());
        let result=observed_wallet_operation(async {Ok(json!({"accepted":true}))},
            ||async {count.set(count.get()+1);if count.get()==1 {bail!("capture failed")};Ok(json!({"coins":["fresh"]}))},
            |name,value|{events.borrow_mut().push((name.to_owned(),value));Ok(())}).await;
        assert_eq!(result.unwrap()["accepted"],true);
        assert_eq!(count.get(),2);
        let events=events.borrow();
        assert_eq!(events[0].0,"client_evidence_gap");
        assert_eq!(events[0].1["phase"],"before");
        assert_eq!(events[1].0,"client_evidence_after");
        assert_eq!(events[1].1["evidence"]["coins"],json!(["fresh"]));
    }

    #[tokio::test]
    async fn failed_logging_preserves_the_original_operation_error() {
        let result=observed_wallet_operation(async {bail!("original operation failure")},
            ||async {Ok(json!({"coins":[]}))},|_,_|bail!("journal unavailable")).await;
        assert_eq!(result.unwrap_err().to_string(),"original operation failure");
    }


    #[test]
    fn exit_budget_never_expands_or_ignores_prior_signed_attempts() {
        assert!(verify_exit_budget(1000,1000,&[400],600).is_ok());
        assert!(verify_exit_budget(1000,1001,&[400],600).is_err(),"a resumed exit silently increased its fee cap");
        assert!(verify_exit_budget(1000,1000,&[400],601).is_err(),"exit ignored already reserved mining fees");
        assert!(verify_exit_budget(1000,1000,&[u64::MAX],1).is_err(),"exit fee sum overflow was accepted");
    }

    #[test]
    fn recycle_psbt_requires_exact_receipt_value_script_and_only_one_input() {
        let outpoint=bitcoin::OutPoint::from_str(&format!("{}:1","a".repeat(64))).unwrap();
        let script=bitcoin::ScriptBuf::from_hex(&format!("0014{}","b".repeat(40))).unwrap();
        let source=json!({"outpoint":outpoint.to_string(),"script":hex(script.as_bytes()),"amount_sat":6481});
        let transaction=bitcoin::Transaction{version:bitcoin::transaction::Version::TWO,lock_time:bitcoin::absolute::LockTime::ZERO,
            input:vec![bitcoin::TxIn{previous_output:outpoint,script_sig:bitcoin::ScriptBuf::new(),sequence:bitcoin::Sequence::MAX,witness:bitcoin::Witness::new()}],output:vec![]};
        let mut psbt=bitcoin::Psbt::from_unsigned_tx(transaction).unwrap();
        psbt.inputs[0].witness_utxo=Some(bitcoin::TxOut{value:Amount::from_sat(6481),script_pubkey:script});
        assert!(verify_recycle_input(&psbt,&source).is_ok());
        let mut wrong=source.clone();wrong["amount_sat"]=json!(6480);assert!(verify_recycle_input(&psbt,&wrong).is_err());
        wrong=source.clone();wrong["script"]=json!(format!("0014{}","c".repeat(40)));assert!(verify_recycle_input(&psbt,&wrong).is_err());
        wrong=source.clone();wrong["outpoint"]=json!(format!("{}:1","d".repeat(64)));assert!(verify_recycle_input(&psbt,&wrong).is_err());
        psbt.unsigned_tx.input.push(psbt.unsigned_tx.input[0].clone());assert!(verify_recycle_input(&psbt,&source).is_err());
        psbt.unsigned_tx.input.pop();psbt.inputs[0].witness_utxo=None;assert!(verify_recycle_input(&psbt,&source).is_err());
    }

    #[test]
    fn payment_success_requires_matching_preimage_without_exporting_it() {
        use protos::lightning_payment_status::PaymentStatus;
        let preimage = vec![7; 32];
        let hash = sha256::Hash::hash(&preimage);
        let success = |bytes| protos::LightningPaymentStatus {
            payment_status: Some(PaymentStatus::Success(protos::PaymentSuccessStatus {
                preimage: bytes,
            })),
        };
        let result = public_payment_status(hash, success(preimage.clone())).unwrap();
        assert_eq!(result["state"], "succeeded");
        assert_eq!(result["success_preimage_hash_valid"], true);
        assert_eq!(result["read_only"], true);
        assert!(result.get("preimage").is_none());
        assert!(public_payment_status(sha256::Hash::hash(&[8; 32]), success(preimage)).is_err());
        assert!(public_payment_status(hash, success(vec![7; 31])).is_err());
    }

    #[test]
    fn pending_failed_and_missing_status_never_count_as_success() {
        use protos::lightning_payment_status::PaymentStatus;
        let hash = sha256::Hash::hash(&[7; 32]);
        for (status, state) in [
            (PaymentStatus::Pending(protos::Empty {}), "pending"),
            (PaymentStatus::Failed(protos::Empty {}), "failed"),
        ] {
            let result = public_payment_status(
                hash,
                protos::LightningPaymentStatus {
                    payment_status: Some(status),
                },
            )
            .unwrap();
            assert_eq!(result["state"], state);
            assert_eq!(result["success_preimage_hash_valid"], false);
        }
        assert!(
            public_payment_status(
                hash,
                protos::LightningPaymentStatus {
                    payment_status: None,
                }
            )
            .is_err()
        );
    }

    #[test]
    fn fallback_signature_binds_chain_and_script() {
        let key = Keypair::from_seckey_slice(&SECP, &[1; 32]).unwrap();
        let script =
            bitcoin::ScriptBuf::from_hex("00141111111111111111111111111111111111111111").unwrap();
        let record = record_bytes(ChainHash::SIGNET, &script, 123, &key);
        let signature = <FallbackRecordAttestation as ProtocolEncoding>::deserialize(
            &record[record.len() - 64..],
        )
        .unwrap();
        signature
            .verify(ChainHash::SIGNET, &script, 123, key.public_key())
            .unwrap();
        assert!(
            signature
                .verify(ChainHash::REGTEST, &script, 123, key.public_key())
                .is_err()
        );
        let other =
            bitcoin::ScriptBuf::from_hex("00142222222222222222222222222222222222222222").unwrap();
        assert!(
            signature
                .verify(ChainHash::SIGNET, &other, 123, key.public_key())
                .is_err()
        );
    }

    #[test]
    fn fallback_signature_binds_sequence_and_owner() {
        let key = Keypair::from_seckey_slice(&SECP, &[1; 32]).unwrap();
        let other = Keypair::from_seckey_slice(&SECP, &[2; 32]).unwrap();
        let script =
            bitcoin::ScriptBuf::from_hex("00141111111111111111111111111111111111111111").unwrap();
        let record = record_bytes(ChainHash::SIGNET, &script, 123, &key);
        let signature = <FallbackRecordAttestation as ProtocolEncoding>::deserialize(
            &record[record.len() - 64..],
        )
        .unwrap();
        assert!(
            signature
                .verify(ChainHash::SIGNET, &script, 124, key.public_key())
                .is_err()
        );
        assert!(
            signature
                .verify(ChainHash::SIGNET, &script, 123, other.public_key())
                .is_err()
        );
    }

    #[test]
    fn network_guard_refuses_mainnet_and_remote_regtest() {
        assert!(allowed_network("bitcoin", "http://127.0.0.1:1").is_err());
        assert!(allowed_network("testnet", "http://127.0.0.1:1").is_err());
        assert!(allowed_network("regtest", "http://example.org:1").is_err());
        assert_eq!(
            allowed_network("regtest", "http://127.0.0.1:3535").unwrap(),
            Network::Regtest
        );
        assert_eq!(
            allowed_network("signet", "https://example.org:3535").unwrap(),
            Network::Signet
        );
    }

    #[test]
    fn lightning_ceiling_covers_every_expiry_and_fragmentation() {
        use ark::fees::{FeeSchedule, PpmExpiryFeeEntry, PpmFeeRate, VtxoFeeInfo};
        let mut fees = FeeSchedule::default();
        fees.lightning_send.base_fee = Amount::from_sat(17);
        fees.lightning_send.min_fee = Amount::from_sat(20);
        fees.lightning_send.ppm_expiry_table = vec![
            PpmExpiryFeeEntry {
                expiry_blocks_threshold: 0,
                ppm: PpmFeeRate(100),
            },
            PpmExpiryFeeEntry {
                expiry_blocks_threshold: 30,
                ppm: PpmFeeRate(10000),
            },
            PpmExpiryFeeEntry {
                expiry_blocks_threshold: 100,
                ppm: PpmFeeRate(50000),
            },
        ];
        let amount = Amount::from_sat(1001);
        let bound = lightning_fee_ceiling(&fees, amount).unwrap();
        assert_eq!(bound.to_sat(), 68);
        for expiry in [0, 29, 30, 99, 100, u32::MAX] {
            let fee = fees
                .lightning_send
                .calculate(
                    amount,
                    [
                        VtxoFeeInfo {
                            amount: Amount::from_sat(500),
                            expiry_blocks: expiry,
                        },
                        VtxoFeeInfo {
                            amount: Amount::from_sat(1000),
                            expiry_blocks: expiry,
                        },
                    ],
                )
                .unwrap();
            assert!(fee <= bound);
        }
        fees.lightning_send.ppm_expiry_table.reverse();
        assert!(lightning_fee_ceiling(&fees, amount).is_err());
    }

    #[test]
    fn outstanding_invoices_can_progress_under_the_original_fee_cap() {
        let selection = receive_sync_selection(&[150; 20], 2000,0).unwrap();
        assert!(!selection.is_empty(), "twenty outstanding invoices must not deadlock sync");
        assert_eq!(selection.len(), 13);
        assert_eq!(selection.iter().map(|_|150u64).sum::<u64>(),1950);
    }

    #[test]
    fn funded_tail_checkpoint_is_polled_on_the_next_bounded_pass() {
        let hashes=(0..20).map(|i|format!("{i:064x}")).collect::<Vec<_>>();
        let fees=[104;20];
        let first=receive_sync_selection(&fees,2000,0).unwrap();
        assert_eq!(first.len(),19);
        assert!(!first.contains(&19));
        let cursor=&hashes[*first.last().unwrap()];
        let start=receive_sync_start(&hashes,&json!({"receive_sync_start_after":cursor})).unwrap();
        let second=receive_sync_selection(&fees,2000,start).unwrap();
        assert_eq!(second[0],19);
        assert_eq!(second.iter().copied().collect::<std::collections::HashSet<_>>().len(),19);
        assert_eq!(second.iter().map(|i|fees[*i]).sum::<u64>(),1976);
        assert!(first.iter().chain(&second).copied().collect::<std::collections::HashSet<_>>().len()==20);
    }

    #[test]
    fn receive_cursor_removal_validation_and_checkpoint_limit() {
        let hashes=(0..64).map(|i|format!("{i:064x}")).collect::<Vec<_>>();
        let first=receive_sync_selection(&[0;64],0,0).unwrap();
        let start=receive_sync_start(&hashes,&json!({"receive_sync_start_after":hashes[31]})).unwrap();
        let second=receive_sync_selection(&[0;64],0,start).unwrap();
        assert_eq!(first,(0..32).collect::<Vec<_>>());
        assert_eq!(second,(32..64).collect::<Vec<_>>());
        assert_eq!(receive_sync_start(&[],&json!({"receive_sync_start_after":hashes[31]})).unwrap(),0);
        assert_eq!(receive_sync_start(&hashes[32..],&json!({"receive_sync_start_after":hashes[31]})).unwrap(),0);
        assert!(receive_sync_start(&hashes,&json!({"receive_sync_start_after":"not-a-hash"})).is_err());
        assert!(receive_sync_start(&hashes,&json!({"receive_sync_start_after":3})).is_err());
        assert!(receive_sync_start(&hashes,&json!({"receive_sync_start_after":"A".repeat(64)})).is_err());
        assert!(receive_sync_selection(&[1],2000,1).is_err());
    }

    #[test]
    fn receive_selection_never_crosses_the_fee_cap_or_repeats_a_checkpoint() {
        let fees=[2001,150,150,0];
        let selection=receive_sync_selection(&fees,300,0).unwrap();
        assert_eq!(selection,vec![1,2,3]);
        assert!(selection.iter().map(|i|fees[*i]).sum::<u64>()<=300);
        assert!(receive_sync_selection(&[2001],2000,0).unwrap().is_empty());
        assert!(receive_sync_selection(&[u64::MAX,1],u64::MAX,0).is_err());
    }

    #[test]
    fn funded_receive_target_preempts_stale_cursor() {
        let hashes=(0..20).map(|i|format!("{i:064x}")).collect::<Vec<_>>();
        let args=json!({"receive_payment_hash":hashes[19],"receive_sync_start_after":hashes[0]});
        assert_eq!(receive_sync_start(&hashes,&args).unwrap(),19);
        assert!(receive_sync_start(&hashes,&json!({"receive_payment_hash":"f".repeat(64)})).is_err());
        assert!(receive_sync_start(&hashes,&json!({"receive_payment_hash":"not-a-hash"})).is_err());
    }

    #[test]
    fn cancellation_requires_all_three_native_facts() {
        use protos::LightningReceiveStatus as S;
        assert!(cancellation_is_terminal(true,true,S::Canceled));
        assert!(!cancellation_is_terminal(false,true,S::Canceled));
        assert!(!cancellation_is_terminal(true,false,S::Canceled));
        for status in [S::Created,S::Accepted,S::HtlcsReady,S::Settled] {
            assert!(!cancellation_is_terminal(true,true,status));
        }
    }

    #[test]
    fn zero_fee_receive_polling_remains_bounded() {
        assert_eq!(receive_sync_selection(&[0;100],0,0).unwrap().len(),32);
        assert!(receive_sync_selection(&[],0,0).unwrap().is_empty());
    }

    #[test]
    fn monetary_input_rejects_float_zero_and_negative() {
        assert_eq!(
            amount(&json!({"amount_sat": 1000})).unwrap(),
            Amount::from_sat(1000)
        );
        for value in [json!(0), json!(-1), json!(1.5), json!("1000")] {
            assert!(amount(&json!({"amount_sat": value})).is_err());
        }
    }
}
