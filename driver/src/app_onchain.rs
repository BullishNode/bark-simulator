//! Attach the existing test application's wallet without copying its signer.
use anyhow::{Context, Result, bail, ensure};
use ark_testing::onchain::AppBip84Wallet;
use bark::chain::{ChainSource, ChainSourceSpec};
use bark::onchain::{OnchainWallet, OnchainWalletTrait};
use bitcoin::{BlockHash, Network};
use bitcoin_ext::{BlockHeight, rpc::BitcoinRpcClient};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
pub(crate) struct ChainAnchor {
    height: u32,
    hash: BlockHash,
}

pub(crate) async fn bound_core(
    config: &bark::Config,
    network: Network,
    anchor: &ChainAnchor,
) -> Result<BitcoinRpcClient> {
    // Signet's network identifier alone does not identify a private chain.
    // The bootstrap supplies an actual mined block, not an invented RPC field.
    ensure!(anchor.height > 0, "bootstrap anchor must be a mined block");
    let spec = config.chain_source()?;
    let rpc = match &spec {
        ChainSourceSpec::Bitcoind { url, auth, .. } => BitcoinRpcClient::new(url, auth.clone())?,
        ChainSourceSpec::Esplora { .. } => bail!("app_bip84 requires configured Core"),
    };
    let chain = ChainSource::new(spec, network, None, None).await?;
    let tip = chain.tip_ref().await?;
    ensure!(tip.height.to_u32() >= anchor.height, "Core has not reached bootstrap anchor");
    ensure!(chain.block_ref(BlockHeight::new(anchor.height)).await?.hash == anchor.hash,
        "configured Core differs from bootstrap chain anchor");
    Ok(rpc)
}

pub(crate) fn inventory(wallet: &dyn OnchainWalletTrait) -> Result<Value> {
    let any = wallet as &dyn std::any::Any;
    if let Some(native) = any.downcast_ref::<OnchainWallet>() {
        return crate::onchain_inventory::collect(native);
    }
    let app = any.downcast_ref::<AppBip84Wallet>().context("unsupported onchain wallet adapter")?;
    let unspent = app.list_unspent();
    ensure!(unspent.len() <= 2_000, "application UTXO inventory bound exceeded");
    let outputs = unspent.iter().map(|output| json!({
        "outpoint":output.outpoint.to_string(), "value_sat":output.txout.value.to_sat(),
        "script_pubkey":crate::hex(output.txout.script_pubkey.as_bytes()),
        "confirmed_height_upper_bound":output.chain_position.confirmation_height_upper_bound(),
    })).collect::<Vec<_>>();
    // The reused adapter deliberately exposes no complete transaction graph.
    Ok(json!({"schema_version":1,"read_only":true,"complete":false,
        "scope":"application BIP84 list_unspent; no sync or complete graph qualification",
        "confirmed_fee_eligibility":"not qualified", "utxos":outputs}))
}
