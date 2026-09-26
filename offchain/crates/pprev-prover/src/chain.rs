//! Register transaction (Section V-D): the payload the owner submits once it holds sigma_R, and its
//! submission to a JSON-RPC node.

use std::time::{Duration, Instant};

use alloy::network::EthereumWallet;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolInterface};
use alloy_primitives::{Address, B256, Bytes, U256};
use anyhow::{Context, Result, bail};
use pprev_types::statement::TxData;
use serde::{Deserialize, Serialize};

sol! {
    #[sol(all_derives)]
    interface IPPREV {
        struct TxDataAbi {
            bytes32 propertyId;
            uint256 amount;
            uint256 settlementShare;
        }

        function register(
            bytes32 cTx,
            TxDataAbi txData,
            bytes32 policyIdR,
            bytes32 r,
            bytes sigmaR,
            bytes32 etaR,
            uint64 tAttR
        ) external payable returns (uint256 txId);

        event Registered(
            uint256 indexed txId,
            address indexed owner,
            bytes32 cTx,
            bytes32 policyIdR,
            TxDataAbi txData,
            bytes32 r,
            uint256 collateral
        );

        error UnknownPolicy(bytes32 policyIdR);
        error CommitmentMismatch();
        error InvalidNotarySignature();
        error NonceConsumed(bytes32 eta);
        error AttestationFromFuture(uint64 tAtt);
        error AttestationExpired(uint64 tAtt);
        error CommitmentRegistered(bytes32 cTx);
        error CollateralOutOfBounds(uint256 collateral);
        error SettlementShareTooHigh(uint256 settlementShare);
    }
}

/// Interval at which the receipt is polled. alloy's default for a local node (250 ms) would dominate
/// t_incl on a chain that includes the transaction at once.
pub const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Arguments of one `register` call and the value sent with it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPayload {
    pub chain_id: u64,
    pub contract: Address,
    /// a_P in x_R: the only account whose call the signature admits.
    pub submitter: Address,
    pub c_tx: B256,
    pub property_id: B256,
    pub amount: U256,
    pub settlement_share: U256,
    pub policy_id_r: B256,
    pub r: B256,
    pub sigma_r: Bytes,
    pub eta_r: B256,
    pub t_att_r: u64,
    pub collateral: U256,
}

impl RegisterPayload {
    pub fn tx_data(&self) -> TxData {
        TxData {
            propertyId: self.property_id,
            amount: self.amount,
            settlementShare: self.settlement_share,
        }
    }

    fn calldata(&self) -> Vec<u8> {
        IPPREV::registerCall {
            cTx: self.c_tx,
            txData: IPPREV::TxDataAbi {
                propertyId: self.property_id,
                amount: self.amount,
                settlementShare: self.settlement_share,
            },
            policyIdR: self.policy_id_r,
            r: self.r,
            sigmaR: self.sigma_r.clone(),
            etaR: self.eta_r,
            tAttR: self.t_att_r,
        }
        .abi_encode()
    }
}

/// The `Registered` event of an included transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredEvent {
    pub tx_id: U256,
    pub owner: Address,
    pub c_tx: B256,
    pub policy_id_r: B256,
    pub property_id: B256,
    pub amount: U256,
    pub settlement_share: U256,
    pub r: B256,
    pub collateral: U256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "outcome"
)]
pub enum SubmitOutcome {
    /// The transaction was included and emitted `Registered`.
    Included {
        tx_hash: B256,
        block_number: u64,
        block_timestamp: u64,
        gas_used: u64,
        /// From sending the transaction to holding its receipt: t_incl.
        t_incl_ms: f64,
        event: Box<RegisteredEvent>,
    },
    /// The node rejected the call; `error` is the contract's custom error when it has one.
    Reverted { error: String },
}

/// Sends the `register` transaction from `key` and waits for its receipt.
pub async fn submit_register(
    rpc_url: &str,
    key: &PrivateKeySigner,
    payload: &RegisterPayload,
) -> Result<SubmitOutcome> {
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(key.clone()))
        .connect_http(rpc_url.parse().context("RPC URL")?);
    provider.client().set_poll_interval(RECEIPT_POLL_INTERVAL);
    let chain_id = provider.get_chain_id().await?;
    if chain_id != payload.chain_id {
        bail!(
            "the node is on chain {chain_id}, the payload on {}",
            payload.chain_id
        );
    }
    let tx = TransactionRequest::default()
        .to(payload.contract)
        .value(payload.collateral)
        .input(payload.calldata().into());

    let started = Instant::now();
    let pending = match provider.send_transaction(tx).await {
        Ok(pending) => pending,
        Err(e) => return reverted(e),
    };
    let receipt = pending.get_receipt().await?;
    let t_incl_ms = started.elapsed().as_secs_f64() * 1000.0;

    if !receipt.status() {
        return Ok(SubmitOutcome::Reverted {
            error: "reverted on-chain without revert data".into(),
        });
    }
    let block_number = receipt
        .block_number
        .context("receipt has no block number")?;
    let block = provider
        .get_block_by_number(block_number.into())
        .await?
        .context("inclusion block not found")?;
    let log = receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| log.log_decode::<IPPREV::Registered>().ok())
        .context("receipt has no Registered event")?;
    let e = log.inner.data;
    Ok(SubmitOutcome::Included {
        tx_hash: receipt.transaction_hash,
        block_number,
        block_timestamp: block.header.timestamp,
        gas_used: receipt.gas_used,
        t_incl_ms,
        event: Box::new(RegisteredEvent {
            tx_id: e.txId,
            owner: e.owner,
            c_tx: e.cTx,
            policy_id_r: e.policyIdR,
            property_id: e.txData.propertyId,
            amount: e.txData.amount,
            settlement_share: e.txData.settlementShare,
            r: e.r,
            collateral: e.collateral,
        }),
    })
}

/// Classifies a rejected call by the contract's custom error; any other failure is an error.
fn reverted(e: alloy::transports::TransportError) -> Result<SubmitOutcome> {
    let Some(data) = e.as_error_resp().and_then(|p| p.as_revert_data()) else {
        return Err(anyhow::Error::from(e).context("sending the register transaction"));
    };
    let error = match IPPREV::IPPREVErrors::abi_decode(&data) {
        Ok(decoded) => format!("{decoded:?}"),
        Err(_) => format!("unknown revert data 0x{}", hex::encode(&data)),
    };
    Ok(SubmitOutcome::Reverted { error })
}

pub fn read_private_key(path: &std::path::Path) -> Result<PrivateKeySigner> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    text.trim()
        .parse()
        .with_context(|| format!("{}: not a private key", path.display()))
}

/// Chain ID of the node at `rpc_url`.
pub async fn chain_id(rpc_url: &str) -> Result<u64> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().context("RPC URL")?);
    Ok(provider.get_chain_id().await?)
}
