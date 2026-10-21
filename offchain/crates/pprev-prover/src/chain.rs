//! Attested transactions (Sections V-D, V-E, V-G) and Engage (Section V-F): the payloads the parties
//! submit once they hold sigma_psi, and their submission to a JSON-RPC node.

use std::time::{Duration, Instant};

use alloy::network::EthereumWallet;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolInterface};
use alloy_primitives::{Address, B256, Bytes, U256};
use anyhow::{Context, Result, bail};
use pprev_types::statement::{TxData, commitment};
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

        function applyFor(
            uint256 txId,
            TxDataAbi txData,
            bytes32 r,
            bytes32 cB,
            bytes sigmaA,
            bytes32 etaA,
            uint64 tAttA
        ) external payable returns (uint256 appId);

        function engage(uint256 txId, uint256 appId) external returns (uint256 engId);

        function settle(
            uint256 engId,
            TxDataAbi txData,
            bytes32 r,
            bytes sigmaS,
            bytes32 etaS,
            uint64 tAttS
        ) external;

        function TAU_LOCK() external view returns (uint256);

        event Applied(
            uint256 indexed appId,
            uint256 indexed txId,
            address indexed applicant,
            bytes32 cB,
            uint256 deposit
        );
        event Engaged(uint256 indexed engId, uint256 indexed txId, uint256 indexed appId, uint256 expiresAt);
        event Settled(uint256 indexed engId, uint256 indexed txId, uint256 toOwner, uint256 toCounterparty);

        error UnknownPolicy(bytes32 policyIdR);
        error CommitmentMismatch();
        error InvalidNotarySignature();
        error NonceConsumed(bytes32 eta);
        error AttestationFromFuture(uint64 tAtt);
        error AttestationExpired(uint64 tAtt);
        error CommitmentRegistered(bytes32 cTx);
        error CollateralOutOfBounds(uint256 collateral);
        error SettlementShareTooHigh(uint256 settlementShare);
        error ListingNotOpen(uint256 txId);
        error OwnerCannotApply();
        error PendingApplicationExists(uint256 appId);
        error InsufficientDeposit(uint256 deposit);
        error NotListingOwner();
        error ApplicationNotPending(uint256 appId);
        error ApplicationTxMismatch();
        error UnknownEngagement(uint256 engId);
        error NotLocked(uint256 txId);
        error LockWindowElapsed();
    }
}

fn tx_data_abi(tx_data: &TxData) -> IPPREV::TxDataAbi {
    IPPREV::TxDataAbi {
        propertyId: tx_data.propertyId,
        amount: tx_data.amount,
        settlementShare: tx_data.settlementShare,
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

/// An included transaction.
pub struct Inclusion {
    pub receipt: TransactionReceipt,
    pub block_number: u64,
    pub block_timestamp: u64,
    /// From sending the transaction to holding its receipt: t_incl.
    pub t_incl_ms: f64,
}

/// Sends a transaction to `contract` from `key` and waits for its receipt. A rejected call is
/// `Err(error)` with the contract's custom error when it has one; any other failure is an error.
pub async fn send(
    rpc_url: &str,
    key: &PrivateKeySigner,
    expected_chain_id: u64,
    contract: Address,
    value: U256,
    calldata: Vec<u8>,
) -> Result<std::result::Result<Inclusion, String>> {
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(key.clone()))
        .connect_http(rpc_url.parse().context("RPC URL")?);
    provider.client().set_poll_interval(RECEIPT_POLL_INTERVAL);
    let chain_id = provider.get_chain_id().await?;
    if chain_id != expected_chain_id {
        bail!("the node is on chain {chain_id}, the payload on {expected_chain_id}");
    }
    let tx = TransactionRequest::default()
        .to(contract)
        .value(value)
        .input(calldata.into());

    let started = Instant::now();
    let pending = match provider.send_transaction(tx).await {
        Ok(pending) => pending,
        Err(e) => return Ok(Err(revert_reason(e)?)),
    };
    let receipt = pending.get_receipt().await?;
    let t_incl_ms = started.elapsed().as_secs_f64() * 1000.0;

    if !receipt.status() {
        return Ok(Err("reverted on-chain without revert data".into()));
    }
    let block_number = receipt
        .block_number
        .context("receipt has no block number")?;
    let block = provider
        .get_block_by_number(block_number.into())
        .await?
        .context("inclusion block not found")?;
    Ok(Ok(Inclusion {
        receipt,
        block_number,
        block_timestamp: block.header.timestamp,
        t_incl_ms,
    }))
}

/// Sends the `register` transaction from `key` and waits for its receipt.
pub async fn submit_register(
    rpc_url: &str,
    key: &PrivateKeySigner,
    payload: &RegisterPayload,
) -> Result<SubmitOutcome> {
    let inclusion = match send(
        rpc_url,
        key,
        payload.chain_id,
        payload.contract,
        payload.collateral,
        payload.calldata(),
    )
    .await?
    {
        Ok(inclusion) => inclusion,
        Err(error) => return Ok(SubmitOutcome::Reverted { error }),
    };
    let receipt = &inclusion.receipt;
    let log = receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| log.log_decode::<IPPREV::Registered>().ok())
        .context("receipt has no Registered event")?;
    let e = log.inner.data;
    Ok(SubmitOutcome::Included {
        tx_hash: receipt.transaction_hash,
        block_number: inclusion.block_number,
        block_timestamp: inclusion.block_timestamp,
        gas_used: receipt.gas_used,
        t_incl_ms: inclusion.t_incl_ms,
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
fn revert_reason(e: alloy::transports::TransportError) -> Result<String> {
    let Some(data) = e.as_error_resp().and_then(|p| p.as_revert_data()) else {
        return Err(anyhow::Error::from(e).context("sending the transaction"));
    };
    Ok(match IPPREV::IPPREVErrors::abi_decode(&data) {
        Ok(decoded) => format!("{decoded:?}"),
        Err(_) => format!("unknown revert data 0x{}", hex::encode(&data)),
    })
}

/// The outcome of an Apply, Engage, or Settle transaction: the inclusion with the decoded event, or
/// the contract's error.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "outcome"
)]
pub enum PhaseOutcome<E> {
    Included {
        tx_hash: B256,
        block_number: u64,
        block_timestamp: u64,
        gas_used: u64,
        t_incl_ms: f64,
        event: E,
    },
    Reverted {
        error: String,
    },
}

/// One contract call: the chain it is meant for, the contract, the value sent, and the calldata.
struct Call {
    chain_id: u64,
    contract: Address,
    value: U256,
    calldata: Vec<u8>,
}

async fn submit_phase<E, L>(
    rpc_url: &str,
    key: &PrivateKeySigner,
    call: Call,
    decode: impl Fn(&alloy::rpc::types::Log) -> Option<L>,
    into_event: impl Fn(L) -> E,
    name: &str,
) -> Result<PhaseOutcome<E>> {
    let inclusion = match send(
        rpc_url,
        key,
        call.chain_id,
        call.contract,
        call.value,
        call.calldata,
    )
    .await?
    {
        Ok(inclusion) => inclusion,
        Err(error) => return Ok(PhaseOutcome::Reverted { error }),
    };
    let receipt = &inclusion.receipt;
    let event = receipt
        .inner
        .logs()
        .iter()
        .find_map(decode)
        .with_context(|| format!("receipt has no {name} event"))?;
    Ok(PhaseOutcome::Included {
        tx_hash: receipt.transaction_hash,
        block_number: inclusion.block_number,
        block_timestamp: inclusion.block_timestamp,
        gas_used: receipt.gas_used,
        t_incl_ms: inclusion.t_incl_ms,
        event: into_event(event),
    })
}

/// Arguments of one `applyFor` call and the deposit sent with it, with the opening of c_B that the
/// counterparty hands to the owner for phi_S (Section V-G).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyPayload {
    pub chain_id: u64,
    pub contract: Address,
    /// a_B in x_A.
    pub submitter: Address,
    pub tx_id: U256,
    pub property_id: B256,
    pub amount: U256,
    pub settlement_share: U256,
    pub r: B256,
    pub c_b: B256,
    pub sigma_a: Bytes,
    pub eta_a: B256,
    pub t_att_a: u64,
    pub deposit: U256,
    /// Opening of c_B: the identifier, padded to its layout width, and the salt.
    pub identifier: String,
    pub salt: B256,
}

impl ApplyPayload {
    pub fn tx_data(&self) -> TxData {
        TxData {
            propertyId: self.property_id,
            amount: self.amount,
            settlementShare: self.settlement_share,
        }
    }

    pub fn calldata(&self) -> Vec<u8> {
        IPPREV::applyForCall {
            txId: self.tx_id,
            txData: tx_data_abi(&self.tx_data()),
            r: self.r,
            cB: self.c_b,
            sigmaA: self.sigma_a.clone(),
            etaA: self.eta_a,
            tAttA: self.t_att_a,
        }
        .abi_encode()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppliedEvent {
    pub app_id: U256,
    pub tx_id: U256,
    pub applicant: Address,
    pub c_b: B256,
    pub deposit: U256,
}

/// Sends the `applyFor` transaction from `key` with the deposit and waits for its receipt.
pub async fn submit_apply(
    rpc_url: &str,
    key: &PrivateKeySigner,
    payload: &ApplyPayload,
) -> Result<PhaseOutcome<AppliedEvent>> {
    submit_phase(
        rpc_url,
        key,
        Call {
            chain_id: payload.chain_id,
            contract: payload.contract,
            value: payload.deposit,
            calldata: payload.calldata(),
        },
        |log| log.log_decode::<IPPREV::Applied>().ok(),
        |log| {
            let e = log.inner.data;
            AppliedEvent {
                app_id: e.appId,
                tx_id: e.txId,
                applicant: e.applicant,
                c_b: e.cB,
                deposit: e.deposit,
            }
        },
        "Applied",
    )
    .await
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngagedEvent {
    pub eng_id: U256,
    pub tx_id: U256,
    pub app_id: U256,
    pub expires_at: U256,
}

/// Sends `engage(txId, appId)` from the owner's `key` and waits for its receipt.
pub async fn submit_engage(
    rpc_url: &str,
    key: &PrivateKeySigner,
    contract: Address,
    tx_id: U256,
    app_id: U256,
) -> Result<PhaseOutcome<EngagedEvent>> {
    let chain_id = chain_id(rpc_url).await?;
    submit_phase(
        rpc_url,
        key,
        Call {
            chain_id,
            contract,
            value: U256::ZERO,
            calldata: IPPREV::engageCall {
                txId: tx_id,
                appId: app_id,
            }
            .abi_encode(),
        },
        |log| log.log_decode::<IPPREV::Engaged>().ok(),
        |log| {
            let e = log.inner.data;
            EngagedEvent {
                eng_id: e.engId,
                tx_id: e.txId,
                app_id: e.appId,
                expires_at: e.expiresAt,
            }
        },
        "Engaged",
    )
    .await
}

/// Arguments of one `settle` call.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlePayload {
    pub chain_id: u64,
    pub contract: Address,
    /// a_P in x_S.
    pub submitter: Address,
    pub eng_id: U256,
    pub property_id: B256,
    pub amount: U256,
    pub settlement_share: U256,
    pub r: B256,
    pub sigma_s: Bytes,
    pub eta_s: B256,
    pub t_att_s: u64,
}

impl SettlePayload {
    pub fn tx_data(&self) -> TxData {
        TxData {
            propertyId: self.property_id,
            amount: self.amount,
            settlementShare: self.settlement_share,
        }
    }

    pub fn calldata(&self) -> Vec<u8> {
        IPPREV::settleCall {
            engId: self.eng_id,
            txData: tx_data_abi(&self.tx_data()),
            r: self.r,
            sigmaS: self.sigma_s.clone(),
            etaS: self.eta_s,
            tAttS: self.t_att_s,
        }
        .abi_encode()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettledEvent {
    pub eng_id: U256,
    pub tx_id: U256,
    pub to_owner: U256,
    pub to_counterparty: U256,
}

/// Sends the `settle` transaction from the owner's `key` and waits for its receipt.
pub async fn submit_settle(
    rpc_url: &str,
    key: &PrivateKeySigner,
    payload: &SettlePayload,
) -> Result<PhaseOutcome<SettledEvent>> {
    submit_phase(
        rpc_url,
        key,
        Call {
            chain_id: payload.chain_id,
            contract: payload.contract,
            value: U256::ZERO,
            calldata: payload.calldata(),
        },
        |log| log.log_decode::<IPPREV::Settled>().ok(),
        |log| {
            let e = log.inner.data;
            SettledEvent {
                eng_id: e.engId,
                tx_id: e.txId,
                to_owner: e.toOwner,
                to_counterparty: e.toCounterparty,
            }
        },
        "Settled",
    )
    .await
}

/// The deployment's lock window, `TAU_LOCK()`.
pub async fn tau_lock(rpc_url: &str, contract: Address) -> Result<u64> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().context("RPC URL")?);
    let call = TransactionRequest::default()
        .to(contract)
        .input(IPPREV::TAU_LOCKCall {}.abi_encode().into());
    let out = provider.call(call).await?;
    let value = IPPREV::TAU_LOCKCall::abi_decode_returns(&out)?;
    value.try_into().context("TAU_LOCK exceeds 64 bits")
}

/// C_tx of a listing from its public parameters.
pub fn listing_commitment(tx_data: &TxData, policy_id_r: B256, r: B256) -> B256 {
    commitment(tx_data, policy_id_r, r)
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
