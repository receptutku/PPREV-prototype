// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Values of the transaction-state map TxState[txID] (Section V-A). `None` marks an
/// identifier that has not been assigned.
enum TxState {
    None,
    Active,
    Locked,
    Settled,
    Expired,
    Cancelled
}

enum AppStatus {
    None,
    Pending,
    Engaged,
    Reclaimed
}

enum EngStatus {
    None,
    Open,
    Settled,
    Expired
}

/// @notice Public transaction parameters txData. Every field is a static 32-byte word, so
/// abi.encode(txData, policyIdR, r) is the concatenation txData || policyID_R || r of Eq. (2).
struct TxData {
    bytes32 propertyId;
    uint256 amount;
    /// @dev Part of the counterparty's deposit, in basis points, that Settle pays to the owner.
    uint256 settlementShare;
}

/// @notice PolicyRegistry entry. Registering under policyID_R fixes the whole bundle.
struct Policy {
    bool exists;
    bytes32 policyIdA;
    bytes32 policyIdS;
    uint256 reqEscrow;
    uint256 minCollateral;
    uint256 maxCollateral;
}

/// @notice Transaction record. txData and r are emitted at registration, never stored.
struct Listing {
    bytes32 cTx;
    bytes32 policyIdR;
    address owner;
    /// @dev The owner's remaining collateral.
    uint256 collateral;
    uint256 expirations;
}

struct Application {
    uint256 txId;
    address depositor;
    AppStatus status;
    uint256 deposit;
    bytes32 cB;
}

/// @notice Engagement record. It reaches txID, the counterparty, and c_B through its application.
struct Engagement {
    uint256 appId;
    uint256 expiresAt;
    EngStatus status;
}

event PolicyRegistered(
    bytes32 indexed policyIdR,
    bytes32 policyIdA,
    bytes32 policyIdS,
    uint256 reqEscrow,
    uint256 minCollateral,
    uint256 maxCollateral
);
event NotaryVerifierSet(address indexed verifier);
event Registered(
    uint256 indexed txId,
    address indexed owner,
    bytes32 cTx,
    bytes32 policyIdR,
    TxData txData,
    bytes32 r,
    uint256 collateral
);
event Applied(uint256 indexed appId, uint256 indexed txId, address indexed applicant, bytes32 cB, uint256 deposit);
event Engaged(uint256 indexed engId, uint256 indexed txId, uint256 indexed appId, uint256 expiresAt);
event Settled(uint256 indexed engId, uint256 indexed txId, uint256 toOwner, uint256 toCounterparty);
event Expired(
    uint256 indexed engId,
    uint256 indexed txId,
    uint256 compensation,
    uint256 expirations,
    bool exhausted,
    uint256 returnedToOwner
);
event Reclaimed(uint256 indexed appId, uint256 indexed txId, uint256 deposit);
event Cancelled(uint256 indexed txId, uint256 returnedToOwner);
event PayoutCredited(address indexed recipient, uint256 amount);
event Withdrawn(address indexed recipient, uint256 amount);

error NotOperator();
error InvalidParameters();
error PolicyExists(bytes32 policyIdR);
/// @dev R(a)
error UnknownPolicy(bytes32 policyIdR);
/// @dev R(b), A(c), S(d)
error CommitmentMismatch();
/// @dev R(c), A(d), S(e)
error InvalidNotarySignature();
/// @dev R(d), A(e), S(f)
error NonceConsumed(bytes32 eta);
/// @dev Lower bound of R(e), A(f), S(g)
error AttestationFromFuture(uint64 tAtt);
/// @dev Upper bound of R(e), A(f), S(g)
error AttestationExpired(uint64 tAtt);
/// @dev R(f)
error CommitmentRegistered(bytes32 cTx);
/// @dev R(g)
error CollateralOutOfBounds(uint256 collateral);
/// @dev R(h)
error SettlementShareTooHigh(uint256 settlementShare);
/// @dev A(a), Engage (iii), Cancel
error ListingNotOpen(uint256 txId);
/// @dev A(b)
error OwnerCannotApply();
/// @dev A(g)
error PendingApplicationExists(uint256 appId);
/// @dev A(h)
error InsufficientDeposit(uint256 deposit);
/// @dev Engage (i), S(b), Cancel
error NotListingOwner();
/// @dev Engage (ii), Reclaim
error ApplicationNotPending(uint256 appId);
/// @dev Engage (ii)
error ApplicationTxMismatch();
/// @dev S(a)
error UnknownEngagement(uint256 engId);
/// @dev S(c), E(b)
error NotLocked(uint256 txId);
/// @dev S(h)
error LockWindowElapsed();
/// @dev E(a)
error EngagementNotOpen(uint256 engId);
/// @dev E(c)
error LockWindowNotElapsed();
error NotDepositor();
error NothingToWithdraw();
error WithdrawFailed();
