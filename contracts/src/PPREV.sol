// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {INotaryVerifier} from "./interfaces/INotaryVerifier.sol";
import {PPREVEncoding} from "./PPREVEncoding.sol";
import {
    TxState,
    AppStatus,
    EngStatus,
    TxData,
    Policy,
    Listing,
    Application,
    Engagement,
    PolicyRegistered,
    NotaryVerifierSet,
    Registered,
    Applied,
    Engaged,
    Settled,
    Expired,
    Reclaimed,
    Cancelled,
    PayoutCredited,
    Withdrawn,
    NotOperator,
    InvalidParameters,
    PolicyExists,
    UnknownPolicy,
    CommitmentMismatch,
    InvalidNotarySignature,
    NonceConsumed,
    AttestationFromFuture,
    AttestationExpired,
    CommitmentRegistered,
    CollateralOutOfBounds,
    SettlementShareTooHigh,
    ListingNotOpen,
    OwnerCannotApply,
    PendingApplicationExists,
    InsufficientDeposit,
    NotListingOwner,
    ApplicationNotPending,
    ApplicationTxMismatch,
    UnknownEngagement,
    NotLocked,
    LockWindowElapsed,
    EngagementNotOpen,
    LockWindowNotElapsed,
    NotDepositor,
    NothingToWithdraw,
    WithdrawFailed
} from "./PPREVTypes.sol";

/// @title PPREV on-chain enforcement layer
/// @notice Implements the seven on-chain algorithms of Section V (Register, Apply, Engage, Settle,
/// Expire, Reclaim, Cancel) and the auxiliary Withdraw. Acceptance conditions are checked in the
/// paper's letter order; comments name each condition.
contract PPREV {
    /// @notice Gas forwarded with each payout made by an algorithm (payout rule, Section V-A).
    uint256 public constant PAYOUT_GAS = 30_000;
    /// @notice Basis-point denominator for RHO and the settlement share.
    uint256 public constant BPS = 10_000;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("PPREV");
    bytes32 private constant VERSION_HASH = keccak256("1");

    /// @notice Deployment operator: registers policies and rotates the notary verifier.
    address public immutable OPERATOR;
    /// @notice Freshness window Delta, in seconds.
    uint256 public immutable DELTA;
    /// @notice Lock window tau_lock, in seconds.
    uint256 public immutable TAU_LOCK;
    /// @notice maxExpirations.
    uint256 public immutable MAX_EXPIRATIONS;
    /// @notice Survival ratio rho, in basis points of the remaining collateral.
    uint256 public immutable RHO;

    uint256 private immutable CACHED_CHAIN_ID;
    bytes32 private immutable CACHED_DOMAIN_SEPARATOR;

    /// @notice Verifier holding vk_notary.
    INotaryVerifier public notaryVerifier;

    mapping(bytes32 policyIdR => Policy) public policyRegistry;
    mapping(uint256 txId => Listing) public listings;
    mapping(uint256 txId => TxState) public txState;
    /// @notice Commitment index for R(f).
    mapping(bytes32 cTx => bool) public registered;
    /// @notice Consumed nonces, global across phases.
    mapping(bytes32 eta => bool) public consumed;
    mapping(uint256 appId => Application) public applications;
    /// @notice Pending application of an applicant for a listing, for A(g).
    mapping(uint256 txId => mapping(address applicant => uint256 appId)) public pendingApp;
    mapping(uint256 engId => Engagement) public engagements;
    /// @notice Payouts that could not be delivered, claimable through withdraw().
    mapping(address recipient => uint256 amount) public credit;

    uint256 public nextTxId;
    uint256 public nextAppId;
    uint256 public nextEngId;

    constructor(
        address operator,
        INotaryVerifier verifier,
        uint256 delta,
        uint256 tauLock,
        uint256 maxExpirations,
        uint256 rho
    ) {
        if (
            operator == address(0) || address(verifier) == address(0) || delta == 0 || tauLock == 0
                || maxExpirations == 0 || rho == 0 || rho >= BPS
        ) revert InvalidParameters();
        OPERATOR = operator;
        DELTA = delta;
        TAU_LOCK = tauLock;
        MAX_EXPIRATIONS = maxExpirations;
        RHO = rho;
        CACHED_CHAIN_ID = block.chainid;
        CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator();
        notaryVerifier = verifier;
        // Identifiers start at 1 so that 0 marks an absent record. Every assignment then updates an
        // existing counter slot, as in a deployment that has already processed transactions.
        nextTxId = 1;
        nextAppId = 1;
        nextEngId = 1;
        emit NotaryVerifierSet(address(verifier));
    }

    // ---------------------------------------------------------------------------------------------
    // Administrative operations (Section V-C), outside the eight algorithms
    // ---------------------------------------------------------------------------------------------

    /// @notice Adds a policy bundle keyed by policyID_R. A registered bundle cannot be changed.
    /// @dev minCollateral = 0 and maxCollateral = type(uint256).max leave the collateral unbounded;
    /// reqEscrow = 0 requires no escrow.
    function registerPolicy(
        bytes32 policyIdR,
        bytes32 policyIdA,
        bytes32 policyIdS,
        uint256 reqEscrow,
        uint256 minCollateral,
        uint256 maxCollateral
    ) external {
        if (msg.sender != OPERATOR) revert NotOperator();
        if (
            policyIdR == 0 || policyIdA == 0 || policyIdS == 0 || policyIdR == policyIdA || policyIdR == policyIdS
                || policyIdA == policyIdS || minCollateral > maxCollateral
        ) revert InvalidParameters();
        Policy storage p = policyRegistry[policyIdR];
        if (p.exists) revert PolicyExists(policyIdR);
        p.exists = true;
        p.policyIdA = policyIdA;
        p.policyIdS = policyIdS;
        p.reqEscrow = reqEscrow;
        p.minCollateral = minCollateral;
        p.maxCollateral = maxCollateral;
        emit PolicyRegistered(policyIdR, policyIdA, policyIdS, reqEscrow, minCollateral, maxCollateral);
    }

    /// @notice Rotates vk_notary by installing a new verifier.
    function setNotaryVerifier(INotaryVerifier verifier) external {
        if (msg.sender != OPERATOR) revert NotOperator();
        if (address(verifier) == address(0)) revert InvalidParameters();
        notaryVerifier = verifier;
        emit NotaryVerifierSet(address(verifier));
    }

    // ---------------------------------------------------------------------------------------------
    // Attested algorithms
    // ---------------------------------------------------------------------------------------------

    /// @notice Register (Section V-D). msg.value is the listing collateral.
    function register(
        bytes32 cTx,
        TxData calldata txData,
        bytes32 policyIdR,
        bytes32 r,
        bytes calldata sigmaR,
        bytes32 etaR,
        uint64 tAttR
    ) external payable returns (uint256 txId) {
        Policy storage p = policyRegistry[policyIdR];
        // R(a)
        if (!p.exists) revert UnknownPolicy(policyIdR);
        // R(b)
        if (PPREVEncoding.commitment(txData, policyIdR, r) != cTx) revert CommitmentMismatch();
        // R(c): the contract reconstructs x_R with a_P fixed to the caller.
        {
            PPREVEncoding.RegisterStatement memory xR;
            xR.cTx = cTx;
            xR.txDataHash = PPREVEncoding.hashTxData(txData);
            xR.policyId = policyIdR;
            xR.submitter = msg.sender;
            xR.eta = etaR;
            xR.tAtt = tAttR;
            _verifyNotarySignature(PPREVEncoding.hashRegister(xR), sigmaR);
        }
        // R(d)
        _requireUnconsumed(etaR);
        // R(e)
        _requireFresh(tAttR);
        // R(f)
        if (registered[cTx]) revert CommitmentRegistered(cTx);
        // R(g)
        if (msg.value < p.minCollateral || msg.value > p.maxCollateral) revert CollateralOutOfBounds(msg.value);
        // R(h)
        if (txData.settlementShare > BPS) revert SettlementShareTooHigh(txData.settlementShare);

        txId = nextTxId++;
        Listing storage l = listings[txId];
        l.cTx = cTx;
        l.policyIdR = policyIdR;
        l.owner = msg.sender;
        l.collateral = msg.value;
        txState[txId] = TxState.Active;
        registered[cTx] = true;
        consumed[etaR] = true;
        emit Registered(txId, msg.sender, cTx, policyIdR, txData, r, msg.value);
    }

    /// @notice Apply (Section V-E). msg.value is the escrow deposit. Named applyFor because `apply`
    /// is reserved in Solidity.
    function applyFor(
        uint256 txId,
        TxData calldata txData,
        bytes32 r,
        bytes32 cB,
        bytes calldata sigmaA,
        bytes32 etaA,
        uint64 tAttA
    ) external payable returns (uint256 appId) {
        Listing storage l = listings[txId];
        // A(a)
        if (!_isOpen(txId)) revert ListingNotOpen(txId);
        // A(b)
        if (msg.sender == l.owner) revert OwnerCannotApply();
        // A(c)
        if (PPREVEncoding.commitment(txData, l.policyIdR, r) != l.cTx) revert CommitmentMismatch();
        Policy storage p = policyRegistry[l.policyIdR];
        // A(d): x_A with a_B fixed to the caller; C_tx and policyID_A come from the records.
        {
            PPREVEncoding.ApplyStatement memory xA;
            xA.txId = txId;
            xA.cTx = l.cTx;
            xA.txDataHash = PPREVEncoding.hashTxData(txData);
            xA.cB = cB;
            xA.policyId = p.policyIdA;
            xA.submitter = msg.sender;
            xA.eta = etaA;
            xA.tAtt = tAttA;
            _verifyNotarySignature(PPREVEncoding.hashApply(xA), sigmaA);
        }
        // A(e)
        _requireUnconsumed(etaA);
        // A(f)
        _requireFresh(tAttA);
        // A(g)
        {
            uint256 pending = pendingApp[txId][msg.sender];
            if (pending != 0) revert PendingApplicationExists(pending);
        }
        // A(h)
        if (msg.value < p.reqEscrow) revert InsufficientDeposit(msg.value);

        appId = nextAppId++;
        Application storage a = applications[appId];
        a.txId = txId;
        a.depositor = msg.sender;
        a.status = AppStatus.Pending;
        a.deposit = msg.value;
        a.cB = cB;
        pendingApp[txId][msg.sender] = appId;
        consumed[etaA] = true;
        emit Applied(appId, txId, msg.sender, cB, msg.value);
    }

    /// @notice Settle (Section V-G).
    function settle(uint256 engId, TxData calldata txData, bytes32 r, bytes calldata sigmaS, bytes32 etaS, uint64 tAttS)
        external
    {
        Engagement storage e = engagements[engId];
        // S(a)
        if (e.status == EngStatus.None) revert UnknownEngagement(engId);
        Application storage a = applications[e.appId];
        uint256 txId = a.txId;
        Listing storage l = listings[txId];
        // S(b)
        if (msg.sender != l.owner) revert NotListingOwner();
        // S(c)
        if (txState[txId] != TxState.Locked) revert NotLocked(txId);
        // S(d)
        if (PPREVEncoding.commitment(txData, l.policyIdR, r) != l.cTx) revert CommitmentMismatch();
        // S(e): x_S with a_P fixed to the caller; c_B and expiresAt come from the records.
        {
            PPREVEncoding.SettleStatement memory xS;
            xS.engId = engId;
            xS.txId = txId;
            xS.cTx = l.cTx;
            xS.txDataHash = PPREVEncoding.hashTxData(txData);
            xS.cB = a.cB;
            xS.expiresAt = e.expiresAt;
            xS.policyId = policyRegistry[l.policyIdR].policyIdS;
            xS.submitter = msg.sender;
            xS.eta = etaS;
            xS.tAtt = tAttS;
            _verifyNotarySignature(PPREVEncoding.hashSettle(xS), sigmaS);
        }
        // S(f)
        _requireUnconsumed(etaS);
        // S(g)
        _requireFresh(tAttS);
        // S(h). A block producer moves block.timestamp by seconds at most (within the block
        // interval), which is small against the lock window TAU_LOCK, measured in days.
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > e.expiresAt) revert LockWindowElapsed();

        consumed[etaS] = true;
        e.status = EngStatus.Settled;
        txState[txId] = TxState.Settled;
        uint256 deposit = a.deposit;
        // R(h) bounds the settlement share by BPS, so ownerShare <= deposit.
        uint256 ownerShare = deposit * txData.settlementShare / BPS;
        uint256 toOwner = ownerShare + l.collateral;
        l.collateral = 0;
        emit Settled(engId, txId, toOwner, deposit - ownerShare);
        _pay(l.owner, toOwner);
        _pay(a.depositor, deposit - ownerShare);
    }

    // ---------------------------------------------------------------------------------------------
    // Pure on-chain algorithms
    // ---------------------------------------------------------------------------------------------

    /// @notice Engage (Section V-F).
    function engage(uint256 txId, uint256 appId) external returns (uint256 engId) {
        Listing storage l = listings[txId];
        // (i)
        if (msg.sender != l.owner) revert NotListingOwner();
        // (ii)
        Application storage a = applications[appId];
        if (a.status != AppStatus.Pending) revert ApplicationNotPending(appId);
        if (a.txId != txId) revert ApplicationTxMismatch();
        // (iii)
        if (!_isOpen(txId)) revert ListingNotOpen(txId);

        engId = nextEngId++;
        uint256 expiresAt = block.timestamp + TAU_LOCK;
        Engagement storage e = engagements[engId];
        e.appId = appId;
        e.expiresAt = expiresAt;
        e.status = EngStatus.Open;
        a.status = AppStatus.Engaged;
        delete pendingApp[txId][a.depositor];
        txState[txId] = TxState.Locked;
        emit Engaged(engId, txId, appId, expiresAt);
    }

    /// @notice Expire (Section V-H). Callable by anyone.
    function expire(uint256 engId) external {
        Engagement storage e = engagements[engId];
        // E(a). A listing has at most one open engagement, and only while it is LOCKED, so E(a) also
        // rejects an engagement of an earlier round (Section V-H).
        if (e.status != EngStatus.Open) revert EngagementNotOpen(engId);
        Application storage a = applications[e.appId];
        uint256 txId = a.txId;
        // E(b)
        if (txState[txId] != TxState.Locked) revert NotLocked(txId);
        // E(c). As in S(h), producer influence on block.timestamp (seconds) is small against TAU_LOCK
        // (days).
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp <= e.expiresAt) revert LockWindowNotElapsed();

        Listing storage l = listings[txId];
        e.status = EngStatus.Expired;
        uint256 remaining = l.collateral;
        uint256 surviving = remaining * RHO / BPS;
        uint256 expirations = l.expirations + 1;
        l.expirations = expirations;
        bool exhausted = expirations == MAX_EXPIRATIONS;
        if (exhausted) {
            // The exhausting expiration cancels the listing and returns the surviving collateral.
            txState[txId] = TxState.Cancelled;
            l.collateral = 0;
        } else {
            txState[txId] = TxState.Expired;
            l.collateral = surviving;
        }
        uint256 compensation = remaining - surviving;
        emit Expired(engId, txId, compensation, expirations, exhausted, exhausted ? surviving : 0);
        _pay(a.depositor, a.deposit + compensation);
        if (exhausted) _pay(l.owner, surviving);
    }

    /// @notice Reclaim (Section V-I).
    function reclaim(uint256 appId) external {
        Application storage a = applications[appId];
        if (msg.sender != a.depositor) revert NotDepositor();
        if (a.status != AppStatus.Pending) revert ApplicationNotPending(appId);

        a.status = AppStatus.Reclaimed;
        uint256 txId = a.txId;
        delete pendingApp[txId][msg.sender];
        uint256 deposit = a.deposit;
        emit Reclaimed(appId, txId, deposit);
        _pay(msg.sender, deposit);
    }

    /// @notice Cancel (Section V-J).
    function cancel(uint256 txId) external {
        Listing storage l = listings[txId];
        if (msg.sender != l.owner) revert NotListingOwner();
        // No engagement pending.
        TxState s = txState[txId];
        if (s != TxState.Active && s != TxState.Expired) revert ListingNotOpen(txId);

        txState[txId] = TxState.Cancelled;
        uint256 collateral = l.collateral;
        l.collateral = 0;
        emit Cancelled(txId, collateral);
        _pay(msg.sender, collateral);
    }

    // ---------------------------------------------------------------------------------------------
    // Auxiliary
    // ---------------------------------------------------------------------------------------------

    /// @notice Withdraw: pays the caller the balance credited by undelivered payouts.
    function withdraw() external {
        uint256 amount = credit[msg.sender];
        if (amount == 0) revert NothingToWithdraw();
        credit[msg.sender] = 0;
        emit Withdrawn(msg.sender, amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert WithdrawFailed();
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    // ---------------------------------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------------------------------

    /// @dev Open to applications (Section V-A): TxState in {ACTIVE, EXPIRED} and the expiration
    /// counter below maxExpirations.
    function _isOpen(uint256 txId) internal view returns (bool) {
        TxState s = txState[txId];
        return (s == TxState.Active || s == TxState.Expired) && listings[txId].expirations < MAX_EXPIRATIONS;
    }

    function _verifyNotarySignature(bytes32 structHash, bytes calldata sigma) internal view {
        if (!notaryVerifier.verify(_hashTypedData(structHash), sigma)) revert InvalidNotarySignature();
    }

    function _requireUnconsumed(bytes32 eta) internal view {
        if (consumed[eta]) revert NonceConsumed(eta);
    }

    /// @dev Freshness condition 0 <= now - t_att <= Delta (Section V-B). A block producer moves
    /// block.timestamp by seconds at most (within the block interval), which is small against the
    /// freshness window DELTA (300 s by default).
    function _requireFresh(uint64 tAtt) internal view {
        // forge-lint: disable-next-line(block-timestamp)
        if (tAtt > block.timestamp) revert AttestationFromFuture(tAtt);
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp - tAtt > DELTA) revert AttestationExpired(tAtt);
    }

    /// @dev enc(tag_psi, x_psi, chainID, addr_SC) as an EIP-712 digest.
    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _domainSeparator() internal view returns (bytes32) {
        return block.chainid == CACHED_CHAIN_ID ? CACHED_DOMAIN_SEPARATOR : _buildDomainSeparator();
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    /// @dev Payout rule (Section V-A): forwards PAYOUT_GAS, copies no return data, and credits the
    /// amount to the recipient if the transfer fails, so no recipient can make the algorithm revert.
    function _pay(address to, uint256 amount) private {
        if (amount == 0) return;
        bool ok;
        assembly ("memory-safe") {
            ok := call(PAYOUT_GAS, to, amount, 0, 0, 0, 0)
        }
        if (!ok) {
            credit[to] += amount;
            // The call above failed, and the EVM discards every log emitted inside a failed call, so
            // no log of the recipient can precede or imitate this one.
            // forge-lint: disable-next-line(reentrancy-events)
            emit PayoutCredited(to, amount);
        }
    }
}
