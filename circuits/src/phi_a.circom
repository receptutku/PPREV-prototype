pragma circom 2.2.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "lib/bytes.circom";
include "lib/decimal.circom";

// phi_A, rental eligibility (Sections V-E and VI-A): the eligibility record of the notarised session
// shows a monthly income of at least MULTIPLE times the rent txData.amount, and c_B opens to the
// identifier of the session's account holder.
//
// The two private byte strings are the values of the `account` and `monthlyIncome` fields of the
// response. TLSNotary committed to each with SHA-256(value || blinder) (D3); the policy verifier
// passes the attested hashes, c_B, and txData.amount from x_A as public inputs. The policy fixes
// that the income is written in the denomination and scale of txData.amount.
//
// Parameters come from the response layout and the policy:
//   ACCOUNT_W     width of an account identifier
//   INCOME_W      width of the income, zero-padded decimal digits
//   PAD           padding byte of empty values
//   MULTIPLE      required income as a multiple of the rent
//   AMOUNT_BITS   bound on txData.amount, in bits; the policy verifier refuses larger amounts
template PhiA(ACCOUNT_W, INCOME_W, PAD, MULTIPLE, AMOUNT_BITS) {
    // The comparison operands, an income below 10^INCOME_W and MULTIPLE * amount below
    // MULTIPLE * 2^AMOUNT_BITS, stay below 2^CMP_BITS, so neither wraps around the field.
    var CMP_BITS = 100;
    assert(ACCOUNT_W <= 31);
    assert(10 ** INCOME_W < 2 ** CMP_BITS);
    assert(MULTIPLE > 0 && MULTIPLE * 2 ** AMOUNT_BITS < 2 ** CMP_BITS);

    // Public inputs, in this order.
    signal input accountHash[2];
    signal input incomeHash[2];
    signal input cB;
    signal input amount;
    signal input bind;

    // Private inputs.
    signal input account[ACCOUNT_W];
    signal input income[INCOME_W];
    signal input accountBlinder[16];
    signal input incomeBlinder[16];
    signal input salt;

    // (1) The private values open the attested commitments.
    component openAccount = OpenCommitment(ACCOUNT_W);
    openAccount.message <== account;
    openAccount.blinder <== accountBlinder;
    for (var i = 0; i < 2; i++) {
        openAccount.limbs[i] === accountHash[i];
    }

    component openIncome = OpenCommitment(INCOME_W);
    openIncome.message <== income;
    openIncome.blinder <== incomeBlinder;
    for (var i = 0; i < 2; i++) {
        openIncome.limbs[i] === incomeHash[i];
    }

    // (2) c_B = H_c(identifier, salt) names the account holder of the session (Section V-E). The
    // account is not empty, so c_B cannot name an empty identifier.
    component accountIsPadding = IsEqual();
    accountIsPadding.in[0] <== account[0];
    accountIsPadding.in[1] <== PAD;
    accountIsPadding.out === 0;

    component accountPacked = PackBytes(ACCOUNT_W);
    accountPacked.bytes <== account;
    component commitment = Poseidon(2);
    commitment.inputs[0] <== accountPacked.out;
    commitment.inputs[1] <== salt;
    commitment.out === cB;

    // (3) Income threshold: income >= MULTIPLE * txData.amount.
    component incomeValue = DecimalValue(INCOME_W);
    incomeValue.digits <== income;
    component amountRange = Num2Bits(AMOUNT_BITS);
    amountRange.in <== amount;
    component enough = GreaterEqThan(CMP_BITS);
    enough.in[0] <== incomeValue.out;
    enough.in[1] <== MULTIPLE * amount;
    enough.out === 1;

    // (4) The proof is bound to one statement x_A: bind is its EIP-712 digest modulo the field order.
    signal bindSquared;
    bindSquared <== bind * bind;
}
