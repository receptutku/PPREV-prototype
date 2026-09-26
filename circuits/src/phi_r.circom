pragma circom 2.2.0;

include "circomlib/circuits/comparators.circom";
include "lib/bytes.circom";

// phi_R, rental ownership (Sections IV and VI-A): the registry record names the account holder of
// the notarised session as an owner of the property in txData.
//
// The three private byte strings are the values of the `account`, `owners`, and `propertyId` fields
// of the registry response. TLSNotary committed to each with SHA-256(value || blinder) (D3); the
// policy verifier checks the attestation and passes the committed hashes as public inputs.
//
// Parameters come from the response layout:
//   ACCOUNT_W     width of an account identifier (and of an owner slot)
//   OWNER_SLOTS   number of owner slots
//   OWNER_STRIDE  distance between slot starts: ACCOUNT_W plus the `","` separator
//   OWNERS_LEN    length of the committed owners range (all slots with their separators)
//   PROPERTY_W    width of the property identifier
//   PAD           padding byte of empty values
template PhiR(ACCOUNT_W, OWNER_SLOTS, OWNER_STRIDE, OWNERS_LEN, PROPERTY_W, PAD) {
    assert(OWNER_STRIDE == ACCOUNT_W + 3);
    assert(OWNERS_LEN == (OWNER_SLOTS - 1) * OWNER_STRIDE + ACCOUNT_W);
    assert(ACCOUNT_W <= 31);
    assert(PROPERTY_W <= 32 && PROPERTY_W > 16);

    // Public inputs, in this order.
    signal input accountHash[2];
    signal input ownersHash[2];
    signal input propertyHash[2];
    signal input propertyId[2];
    signal input bind;

    // Private inputs.
    signal input account[ACCOUNT_W];
    signal input owners[OWNERS_LEN];
    signal input property[PROPERTY_W];
    signal input accountBlinder[16];
    signal input ownersBlinder[16];
    signal input propertyBlinder[16];

    // (1) The private values open the attested commitments.
    component openAccount = OpenCommitment(ACCOUNT_W);
    openAccount.message <== account;
    openAccount.blinder <== accountBlinder;
    for (var i = 0; i < 2; i++) {
        openAccount.limbs[i] === accountHash[i];
    }

    component openOwners = OpenCommitment(OWNERS_LEN);
    openOwners.message <== owners;
    openOwners.blinder <== ownersBlinder;
    for (var i = 0; i < 2; i++) {
        openOwners.limbs[i] === ownersHash[i];
    }

    component openProperty = OpenCommitment(PROPERTY_W);
    openProperty.message <== property;
    openProperty.blinder <== propertyBlinder;
    for (var i = 0; i < 2; i++) {
        openProperty.limbs[i] === propertyHash[i];
    }

    // (2) Ownership (Section IV): the identifier that the portal shows for the logged-in account,
    // committed from the same attested response, equals one of the owner slots.
    // The account is not empty, so it cannot match an empty slot.
    component accountIsPadding = IsEqual();
    accountIsPadding.in[0] <== account[0];
    accountIsPadding.in[1] <== PAD;
    accountIsPadding.out === 0;

    // The owner slots are separated by `","` at their layout offsets.
    for (var k = 0; k + 1 < OWNER_SLOTS; k++) {
        owners[k * OWNER_STRIDE + ACCOUNT_W] === 34;
        owners[k * OWNER_STRIDE + ACCOUNT_W + 1] === 44;
        owners[k * OWNER_STRIDE + ACCOUNT_W + 2] === 34;
    }

    component accountPacked = PackBytes(ACCOUNT_W);
    accountPacked.bytes <== account;
    component slotPacked[OWNER_SLOTS];
    component matches[OWNER_SLOTS];
    signal noMatchUpTo[OWNER_SLOTS + 1];
    noMatchUpTo[0] <== 1;
    for (var k = 0; k < OWNER_SLOTS; k++) {
        slotPacked[k] = PackBytes(ACCOUNT_W);
        for (var i = 0; i < ACCOUNT_W; i++) {
            slotPacked[k].bytes[i] <== owners[k * OWNER_STRIDE + i];
        }
        matches[k] = IsEqual();
        matches[k].in[0] <== slotPacked[k].out;
        matches[k].in[1] <== accountPacked.out;
        noMatchUpTo[k + 1] <== noMatchUpTo[k] * (1 - matches[k].out);
    }
    noMatchUpTo[OWNER_SLOTS] === 0;

    // (3) The committed property identifier, zero-padded to 32 bytes, is txData.propertyId.
    component propertyHi = PackBytes(16);
    for (var i = 0; i < 16; i++) {
        propertyHi.bytes[i] <== property[i];
    }
    component propertyLo = PackBytes(PROPERTY_W - 16);
    for (var i = 16; i < PROPERTY_W; i++) {
        propertyLo.bytes[i - 16] <== property[i];
    }
    propertyHi.out === propertyId[0];
    propertyLo.out * (256 ** (32 - PROPERTY_W)) === propertyId[1];

    // (4) The proof is bound to one statement x_R: bind is its EIP-712 digest modulo the field order.
    signal bindSquared;
    bindSquared <== bind * bind;
}
