pragma circom 2.2.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "lib/bytes.circom";
include "lib/date.circom";

// phi_S, rental settlement (Sections V-G and VI-A): a tenancy notation on the property of txData
// names the identity committed in c_B and is dated no earlier than the engagement day.
//
// The three private byte strings are the values of the `propertyId`, `tenant`, and `recordDate`
// fields of the response. TLSNotary committed to each with SHA-256(value || blinder) (D3); the
// policy verifier passes the attested hashes, txData.propertyId, c_B, and the engagement day from
// x_S as public inputs. The engagement day is Y * 10000 + M * 100 + D of the calendar day, in the
// registry's time zone, of expiresAt - tau_lock.
//
// Parameters come from the response layout:
//   PROPERTY_W    width of the property identifier
//   TENANT_W      width of an account identifier
//   PAD           padding byte of empty values
template PhiS(PROPERTY_W, TENANT_W, PAD) {
    assert(PROPERTY_W <= 32 && PROPERTY_W > 16);
    assert(TENANT_W <= 31);

    // Public inputs, in this order.
    signal input propertyHash[2];
    signal input tenantHash[2];
    signal input dateHash[2];
    signal input propertyId[2];
    signal input cB;
    signal input engagementDay;
    signal input bind;

    // Private inputs.
    signal input property[PROPERTY_W];
    signal input tenant[TENANT_W];
    signal input date[10];
    signal input propertyBlinder[16];
    signal input tenantBlinder[16];
    signal input dateBlinder[16];
    signal input salt;

    // (1) The private values open the attested commitments.
    component openProperty = OpenCommitment(PROPERTY_W);
    openProperty.message <== property;
    openProperty.blinder <== propertyBlinder;
    for (var i = 0; i < 2; i++) {
        openProperty.limbs[i] === propertyHash[i];
    }

    component openTenant = OpenCommitment(TENANT_W);
    openTenant.message <== tenant;
    openTenant.blinder <== tenantBlinder;
    for (var i = 0; i < 2; i++) {
        openTenant.limbs[i] === tenantHash[i];
    }

    component openDate = OpenCommitment(10);
    openDate.message <== date;
    openDate.blinder <== dateBlinder;
    for (var i = 0; i < 2; i++) {
        openDate.limbs[i] === dateHash[i];
    }

    // (2) The notation is on the property of txData: the committed identifier, zero-padded to 32
    // bytes, is txData.propertyId (as in phi_R).
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

    // (3) The notation names the identity in c_B = H_c(identifier, salt), which the counterparty
    // committed to at Apply. The tenant is not empty.
    component tenantIsPadding = IsEqual();
    tenantIsPadding.in[0] <== tenant[0];
    tenantIsPadding.in[1] <== PAD;
    tenantIsPadding.out === 0;

    component tenantPacked = PackBytes(TENANT_W);
    tenantPacked.bytes <== tenant;
    component commitment = Poseidon(2);
    commitment.inputs[0] <== tenantPacked.out;
    commitment.inputs[1] <== salt;
    commitment.out === cB;

    // (4) The notation is dated no earlier than the engagement day. 99991231 < 2^27.
    component recordDate = CalendarDate();
    recordDate.date <== date;
    component dayRange = Num2Bits(27);
    dayRange.in <== engagementDay;
    component notBefore = GreaterEqThan(27);
    notBefore.in[0] <== recordDate.ymd;
    notBefore.in[1] <== engagementDay;
    notBefore.out === 1;

    // (5) The proof is bound to one statement x_S: bind is its EIP-712 digest modulo the field order.
    signal bindSquared;
    bindSquared <== bind * bind;
}
