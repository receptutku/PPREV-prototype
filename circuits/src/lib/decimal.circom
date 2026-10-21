pragma circom 2.2.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// Value of one ASCII decimal digit. The byte must be '0'..'9': a byte below '0' wraps around the
// field and fails the 4-bit decomposition, a byte above '9' fails the comparison.
template Digit() {
    signal input byte;
    signal output value;

    value <== byte - 48;
    component bits = Num2Bits(4);
    bits.in <== value;
    component below10 = LessThan(4);
    below10.in[0] <== value;
    below10.in[1] <== 10;
    below10.out === 1;
}

// Value of `n` ASCII decimal digits, most significant first. Every byte must be a digit, so a
// value padded with spaces has no witness; the registry writes numbers zero-padded.
template DecimalValue(n) {
    // 10^n stays below 2^252, the widest input of circomlib's comparators.
    assert(n <= 75);
    signal input digits[n];
    signal output out;

    component d[n];
    var acc = 0;
    for (var i = 0; i < n; i++) {
        d[i] = Digit();
        d[i].byte <== digits[i];
        acc = acc * 10 + d[i].value;
    }
    out <== acc;
}
