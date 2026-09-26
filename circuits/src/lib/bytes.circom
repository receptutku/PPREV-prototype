pragma circom 2.2.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/sha256/sha256.circom";

// Bits of `n` bytes, most significant bit of each byte first (the SHA-256 input order). The
// decomposition also constrains every byte to [0, 255].
template BytesToBitsMsbFirst(n) {
    signal input bytes[n];
    signal output bits[8 * n];

    component dec[n];
    for (var i = 0; i < n; i++) {
        dec[i] = Num2Bits(8);
        dec[i].in <== bytes[i];
        for (var j = 0; j < 8; j++) {
            bits[8 * i + j] <== dec[i].out[7 - j];
        }
    }
}

// Opens a TLSNotary plaintext hash commitment: SHA-256(message || blinder), with a 16-byte blinder
// (tlsn core/src/transcript/hash.rs, hash_plaintext). The digest is returned as two 128-bit limbs,
// most significant limb first, each read big-endian.
template OpenCommitment(n) {
    signal input message[n];
    signal input blinder[16];
    signal output limbs[2];

    component bits = BytesToBitsMsbFirst(n + 16);
    for (var i = 0; i < n; i++) {
        bits.bytes[i] <== message[i];
    }
    for (var i = 0; i < 16; i++) {
        bits.bytes[n + i] <== blinder[i];
    }

    component sha = Sha256(8 * (n + 16));
    for (var i = 0; i < 8 * (n + 16); i++) {
        sha.in[i] <== bits.bits[i];
    }

    // sha.out[0] is the most significant bit of the digest.
    component hi = Bits2Num(128);
    component lo = Bits2Num(128);
    for (var i = 0; i < 128; i++) {
        hi.in[i] <== sha.out[127 - i];
        lo.in[i] <== sha.out[255 - i];
    }
    limbs[0] <== hi.out;
    limbs[1] <== lo.out;
}

// Packs `n` bytes into one field element, big-endian. With n <= 31 the value stays below the field
// order, so equal packings mean equal bytes.
template PackBytes(n) {
    signal input bytes[n];
    signal output out;

    var acc = 0;
    for (var i = 0; i < n; i++) {
        acc = acc * 256 + bytes[i];
    }
    out <== acc;
}
