pragma circom 2.2.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "decimal.circom";

// x mod 4 == 0 for 0 <= x < 128: the two low bits of x are zero.
template DivisibleBy4() {
    signal input in;
    signal output out;

    component bits = Num2Bits(7);
    bits.in <== in;
    component zero = IsZero();
    zero.in <== bits.out[0] + 2 * bits.out[1];
    out <== zero.out;
}

// A calendar date written `YYYY-MM-DD` (proleptic Gregorian), returned as Y * 10000 + M * 100 + D.
// For valid dates this number orders as the dates do, so a comparison of two such numbers compares
// the days. The date must be canonical: four, two, and two digits separated by '-', a month in
// 1..12, and a day in 1 to the length of the month, with February 29 in leap years only.
template CalendarDate() {
    signal input date[10];
    signal output ymd;

    date[4] === 45;
    date[7] === 45;

    component c = DecimalValue(2);
    c.digits <== [date[0], date[1]];
    component y = DecimalValue(2);
    y.digits <== [date[2], date[3]];
    component m = DecimalValue(2);
    m.digits <== [date[5], date[6]];
    component d = DecimalValue(2);
    d.digits <== [date[8], date[9]];

    // 1 <= month <= 12.
    component monthZero = IsZero();
    monthZero.in <== m.out;
    monthZero.out === 0;
    component monthMax = LessThan(7);
    monthMax.in[0] <== m.out;
    monthMax.in[1] <== 13;
    monthMax.out === 1;

    // Leap year: divisible by 4, and by 400 when divisible by 100. With the year written as
    // 100 * c + y, it is leap when y != 0 and 4 | y, or y == 0 and 4 | c.
    component yDiv4 = DivisibleBy4();
    yDiv4.in <== y.out;
    component cDiv4 = DivisibleBy4();
    cDiv4.in <== c.out;
    component yZero = IsZero();
    yZero.in <== y.out;
    signal leapInCentury <== yDiv4.out * (1 - yZero.out);
    signal leapCentury <== cDiv4.out * yZero.out;
    signal leap <== leapInCentury + leapCentury;

    // Length of the month: 31, less 1 for April, June, September, November, less 3 for February
    // of a common year and 2 for February of a leap year.
    var short[4] = [4, 6, 9, 11];
    component isShort[4];
    var shortMonth = 0;
    for (var i = 0; i < 4; i++) {
        isShort[i] = IsEqual();
        isShort[i].in[0] <== m.out;
        isShort[i].in[1] <== short[i];
        shortMonth += isShort[i].out;
    }
    component isFebruary = IsEqual();
    isFebruary.in[0] <== m.out;
    isFebruary.in[1] <== 2;
    signal februaryCut <== isFebruary.out * (3 - leap);
    signal monthLength <== 31 - shortMonth - februaryCut;

    // 1 <= day <= length of the month.
    component dayZero = IsZero();
    dayZero.in <== d.out;
    dayZero.out === 0;
    component dayMax = LessThan(7);
    dayMax.in[0] <== d.out;
    dayMax.in[1] <== monthLength + 1;
    dayMax.out === 1;

    ymd <== (c.out * 100 + y.out) * 10000 + m.out * 100 + d.out;
}
