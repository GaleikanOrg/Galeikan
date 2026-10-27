# Coding challenge: recover a binary record from three damaged captures

Three independent sensors captured the same 32-byte record. Each capture has a few altered bytes, but no byte offset was damaged in more than one capture. Reconstruct the original record, identify every changed offset in each capture, and validate the result.

The record layout is:

| Offset | Field |
| --- | --- |
| 0–3 | ASCII magic `GAK1` |
| 4 | Payload length (one unsigned byte) |
| 5–29 | Payload bytes |
| 30–31 | Big-endian 16-bit sum of bytes 0–29 |

The three input captures are embedded in [the Galeikan solution](../examples/triple_capture_recovery.gak). The algorithm takes the majority byte at each offset, reports an ambiguity if all three values differ, reconstructs the bytes, and independently checks the magic, length, and checksum. It also compares each capture with the recovered record to attribute its changed offsets.

Run it with either execution engine:

~~~sh
galeikan run examples/triple_capture_recovery.gak --engine ast
galeikan run examples/triple_capture_recovery.gak --engine vm
~~~

Expected result: zero ambiguous positions, a valid 32-byte record, and 12 altered positions in total. The recovered bytes are:

~~~text
47414b311972657365617263682d65766964656e63652d323032362d3130095f
~~~

Its SHA-256 is `e4277f095e5f2d13794e24a8907858bed09eea4e5eeed49aa73068c58837dd3f`. Damaged offsets are `[2, 7, 15, 22]`, `[4, 9, 18, 25]`, and `[1, 11, 20, 29]` for captures 1–3 respectively.

For a harder variant, allow two sensors to disagree with the third at some offsets. The majority rule then becomes insufficient: you need additional redundancy or a stronger integrity signal. The additive checksum in this exercise detects many errors but is not a cryptographic proof that a record is authentic.
