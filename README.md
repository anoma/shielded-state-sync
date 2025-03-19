# Shielded State Sync
Synchronize shielded messages using fuzzy message detection (FMD).

## Multi-key extraction
This crate supports multi-key extraction by thresholdizing the original [FMD2 scheme](https://eprint.iacr.org/2021/089). 

Knowing up to `t < d` detection keys leaks no information about the other `d-t` keys. Here `t` is a corruption threshold parameter passed to the multi-key extraction.

For each pair `(d,t)`, there is an associated set `P(d,t)` of valid leaked and filtering rates `(p_l,p_f)`.

* `p_l:=2^{-n}` and `n` is the number of (different) secret subkeys across any `t` detection keys, 
* `p_f:=2^{-δ}`and `δ` is the total number of secret subkeys in the `d` detection keys.

## Key expansion and key randomization
Two implementations are provided. The compact scheme generates short FMD public keys, which can be randomized. 
* Compact public keys can be _publicly_ expanded into FMD public keys. This means that only compact keys need to be made public by key owners (receivers), saving bandwidth and storage.
* Randomized public keys share the same set of detection keys. Can be seen as sybil identities for the same receiver.

## Serialization
Feature `serde` enables serialization/deseralization of public keys, secret keys, detection keys, and flag ciphertexts.

## Benchmarks
Run `cargo bench`.

## Examples
See the examples folder.