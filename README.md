# Shielded State Sync
Synchronize shielded messages using [fuzzy message detection](https://eprint.iacr.org/2021/089) (FMD).

## Multi-key extraction
This crate supports multi-key extraction by thresholdizing the original FMD2 scheme. Refer to the [ART report](https://zenodo.org/records/15186457) for details.

Knowing up to `t < d` detection keys leaks no information about the other `d-t` keys. Here `t` is a corruption threshold parameter passed to the multi-key extraction.

For each pair `(d,t)`, there is an associated set `P(d,t)` of valid leaked and filtering rates `(p_l,p_f)`.

* `p_l:=2^{-n}` and `n` is the number of (different) secret subkeys across any `t` detection keys, 
* `p_f:=2^{-δ}`and `δ` is the total number of secret subkeys in the `d` detection keys.

Thus, the leaked rate is the false-positive rate at which any coalition of `t` servers can filter. The filtering rate is the false-positive rate at which the receiver can filter, after receiving all the filters from the `d` servers.

## Key expansion and key randomization
Two implementations are provided. The compact scheme generates short FMD public keys, which can be randomized. 
* Compact public keys can be _publicly_ expanded into FMD public keys. This means that only compact keys need to be made public by key owners (receivers), saving bandwidth and storage.
* Randomized public keys share the same set of detection keys. Can be seen as Sybil identities for the same receiver.

## Serialization
Feature `serde` enables serialization/deserialization of public keys, secret keys, detection keys, and flag ciphertexts.

## Benchmarks
Run `make bench`.

## Examples
See the examples' folder.
