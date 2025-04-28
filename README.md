# Multi-key fuzzy message detection

[Fuzzy Message Detection]((https://eprint.iacr.org/2021/089)) outsources detection of messages to an untrusted server. This crate implements and extension, called _multi-key_ FMD, described [here](https://eprint.iacr.org/2025/2072). Several servers are given different detection keys, all extracted from a single secret key. Multi-key FMD
allows to combine tests from multiple servers locally by each receiver. This allows to set high false-positive rates on the servers, while attaining low rates on the receiver side. This way, we can obtain a better balance between privacy and efficiency.

Two implementations are provided. [`MultiFmd2`](polyfuzzy/src/multifmd2.rs#L13) is the multi-key version of the original FMD2 scheme from [Beck et. al. paper](https://eprint.iacr.org/2021/089), minor modifications are added to support stealth public keys. The second scheme, [`Polyfuzzy`](polyfuzzy/src/polyfuzzy/mod.rs#L20), it has compact (and stealth) public keys.

* Compact public keys can be _publicly_ expanded into FMD public keys. This means that only short keys need to be made public by key owners (receivers), saving bandwidth and storage.
* Stealth public keys share the same set of detection keys. Can be seen as Sybil identities for the same receiver.

## Default configuration
The default configuration is inferred from the threat model and the total number of servers:
```rust
use polyfuzzy::config::{NumDetectionServers, ThreatModel};

// Polyfuzzy scheme
let polyfuzzy = Polyfuzzy::init(ThreatModel::HonestMajority, NumDetectionServers::Two);

// Mutlifmd2 scheme
let mut multifmd2 = MultiFmd2::init(ThreatModel::DishonestMajority, NumDetectionServers::Three);

```

The default configuration supports up to six detection servers, and it is designed to be _safe_, meaning the false-positive rate leaked to any subset of corrupted servers is always lower-bounded by `1/64`. This leakage is deemed secure even against servers conducting statistical analysis, according to [reported experiments](). See the introduction and section 5 of the [multi-key FMD paper](https://eprint.iacr.org/2025/2072) for more details.

## Benchmarks
Run them with `make bench`. 

The timings below were obtained in a laptop with 12 cores intel i5 13th generation and 16GB RAM, and with default configuration for the schemes.

scheme | flag runtime | flag size | public key size
-------|--------------|-----------|----------------
multifmd2 | 741,63 microseconds | 99 bytes | 608 bytes
polyfuzzy | 787,93 microseconds | 99 bytes | 256 bytes

## Examples
Run `make example`.

## Serialization
Feature `serde` enables serialization/deserialization of public keys, secret keys, detection keys, and flag ciphertexts.