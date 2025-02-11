use criterion::{criterion_group, criterion_main, Criterion};

use fuzzy_message_detection::{
    fmd2::{Fmd2, Fmd2Params},
    FmdKeyGen, FmdScheme,
};

fn benchmark_flag(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;
    let pp = Fmd2Params::new(22);
    let (pk, _sk) = pp.generate_keys(&mut csprng);
    c.bench_function("flag", |b| {
        b.iter(|| <Fmd2 as FmdScheme>::flag(&pk, &mut csprng))
    });
}

fn benchmark_detect(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;

    let pp = Fmd2Params::new(22);
    let (pk, sk) = pp.generate_keys(&mut csprng);
    let flag_cipher = <Fmd2 as FmdScheme>::flag(&pk, &mut csprng);
    let dk = <Fmd2 as FmdScheme>::extract(&sk, &[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20]);
    c.bench_function("detect", |b| {
        b.iter(|| <Fmd2 as FmdScheme>::detect(dk.as_ref().unwrap(), &flag_cipher))
    });
}

criterion_group!(benches, benchmark_flag, benchmark_detect);
criterion_main!(benches);
