use criterion::{criterion_group, criterion_main, Criterion};

use fuzzy_message_detection::{fmd2::Fmd2, FmdKeyGen, FmdScheme};

fn benchmark_flag(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;
    let mut fmd2 = Fmd2::new(22);
    let (_sk, pk) = fmd2.generate_keys(&mut csprng);
    c.bench_function("flag", |b| b.iter(|| fmd2.flag(&pk, &mut csprng)));
}

fn benchmark_detect(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;

    let mut fmd2 = Fmd2::new(22);
    let (sk, pk) = fmd2.generate_keys(&mut csprng);
    let flag_cipher = fmd2.flag(&pk, &mut csprng);
    let dk = fmd2.multi_extract(&sk, 1, 1, 11, 11).unwrap().pop();
    c.bench_function("detect", |b| {
        b.iter(|| fmd2.detect(dk.as_ref().unwrap(), &flag_cipher))
    });
}

criterion_group!(benches, benchmark_flag, benchmark_detect);
criterion_main!(benches);
