use criterion::{criterion_group, criterion_main, Criterion};
use polyfuzzy::{
    combiner::CombineTests,
    config::{NumDetectionServers, SafeRateFunction, ThreatModel},
    Init, MultiFmd2, MultiKeyFmd, Polyfuzzy,
};
use strum::IntoEnumIterator;
fn benchmark_sk_gen_mfmd2(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;
    let mfmd2 = MultiFmd2::init(ThreatModel::HonestMajority, NumDetectionServers::Three);
    c.bench_function("secret_key_gen_mfmd2", |b| {
        b.iter(|| mfmd2.generate_secret_key(&mut csprng))
    });
}

fn benchmark_sk_gen_polyfuzzy(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;
    let polyfuzzy = Polyfuzzy::init(ThreatModel::HonestMajority, NumDetectionServers::Three); // threshold = m-1
    c.bench_function("secret_key_gen_polyfuzzy", |b| {
        b.iter(|| polyfuzzy.generate_secret_key(&mut csprng))
    });
}

fn benchmark_pk_gen_mfmd2(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;
    let mfmd2 = MultiFmd2::init(ThreatModel::HonestMajority, NumDetectionServers::Three);
    let sk = mfmd2.generate_secret_key(&mut csprng);
    c.bench_function("public_key_gen_mfmd2", |b| {
        b.iter(|| mfmd2.generate_public_key(&sk, &[0u8; 64]))
    });
}

fn benchmark_pk_gen_polyfuzzy(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;
    let polyfuzzy = Polyfuzzy::init(ThreatModel::HonestMajority, NumDetectionServers::Three);
    let sk = polyfuzzy.generate_secret_key(&mut csprng);
    c.bench_function("public_key_gen_polyfuzzy", |b| {
        b.iter(|| polyfuzzy.generate_public_key(&sk, &[0u8; 64]))
    });
}

fn benchmark_extract_mfmd2(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;
    let mfmd2 = MultiFmd2::init(ThreatModel::HonestMajority, NumDetectionServers::Three);
    let sk = mfmd2.generate_secret_key(&mut csprng);
    c.bench_function("extract_mfmd2", |b| {
        b.iter(|| mfmd2.extract(&sk, &SafeRateFunction::Six.into()))
    });
}

fn benchmark_extract_polyfuzzy(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;
    let polyfuzzy = Polyfuzzy::init(ThreatModel::HonestMajority, NumDetectionServers::Three);
    let sk = polyfuzzy.generate_secret_key(&mut csprng);
    c.bench_function("extract_polyfuzzy", |b| {
        b.iter(|| polyfuzzy.extract(&sk, &SafeRateFunction::Six.into()))
    });
}

fn benchmark_flag_mfmd2(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;
    let mut mfmd2 = MultiFmd2::init(ThreatModel::HonestMajority, NumDetectionServers::Three);
    let sk = mfmd2.generate_secret_key(&mut csprng);
    let pk = mfmd2.generate_public_key(&sk, &[0u8; 64]);
    c.bench_function("flag_mfmd2", |b| b.iter(|| mfmd2.flag(&pk, &mut csprng)));
}

fn benchmark_flag_polyfuzzy(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;
    let mut polyfuzzy = Polyfuzzy::init(ThreatModel::HonestMajority, NumDetectionServers::Three);
    let sk = polyfuzzy.generate_secret_key(&mut csprng);
    let pk = polyfuzzy.generate_public_key(&sk, &[0u8; 64]);
    c.bench_function("flag_polyfuzzy", |b| {
        b.iter(|| polyfuzzy.flag(&pk, &mut csprng))
    });
}

fn benchmark_flag_expand_polyfuzzy(c: &mut Criterion) {
    let mut csprng = rand_core::OsRng;
    let polyfuzzy = Polyfuzzy::init(ThreatModel::HonestMajority, NumDetectionServers::Three); // threshold = m-1
    let sk = polyfuzzy.generate_secret_key(&mut csprng);
    let pk = polyfuzzy.generate_public_key(&sk, &[0u8; 64]);
    c.bench_function("flag_expand_polyfuzzy", |b| {
        b.iter(|| polyfuzzy.expand_public_key(&pk))
    });
}

fn benchmark_detect_mfmd2(c: &mut Criterion) {
    // also for polyfuzzy
    let mut csprng = rand_core::OsRng;
    let mut mfmd2 = MultiFmd2::init(ThreatModel::HonestMajority, NumDetectionServers::Three);
    let sk = mfmd2.generate_secret_key(&mut csprng);
    let pk = mfmd2.generate_public_key(&sk, &[0u8; 64]);
    let flag = mfmd2.flag(&pk, &mut csprng);
    for leaked_rate in SafeRateFunction::iter() {
        println!("leaked rate: {:?}", leaked_rate);
        let dsk_vec = mfmd2.extract(&sk, &leaked_rate.into()).unwrap();
        c.bench_function("detect_mfmd2", |b| {
            b.iter(|| mfmd2.detect(&[dsk_vec[0].clone()], &flag))
        });
    }
}

fn benchmark_combine_mfmd2(c: &mut Criterion) {
    // also for polyfuzzy
    let mut csprng = rand_core::OsRng;
    let mut mfmd2 = MultiFmd2::init(ThreatModel::HonestMajority, NumDetectionServers::Three);
    let sk = mfmd2.generate_secret_key(&mut csprng);
    let pk = mfmd2.generate_public_key(&sk, &[0u8; 64]);
    let flag = mfmd2.flag(&pk, &mut csprng);
    for leaked_rate in SafeRateFunction::iter() {
        println!("leaked rate: {:?}", leaked_rate);
        let dsk_vec = mfmd2.extract(&sk, &leaked_rate.into()).unwrap();
        let mut test_results = Vec::new();
        for dsk in dsk_vec {
            test_results.push(mfmd2.detect(&[dsk], &flag).unwrap());
        }
        c.bench_function("combine_mfmd2", |b| {
            b.iter(|| mfmd2.combine(test_results.as_slice()))
        });
    }
}

criterion_group!(
    benches,
    benchmark_sk_gen_mfmd2,
    benchmark_sk_gen_polyfuzzy,
    benchmark_pk_gen_mfmd2,
    benchmark_pk_gen_polyfuzzy,
    benchmark_extract_mfmd2,
    benchmark_extract_polyfuzzy,
    benchmark_flag_mfmd2,
    benchmark_flag_polyfuzzy,
    benchmark_flag_expand_polyfuzzy,
    benchmark_detect_mfmd2,
    benchmark_combine_mfmd2,
);
criterion_main!(benches);
