// Run with `cargo run --release --features combine --example basic`

use std::collections::HashMap;

use polyfuzzy::config::{
    get_safe_parameters, NumDetectionServers, SafeRateFunction, ThreatModel, GAMMA,
};
use sha2::{Digest, Sha512};

use polyfuzzy::{Init, MultiFmd2, MultiKeyFmd};

use polyfuzzy::combiner::CombineTests;

fn main() {
    let mut csprng = rand_core::OsRng;

    // The system configuration is given by the threat model and the total number of servers.
    let model = ThreatModel::DishonestMajority;
    let num_servers = NumDetectionServers::Three;

    println!("\nGLOBAL PARAMETERS");
    println!("-----------------");
    println!("gamma parameter: {:?}", GAMMA);
    let (t, d) = get_safe_parameters(model.clone(), num_servers.clone());
    println!("#{{detection servers}}: {:?}", d);
    println!(
        "threshold: {:?} (i.e. assuming {:?} out of the {:?} servers are corrupt)",
        t, t, d
    );

    // Safe initialization.
    let mut multifmd2 = MultiFmd2::init(model.clone(), num_servers.clone());

    println!("\nWORKFLOW");
    println!("--------");
    println!("[Receiver side]");
    println!("\tGenerating a secret FMD key...",);
    let fmd_sk = multifmd2.generate_secret_key(&mut csprng);

    println!("\tDeriving a stealth public FMD key for a publicly known address tag...");
    // Use a random-looking public tag to hash into basepoints.
    let mut hasher = Sha512::new();
    hasher.update(b"my_publicly_known_tag");
    let tag_bytes: [u8; 64] = hasher.finalize().into();
    let fmd_pk = multifmd2.generate_public_key(&fmd_sk, &tag_bytes);

    println!(
        "\tExtracting {:?} detection keys (one per server)...",
        num_servers.clone()
    );
    let detection_keys = multifmd2
        .extract(&fmd_sk, &SafeRateFunction::Six.into())
        .unwrap();

    let (n, delta) = SafeRateFunction::Six.filtering_rates(model, num_servers.clone());
    println!(
        "\tReceiver parameters: server filtering rate = {:?}, receiver filtering rate = {:?}",
        0.5_f32.powf(n as f32),
        0.5_f32.powf(delta as f32)
    );

    println!("[Sender side]");

    println!("\tFlagging a message with the FMD public key...");
    let flag = multifmd2.flag(&fmd_pk, &mut csprng);

    let mut storage_pool = HashMap::new();
    storage_pool.insert(0_u32, (flag, "shielded message for receiver".to_string()));

    println!("[Storage pool side]");

    let stored_msgs = 100;
    println!("\tIt has message/flag pairs for other receivers.");
    println!(
        "\tPopulating the pool with {:?} extra message/flag pairs. It may take sometime...",
        stored_msgs
    );

    for i in 1..stored_msgs {
        let another_fmd_pk =
            multifmd2.generate_public_key(&multifmd2.generate_secret_key(&mut csprng), &[1u8; 64]);
        let another_flag = multifmd2.flag(&another_fmd_pk, &mut csprng);

        storage_pool.insert(
            i,
            (
                another_flag,
                format!("shielded message for another receiver ({:?})", i),
            ),
        );
    }

    println!(
        "[Detection server side ({:?} servers)]",
        num_servers.clone()
    );
    let mut all_detect_results = vec![];
    for (j, detection_key) in detection_keys.iter().enumerate() {
        println!("\tRunning detection in server {:?}...", j);
        let mut detect_results = HashMap::new();
        let mut positive_flags = 0_u32;
        for index in storage_pool.keys() {
            let flag = storage_pool.get(index).unwrap().0.clone();
            let is_positive = multifmd2.detect(&[detection_key.clone()], &flag).unwrap();
            detect_results.insert(index, (flag, is_positive));
            if is_positive {
                positive_flags += 1
            };
        }
        println!("\t\tNumber of positive flags: {:?}", positive_flags);

        all_detect_results.push(detect_results);
    }

    println!("[Receiver side]");
    println!(
        "\tCombining results from the {:?} detection servers...",
        num_servers
    );

    let mut receiver_positive_indices = vec![];

    for index in storage_pool.keys() {
        let mut results_for_flag = vec![];
        for server_results in all_detect_results.clone() {
            results_for_flag.push(server_results.get(index).unwrap().1);
        }
        let receiver_result = multifmd2.combine(&results_for_flag);

        if receiver_result {
            receiver_positive_indices.push(index);
        }
    }

    println!(
        "\t\tSize of combined shielded messages: {:?}",
        receiver_positive_indices.len()
    );
    println!("\tNow you can retrieve the messages and run trial-decryption on them.");
}
