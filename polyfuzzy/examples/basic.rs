// Run with `cargo run --example basic`

use polyfuzzy::{fmd2::MultiFmd2, FilterCombiner, FmdKeyGen, MultiFmdScheme};

fn main() {
    let mut csprng = rand_core::OsRng;

    // Params
    let gamma = 12; // Gamma parameter from FMD2.
    let d = 3; // #{detection keys}
    let t = 2; // corruption threshold
    let n = t; // leaked_rate = 2^{-n}
    let delta = n + (d - t) * n / t; // filtering_rate = 2^{-delta}

    // Basic multi-key FMD scheme
    let mut multi_fmd2 = MultiFmd2::new(gamma);

    println!("\nGLOBAL PARAMETERS");
    println!("-----------------");
    println!("gamma parameter: {:?}", gamma);
    println!("#{{detection servers}}: {:?}", d);
    println!(
        "threshold: {:?} (i.e. assuming {:?} out of the {:?} servers are corrupt)",
        t, t, d
    );

    println!("\nWORKFLOW");
    println!("--------");
    println!("[Receiver side]");
    println!(
        "\tReceiver parameters: leaked rate = {:?}, filtering rate = {:?}",
        0.5_f32.powf(n as f32),
        0.5_f32.powf(delta as f32)
    );
    println!(
        "\tGenerating secret and public FMD keys with {:?} subkeys...",
        gamma
    );
    let (fmd_sk, fmd_pk) = multi_fmd2.generate_keys(&mut csprng);

    println!("\tExtracting {:?} detection keys (one per server)...", d);
    let detection_keys = multi_fmd2.multi_extract(&fmd_sk, d, t, n, delta).unwrap();

    println!("[Sender side]");
    let mut storage_pool = vec![];

    println!("\tFlagging a message with the FMD public key...");
    let flag = multi_fmd2.flag(&fmd_pk, &mut csprng);

    storage_pool.push(("shielded message for receiver".to_string(), flag));

    println!("[Storage pool side]");
    let stored_msgs = 1000;
    println!("\tIt has message/flag pairs for other receivers.");
    println!(
        "\tPopulating the pool with {:?} extra message/flag pairs. It may take sometime...",
        stored_msgs
    );

    for i in 0..stored_msgs {
        let (_, another_fmd_pk) = multi_fmd2.generate_keys(&mut csprng);
        let another_flag = multi_fmd2.flag(&another_fmd_pk, &mut csprng);

        storage_pool.push((
            format!("shielded message for another receiver ({:?})", i),
            another_flag,
        ));
    }

    println!("[Detection server side ({:?} servers)]", d);
    let mut all_filtered_messages = vec![];
    for (j, detection_key) in detection_keys.iter().enumerate() {
        println!("\tFiltering messages in server {:?}...", j);
        let mut filtered_messages = vec![];
        for (message, flag) in storage_pool.iter() {
            let is_positive = multi_fmd2.detect(detection_key, flag);
            if is_positive {
                filtered_messages.push(message);
            }
        }
        println!("\t\tFiltered messages: {:?}", filtered_messages.len());
        all_filtered_messages.push(filtered_messages);
    }

    println!("[Receiver side]");
    println!("\tCombining messages from the {:?} detection servers...", d);

    let combined_messages = FilterCombiner::combine(&all_filtered_messages);
    println!(
        "\t\tSize of combined shielded messages: {:?}",
        combined_messages.len()
    );
    println!("\tNow you can run trial-decryption on the combined shielded messages.");
}
