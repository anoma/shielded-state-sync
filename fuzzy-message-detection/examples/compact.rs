// Run with `cargo run --example compact`
use sha2::{Digest, Sha512};

use fuzzy_message_detection::{
    fmd2_compact::MultiFmd2CompactScheme, FmdKeyGen, KeyExpansion, KeyRandomization, MultiFmdScheme,
};
fn main() {
    let mut csprng = rand_core::OsRng;

    // Params
    let gamma = 12; // Gamma parameter from FMD2.
    let d = 2; // #{detection keys}
    let t = 1; // corruption threshold
    let n = t; // leaked_rate = 2^{-n}
    let delta = n + (d - t) * n / t; // filtering_rate = 2^{-delta}

    // Compact multi-key FMD scheme
    let mut compact_multi_fmd2 = MultiFmd2CompactScheme::new(gamma, t);

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
    println!("\tGenerating compact secret and public keys...");
    let (cmp_sk, cmp_pk) = compact_multi_fmd2.generate_keys(&mut csprng);

    println!("\tExpanding onto an FMD secret key...");
    let (fmd_sk, _) = compact_multi_fmd2.expand_keypair(&cmp_sk, &cmp_pk);

    println!(
        "\tExtracting {:?} detection keys (one per server) from the expanded FMD secret key...",
        d
    );
    let _detection_keys = compact_multi_fmd2
        .multi_extract(&fmd_sk, d, t, n, delta)
        .unwrap();

    println!(
        "\tRandomizing the compact public key using a public tag (does not change detection keys)"
    );
    // Use a randomly-looking public tag to hash into basepoints.
    let mut hasher = Sha512::new();
    hasher.update("some receiver public tag");
    let tag_bytes: [u8; 64] = hasher.finalize().try_into().unwrap();

    let cmp_pk_1 = compact_multi_fmd2.randomize(&cmp_sk, &tag_bytes);

    println!("\tCompressing the (randomized) compact public key before transmission");
    let c_cmp_pk = cmp_pk_1.compress();

    println!("[Sender side]");

    // Decompress compact public key.
    println!(
        "\tDecompressing the transmitted compact public key (using same receiver's public tag)"
    );
    let cmp_pk_1 = c_cmp_pk.decompress(&tag_bytes);

    // Flag twice for same receiver.
    println!("\tFlagging a message with the compact public key (in the first flag operation the compact public key is expanded)...");
    let _flag = compact_multi_fmd2.flag(&cmp_pk_1, &mut csprng);

    // Don't forget to reset `compact_multi_fmd2` if flagging to another receiver!

    println!("[Rest of the workflow]");
    println!("\tDetection servers and back to receiver side: As in the basic multi-key FMD2 scheme. Run example `basic.rs`")
}
