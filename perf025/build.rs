use std::env;
use std::fs;
use std::path::PathBuf;

mod perf024_builder {
    include!("../perf024/build.rs");
    pub fn run() {
        main();
    }
}

fn replace_once(src: &mut String, from: &str, to: &str, label: &str) {
    let n = src.matches(from).count();
    assert_eq!(n, 1, "PERF-025 transform expected exactly one {label}, found {n}");
    *src = src.replacen(from, to, 1);
}

fn main() {
    println!("cargo:rerun-if-changed=../perf024/build.rs");
    println!("cargo:rerun-if-changed=../perf022/build.rs");
    println!("cargo:rerun-if-changed=../perf021/build.rs");
    println!("cargo:rerun-if-changed=../perf014/src/main.rs");

    // PERF-025 deliberately changes no monetary or cryptographic semantics. It reuses the
    // PERF-024 buffered-BLAKE3 certified engine and changes only the benchmark sweep/defaults
    // so we can test CPU-budget balance between execution workers and TCP/hash receiver threads.
    // On an 8-core machine, e.g. 6 execution workers + 2 receiver streams gives 8 hot workers,
    // while 7 + 2 oversubscribes the physical cores. This experiment asks whether the remaining
    // certified-path loss is partly scheduler/core contention rather than cryptographic work.
    perf024_builder::run();

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let generated = out_dir.join("generated.rs");
    let mut src = fs::read_to_string(&generated).expect("read PERF-024-generated source");

    src = src.replace("PERF-024", "PERF-025");
    src = src.replace("_0024", "_0025");
    src = src.replace("v2.4.0", "v2.5.0");

    replace_once(
        &mut src,
        "BUFFERED BLAKE3 AUTHORIZATION-BATCH CERTIFICATES -> SPSC OWNER-LOCAL ATOMIC ENGINE",
        "CPU-BALANCED BUFFERED BLAKE3 CERTIFICATE SWEEP -> SPSC OWNER-LOCAL ATOMIC ENGINE",
        "title",
    );
    replace_once(
        &mut src,
        "Change vs PERF-022: replace one BLAKE3 update per transaction with one contiguous BLAKE3 hash per stream-batch",
        "Change vs PERF-024: no protocol change; sweep execution-worker/receiver-stream balance to test core contention",
        "description",
    );
    replace_once(
        &mut src,
        "Target: recover the PERF-022 hashing loss without weakening exact-content certificate binding",
        "Target: find the best certified-path worker/stream balance and determine whether oversubscription is material",
        "target",
    );

    // Wider defaults for the CPU-balance experiment. CLI flags still override these values.
    replace_once(
        &mut src,
        "    let workers = parse_list(&args, \"--workers\", vec![6usize, 7, 8]);",
        "    let workers = parse_list(&args, \"--workers\", vec![4usize, 5, 6, 7]);",
        "worker sweep defaults",
    );
    replace_once(
        &mut src,
        "    let batches = parse_list(&args, \"--batches\", vec![4096usize, 6144, 8192, 12288]);",
        "    let batches = parse_list(&args, \"--batches\", vec![3072usize, 4096, 5120, 6144, 8192]);",
        "batch sweep defaults",
    );

    // Make the intent obvious in the output without altering the measured path.
    replace_once(
        &mut src,
        "    println!(\"CPU-BALANCED BUFFERED BLAKE3 CERTIFICATE SWEEP -> SPSC OWNER-LOCAL ATOMIC ENGINE\");",
        "    println!(\"CPU-BALANCED BUFFERED BLAKE3 CERTIFICATE SWEEP -> SPSC OWNER-LOCAL ATOMIC ENGINE\");\n    println!(\"PERF-025 PROTOCOL DELTA: NONE - parameter/core-budget experiment over PERF-024\");\n    println!(\"Hot-thread approximation: execution workers + TCP receiver streams (coordinator/senders also exist)\");",
        "intent print",
    );

    fs::write(&generated, src).expect("write PERF-025 generated source");
}
