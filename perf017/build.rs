use std::env;
use std::fs;
use std::path::PathBuf;

fn replace_once(src: &mut String, from: &str, to: &str, label: &str) {
    let n = src.matches(from).count();
    assert_eq!(n, 1, "PERF-017 transform expected exactly one {label}, found {n}");
    *src = src.replacen(from, to, 1);
}

fn replace_some(src: &mut String, from: &str, to: &str, min: usize, label: &str) {
    let n = src.matches(from).count();
    assert!(n >= min, "PERF-017 transform expected at least {min} {label}, found {n}");
    *src = src.replace(from, to);
}

fn main() {
    println!("cargo:rerun-if-changed=../perf014/src/main.rs");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let source_path = manifest.join("../perf014/src/main.rs");
    let mut src = fs::read_to_string(&source_path).expect("read PERF-014 source");

    // Start from the proven PERF-014 SPSC integrated engine, then apply PERF-015's packed
    // prepare accumulator and finally add one real Ed25519 authorization verification per tx.
    replace_once(
        &mut src,
        "use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};",
        "use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};\nuse ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};",
        "atomic/ed25519 imports",
    );

    replace_some(&mut src, "_0014", "_0017", 3, "domain constants");
    replace_some(&mut src, "PERF-014", "PERF-017", 5, "PERF labels");
    replace_once(&mut src, "v1.4.0", "v1.7.0", "version label");
    replace_once(&mut src, "const MIN_RECORD: usize = 96;", "const MIN_RECORD: usize = 192;", "minimum authenticated wire size");

    // PERF-015 packed prepare accumulator: one atomic RMW per prepared input instead of two.
    replace_once(
        &mut src,
        "    let prepared_counts: Arc<Vec<AtomicU8>> =\n        Arc::new((0..txs).map(|_| AtomicU8::new(0)).collect());\n    let prepared_values: Arc<Vec<AtomicU64>> =\n        Arc::new((0..txs).map(|_| AtomicU64::new(0)).collect());",
        "    let prepared_accum: Arc<Vec<AtomicU64>> =\n        Arc::new((0..txs).map(|_| AtomicU64::new(0)).collect());",
        "packed prepare allocation",
    );
    replace_once(
        &mut src,
        "        let prepared_counts = Arc::clone(&prepared_counts);\n        let prepared_values = Arc::clone(&prepared_values);",
        "        let prepared_accum = Arc::clone(&prepared_accum);",
        "packed prepare clone",
    );
    replace_some(
        &mut src,
        "                            prepared_counts[item.tx as usize].fetch_add(1, Ordering::Relaxed);\n                            prepared_values[item.tx as usize].fetch_add(cell.value, Ordering::Relaxed);",
        "                            prepared_accum[item.tx as usize]\n                                .fetch_add((cell.value << 8) | 1, Ordering::Relaxed);",
        1,
        "packed prepare update",
    );
    replace_some(
        &mut src,
        "                    let eligible =\n                        prepared_counts[tx as usize].load(Ordering::Relaxed) as usize == arity;",
        "                    let packed = prepared_accum[tx as usize].load(Ordering::Relaxed);\n                    let eligible = (packed & 0xff) as usize == arity;",
        2,
        "packed eligibility",
    );
    replace_once(
        &mut src,
        "                        let value = prepared_values[tx as usize].load(Ordering::Relaxed);",
        "                        let value = packed >> 8;",
        "packed value extraction",
    );

    // Canonical authorization message: tx id + declared value + arity + all 8 input references.
    let wire_tag_fn = r#"#[inline(always)]
fn wire_tag(tx: u64, arity: usize, value: u64, inputs: &[u64; MAX_ARITY]) -> u64 {
    let mut x = mix64(tx ^ MAGIC ^ (arity as u64).rotate_left(11) ^ value.rotate_left(23));
    for (k, serial) in inputs.iter().take(arity).enumerate() {
        x = mix64(x ^ serial.rotate_left(((k * 7 + 3) & 63) as u32));
    }
    x
}"#;
    let wire_tag_plus_auth = r#"#[inline(always)]
fn wire_tag(tx: u64, arity: usize, value: u64, inputs: &[u64; MAX_ARITY]) -> u64 {
    let mut x = mix64(tx ^ MAGIC ^ (arity as u64).rotate_left(11) ^ value.rotate_left(23));
    for (k, serial) in inputs.iter().take(arity).enumerate() {
        x = mix64(x ^ serial.rotate_left(((k * 7 + 3) & 63) as u32));
    }
    x
}

#[derive(Clone, Copy)]
struct AuthMaterial {
    public: [u8; 32],
    signature: [u8; 64],
}

#[inline(always)]
fn auth_message(tx: u64, arity: usize, value: u64, inputs: &[u64; MAX_ARITY]) -> [u8; 88] {
    let mut msg = [0u8; 88];
    msg[0..8].copy_from_slice(&tx.to_le_bytes());
    msg[8..16].copy_from_slice(&value.to_le_bytes());
    msg[16..24].copy_from_slice(&(arity as u64).to_le_bytes());
    for (k, serial) in inputs.iter().enumerate() {
        let off = 24 + k * 8;
        msg[off..off + 8].copy_from_slice(&serial.to_le_bytes());
    }
    msg
}

fn deterministic_signing_key(index: u64) -> SigningKey {
    let mut seed = [0u8; 32];
    for i in 0..4u64 {
        let x = mix64(index ^ 0xED25_5190_CA11_0017u64 ^ i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        seed[(i as usize) * 8..(i as usize + 1) * 8].copy_from_slice(&x.to_le_bytes());
    }
    SigningKey::from_bytes(&seed)
}"#;
    replace_once(&mut src, wire_tag_fn, wire_tag_plus_auth, "auth helpers");

    // Pre-sign outside timing. The timed path measures verification, parsing, routing, and execution.
    replace_once(
        &mut src,
        "    let total_inputs = txs * arity as u64;\n    let batches = ((txs as usize) + batch_size - 1) / batch_size;",
        "    let total_inputs = txs * arity as u64;\n    let batches = ((txs as usize) + batch_size - 1) / batch_size;\n\n    // Client-side signing is intentionally outside the timed server path. Use a 1024-key pool\n    // so verification is not artificially benchmarked against one permanently hot public key.\n    let auth_keys: Vec<SigningKey> = (0..1024u64).map(deterministic_signing_key).collect();\n    let auth_materials: Arc<Vec<AuthMaterial>> = Arc::new((0..txs).map(|tx| {\n        let mut inputs = [u64::MAX; MAX_ARITY];\n        for (k, slot) in inputs.iter_mut().take(arity).enumerate() {\n            *slot = referenced_serial(tx, k, arity, conflict_pct);\n        }\n        let value = arity as u64 * VALUE;\n        let msg = auth_message(tx, arity, value, &inputs);\n        let sk = &auth_keys[tx as usize % auth_keys.len()];\n        let sig = sk.sign(&msg);\n        AuthMaterial { public: sk.verifying_key().to_bytes(), signature: sig.to_bytes() }\n    }).collect());",
        "auth precompute",
    );

    // Verify the exact transaction authorization received on the wire before it is routed to state.
    replace_once(
        &mut src,
        "                    assert_eq!(tag, wire_tag(tx, arity, declared_value, &inputs), \"PERF-017 integrity mismatch\");",
        "                    assert_eq!(tag, wire_tag(tx, arity, declared_value, &inputs), \"PERF-017 integrity mismatch\");\n\n                    let mut public = [0u8; 32];\n                    public.copy_from_slice(&record[96..128]);\n                    let mut sig_bytes = [0u8; 64];\n                    sig_bytes.copy_from_slice(&record[128..192]);\n                    let verifying_key = VerifyingKey::from_bytes(&public)\n                        .expect(\"PERF-017 invalid Ed25519 public key\");\n                    let signature = Signature::from_bytes(&sig_bytes);\n                    let msg = auth_message(tx, arity, declared_value, &inputs);\n                    verifying_key.verify_strict(&msg, &signature)\n                        .expect(\"PERF-017 Ed25519 authorization rejected\");",
        "receiver Ed25519 verification",
    );

    // Sender writes the already-created client authorization bytes into the 192-byte envelope.
    replace_once(
        &mut src,
        "    for s in 0..streams {\n        let ready = Arc::clone(&ready);\n        let go = Arc::clone(&go);\n        senders.push(thread::spawn(move || {",
        "    for s in 0..streams {\n        let ready = Arc::clone(&ready);\n        let go = Arc::clone(&go);\n        let auth_materials = Arc::clone(&auth_materials);\n        senders.push(thread::spawn(move || {",
        "sender auth material clone",
    );
    replace_once(
        &mut src,
        "                record[0..8].copy_from_slice(&tx.to_le_bytes());\n                record[8..16].copy_from_slice(&tag.to_le_bytes());\n                writer.write_all(&record).expect(\"write complete PERF-017 record\");",
        "                record[0..8].copy_from_slice(&tx.to_le_bytes());\n                record[8..16].copy_from_slice(&tag.to_le_bytes());\n                let auth = &auth_materials[tx as usize];\n                record[96..128].copy_from_slice(&auth.public);\n                record[128..192].copy_from_slice(&auth.signature);\n                writer.write_all(&record).expect(\"write complete PERF-017 record\");",
        "sender auth bytes",
    );

    // Make the benchmark's user-visible claims precise.
    replace_once(
        &mut src,
        "    let sizes = parse_list(&args, \"--sizes\", vec![128usize]);",
        "    let sizes = parse_list(&args, \"--sizes\", vec![192usize]);",
        "default authenticated record size",
    );
    replace_once(
        &mut src,
        "    println!(\"PREALLOCATED SPSC ROUTE-LANES -> OWNER-LOCAL ATOMIC ENGINE\");",
        "    println!(\"ED25519 AUTHORIZATION -> SPSC ROUTE-LANES -> OWNER-LOCAL ATOMIC ENGINE\");",
        "benchmark title",
    );
    replace_once(
        &mut src,
        "    println!(\"Change vs PERF-013: remove heavy routed WorkItem MPSC chunks and per-batch Vec transfer\");",
        "    println!(\"Change vs PERF-015: add one real Ed25519 verification per transaction on the timed receive path\");\n    println!(\"Ed25519 client signing/precomputation: OUTSIDE timing | key pool: 1024\");\n    println!(\"Authorization proves control of the included key and signed tx fields; input ownership binding: NOT YET\");",
        "change/auth description",
    );
    replace_once(
        &mut src,
        "    println!(\"Target: >5M integrated committed arity-8 tx/s\");",
        "    println!(\"Target: measure the real Ed25519 authorization cost against a same-size PERF-015 baseline\");",
        "target label",
    );
    replace_once(
        &mut src,
        "        \"BEST NO-CONFLICT INTEGRATED COMMIT TPS: {:.0} | workers={} streams={} batch={} | p95={:.1}us\",",
        "        \"BEST ED25519-AUTHENTICATED COMMIT TPS: {:.0} | workers={} streams={} batch={} | p95={:.1}us\",",
        "best label",
    );
    replace_once(
        &mut src,
        "            \"PERF-013 LOW-LATENCY REFERENCE SHAPE / 7W / 2S / B6144: {:.0} committed tx/s | p95={:.1}us\",",
        "            \"AUTH REFERENCE SHAPE / 7W / 2S / B6144: {:.0} committed tx/s | p95={:.1}us\",",
        "reference label",
    );
    replace_once(
        &mut src,
        "    println!(\"SIGNATURE VERIFICATION INCLUDED: NO\");",
        "    println!(\"ED25519 SIGNATURE VERIFICATION INCLUDED: YES - ONE PER TRANSACTION\");\n    println!(\"INPUT-CELL OWNERSHIP BINDING TO SIGNING KEY INCLUDED: NO\");",
        "signature claim",
    );

    // Existing integration tests must use a record large enough to carry key + signature.
    replace_some(&mut src, "run_case(20_000, 8, 4, 256, 0, 1024, 2, 128)", "run_case(20_000, 8, 4, 256, 0, 1024, 2, 192)", 1, "no-conflict auth test size");
    replace_some(&mut src, "run_case(20_000, 8, 4, 256, 10, 1024, 2, 128)", "run_case(20_000, 8, 4, 256, 10, 1024, 2, 192)", 1, "conflict auth test size");

    replace_once(
        &mut src,
        "    #[test]\n    fn stream_partition_and_lane_capacity() {",
        "    #[test]\n    fn ed25519_authorization_accepts_and_tamper_rejects() {\n        let sk = deterministic_signing_key(7);\n        let vk = sk.verifying_key();\n        let mut inputs = [u64::MAX; MAX_ARITY];\n        for (k, slot) in inputs.iter_mut().enumerate() { *slot = k as u64 + 10; }\n        let msg = auth_message(42, 8, 800, &inputs);\n        let sig = sk.sign(&msg);\n        assert!(vk.verify_strict(&msg, &sig).is_ok());\n        let mut bad = msg;\n        bad[0] ^= 1;\n        assert!(vk.verify_strict(&bad, &sig).is_err());\n    }\n\n    #[test]\n    fn packed_prepare_accumulator_round_trip() {\n        let a = AtomicU64::new(0);\n        for v in [100u64, 200, 300] { a.fetch_add((v << 8) | 1, Ordering::Relaxed); }\n        let packed = a.load(Ordering::Relaxed);\n        assert_eq!((packed & 0xff) as usize, 3);\n        assert_eq!(packed >> 8, 600);\n    }\n\n    #[test]\n    fn stream_partition_and_lane_capacity() {",
        "auth/packed unit tests",
    );

    assert!(!src.contains("prepared_counts"), "PERF-017 generated source still contains prepared_counts");
    assert!(!src.contains("prepared_values"), "PERF-017 generated source still contains prepared_values");

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("generated.rs");
    fs::write(out, src).expect("write PERF-017 generated source");
}
