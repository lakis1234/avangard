use std::env;
use std::fs;
use std::path::PathBuf;

fn replace_once(src: &mut String, from: &str, to: &str, label: &str) {
    let n = src.matches(from).count();
    assert_eq!(n, 1, "PERF-021 transform expected exactly one {label}, found {n}");
    *src = src.replacen(from, to, 1);
}

fn replace_some(src: &mut String, from: &str, to: &str, min: usize, label: &str) {
    let n = src.matches(from).count();
    assert!(n >= min, "PERF-021 transform expected at least {min} {label}, found {n}");
    *src = src.replace(from, to);
}

fn main() {
    println!("cargo:rerun-if-changed=../perf014/src/main.rs");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let source_path = manifest.join("../perf014/src/main.rs");
    let mut src = fs::read_to_string(&source_path).expect("read PERF-014 source");

    // Start from the proven SPSC integrated engine, retain PERF-015's packed PREPARE accounting,
    // and add one Ed25519 authorization certificate per (stream,batch). The certificate signs a
    // SHA-256 digest of the exact canonical wire records for that stream/batch.
    replace_once(
        &mut src,
        "use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};",
        "use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};\nuse ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};\nuse sha2::{Digest, Sha256};",
        "imports",
    );

    replace_some(&mut src, "_0014", "_0021", 3, "domain constants");
    replace_some(&mut src, "PERF-014", "PERF-021", 5, "PERF labels");
    replace_once(&mut src, "v1.4.0", "v2.1.0", "version label");

    // PERF-015 packed PREPARE accumulator.
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

    let wire_tag_fn = r#"#[inline(always)]
fn wire_tag(tx: u64, arity: usize, value: u64, inputs: &[u64; MAX_ARITY]) -> u64 {
    let mut x = mix64(tx ^ MAGIC ^ (arity as u64).rotate_left(11) ^ value.rotate_left(23));
    for (k, serial) in inputs.iter().take(arity).enumerate() {
        x = mix64(x ^ serial.rotate_left(((k * 7 + 3) & 63) as u32));
    }
    x
}"#;

    let wire_tag_plus_cert = r#"#[inline(always)]
fn wire_tag(tx: u64, arity: usize, value: u64, inputs: &[u64; MAX_ARITY]) -> u64 {
    let mut x = mix64(tx ^ MAGIC ^ (arity as u64).rotate_left(11) ^ value.rotate_left(23));
    for (k, serial) in inputs.iter().take(arity).enumerate() {
        x = mix64(x ^ serial.rotate_left(((k * 7 + 3) & 63) as u32));
    }
    x
}

#[derive(Clone, Copy)]
struct BatchCert {
    public: [u8; 32],
    signature: [u8; 64],
}

fn deterministic_cert_key() -> SigningKey {
    let mut seed = [0u8; 32];
    for i in 0..4u64 {
        let x = mix64(0xCE47_1F1C_CA11_0021u64 ^ i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        seed[(i as usize) * 8..(i as usize + 1) * 8].copy_from_slice(&x.to_le_bytes());
    }
    SigningKey::from_bytes(&seed)
}

#[inline(always)]
fn cert_message(batch: usize, stream: usize, digest: &[u8; 32]) -> [u8; 48] {
    let mut msg = [0u8; 48];
    msg[0..8].copy_from_slice(&(batch as u64).to_le_bytes());
    msg[8..16].copy_from_slice(&(stream as u64).to_le_bytes());
    msg[16..48].copy_from_slice(digest);
    msg
}

fn canonical_record96(tx: u64, arity: usize, conflict_pct: u32) -> [u8; 96] {
    let mut record = [0u8; 96];
    let mut inputs = [u64::MAX; MAX_ARITY];
    for (k, slot) in inputs.iter_mut().take(arity).enumerate() {
        *slot = referenced_serial(tx, k, arity, conflict_pct);
        let off = 16 + k * 8;
        record[off..off + 8].copy_from_slice(&slot.to_le_bytes());
    }
    let value = arity as u64 * VALUE;
    record[80..88].copy_from_slice(&value.to_le_bytes());
    record[88..96].copy_from_slice(&(arity as u64).to_le_bytes());
    let tag = wire_tag(tx, arity, value, &inputs);
    record[0..8].copy_from_slice(&tx.to_le_bytes());
    record[8..16].copy_from_slice(&tag.to_le_bytes());
    record
}

fn build_batch_certs(
    txs: u64,
    arity: usize,
    conflict_pct: u32,
    batch_size: usize,
    streams: usize,
) -> Vec<BatchCert> {
    let batches = ((txs as usize) + batch_size - 1) / batch_size;
    let sk = deterministic_cert_key();
    let public = sk.verifying_key().to_bytes();
    let mut out = Vec::with_capacity(batches * streams);
    for b in 0..batches {
        let start = (b * batch_size) as u64;
        let end = ((b + 1) * batch_size).min(txs as usize) as u64;
        for s in 0..streams {
            let mut hasher = Sha256::new();
            for tx in start..end {
                if tx as usize % streams == s {
                    hasher.update(canonical_record96(tx, arity, conflict_pct));
                }
            }
            let digest: [u8; 32] = hasher.finalize().into();
            let signature = sk.sign(&cert_message(b, s, &digest)).to_bytes();
            out.push(BatchCert { public, signature });
        }
    }
    out
}"#;
    replace_once(&mut src, wire_tag_fn, wire_tag_plus_cert, "batch certificate helpers");

    replace_once(
        &mut src,
        "    let total_inputs = txs * arity as u64;\n    let batches = ((txs as usize) + batch_size - 1) / batch_size;",
        "    let total_inputs = txs * arity as u64;\n    let batches = ((txs as usize) + batch_size - 1) / batch_size;\n\n    // Upstream authorization/certificate construction is outside timing. The measured core path\n    // recomputes a SHA-256 content digest and verifies one Ed25519 certificate per stream-batch.\n    let batch_certs: Arc<Vec<BatchCert>> = Arc::new(build_batch_certs(\n        txs, arity, conflict_pct, batch_size, streams,\n    ));",
        "batch certificate precompute",
    );

    replace_once(
        &mut src,
        "    let rbr = batch_ready_tx.clone();\n    let rlanes = Arc::clone(&lanes);",
        "    let rbr = batch_ready_tx.clone();\n    let rlanes = Arc::clone(&lanes);\n    let rcerts = Arc::clone(&batch_certs);",
        "receiver cert manager clone",
    );

    replace_once(
        &mut src,
        "            let batch_ready_tx = rbr.clone();\n            let lanes = Arc::clone(&rlanes);\n            let expected = stream_count(txs, streams, s);",
        "            let batch_ready_tx = rbr.clone();\n            let lanes = Arc::clone(&rlanes);\n            let batch_certs = Arc::clone(&rcerts);\n            let expected = stream_count(txs, streams, s);",
        "receiver cert clone",
    );

    replace_once(
        &mut src,
        "                let mut current_batch: Option<usize> = None;\n                let mut cursors = vec![0usize; workers];\n                let mut batch_starts = vec![0usize; workers];",
        "                let mut current_batch: Option<usize> = None;\n                let mut batch_hasher = Sha256::new();\n                let mut cursors = vec![0usize; workers];\n                let mut batch_starts = vec![0usize; workers];",
        "receiver batch hasher",
    );

    let old_flush = r#"                let flush_batch = |batch: usize,
                                   cursors: &Vec<usize>,
                                   batch_starts: &mut Vec<usize>| {
                    for w in 0..workers {
                        let lane = &lanes[s * workers + w];
                        lane.publish(batch, batch_starts[w], cursors[w]);
                        batch_starts[w] = cursors[w];
                    }
                    let done = stream_done[batch].fetch_add(1, Ordering::AcqRel) + 1;
                    if done == expected_streams[batch] {
                        batch_ready_tx
                            .send(batch)
                            .expect("send PERF-021 batch-ready notification");
                    }
                };"#;
    let new_flush = r#"                let flush_batch = |batch: usize,
                                   digest: [u8; 32],
                                   cursors: &Vec<usize>,
                                   batch_starts: &mut Vec<usize>| {
                    // A stream-batch becomes executable only after its content digest is certified.
                    let cert = batch_certs[batch * streams + s];
                    let vk = VerifyingKey::from_bytes(&cert.public)
                        .expect("PERF-021 invalid certificate public key");
                    let sig = Signature::from_bytes(&cert.signature);
                    vk.verify_strict(&cert_message(batch, s, &digest), &sig)
                        .expect("PERF-021 batch authorization certificate rejected");

                    for w in 0..workers {
                        let lane = &lanes[s * workers + w];
                        lane.publish(batch, batch_starts[w], cursors[w]);
                        batch_starts[w] = cursors[w];
                    }
                    let done = stream_done[batch].fetch_add(1, Ordering::AcqRel) + 1;
                    if done == expected_streams[batch] {
                        batch_ready_tx
                            .send(batch)
                            .expect("send PERF-021 batch-ready notification");
                    }
                };"#;
    replace_once(&mut src, old_flush, new_flush, "certificate-gated flush");

    replace_once(
        &mut src,
        "                    let b = tx as usize / batch_size;\n                    if current_batch != Some(b) {\n                        if let Some(prev) = current_batch {\n                            flush_batch(prev, &cursors, &mut batch_starts);\n                        }\n                        current_batch = Some(b);\n                    }",
        "                    let b = tx as usize / batch_size;\n                    if current_batch != Some(b) {\n                        if let Some(prev) = current_batch {\n                            let digest: [u8; 32] = std::mem::take(&mut batch_hasher).finalize().into();\n                            flush_batch(prev, digest, &cursors, &mut batch_starts);\n                        }\n                        current_batch = Some(b);\n                    }\n                    batch_hasher.update(&record[..96]);",
        "per-record digest and prior batch certificate",
    );

    replace_once(
        &mut src,
        "                if let Some(last) = current_batch {\n                    flush_batch(last, &cursors, &mut batch_starts);\n                }",
        "                if let Some(last) = current_batch {\n                    let digest: [u8; 32] = std::mem::take(&mut batch_hasher).finalize().into();\n                    flush_batch(last, digest, &cursors, &mut batch_starts);\n                }",
        "last batch certificate",
    );

    replace_once(
        &mut src,
        "    println!(\"PREALLOCATED SPSC ROUTE-LANES -> OWNER-LOCAL ATOMIC ENGINE\");",
        "    println!(\"VERIFIED AUTHORIZATION-BATCH CERTIFICATES -> SPSC OWNER-LOCAL ATOMIC ENGINE\");",
        "title",
    );
    replace_once(
        &mut src,
        "    println!(\"Change vs PERF-013: remove heavy routed WorkItem MPSC chunks and per-batch Vec transfer\");",
        "    println!(\"Change vs PERF-015: verify one Ed25519 authorization certificate per stream-batch over a SHA-256 content digest\");\n    println!(\"UPSTREAM USER-SIGNATURE VERIFICATION: ASSUMED PREVERIFIED, NOT INCLUDED IN THIS CORE TIMING\");\n    println!(\"Certificate construction/signing: OUTSIDE timing | certificate transport bytes: NOT INCLUDED\");",
        "description",
    );
    replace_once(
        &mut src,
        "    println!(\"Target: >5M integrated committed arity-8 tx/s\");",
        "    println!(\"Target: preserve the ~5M PERF-015 core while cryptographically gating each stream-batch before execution\");",
        "target",
    );
    replace_once(
        &mut src,
        "            \"PERF-013 LOW-LATENCY REFERENCE SHAPE / 7W / 2S / B6144: {:.0} committed tx/s | p95={:.1}us\",",
        "            \"PERF-015 REFERENCE SHAPE / 7W / 2S / B6144: {:.0} committed tx/s | p95={:.1}us\",",
        "reference label",
    );
    replace_once(
        &mut src,
        "    println!(\"PREALLOCATED SPSC ROUTE LANES ACTIVE: YES\");",
        "    println!(\"PACKED PREPARE ACCUMULATOR ACTIVE: YES\");\n    println!(\"PREALLOCATED SPSC ROUTE LANES ACTIVE: YES\");\n    println!(\"SHA256 STREAM-BATCH CONTENT DIGEST INCLUDED: YES\");\n    println!(\"ED25519 STREAM-BATCH CERTIFICATE VERIFICATION INCLUDED: YES\");",
        "decision certificate labels",
    );
    replace_once(
        &mut src,
        "    println!(\"SIGNATURE VERIFICATION INCLUDED: NO\");",
        "    println!(\"INDIVIDUAL USER SIGNATURE VERIFICATION INCLUDED IN CORE: NO\");\n    println!(\"UPSTREAM AUTHORIZATION TIER REQUIRED: YES\");",
        "signature claim",
    );

    // Add certificate and packed-accumulator tests. Existing integrated tests now also cross the
    // certificate gate because run_case itself verifies certificates before publishing lanes.
    replace_once(
        &mut src,
        "    #[test]\n    fn stream_partition_and_lane_capacity() {",
        "    #[test]\n    fn batch_certificate_accepts_and_tamper_rejects() {\n        let certs = build_batch_certs(100, 8, 0, 32, 2);\n        let b = 1usize;\n        let s = 1usize;\n        let mut h = Sha256::new();\n        for tx in 32u64..64u64 {\n            if tx as usize % 2 == s { h.update(canonical_record96(tx, 8, 0)); }\n        }\n        let digest: [u8; 32] = h.finalize().into();\n        let cert = certs[b * 2 + s];\n        let vk = VerifyingKey::from_bytes(&cert.public).unwrap();\n        let sig = Signature::from_bytes(&cert.signature);\n        assert!(vk.verify_strict(&cert_message(b, s, &digest), &sig).is_ok());\n        let mut bad = digest;\n        bad[0] ^= 1;\n        assert!(vk.verify_strict(&cert_message(b, s, &bad), &sig).is_err());\n    }\n\n    #[test]\n    fn packed_prepare_accumulator_round_trip() {\n        let a = AtomicU64::new(0);\n        for v in [100u64, 200, 300] { a.fetch_add((v << 8) | 1, Ordering::Relaxed); }\n        let packed = a.load(Ordering::Relaxed);\n        assert_eq!((packed & 0xff) as usize, 3);\n        assert_eq!(packed >> 8, 600);\n    }\n\n    #[test]\n    fn stream_partition_and_lane_capacity() {",
        "certificate tests",
    );

    assert!(!src.contains("prepared_counts"), "PERF-021 generated source still contains prepared_counts");
    assert!(!src.contains("prepared_values"), "PERF-021 generated source still contains prepared_values");

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("generated.rs");
    fs::write(out, src).expect("write PERF-021 generated source");
}
