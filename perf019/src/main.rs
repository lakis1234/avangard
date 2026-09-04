use ed25519_dalek::{verify_batch, Signature, Signer, SigningKey, VerifyingKey};
use std::env;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

const MAX_ARITY: usize = 8;
const VALUE: u64 = 100;
const KEY_POOL: usize = 1024;
const DOMAIN: u64 = 0xCA11_BAF0_0000_0019;

#[inline(always)]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[inline(always)]
fn referenced_serial(tx: u64, k: usize, arity: usize) -> u64 {
    tx * arity as u64 + k as u64
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
        let x = mix64(index ^ DOMAIN ^ i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        seed[(i as usize) * 8..(i as usize + 1) * 8].copy_from_slice(&x.to_le_bytes());
    }
    SigningKey::from_bytes(&seed)
}

#[derive(Clone, Copy)]
struct AuthMaterial {
    tx: u64,
    arity: usize,
    value: u64,
    inputs: [u64; MAX_ARITY],
    public: [u8; 32],
    signature: [u8; 64],
}

fn parse_list<T: std::str::FromStr>(args: &[String], flag: &str, default: Vec<T>) -> Vec<T> {
    if let Some(i) = args.iter().position(|x| x == flag) {
        if let Some(v) = args.get(i + 1) {
            let out: Vec<T> = v
                .split(',')
                .filter_map(|x| x.trim().parse::<T>().ok())
                .collect();
            if !out.is_empty() {
                return out;
            }
        }
    }
    default
}

fn build_materials(txs: usize) -> Vec<AuthMaterial> {
    let keys: Vec<SigningKey> = (0..KEY_POOL as u64)
        .map(deterministic_signing_key)
        .collect();

    (0..txs)
        .map(|i| {
            let tx = i as u64;
            let arity = MAX_ARITY;
            let value = arity as u64 * VALUE;
            let mut inputs = [u64::MAX; MAX_ARITY];
            for (k, slot) in inputs.iter_mut().enumerate() {
                *slot = referenced_serial(tx, k, arity);
            }
            let msg = auth_message(tx, arity, value, &inputs);
            let sk = &keys[i % keys.len()];
            let sig = sk.sign(&msg);
            AuthMaterial {
                tx,
                arity,
                value,
                inputs,
                public: sk.verifying_key().to_bytes(),
                signature: sig.to_bytes(),
            }
        })
        .collect()
}

#[derive(Clone, Copy)]
struct IndividualRow {
    workers: usize,
    txs: usize,
    elapsed_s: f64,
    verify_tps: f64,
    checksum: u64,
}

fn run_individual(materials: Arc<Vec<AuthMaterial>>, workers: usize) -> IndividualRow {
    let txs = materials.len();
    let ready = Arc::new(Barrier::new(workers + 1));
    let go = Arc::new(Barrier::new(workers + 1));
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let materials = Arc::clone(&materials);
        let ready = Arc::clone(&ready);
        let go = Arc::clone(&go);
        handles.push(thread::spawn(move || {
            ready.wait();
            go.wait();
            let mut verified = 0usize;
            let mut checksum = 0u64;
            for i in (w..materials.len()).step_by(workers) {
                let a = materials[i];
                let vk = VerifyingKey::from_bytes(&a.public).expect("PERF-019 individual key parse");
                let sig = Signature::from_bytes(&a.signature);
                let msg = auth_message(a.tx, a.arity, a.value, &a.inputs);
                vk.verify_strict(&msg, &sig)
                    .expect("PERF-019 individual authorization rejected");
                verified += 1;
                checksum ^= mix64(a.tx ^ (a.public[0] as u64).rotate_left(17));
            }
            (verified, checksum)
        }));
    }

    ready.wait();
    let start = Instant::now();
    go.wait();

    let mut verified = 0usize;
    let mut checksum = 0u64;
    for h in handles {
        let (v, c) = h.join().expect("PERF-019 individual worker panic");
        verified += v;
        checksum ^= c;
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    assert_eq!(verified, txs);

    IndividualRow {
        workers,
        txs,
        elapsed_s,
        verify_tps: txs as f64 / elapsed_s,
        checksum,
    }
}

#[derive(Clone, Copy)]
struct BatchRow {
    workers: usize,
    batch_size: usize,
    txs: usize,
    batches: usize,
    elapsed_s: f64,
    verify_tps: f64,
    checksum: u64,
}

fn run_batch(materials: Arc<Vec<AuthMaterial>>, workers: usize, batch_size: usize) -> BatchRow {
    assert!(workers > 0 && workers <= 64);
    assert!(batch_size > 0);
    let txs = materials.len();

    let ready = Arc::new(Barrier::new(workers + 1));
    let go = Arc::new(Barrier::new(workers + 1));
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let materials = Arc::clone(&materials);
        let ready = Arc::clone(&ready);
        let go = Arc::clone(&go);
        handles.push(thread::spawn(move || {
            let start_index = txs * w / workers;
            let end_index = txs * (w + 1) / workers;
            ready.wait();
            go.wait();

            let mut cursor = start_index;
            let mut verified = 0usize;
            let mut batch_count = 0usize;
            let mut checksum = 0u64;

            while cursor < end_index {
                let end = (cursor + batch_size).min(end_index);
                let len = end - cursor;

                // These allocations, public-key parses, signature parses and message rebuilds are
                // intentionally INSIDE timing. The only thing outside timing is client signing/material generation.
                let mut messages: Vec<[u8; 88]> = Vec::with_capacity(len);
                let mut signatures: Vec<Signature> = Vec::with_capacity(len);
                let mut keys: Vec<VerifyingKey> = Vec::with_capacity(len);

                for i in cursor..end {
                    let a = materials[i];
                    messages.push(auth_message(a.tx, a.arity, a.value, &a.inputs));
                    signatures.push(Signature::from_bytes(&a.signature));
                    keys.push(VerifyingKey::from_bytes(&a.public).expect("PERF-019 batch key parse"));
                    checksum ^= mix64(a.tx ^ (a.public[0] as u64).rotate_left(17));
                }

                let message_refs: Vec<&[u8]> = messages.iter().map(|m| &m[..]).collect();
                verify_batch(&message_refs, &signatures, &keys)
                    .expect("PERF-019 Ed25519 batch authorization rejected");

                verified += len;
                batch_count += 1;
                cursor = end;
            }

            (verified, batch_count, checksum)
        }));
    }

    ready.wait();
    let start = Instant::now();
    go.wait();

    let mut verified = 0usize;
    let mut batches = 0usize;
    let mut checksum = 0u64;
    for h in handles {
        let (v, b, c) = h.join().expect("PERF-019 batch worker panic");
        verified += v;
        batches += b;
        checksum ^= c;
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    assert_eq!(verified, txs);

    BatchRow {
        workers,
        batch_size,
        txs,
        batches,
        elapsed_s,
        verify_tps: txs as f64 / elapsed_s,
        checksum,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let txs_list = parse_list(&args, "--txs", vec![200_000usize]);
    let workers_list = parse_list(&args, "--workers", vec![1usize, 2, 4, 6, 8]);
    let batch_sizes = parse_list(&args, "--batches", vec![8usize, 32, 128, 512, 2048]);
    let baseline_workers = parse_list(&args, "--baseline-workers", vec![8usize])[0];

    println!("CALIBRE GEN2 PERF-019 v1.9.0");
    println!("REAL ED25519 BATCH-VERIFICATION SCALING GATE");
    println!("Purpose: test whether official ed25519-dalek verify_batch can amortize authorization cost");
    println!("Timed batch path: message rebuild + public-key parse + signature parse + verify_batch");
    println!("Client signing/material generation: OUTSIDE timing | key pool: {}", KEY_POOL);
    println!("IMPORTANT: BATCH VERIFICATION IS NOT SIGNATURE AGGREGATION; every tx still has its own key+signature.");
    println!("This is a CRYPTO MICROBENCHMARK, NOT CALIBRE network TPS.");
    println!();

    let mut all_batch_rows = Vec::new();

    for txs in txs_list {
        println!("Preparing {} real signed authorizations outside timing...", txs);
        let materials = Arc::new(build_materials(txs));
        println!("Preparation complete.");

        let individual = run_individual(Arc::clone(&materials), baseline_workers);
        println!(
            "INDIVIDUAL baseline: txs={:<8} workers={:<2} verifyTPS={:>10.0} elapsed={:>7.3}s checksum={:016x}",
            individual.txs,
            individual.workers,
            individual.verify_tps,
            individual.elapsed_s,
            individual.checksum
        );
        println!();

        for &batch_size in &batch_sizes {
            for &workers in &workers_list {
                let r = run_batch(Arc::clone(&materials), workers, batch_size);
                assert_eq!(r.checksum, individual.checksum, "PERF-019 checksum mismatch");
                println!(
                    "txs={:<8} workers={:<2} batch={:<5} batchCalls={:<6} verifyTPS={:>10.0} speedupVsIndividual8={:>6.2}x elapsed={:>7.3}s checksum={:016x}",
                    r.txs,
                    r.workers,
                    r.batch_size,
                    r.batches,
                    r.verify_tps,
                    r.verify_tps / individual.verify_tps,
                    r.elapsed_s,
                    r.checksum
                );
                all_batch_rows.push((r, individual.verify_tps));
            }
            println!();
        }
    }

    let (best, individual_tps) = all_batch_rows
        .iter()
        .max_by(|(a, _), (b, _)| a.verify_tps.partial_cmp(&b.verify_tps).unwrap())
        .expect("PERF-019 rows");

    println!("=== DECISION ===");
    println!(
        "BEST REAL ED25519 BATCH VERIFY TPS: {:.0} | workers={} | batch={} | speedupVsIndividual8={:.2}x",
        best.verify_tps,
        best.workers,
        best.batch_size,
        best.verify_tps / individual_tps
    );
    println!(
        "1M ED25519 AUTHORIZATIONS/S VIA BATCH VERIFY: {}",
        if best.verify_tps >= 1_000_000.0 { "PASS" } else { "NOT YET" }
    );
    println!(
        "5M ED25519 AUTHORIZATIONS/S VIA BATCH VERIFY: {}",
        if best.verify_tps >= 5_000_000.0 { "PASS" } else { "NOT YET" }
    );
    println!("REAL ED25519_DALEK VERIFY_BATCH INCLUDED: YES");
    println!("ONE PUBLIC KEY + ONE SIGNATURE PER TRANSACTION STILL REQUIRED: YES");
    println!("SIGNING INCLUDED IN TIMING: NO");
    println!("TCP/STATE EXECUTION INCLUDED: NO");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_accepts_valid_and_rejects_tamper() {
        let materials = build_materials(64);
        let mut messages: Vec<[u8; 88]> = materials
            .iter()
            .map(|a| auth_message(a.tx, a.arity, a.value, &a.inputs))
            .collect();
        let signatures: Vec<Signature> = materials
            .iter()
            .map(|a| Signature::from_bytes(&a.signature))
            .collect();
        let keys: Vec<VerifyingKey> = materials
            .iter()
            .map(|a| VerifyingKey::from_bytes(&a.public).unwrap())
            .collect();
        let refs: Vec<&[u8]> = messages.iter().map(|m| &m[..]).collect();
        assert!(verify_batch(&refs, &signatures, &keys).is_ok());

        messages[17][0] ^= 1;
        let bad_refs: Vec<&[u8]> = messages.iter().map(|m| &m[..]).collect();
        assert!(verify_batch(&bad_refs, &signatures, &keys).is_err());
    }

    #[test]
    fn parallel_batch_counts_all_authorizations() {
        let materials = Arc::new(build_materials(4_096));
        let r = run_batch(materials, 4, 128);
        assert_eq!(r.txs, 4_096);
        assert!(r.verify_tps > 0.0);
        assert!(r.batches > 0);
    }

    #[test]
    fn batch_and_individual_checksums_match() {
        let materials = Arc::new(build_materials(2_048));
        let i = run_individual(Arc::clone(&materials), 4);
        let b = run_batch(materials, 4, 64);
        assert_eq!(i.checksum, b.checksum);
    }
}
