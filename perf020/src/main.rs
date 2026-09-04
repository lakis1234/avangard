use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use std::env;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

const MAX_ARITY: usize = 8;
const VALUE: u64 = 100;
const KEY_POOL: usize = 1024;
const DOMAIN: u64 = 0xCA11_BAF1_0000_0020;
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

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

fn deterministic_secret_key(index: u64) -> SecretKey {
    let mut ikm = [0u8; 32];
    for i in 0..4u64 {
        let x = mix64(index ^ DOMAIN ^ i.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        ikm[(i as usize) * 8..(i as usize + 1) * 8].copy_from_slice(&x.to_le_bytes());
    }
    SecretKey::key_gen(&ikm, &[]).expect("PERF-020 BLS key_gen")
}

#[derive(Clone, Copy)]
struct AuthMaterial {
    tx: u64,
    arity: usize,
    value: u64,
    inputs: [u64; MAX_ARITY],
    public: [u8; 48],
    signature: [u8; 96],
}

#[derive(Clone, Copy)]
struct AggregateBatch {
    start: usize,
    end: usize,
    signature: [u8; 96],
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
    let keys: Vec<SecretKey> = (0..KEY_POOL as u64)
        .map(deterministic_secret_key)
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
            let pk = sk.sk_to_pk();
            let sig = sk.sign(&msg, DST, &[]);
            AuthMaterial {
                tx,
                arity,
                value,
                inputs,
                public: pk.to_bytes(),
                signature: sig.to_bytes(),
            }
        })
        .collect()
}

fn build_aggregate_batches(materials: &[AuthMaterial], batch_size: usize) -> Vec<AggregateBatch> {
    assert!(batch_size > 0);
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < materials.len() {
        let end = (start + batch_size).min(materials.len());
        let sigs: Vec<Signature> = materials[start..end]
            .iter()
            .map(|a| Signature::from_bytes(&a.signature).expect("PERF-020 aggregate source sig parse"))
            .collect();
        let refs: Vec<&Signature> = sigs.iter().collect();
        let aggregate = AggregateSignature::aggregate(&refs, true)
            .expect("PERF-020 aggregate construction outside timing")
            .to_signature();
        out.push(AggregateBatch {
            start,
            end,
            signature: aggregate.to_bytes(),
        });
        start = end;
    }
    out
}

#[derive(Clone, Copy)]
struct Row {
    mode: &'static str,
    workers: usize,
    batch_size: usize,
    txs: usize,
    elapsed_s: f64,
    auth_tps: f64,
    checksum: u64,
}

fn run_individual(materials: Arc<Vec<AuthMaterial>>, workers: usize) -> Row {
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
                let pk = PublicKey::from_bytes(&a.public).expect("PERF-020 individual pk parse");
                let sig = Signature::from_bytes(&a.signature).expect("PERF-020 individual sig parse");
                let msg = auth_message(a.tx, a.arity, a.value, &a.inputs);
                let result = sig.verify(true, &msg, DST, &[], &pk, true);
                assert_eq!(result, BLST_ERROR::BLST_SUCCESS, "PERF-020 individual BLS reject");
                verified += 1;
                checksum ^= mix64(a.tx ^ (a.public[0] as u64).rotate_left(19));
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
        let (v, c) = h.join().expect("PERF-020 individual worker panic");
        verified += v;
        checksum ^= c;
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    assert_eq!(verified, txs);

    Row {
        mode: "individual",
        workers,
        batch_size: 1,
        txs,
        elapsed_s,
        auth_tps: txs as f64 / elapsed_s,
        checksum,
    }
}

fn run_aggregate_verify_only(
    materials: Arc<Vec<AuthMaterial>>,
    batches: Arc<Vec<AggregateBatch>>,
    workers: usize,
    batch_size: usize,
) -> Row {
    let txs = materials.len();
    let ready = Arc::new(Barrier::new(workers + 1));
    let go = Arc::new(Barrier::new(workers + 1));
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let materials = Arc::clone(&materials);
        let batches = Arc::clone(&batches);
        let ready = Arc::clone(&ready);
        let go = Arc::clone(&go);
        handles.push(thread::spawn(move || {
            ready.wait();
            go.wait();
            let mut verified = 0usize;
            let mut checksum = 0u64;

            for bi in (w..batches.len()).step_by(workers) {
                let b = batches[bi];
                let len = b.end - b.start;
                let mut messages: Vec<[u8; 88]> = Vec::with_capacity(len);
                let mut keys: Vec<PublicKey> = Vec::with_capacity(len);

                for a in &materials[b.start..b.end] {
                    messages.push(auth_message(a.tx, a.arity, a.value, &a.inputs));
                    keys.push(PublicKey::from_bytes(&a.public).expect("PERF-020 aggregate pk parse"));
                    checksum ^= mix64(a.tx ^ (a.public[0] as u64).rotate_left(19));
                }

                let msg_refs: Vec<&[u8]> = messages.iter().map(|m| &m[..]).collect();
                let key_refs: Vec<&PublicKey> = keys.iter().collect();
                let agg_sig = Signature::from_bytes(&b.signature).expect("PERF-020 aggregate sig parse");
                let result = agg_sig.aggregate_verify(true, &msg_refs, DST, &key_refs, true);
                assert_eq!(result, BLST_ERROR::BLST_SUCCESS, "PERF-020 aggregate verify reject");
                verified += len;
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
        let (v, c) = h.join().expect("PERF-020 aggregate verify worker panic");
        verified += v;
        checksum ^= c;
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    assert_eq!(verified, txs);

    Row {
        mode: "aggregate-verify-only",
        workers,
        batch_size,
        txs,
        elapsed_s,
        auth_tps: txs as f64 / elapsed_s,
        checksum,
    }
}

fn run_aggregate_construct_and_verify(
    materials: Arc<Vec<AuthMaterial>>,
    workers: usize,
    batch_size: usize,
) -> Row {
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
            let mut checksum = 0u64;

            while cursor < end_index {
                let end = (cursor + batch_size).min(end_index);
                let len = end - cursor;
                let mut messages: Vec<[u8; 88]> = Vec::with_capacity(len);
                let mut keys: Vec<PublicKey> = Vec::with_capacity(len);
                let mut sigs: Vec<Signature> = Vec::with_capacity(len);

                for a in &materials[cursor..end] {
                    messages.push(auth_message(a.tx, a.arity, a.value, &a.inputs));
                    keys.push(PublicKey::from_bytes(&a.public).expect("PERF-020 construct pk parse"));
                    sigs.push(Signature::from_bytes(&a.signature).expect("PERF-020 construct sig parse"));
                    checksum ^= mix64(a.tx ^ (a.public[0] as u64).rotate_left(19));
                }

                let sig_refs: Vec<&Signature> = sigs.iter().collect();
                let agg_sig = AggregateSignature::aggregate(&sig_refs, true)
                    .expect("PERF-020 aggregate inside timing")
                    .to_signature();
                let msg_refs: Vec<&[u8]> = messages.iter().map(|m| &m[..]).collect();
                let key_refs: Vec<&PublicKey> = keys.iter().collect();
                let result = agg_sig.aggregate_verify(true, &msg_refs, DST, &key_refs, true);
                assert_eq!(result, BLST_ERROR::BLST_SUCCESS, "PERF-020 construct+verify reject");

                verified += len;
                cursor = end;
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
        let (v, c) = h.join().expect("PERF-020 construct+verify worker panic");
        verified += v;
        checksum ^= c;
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    assert_eq!(verified, txs);

    Row {
        mode: "aggregate-construct+verify",
        workers,
        batch_size,
        txs,
        elapsed_s,
        auth_tps: txs as f64 / elapsed_s,
        checksum,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let txs_list = parse_list(&args, "--txs", vec![100_000usize]);
    let workers_list = parse_list(&args, "--workers", vec![1usize, 2, 4, 8]);
    let batch_sizes = parse_list(&args, "--batches", vec![8usize, 32, 128, 512, 2048]);
    let baseline_workers = parse_list(&args, "--baseline-workers", vec![8usize])[0];

    println!("CALIBRE GEN2 PERF-020 v2.0.0");
    println!("BLS12-381 DISTINCT-MESSAGE AGGREGATE AUTHORIZATION GATE");
    println!("Purpose: test real signature aggregation after Ed25519 batch verification remained <1M/s");
    println!("Scheme: blst min_pk BLS12-381 basic/distinct-message aggregate verification");
    println!("Each transaction still has an independent signer and independent signed CALIBRE-style message");
    println!("VERIFY-ONLY mode receives one already-aggregated 96-byte BLS signature per batch");
    println!("CONSTRUCT+VERIFY mode also includes aggregation of the individual signatures inside timing");
    println!("Public-key parse + message rebuild are inside timing in both aggregate modes");
    println!("Client signing/material generation: OUTSIDE timing | key pool: {}", KEY_POOL);
    println!("Proof-of-possession / production rogue-key hardening: NOT INCLUDED");
    println!("This is a CRYPTO MICROBENCHMARK, NOT CALIBRE network TPS.");
    println!();

    let mut all_rows = Vec::new();

    for txs in txs_list {
        println!("Preparing {} real BLS-signed authorizations outside timing...", txs);
        let materials = Arc::new(build_materials(txs));
        println!("Preparation complete.");

        let baseline = run_individual(Arc::clone(&materials), baseline_workers);
        println!(
            "BLS INDIVIDUAL baseline: txs={:<8} workers={:<2} verifyTPS={:>10.0} elapsed={:>7.3}s checksum={:016x}",
            baseline.txs, baseline.workers, baseline.auth_tps, baseline.elapsed_s, baseline.checksum
        );
        all_rows.push(baseline);
        println!();

        for &batch_size in &batch_sizes {
            let preaggregated = Arc::new(build_aggregate_batches(&materials, batch_size));
            for &workers in &workers_list {
                let verify_only = run_aggregate_verify_only(
                    Arc::clone(&materials),
                    Arc::clone(&preaggregated),
                    workers,
                    batch_size,
                );
                println!(
                    "mode=verify-only      txs={:<8} workers={:<2} batch={:<5} authTPS={:>10.0} speedupVsBlsIndividual8={:>6.2}x elapsed={:>7.3}s checksum={:016x}",
                    verify_only.txs,
                    verify_only.workers,
                    verify_only.batch_size,
                    verify_only.auth_tps,
                    verify_only.auth_tps / baseline.auth_tps,
                    verify_only.elapsed_s,
                    verify_only.checksum,
                );
                all_rows.push(verify_only);
            }

            for &workers in &workers_list {
                let full = run_aggregate_construct_and_verify(
                    Arc::clone(&materials),
                    workers,
                    batch_size,
                );
                println!(
                    "mode=construct+verify txs={:<8} workers={:<2} batch={:<5} authTPS={:>10.0} speedupVsBlsIndividual8={:>6.2}x elapsed={:>7.3}s checksum={:016x}",
                    full.txs,
                    full.workers,
                    full.batch_size,
                    full.auth_tps,
                    full.auth_tps / baseline.auth_tps,
                    full.elapsed_s,
                    full.checksum,
                );
                all_rows.push(full);
            }
            println!();
        }
    }

    let best_verify_only = all_rows
        .iter()
        .filter(|r| r.mode == "aggregate-verify-only")
        .max_by(|a, b| a.auth_tps.partial_cmp(&b.auth_tps).unwrap())
        .expect("PERF-020 verify-only rows");
    let best_full = all_rows
        .iter()
        .filter(|r| r.mode == "aggregate-construct+verify")
        .max_by(|a, b| a.auth_tps.partial_cmp(&b.auth_tps).unwrap())
        .expect("PERF-020 construct+verify rows");

    println!("=== DECISION ===");
    println!(
        "BEST BLS AGGREGATE VERIFY-ONLY TPS: {:.0} | workers={} | batch={}",
        best_verify_only.auth_tps, best_verify_only.workers, best_verify_only.batch_size
    );
    println!(
        "BEST BLS AGGREGATE CONSTRUCT+VERIFY TPS: {:.0} | workers={} | batch={}",
        best_full.auth_tps, best_full.workers, best_full.batch_size
    );
    println!(
        "1M INDEPENDENT AUTHORIZATIONS/S VIA BLS AGGREGATE VERIFY: {}",
        if best_verify_only.auth_tps >= 1_000_000.0 { "PASS" } else { "NOT YET" }
    );
    println!(
        "5M INDEPENDENT AUTHORIZATIONS/S VIA BLS AGGREGATE VERIFY: {}",
        if best_verify_only.auth_tps >= 5_000_000.0 { "PASS" } else { "NOT YET" }
    );
    println!("BLS SIGNATURE AGGREGATION INCLUDED: YES");
    println!("DISTINCT SIGNERS + DISTINCT MESSAGES INCLUDED: YES");
    println!("TCP/STATE EXECUTION INCLUDED: NO");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bls_individual_accepts_and_tamper_rejects() {
        let sk = deterministic_secret_key(7);
        let pk = sk.sk_to_pk();
        let mut inputs = [0u64; MAX_ARITY];
        for (k, x) in inputs.iter_mut().enumerate() {
            *x = 100 + k as u64;
        }
        let msg = auth_message(42, 8, 800, &inputs);
        let sig = sk.sign(&msg, DST, &[]);
        assert_eq!(sig.verify(true, &msg, DST, &[], &pk, true), BLST_ERROR::BLST_SUCCESS);
        let mut bad = msg;
        bad[5] ^= 1;
        assert_ne!(sig.verify(true, &bad, DST, &[], &pk, true), BLST_ERROR::BLST_SUCCESS);
    }

    #[test]
    fn bls_aggregate_accepts_and_tamper_rejects() {
        let materials = build_materials(16);
        let batch = build_aggregate_batches(&materials, 16)[0];
        let mut messages: Vec<[u8; 88]> = materials
            .iter()
            .map(|a| auth_message(a.tx, a.arity, a.value, &a.inputs))
            .collect();
        let keys: Vec<PublicKey> = materials
            .iter()
            .map(|a| PublicKey::from_bytes(&a.public).unwrap())
            .collect();
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| &m[..]).collect();
        let key_refs: Vec<&PublicKey> = keys.iter().collect();
        let sig = Signature::from_bytes(&batch.signature).unwrap();
        assert_eq!(sig.aggregate_verify(true, &msg_refs, DST, &key_refs, true), BLST_ERROR::BLST_SUCCESS);

        messages[3][0] ^= 1;
        let bad_refs: Vec<&[u8]> = messages.iter().map(|m| &m[..]).collect();
        assert_ne!(sig.aggregate_verify(true, &bad_refs, DST, &key_refs, true), BLST_ERROR::BLST_SUCCESS);
    }

    #[test]
    fn aggregate_modes_count_every_authorization() {
        let materials = Arc::new(build_materials(512));
        let batches = Arc::new(build_aggregate_batches(&materials, 32));
        let a = run_aggregate_verify_only(Arc::clone(&materials), batches, 4, 32);
        let b = run_aggregate_construct_and_verify(materials, 4, 32);
        assert_eq!(a.txs, 512);
        assert_eq!(b.txs, 512);
        assert_eq!(a.checksum, b.checksum);
        assert!(a.auth_tps > 0.0 && b.auth_tps > 0.0);
    }
}
