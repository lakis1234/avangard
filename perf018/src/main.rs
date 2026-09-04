use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::env;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

const MAX_ARITY: usize = 8;
const VALUE: u64 = 100;
const KEY_POOL: usize = 1024;
const DOMAIN: u64 = 0xCA11_BAEF_0000_0018;

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

#[derive(Clone, Copy)]
struct Row {
    workers: usize,
    txs: usize,
    elapsed_s: f64,
    verify_tps: f64,
    checksum: u64,
}

fn run_case(materials: Arc<Vec<AuthMaterial>>, workers: usize) -> Row {
    let txs = materials.len();
    assert!(workers > 0 && workers <= 64);

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
                let vk = VerifyingKey::from_bytes(&a.public).expect("PERF-018 public key parse");
                let sig = Signature::from_bytes(&a.signature);
                let msg = auth_message(a.tx, a.arity, a.value, &a.inputs);
                vk.verify_strict(&msg, &sig)
                    .expect("PERF-018 Ed25519 authorization rejected");
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
        let (v, c) = h.join().expect("PERF-018 verification worker panic");
        verified += v;
        checksum ^= c;
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    assert_eq!(verified, txs);

    Row {
        workers,
        txs,
        elapsed_s,
        verify_tps: txs as f64 / elapsed_s,
        checksum,
    }
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

fn main() {
    let args: Vec<String> = env::args().collect();
    let txs = parse_list(&args, "--txs", vec![200_000usize]);
    let workers = parse_list(&args, "--workers", vec![1usize, 2, 4, 6, 8]);

    println!("CALIBRE GEN2 PERF-018 v1.8.0");
    println!("ED25519 AUTHORIZATION VERIFICATION SCALING CEILING");
    println!("Purpose: isolate real Ed25519 verification throughput from TCP/state execution");
    println!("Timed path per tx: public-key parse + auth-message rebuild + verify_strict");
    println!("Client signing/material generation: OUTSIDE timing | key pool: {}", KEY_POOL);
    println!("This is a CRYPTO MICROBENCHMARK, NOT CALIBRE network TPS.");
    println!();

    let mut rows = Vec::new();
    for n in txs {
        println!("Preparing {} real signed authorizations outside timing...", n);
        let materials = Arc::new(build_materials(n));
        println!("Preparation complete.");
        for &w in &workers {
            let r = run_case(Arc::clone(&materials), w);
            println!(
                "txs={:<8} workers={:<2} verifyTPS={:>10.0} elapsed={:>7.3}s checksum={:016x}",
                r.txs, r.workers, r.verify_tps, r.elapsed_s, r.checksum
            );
            rows.push(r);
        }
        println!();
    }

    let best = rows
        .iter()
        .max_by(|a, b| a.verify_tps.partial_cmp(&b.verify_tps).unwrap())
        .expect("PERF-018 rows");

    println!("=== DECISION ===");
    println!(
        "BEST REAL ED25519 VERIFY TPS: {:.0} | workers={}",
        best.verify_tps, best.workers
    );
    println!(
        "1M INDIVIDUAL ED25519 VERIFICATIONS/S TARGET: {}",
        if best.verify_tps >= 1_000_000.0 { "PASS" } else { "NOT YET" }
    );
    println!(
        "5M INDIVIDUAL ED25519 VERIFICATIONS/S TARGET: {}",
        if best.verify_tps >= 5_000_000.0 { "PASS" } else { "NOT YET" }
    );
    println!("REAL ED25519 VERIFY_STRICT INCLUDED: YES");
    println!("SIGNING INCLUDED IN TIMING: NO");
    println!("TCP/STATE EXECUTION INCLUDED: NO");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_accepts_and_tamper_rejects() {
        let sk = deterministic_signing_key(7);
        let vk = sk.verifying_key();
        let mut inputs = [0u64; MAX_ARITY];
        for (k, x) in inputs.iter_mut().enumerate() {
            *x = 100 + k as u64;
        }
        let msg = auth_message(42, 8, 800, &inputs);
        let sig = sk.sign(&msg);
        assert!(vk.verify_strict(&msg, &sig).is_ok());
        let mut bad = msg;
        bad[7] ^= 1;
        assert!(vk.verify_strict(&bad, &sig).is_err());
    }

    #[test]
    fn parallel_counts_all_authorizations() {
        let materials = Arc::new(build_materials(2_000));
        let r = run_case(materials, 4);
        assert_eq!(r.txs, 2_000);
        assert!(r.verify_tps > 0.0);
    }
}
