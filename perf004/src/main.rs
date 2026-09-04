use std::collections::HashMap;
use std::env;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Instant;

const VALUE: u64 = 100;

#[derive(Clone, Copy)]
struct Cell {
    id: u64,
    value: u64,
    generation: u64,
}

#[derive(Default)]
struct U64Hasher(u64);

impl Hasher for U64Hasher {
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        let mut x = 0u64;
        for (i, b) in bytes.iter().take(8).enumerate() {
            x |= (*b as u64) << (i * 8);
        }
        self.0 = mix64(x);
    }

    #[inline(always)]
    fn write_u64(&mut self, i: u64) {
        self.0 = mix64(i);
    }

    #[inline(always)]
    fn finish(&self) -> u64 {
        self.0
    }
}

type FastMap = HashMap<u64, Cell, BuildHasherDefault<U64Hasher>>;

#[inline(always)]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[inline(always)]
fn make_id(local: u64, shard: usize, shard_bits: u32) -> u64 {
    (local << shard_bits) | shard as u64
}

#[inline(always)]
fn input_shard(serial: u64, shards: usize) -> usize {
    (mix64(serial ^ 0xA11C_E001_5EED_0001) as usize) & (shards - 1)
}

#[inline(always)]
fn input_id(serial: u64, shards: usize, shard_bits: u32) -> u64 {
    make_id(serial + 1, input_shard(serial, shards), shard_bits)
}

#[inline(always)]
fn output_shard(tx: u64, shards: usize) -> usize {
    (mix64(tx ^ 0x0A7B_17A5_F00D_0004) as usize) & (shards - 1)
}

#[inline(always)]
fn output_id(tx: u64, shard: usize, shard_bits: u32) -> u64 {
    let local = (1u64 << 48) + tx + 1;
    make_id(local, shard, shard_bits)
}

#[derive(Clone)]
struct Row {
    txs: u64,
    arity: usize,
    workers: usize,
    shards: usize,
    elapsed_s: f64,
    tps: f64,
    input_ops_s: f64,
    checksum: u64,
    final_cells: u64,
    total_value: u128,
}

fn run_case(txs: u64, arity: usize, workers: usize, shards: usize) -> Row {
    assert!(txs > 0);
    assert!(arity >= 1 && arity <= 16);
    assert!(workers >= 1 && workers <= 256);
    assert!(shards.is_power_of_two());
    assert!(shards >= 2);

    let shard_bits = shards.trailing_zeros();
    let total_inputs = txs * arity as u64;
    let per_shard = (total_inputs as usize / shards).saturating_add(32);

    let mut maps: Vec<FastMap> = (0..shards)
        .map(|_| {
            HashMap::with_capacity_and_hasher(
                per_shard.saturating_mul(2).saturating_add(16),
                BuildHasherDefault::default(),
            )
        })
        .collect();

    for serial in 0..total_inputs {
        let shard = input_shard(serial, shards);
        let id = input_id(serial, shards, shard_bits);
        let old = maps[shard].insert(
            id,
            Cell {
                id,
                value: VALUE,
                generation: 0,
            },
        );
        assert!(old.is_none());
    }

    let state: Arc<Vec<Mutex<FastMap>>> = Arc::new(maps.into_iter().map(Mutex::new).collect());
    let barrier = Arc::new(Barrier::new(workers + 1));
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let state = Arc::clone(&state);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut checksum = 0u64;
            let mut processed = 0u64;
            let mut lock_shards: Vec<usize> = Vec::with_capacity(arity + 1);

            barrier.wait();

            for tx in (w as u64..txs).step_by(workers) {
                lock_shards.clear();
                for k in 0..arity {
                    let serial = tx * arity as u64 + k as u64;
                    lock_shards.push(input_shard(serial, shards));
                }
                let out_shard = output_shard(tx, shards);
                lock_shards.push(out_shard);
                lock_shards.sort_unstable();
                lock_shards.dedup();

                let mut guards = Vec::with_capacity(lock_shards.len());
                for &sid in &lock_shards {
                    guards.push(state[sid].lock().expect("shard mutex poisoned"));
                }

                let mut bundle_value = 0u64;
                let mut max_generation = 0u64;
                for k in 0..arity {
                    let serial = tx * arity as u64 + k as u64;
                    let sid = input_shard(serial, shards);
                    let pos = lock_shards.binary_search(&sid).unwrap();
                    let id = input_id(serial, shards, shard_bits);
                    let old = guards[pos].remove(&id).expect("atomic bundle input missing");
                    bundle_value = bundle_value.checked_add(old.value).expect("value overflow");
                    max_generation = max_generation.max(old.generation);
                    checksum ^= mix64(old.id ^ old.generation ^ old.value);
                }

                let out_pos = lock_shards.binary_search(&out_shard).unwrap();
                let new_id = output_id(tx, out_shard, shard_bits);
                let next = Cell {
                    id: new_id,
                    value: bundle_value,
                    generation: max_generation + 1,
                };
                if guards[out_pos].insert(new_id, next).is_some() {
                    panic!("unexpected output collision");
                }
                checksum ^= mix64(next.id ^ next.generation ^ next.value);
                processed += 1;
            }

            (checksum, processed)
        }));
    }

    let start = Instant::now();
    barrier.wait();

    let mut checksum = 0u64;
    let mut processed = 0u64;
    for h in handles {
        let (c, p) = h.join().expect("worker panic");
        checksum ^= c;
        processed += p;
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    assert_eq!(processed, txs);

    let mut final_cells = 0u64;
    let mut total_value = 0u128;
    for shard in state.iter() {
        let map = shard.lock().expect("post-run shard mutex poisoned");
        final_cells += map.len() as u64;
        total_value += map.values().map(|c| c.value as u128).sum::<u128>();
    }

    assert_eq!(final_cells, txs);
    let expected_value = txs as u128 * arity as u128 * VALUE as u128;
    assert_eq!(total_value, expected_value);

    let tps = txs as f64 / elapsed_s;
    Row {
        txs,
        arity,
        workers,
        shards,
        elapsed_s,
        tps,
        input_ops_s: tps * arity as f64,
        checksum,
        final_cells,
        total_value,
    }
}

fn parse_list<T: std::str::FromStr>(args: &[String], flag: &str, default: Vec<T>) -> Vec<T> {
    if let Some(i) = args.iter().position(|x| x == flag) {
        if let Some(v) = args.get(i + 1) {
            let out: Vec<T> = v.split(',').filter_map(|x| x.trim().parse::<T>().ok()).collect();
            if !out.is_empty() {
                return out;
            }
        }
    }
    default
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let txs = parse_list(&args, "--txs", vec![250_000u64, 1_000_000]);
    let workers = parse_list(&args, "--workers", vec![8usize, 16]);
    let shards = parse_list(&args, "--shards", vec![256usize, 1024]);
    let arities = parse_list(&args, "--arities", vec![1usize, 2, 4, 8]);

    println!("CALIBRE GEN2 PERF-004 v0.4.0");
    println!("NATIVE ATOMIC MULTI-INPUT / CROSS-SHARD BUNDLE ENGINE");
    println!("Security: OFF | Consensus: OFF | Persistence: OFF | Network: OFF");
    println!("Each transaction atomically consumes N independent inputs and creates one value-conserving output.");
    println!("Shard locks are acquired in deterministic ascending order to prevent local deadlock.");
    println!();

    let mut rows = Vec::new();

    for &n in &txs {
        println!("=== TXS={} ===", n);
        for &arity in &arities {
            println!("--- INPUT ARITY={} ---", arity);
            for &s in &shards {
                for &w in &workers {
                    let r = run_case(n, arity, w, s);
                    println!(
                        "shards={:<5} workers={:<3} TPS={:>12.0} input-cell-ops/s={:>12.0} elapsed={:>7.3}s checksum={:016x}",
                        s, w, r.tps, r.input_ops_s, r.elapsed_s, r.checksum
                    );
                    rows.push(r);
                }
            }
        }
        println!();
    }

    let best = rows
        .iter()
        .max_by(|a, b| a.tps.partial_cmp(&b.tps).unwrap())
        .expect("results");

    println!("=== DECISION ===");
    println!(
        "BEST TRANSACTION TPS: {:.0} | txs={} arity={} shards={} workers={}",
        best.tps, best.txs, best.arity, best.shards, best.workers
    );

    for arity in [1usize, 2, 4, 8] {
        if let Some(r) = rows.iter().find(|r| r.txs == 1_000_000 && r.arity == arity && r.shards == 1024 && r.workers == 8) {
            println!(
                "1M TX / 1024 SHARDS / 8 WORKERS / ARITY {}: {:.0} tx/s | {:.0} input-cell-ops/s",
                arity, r.tps, r.input_ops_s
            );
        }
    }

    if let (Some(base), Some(a8)) = (
        rows.iter().find(|r| r.txs == 1_000_000 && r.arity == 1 && r.shards == 1024 && r.workers == 8),
        rows.iter().find(|r| r.txs == 1_000_000 && r.arity == 8 && r.shards == 1024 && r.workers == 8),
    ) {
        println!("ARITY-8 TPS RETENTION VS ARITY-1: {:.1}%", 100.0 * a8.tps / base.tps);
    }

    println!("ATOMIC MULTI-INPUT VALUE CONSERVATION: PASS if run completed");
    println!("FINAL ACTIVE CELL COUNT: one output per transaction");
    println!("DEADLOCK ORDERING RULE: deterministic ascending shard locks");
    println!("DISTRIBUTED ATOMICITY PROVEN: NO");
    println!("NETWORK TPS PROVEN: NO");

    let _sanity = rows.iter().fold((0u64, 0u128), |acc, r| {
        (acc.0 ^ r.final_cells, acc.1 ^ r.total_value)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_ids_are_sharded_and_unique() {
        let shards = 256usize;
        let bits = shards.trailing_zeros();
        let a = input_id(1, shards, bits);
        let b = input_id(2, shards, bits);
        assert_ne!(a, b);
        assert_eq!((a & (shards as u64 - 1)) as usize, input_shard(1, shards));
    }

    #[test]
    fn atomic_bundle_preserves_value_arity4() {
        let r = run_case(20_000, 4, 4, 256);
        assert_eq!(r.final_cells, 20_000);
        assert_eq!(r.total_value, 20_000u128 * 4u128 * VALUE as u128);
        assert!(r.tps > 0.0);
    }

    #[test]
    fn atomic_bundle_preserves_value_arity8() {
        let r = run_case(10_000, 8, 4, 256);
        assert_eq!(r.final_cells, 10_000);
        assert_eq!(r.total_value, 10_000u128 * 8u128 * VALUE as u128);
        assert!(r.tps > 0.0);
    }
}
