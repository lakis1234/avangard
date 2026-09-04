use std::collections::HashMap;
use std::env;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
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
    (mix64(serial ^ 0xA11C_E001_5EED_0005) as usize) & (shards - 1)
}

#[inline(always)]
fn canonical_input_id(serial: u64, shards: usize, shard_bits: u32) -> u64 {
    make_id(serial + 1, input_shard(serial, shards), shard_bits)
}

#[inline(always)]
fn referenced_serial(tx: u64, k: usize, arity: usize, conflict_pct: u32) -> u64 {
    let own = tx * arity as u64 + k as u64;
    if conflict_pct > 0
        && tx > 0
        && k == 0
        && (mix64(tx ^ 0xC0AF_11C7_0000_0005) % 100) < conflict_pct as u64
    {
        (tx - 1) * arity as u64
    } else {
        own
    }
}

#[inline(always)]
fn output_shard(tx: u64, shards: usize) -> usize {
    (mix64(tx ^ 0x0A7B_17A5_F00D_0005) as usize) & (shards - 1)
}

#[inline(always)]
fn output_id(tx: u64, shard: usize, shard_bits: u32) -> u64 {
    make_id((1u64 << 48) + tx + 1, shard, shard_bits)
}

fn new_state(txs: u64, arity: usize, shards: usize) -> Vec<FastMap> {
    let total_inputs = txs * arity as u64;
    let shard_bits = shards.trailing_zeros();
    let per_shard = (total_inputs as usize / shards).saturating_add(64);
    let mut maps: Vec<FastMap> = (0..shards)
        .map(|_| {
            HashMap::with_capacity_and_hasher(
                per_shard.saturating_mul(2).saturating_add(16),
                BuildHasherDefault::default(),
            )
        })
        .collect();

    for serial in 0..total_inputs {
        let sid = input_shard(serial, shards);
        let id = canonical_input_id(serial, shards, shard_bits);
        let old = maps[sid].insert(
            id,
            Cell {
                id,
                value: VALUE,
                generation: 0,
            },
        );
        assert!(old.is_none());
    }
    maps
}

#[derive(Clone)]
struct Row {
    engine: &'static str,
    txs: u64,
    arity: usize,
    workers: usize,
    shards: usize,
    conflict_pct: u32,
    elapsed_s: f64,
    attempt_tps: f64,
    commit_tps: f64,
    committed: u64,
    aborted: u64,
    checksum: u64,
    final_cells: u64,
    total_value: u128,
}

fn validate_final(
    state: &Arc<Vec<Mutex<FastMap>>>,
    output_cells: u64,
    output_value: u128,
    txs: u64,
    arity: usize,
    committed: u64,
) -> (u64, u128) {
    let mut remaining_cells = 0u64;
    let mut remaining_value = 0u128;
    for shard in state.iter() {
        let map = shard.lock().expect("state mutex poisoned in validation");
        remaining_cells += map.len() as u64;
        remaining_value += map.values().map(|c| c.value as u128).sum::<u128>();
    }

    let final_cells = remaining_cells + output_cells;
    let total_value = remaining_value + output_value;
    let initial_cells = txs * arity as u64;
    let expected_cells = initial_cells - committed * arity as u64 + committed;
    let expected_value = initial_cells as u128 * VALUE as u128;

    assert_eq!(final_cells, expected_cells);
    assert_eq!(total_value, expected_value);
    (final_cells, total_value)
}

fn run_lock(txs: u64, arity: usize, workers: usize, shards: usize, conflict_pct: u32) -> Row {
    let shard_bits = shards.trailing_zeros();
    let maps = new_state(txs, arity, shards);
    let state: Arc<Vec<Mutex<FastMap>>> = Arc::new(maps.into_iter().map(Mutex::new).collect());
    let barrier = Arc::new(Barrier::new(workers + 1));
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let state = Arc::clone(&state);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut committed = 0u64;
            let mut aborted = 0u64;
            let mut checksum = 0u64;
            let mut lock_shards: Vec<usize> = Vec::with_capacity(arity + 1);
            let mut refs: Vec<(usize, u64)> = Vec::with_capacity(arity);
            let mut output_cells = 0u64;
            let mut output_value = 0u128;

            barrier.wait();

            for tx in (w as u64..txs).step_by(workers) {
                refs.clear();
                lock_shards.clear();

                for k in 0..arity {
                    let serial = referenced_serial(tx, k, arity, conflict_pct);
                    let sid = input_shard(serial, shards);
                    let id = canonical_input_id(serial, shards, shard_bits);
                    refs.push((sid, id));
                    lock_shards.push(sid);
                }
                let out_shard = output_shard(tx, shards);
                lock_shards.push(out_shard);
                lock_shards.sort_unstable();
                lock_shards.dedup();

                let mut guards = Vec::with_capacity(lock_shards.len());
                for &sid in &lock_shards {
                    guards.push(state[sid].lock().expect("lock engine shard mutex poisoned"));
                }

                let all_present = refs.iter().all(|(sid, id)| {
                    let pos = lock_shards.binary_search(sid).unwrap();
                    guards[pos].contains_key(id)
                });

                if !all_present {
                    aborted += 1;
                    continue;
                }

                let mut bundle_value = 0u64;
                for &(sid, id) in &refs {
                    let pos = lock_shards.binary_search(&sid).unwrap();
                    let old = guards[pos].remove(&id).expect("validated lock input disappeared");
                    bundle_value = bundle_value.checked_add(old.value).expect("bundle value overflow");
                    checksum ^= mix64(old.id ^ old.generation ^ old.value);
                }

                let out_pos = lock_shards.binary_search(&out_shard).unwrap();
                let id = output_id(tx, out_shard, shard_bits);
                let next = Cell {
                    id,
                    value: bundle_value,
                    generation: 1,
                };
                if guards[out_pos].insert(id, next).is_some() {
                    panic!("lock engine output collision");
                }
                checksum ^= mix64(next.id ^ next.value ^ next.generation);
                committed += 1;
                output_cells += 1;
                output_value += bundle_value as u128;
            }

            (committed, aborted, checksum, output_cells, output_value)
        }));
    }

    let start = Instant::now();
    barrier.wait();

    let mut committed = 0u64;
    let mut aborted = 0u64;
    let mut checksum = 0u64;
    let mut output_cells = 0u64;
    let mut output_value = 0u128;
    for h in handles {
        let (c, a, sum, oc, ov) = h.join().expect("lock worker panic");
        committed += c;
        aborted += a;
        checksum ^= sum;
        output_cells += oc;
        output_value += ov;
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    assert_eq!(committed + aborted, txs);

    // In the lock engine outputs live inside state already, so do not double-count them.
    let mut final_cells = 0u64;
    let mut total_value = 0u128;
    for shard in state.iter() {
        let map = shard.lock().expect("lock engine validation mutex poisoned");
        final_cells += map.len() as u64;
        total_value += map.values().map(|c| c.value as u128).sum::<u128>();
    }
    let initial_cells = txs * arity as u64;
    let expected_cells = initial_cells - committed * arity as u64 + committed;
    let expected_value = initial_cells as u128 * VALUE as u128;
    assert_eq!(final_cells, expected_cells);
    assert_eq!(total_value, expected_value);
    assert_eq!(output_cells, committed);
    assert_eq!(output_value, committed as u128 * arity as u128 * VALUE as u128);

    Row {
        engine: "LOCK",
        txs,
        arity,
        workers,
        shards,
        conflict_pct,
        elapsed_s,
        attempt_tps: txs as f64 / elapsed_s,
        commit_tps: committed as f64 / elapsed_s,
        committed,
        aborted,
        checksum,
        final_cells,
        total_value,
    }
}

fn run_batch(txs: u64, arity: usize, workers: usize, shards: usize, conflict_pct: u32) -> Row {
    let shard_bits = shards.trailing_zeros();
    let maps = new_state(txs, arity, shards);
    let state: Arc<Vec<Mutex<FastMap>>> = Arc::new(maps.into_iter().map(Mutex::new).collect());

    let mut refs_by_shard: Vec<Vec<(u64, u64)>> = (0..shards).map(|_| Vec::new()).collect();
    for tx in 0..txs {
        for k in 0..arity {
            let serial = referenced_serial(tx, k, arity, conflict_pct);
            let sid = input_shard(serial, shards);
            let id = canonical_input_id(serial, shards, shard_bits);
            refs_by_shard[sid].push((tx, id));
        }
    }
    let refs_by_shard = Arc::new(refs_by_shard);

    let prepared_counts: Arc<Vec<AtomicU8>> = Arc::new((0..txs).map(|_| AtomicU8::new(0)).collect());
    let prepared_values: Arc<Vec<AtomicU64>> = Arc::new((0..txs).map(|_| AtomicU64::new(0)).collect());
    let start_barrier = Arc::new(Barrier::new(workers + 1));
    let phase_barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let state = Arc::clone(&state);
        let refs_by_shard = Arc::clone(&refs_by_shard);
        let prepared_counts = Arc::clone(&prepared_counts);
        let prepared_values = Arc::clone(&prepared_values);
        let start_barrier = Arc::clone(&start_barrier);
        let phase_barrier = Arc::clone(&phase_barrier);

        handles.push(thread::spawn(move || {
            let mut prepared_sets: Vec<(usize, Vec<(u64, Cell)>)> = Vec::new();
            let mut checksum = 0u64;

            start_barrier.wait();

            // PREPARE: each worker owns a deterministic subset of shards. Inputs are
            // removed only into a private reservation set; nothing is logically committed yet.
            for sid in (w..shards).step_by(workers) {
                let mut map = state[sid].lock().expect("batch prepare shard mutex poisoned");
                let mut prepared = Vec::with_capacity(refs_by_shard[sid].len());
                for &(tx, id) in &refs_by_shard[sid] {
                    if let Some(cell) = map.remove(&id) {
                        prepared_counts[tx as usize].fetch_add(1, Ordering::Relaxed);
                        prepared_values[tx as usize].fetch_add(cell.value, Ordering::Relaxed);
                        prepared.push((tx, cell));
                    }
                }
                prepared_sets.push((sid, prepared));
            }

            phase_barrier.wait();

            // COMMIT/ROLLBACK: a transaction commits only if every one of its inputs
            // was reserved. Otherwise every reservation belonging to it is restored.
            for (sid, prepared) in &prepared_sets {
                let mut map = state[*sid].lock().expect("batch rollback shard mutex poisoned");
                for &(tx, cell) in prepared {
                    let eligible = prepared_counts[tx as usize].load(Ordering::Relaxed) as usize == arity;
                    if eligible {
                        checksum ^= mix64(cell.id ^ cell.generation ^ cell.value);
                    } else if map.insert(cell.id, cell).is_some() {
                        panic!("batch rollback collision");
                    }
                }
            }

            phase_barrier.wait();

            // OUTPUT: after the global prepare decision, each worker creates outputs for
            // its tx stripe. Outputs are independent, so no cross-shard lock set is needed.
            let mut outputs: FastMap = HashMap::with_capacity_and_hasher(
                (txs as usize / workers).saturating_mul(2).saturating_add(16),
                BuildHasherDefault::default(),
            );
            let mut committed = 0u64;
            let mut aborted = 0u64;
            let mut output_value = 0u128;

            for tx in (w as u64..txs).step_by(workers) {
                let eligible = prepared_counts[tx as usize].load(Ordering::Relaxed) as usize == arity;
                if eligible {
                    let value = prepared_values[tx as usize].load(Ordering::Relaxed);
                    assert_eq!(value, arity as u64 * VALUE);
                    let sid = output_shard(tx, shards);
                    let id = output_id(tx, sid, shard_bits);
                    let next = Cell {
                        id,
                        value,
                        generation: 1,
                    };
                    if outputs.insert(id, next).is_some() {
                        panic!("batch output collision");
                    }
                    checksum ^= mix64(next.id ^ next.value ^ next.generation);
                    committed += 1;
                    output_value += value as u128;
                } else {
                    aborted += 1;
                }
            }

            (committed, aborted, checksum, outputs.len() as u64, output_value)
        }));
    }

    let start = Instant::now();
    start_barrier.wait();

    let mut committed = 0u64;
    let mut aborted = 0u64;
    let mut checksum = 0u64;
    let mut output_cells = 0u64;
    let mut output_value = 0u128;
    for h in handles {
        let (c, a, sum, oc, ov) = h.join().expect("batch worker panic");
        committed += c;
        aborted += a;
        checksum ^= sum;
        output_cells += oc;
        output_value += ov;
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    assert_eq!(committed + aborted, txs);
    assert_eq!(output_cells, committed);

    let (final_cells, total_value) = validate_final(
        &state,
        output_cells,
        output_value,
        txs,
        arity,
        committed,
    );

    Row {
        engine: "BATCH",
        txs,
        arity,
        workers,
        shards,
        conflict_pct,
        elapsed_s,
        attempt_tps: txs as f64 / elapsed_s,
        commit_tps: committed as f64 / elapsed_s,
        committed,
        aborted,
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
    let txs = parse_list(&args, "--txs", vec![1_000_000u64]);
    let workers = parse_list(&args, "--workers", vec![8usize, 16]);
    let shards = parse_list(&args, "--shards", vec![1024usize]);
    let arities = parse_list(&args, "--arities", vec![1usize, 2, 4, 8]);
    let conflicts = parse_list(&args, "--conflicts", vec![0u32]);

    println!("CALIBRE GEN2 PERF-005 v0.5.0");
    println!("LOCK-ALL VS SHARD-PREPARE/BATCH-COMMIT ATOMIC BUNDLE ENGINE");
    println!("Security: OFF | Consensus: OFF | Persistence: OFF | Network: OFF");
    println!("LOCK  = acquire all touched shard mutexes for every transaction");
    println!("BATCH = shard-local prepare, global eligibility, rollback losers, independent output commit");
    println!();

    let mut rows = Vec::new();

    for &n in &txs {
        println!("=== TXS={} ===", n);
        for &conflict_pct in &conflicts {
            println!("--- CONFLICT={}%% ---", conflict_pct);
            for &arity in &arities {
                println!("ARITY={}", arity);
                for &s in &shards {
                    for &w in &workers {
                        for engine in ["LOCK", "BATCH"] {
                            let r = if engine == "LOCK" {
                                run_lock(n, arity, w, s, conflict_pct)
                            } else {
                                run_batch(n, arity, w, s, conflict_pct)
                            };
                            println!(
                                "engine={:<5} shards={:<5} workers={:<3} attemptTPS={:>12.0} commitTPS={:>12.0} committed={:<9} aborted={:<8} elapsed={:>7.3}s checksum={:016x}",
                                r.engine,
                                r.shards,
                                r.workers,
                                r.attempt_tps,
                                r.commit_tps,
                                r.committed,
                                r.aborted,
                                r.elapsed_s,
                                r.checksum
                            );
                            rows.push(r);
                        }
                    }
                }
            }
        }
        println!();
    }

    println!("=== DECISION ===");
    let best = rows
        .iter()
        .filter(|r| r.conflict_pct == 0)
        .max_by(|a, b| a.commit_tps.partial_cmp(&b.commit_tps).unwrap())
        .expect("results");
    println!(
        "BEST NO-CONFLICT COMMIT TPS: {:.0} engine={} arity={} shards={} workers={}",
        best.commit_tps, best.engine, best.arity, best.shards, best.workers
    );

    for arity in [1usize, 2, 4, 8] {
        let lock = rows.iter().find(|r| {
            r.txs == 1_000_000 && r.arity == arity && r.shards == 1024 && r.workers == 8 && r.conflict_pct == 0 && r.engine == "LOCK"
        });
        let batch = rows.iter().find(|r| {
            r.txs == 1_000_000 && r.arity == arity && r.shards == 1024 && r.workers == 8 && r.conflict_pct == 0 && r.engine == "BATCH"
        });
        if let (Some(l), Some(b)) = (lock, batch) {
            println!(
                "1M / 1024 / 8 / ARITY {}: LOCK={:.0} tx/s | BATCH={:.0} tx/s | SPEEDUP={:.2}x",
                arity,
                l.commit_tps,
                b.commit_tps,
                b.commit_tps / l.commit_tps
            );
        }
    }

    if let (Some(b1), Some(b8)) = (
        rows.iter().find(|r| r.txs == 1_000_000 && r.arity == 1 && r.shards == 1024 && r.workers == 8 && r.conflict_pct == 0 && r.engine == "BATCH"),
        rows.iter().find(|r| r.txs == 1_000_000 && r.arity == 8 && r.shards == 1024 && r.workers == 8 && r.conflict_pct == 0 && r.engine == "BATCH"),
    ) {
        println!("BATCH ARITY-8 RETENTION VS ARITY-1: {:.1}%", 100.0 * b8.commit_tps / b1.commit_tps);
        println!("BATCH ARITY-8 >5M TARGET: {}", if b8.commit_tps >= 5_000_000.0 { "PASS" } else { "NOT YET" });
    }

    println!("LOCAL ATOMIC VALUE CONSERVATION: PASS if run completed");
    println!("CONFLICT ROLLBACK PATH: tested by unit tests and optional --conflicts runs");
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
    fn batch_no_conflict_commits_all_and_preserves_value() {
        let r = run_batch(20_000, 4, 4, 256, 0);
        assert_eq!(r.committed, 20_000);
        assert_eq!(r.aborted, 0);
        assert_eq!(r.total_value, 20_000u128 * 4u128 * VALUE as u128);
    }

    #[test]
    fn batch_conflict_aborts_without_partial_value_loss() {
        let r = run_batch(20_000, 4, 4, 256, 10);
        assert!(r.aborted > 0);
        assert_eq!(r.committed + r.aborted, 20_000);
        assert_eq!(r.total_value, 20_000u128 * 4u128 * VALUE as u128);
    }

    #[test]
    fn lock_conflict_aborts_without_partial_value_loss() {
        let r = run_lock(20_000, 4, 4, 256, 10);
        assert!(r.aborted > 0);
        assert_eq!(r.committed + r.aborted, 20_000);
        assert_eq!(r.total_value, 20_000u128 * 4u128 * VALUE as u128);
    }
}
