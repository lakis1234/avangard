use std::collections::HashMap;
use std::env;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

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
    (mix64(serial ^ 0xA11C_E001_5EED_0006) as usize) & (shards - 1)
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
        && (mix64(tx ^ 0xC0AF_11C7_0000_0006) % 100) < conflict_pct as u64
    {
        (tx - 1) * arity as u64
    } else {
        own
    }
}

#[inline(always)]
fn output_shard(tx: u64, shards: usize) -> usize {
    (mix64(tx ^ 0x0A7B_17A5_F00D_0006) as usize) & (shards - 1)
}

#[inline(always)]
fn output_id(tx: u64, shard: usize, shard_bits: u32) -> u64 {
    make_id((1u64 << 48) + tx + 1, shard, shard_bits)
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

#[derive(Clone)]
struct Row {
    txs: u64,
    arity: usize,
    workers: usize,
    shards: usize,
    conflict_pct: u32,
    batch_size: usize,
    elapsed_s: f64,
    attempt_tps: f64,
    commit_tps: f64,
    committed: u64,
    aborted: u64,
    p50_us: f64,
    p95_us: f64,
    p99_us: f64,
    checksum: u64,
}

fn quantile_us(samples: &[Duration], q: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut v: Vec<u128> = samples.iter().map(|d| d.as_nanos()).collect();
    v.sort_unstable();
    let idx = (((v.len() - 1) as f64) * q).round() as usize;
    v[idx] as f64 / 1_000.0
}

fn run_case(
    txs: u64,
    arity: usize,
    workers: usize,
    shards: usize,
    conflict_pct: u32,
    batch_size: usize,
) -> Row {
    assert!(txs > 0);
    assert!((1..=16).contains(&arity));
    assert!((1..=64).contains(&workers));
    assert!(shards.is_power_of_two());
    assert!(shards >= workers);
    assert!(batch_size >= 1);
    assert!(conflict_pct <= 100);

    let shard_bits = shards.trailing_zeros();
    let total_inputs = txs * arity as u64;

    // Every shard has exactly one owner worker: owner = shard % workers.
    // This removes cross-worker shard mutexes from the hot path.
    let mut maps_by_worker: Vec<Vec<FastMap>> = (0..workers)
        .map(|w| {
            let owned = if w < shards {
                (shards - 1 - w) / workers + 1
            } else {
                0
            };
            (0..owned)
                .map(|_| {
                    HashMap::with_capacity_and_hasher(
                        ((total_inputs as usize / shards).saturating_mul(2)).saturating_add(32),
                        BuildHasherDefault::default(),
                    )
                })
                .collect()
        })
        .collect();

    for serial in 0..total_inputs {
        let sid = input_shard(serial, shards);
        let owner = sid % workers;
        let slot = sid / workers;
        let id = canonical_input_id(serial, shards, shard_bits);
        let old = maps_by_worker[owner][slot].insert(
            id,
            Cell {
                id,
                value: VALUE,
                generation: 0,
            },
        );
        assert!(old.is_none());
    }

    // References are pre-routed to the owner of the shard they touch and remain tx-sorted.
    let mut refs_by_worker: Vec<Vec<(u64, usize, u64)>> = (0..workers).map(|_| Vec::new()).collect();
    for tx in 0..txs {
        for k in 0..arity {
            let serial = referenced_serial(tx, k, arity, conflict_pct);
            let sid = input_shard(serial, shards);
            let owner = sid % workers;
            let slot = sid / workers;
            let id = canonical_input_id(serial, shards, shard_bits);
            refs_by_worker[owner].push((tx, slot, id));
        }
    }

    let prepared_counts: Arc<Vec<AtomicU8>> =
        Arc::new((0..txs).map(|_| AtomicU8::new(0)).collect());
    let prepared_values: Arc<Vec<AtomicU64>> =
        Arc::new((0..txs).map(|_| AtomicU64::new(0)).collect());

    let batches = ((txs as usize) + batch_size - 1) / batch_size;
    let phase = Arc::new(Barrier::new(workers + 1));
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let mut maps = std::mem::take(&mut maps_by_worker[w]);
        let refs = std::mem::take(&mut refs_by_worker[w]);
        let prepared_counts = Arc::clone(&prepared_counts);
        let prepared_values = Arc::clone(&prepared_values);
        let phase = Arc::clone(&phase);

        handles.push(thread::spawn(move || {
            let mut ref_cursor = 0usize;
            let mut checksum = 0u64;
            let mut committed = 0u64;
            let mut aborted = 0u64;
            let mut outputs: FastMap = HashMap::with_capacity_and_hasher(
                (txs as usize / workers).saturating_mul(2).saturating_add(32),
                BuildHasherDefault::default(),
            );

            for b in 0..batches {
                let start_tx = b * batch_size;
                let end_tx = ((b + 1) * batch_size).min(txs as usize);
                let mut prepared: Vec<(usize, u64, Cell)> = Vec::new();

                // Batch start.
                phase.wait();

                // PREPARE: each worker touches only its own shard maps.
                while ref_cursor < refs.len() && (refs[ref_cursor].0 as usize) < end_tx {
                    let (tx, slot, id) = refs[ref_cursor];
                    if (tx as usize) >= start_tx {
                        if let Some(cell) = maps[slot].remove(&id) {
                            prepared_counts[tx as usize].fetch_add(1, Ordering::Relaxed);
                            prepared_values[tx as usize].fetch_add(cell.value, Ordering::Relaxed);
                            prepared.push((slot, tx, cell));
                        }
                    }
                    ref_cursor += 1;
                }

                phase.wait();

                // COMMIT INPUTS OR ROLLBACK LOSERS.
                for (slot, tx, cell) in prepared.drain(..) {
                    let eligible =
                        prepared_counts[tx as usize].load(Ordering::Relaxed) as usize == arity;
                    if eligible {
                        checksum ^= mix64(cell.id ^ cell.generation ^ cell.value);
                    } else if maps[slot].insert(cell.id, cell).is_some() {
                        panic!("microbatch rollback collision");
                    }
                }

                phase.wait();

                // CREATE INDEPENDENT OUTPUTS FOR ELIGIBLE TRANSACTIONS.
                for tx in (start_tx as u64 + w as u64..end_tx as u64).step_by(workers) {
                    let eligible =
                        prepared_counts[tx as usize].load(Ordering::Relaxed) as usize == arity;
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
                            panic!("microbatch output collision");
                        }
                        checksum ^= mix64(next.id ^ next.value ^ next.generation);
                        committed += 1;
                    } else {
                        aborted += 1;
                    }
                }

                phase.wait();
            }

            let remaining_cells: u64 = maps.iter().map(|m| m.len() as u64).sum();
            let remaining_value: u128 = maps
                .iter()
                .map(|m| m.values().map(|c| c.value as u128).sum::<u128>())
                .sum();
            let output_cells = outputs.len() as u64;
            let output_value: u128 = outputs.values().map(|c| c.value as u128).sum();

            (
                committed,
                aborted,
                checksum,
                remaining_cells,
                remaining_value,
                output_cells,
                output_value,
            )
        }));
    }

    let overall = Instant::now();
    let mut batch_latencies = Vec::with_capacity(batches);
    for _ in 0..batches {
        phase.wait();
        let start = Instant::now();
        phase.wait();
        phase.wait();
        phase.wait();
        batch_latencies.push(start.elapsed());
    }
    let elapsed_s = overall.elapsed().as_secs_f64();

    let mut committed = 0u64;
    let mut aborted = 0u64;
    let mut checksum = 0u64;
    let mut remaining_cells = 0u64;
    let mut remaining_value = 0u128;
    let mut output_cells = 0u64;
    let mut output_value = 0u128;

    for h in handles {
        let (c, a, sum, rc, rv, oc, ov) = h.join().expect("microbatch worker panic");
        committed += c;
        aborted += a;
        checksum ^= sum;
        remaining_cells += rc;
        remaining_value += rv;
        output_cells += oc;
        output_value += ov;
    }

    assert_eq!(committed + aborted, txs);
    assert_eq!(output_cells, committed);

    let initial_cells = total_inputs;
    let final_cells = remaining_cells + output_cells;
    let expected_cells = initial_cells - committed * arity as u64 + committed;
    assert_eq!(final_cells, expected_cells);

    let total_value = remaining_value + output_value;
    let expected_value = initial_cells as u128 * VALUE as u128;
    assert_eq!(total_value, expected_value);

    Row {
        txs,
        arity,
        workers,
        shards,
        conflict_pct,
        batch_size,
        elapsed_s,
        attempt_tps: txs as f64 / elapsed_s,
        commit_tps: committed as f64 / elapsed_s,
        committed,
        aborted,
        p50_us: quantile_us(&batch_latencies, 0.50),
        p95_us: quantile_us(&batch_latencies, 0.95),
        p99_us: quantile_us(&batch_latencies, 0.99),
        checksum,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let txs = parse_list(&args, "--txs", vec![1_000_000u64]);
    let arities = parse_list(&args, "--arities", vec![8usize]);
    let workers = parse_list(&args, "--workers", vec![8usize]);
    let shards = parse_list(&args, "--shards", vec![1024usize]);
    let conflicts = parse_list(&args, "--conflicts", vec![0u32, 10]);
    let batches = parse_list(
        &args,
        "--batches",
        vec![256usize, 1024, 4096, 16_384, 65_536, 1_000_000],
    );

    println!("CALIBRE GEN2 PERF-006 v0.6.0");
    println!("PIPELINED MICRO-BATCH ATOMIC ENGINE");
    println!("Security: OFF | Consensus: OFF | Persistence: OFF | Network: OFF");
    println!("Question: can shard-prepare/batch-commit keep multi-input throughput with bounded batch latency?");
    println!();

    let mut rows = Vec::new();

    for &n in &txs {
        for &arity in &arities {
            for &s in &shards {
                for &w in &workers {
                    for &conflict in &conflicts {
                        println!(
                            "=== TXS={} ARITY={} SHARDS={} WORKERS={} CONFLICT={}%% ===",
                            n, arity, s, w, conflict
                        );
                        for &batch in &batches {
                            let r = run_case(n, arity, w, s, conflict, batch);
                            println!(
                                "batch={:<8} attemptTPS={:>11.0} commitTPS={:>11.0} committed={:<9} aborted={:<8} p50={:>9.1}us p95={:>9.1}us p99={:>9.1}us checksum={:016x}",
                                r.batch_size,
                                r.attempt_tps,
                                r.commit_tps,
                                r.committed,
                                r.aborted,
                                r.p50_us,
                                r.p95_us,
                                r.p99_us,
                                r.checksum
                            );
                            rows.push(r);
                        }
                        println!();
                    }
                }
            }
        }
    }

    println!("=== DECISION ===");
    if let Some(best) = rows
        .iter()
        .filter(|r| r.conflict_pct == 0)
        .max_by(|a, b| a.commit_tps.partial_cmp(&b.commit_tps).unwrap())
    {
        println!(
            "BEST NO-CONFLICT COMMIT TPS: {:.0} | batch={} arity={} shards={} workers={}",
            best.commit_tps, best.batch_size, best.arity, best.shards, best.workers
        );
    }

    if let Some(low) = rows
        .iter()
        .filter(|r| r.conflict_pct == 0 && r.batch_size <= 4096)
        .max_by(|a, b| a.commit_tps.partial_cmp(&b.commit_tps).unwrap())
    {
        println!(
            "BEST BATCH<=4096 COMMIT TPS: {:.0} | batch={} p95={:.1}us",
            low.commit_tps, low.batch_size, low.p95_us
        );
        println!(
            "LOW-LATENCY >5M TARGET: {}",
            if low.commit_tps >= 5_000_000.0 { "PASS" } else { "NOT YET" }
        );
    }

    if let (Some(small), Some(giant)) = (
        rows.iter().find(|r| r.conflict_pct == 0 && r.batch_size == 4096),
        rows.iter().find(|r| r.conflict_pct == 0 && r.batch_size >= r.txs as usize),
    ) {
        println!(
            "BATCH4096 THROUGHPUT RETENTION VS GIANT: {:.1}%",
            100.0 * small.commit_tps / giant.commit_tps
        );
    }

    println!("MICROBATCH ATOMIC VALUE CONSERVATION: PASS if run completed");
    println!("CONFLICT ROLLBACK: PASS if conflict runs completed without invariant failure");
    println!("DISTRIBUTED ATOMICITY PROVEN: NO");
    println!("NETWORK TPS PROVEN: NO");

    let _meta = rows.iter().fold((0u64, 0.0f64), |acc, r| {
        (acc.0 ^ r.checksum, acc.1 + r.elapsed_s)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microbatch_no_conflict_preserves_value() {
        let r = run_case(20_000, 4, 4, 256, 0, 1024);
        assert_eq!(r.committed, 20_000);
        assert_eq!(r.aborted, 0);
        assert!(r.commit_tps > 0.0);
    }

    #[test]
    fn microbatch_conflict_rolls_back_safely() {
        let r = run_case(20_000, 4, 4, 256, 20, 512);
        assert!(r.committed > 0);
        assert!(r.aborted > 0);
        assert_eq!(r.committed + r.aborted, 20_000);
    }

    #[test]
    fn tiny_batches_run() {
        let r = run_case(10_000, 2, 4, 256, 0, 64);
        assert_eq!(r.committed, 10_000);
        assert!(r.p95_us > 0.0);
    }
}
