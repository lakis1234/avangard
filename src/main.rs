use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{BufWriter, Write};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

const VALUE: u64 = 100;
const SHARD_BITS: u32 = 8;
const SHARD_MASK: u64 = (1u64 << SHARD_BITS) - 1;

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
fn make_id(local: u64, shard: u64) -> u64 {
    (local << SHARD_BITS) | (shard & SHARD_MASK)
}

#[inline(always)]
fn shard_of(id: u64) -> u64 {
    id & SHARD_MASK
}

#[inline(always)]
fn successor_id(cell: Cell, serial: u64) -> u64 {
    let shard = shard_of(cell.id);
    let local = mix64(
        (cell.id >> SHARD_BITS)
            ^ cell.generation.rotate_left(17)
            ^ serial.rotate_left(31)
            ^ cell.value,
    ) >> SHARD_BITS;
    make_id(local, shard)
}

#[derive(Clone)]
struct Row {
    engine: &'static str,
    transitions: u64,
    workers: usize,
    elapsed_s: f64,
    tps: f64,
    checksum: u64,
    final_cells: u64,
}

fn dense_worker(worker: usize, n: u64, barrier: Arc<Barrier>) -> (u64, u64) {
    let shard = worker as u64 & SHARD_MASK;
    let mut cells = Vec::with_capacity(n as usize);

    for i in 0..n {
        cells.push(Cell {
            id: make_id(i + 1, shard),
            value: VALUE,
            generation: 0,
        });
    }

    barrier.wait();

    let mut checksum = 0u64;
    for (serial, cell) in cells.iter_mut().enumerate() {
        let old = *cell;
        let next = Cell {
            id: successor_id(old, serial as u64),
            value: old.value,
            generation: old.generation + 1,
        };
        *cell = next;
        checksum ^= mix64(next.id ^ next.generation ^ next.value);
    }

    assert_eq!(cells.len() as u64, n);
    (checksum, cells.len() as u64)
}

fn hash_worker(worker: usize, n: u64, barrier: Arc<Barrier>) -> (u64, u64) {
    let shard = worker as u64 & SHARD_MASK;
    let mut state: FastMap = HashMap::with_capacity_and_hasher(
        (n as usize).saturating_mul(2) + 1,
        BuildHasherDefault::default(),
    );

    let mut ids = Vec::with_capacity(n as usize);

    for i in 0..n {
        let id = make_id(i + 1, shard);
        state.insert(
            id,
            Cell {
                id,
                value: VALUE,
                generation: 0,
            },
        );
        ids.push(id);
    }

    barrier.wait();

    let mut checksum = 0u64;

    for (serial, input_id) in ids.into_iter().enumerate() {
        let old = state.remove(&input_id).expect("current input missing");
        let next = Cell {
            id: successor_id(old, serial as u64),
            value: old.value,
            generation: old.generation + 1,
        };

        checksum ^= mix64(next.id ^ next.generation ^ next.value);

        if state.insert(next.id, next).is_some() {
            panic!("unexpected successor collision");
        }
    }

    assert_eq!(state.len() as u64, n);
    (checksum, state.len() as u64)
}

fn run_case(engine: &'static str, total: u64, workers: usize) -> Row {
    assert!(workers >= 1 && workers <= 256);

    let base = total / workers as u64;
    let extra = total % workers as u64;
    let barrier = Arc::new(Barrier::new(workers + 1));
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let n = base + if (w as u64) < extra { 1 } else { 0 };
        let b = Arc::clone(&barrier);

        handles.push(thread::spawn(move || match engine {
            "dense" => dense_worker(w, n, b),
            "hash" => hash_worker(w, n, b),
            _ => unreachable!(),
        }));
    }

    let start = Instant::now();
    barrier.wait();

    let mut checksum = 0u64;
    let mut final_cells = 0u64;

    for h in handles {
        let (c, n) = h.join().expect("worker panic");
        checksum ^= c;
        final_cells += n;
    }

    let elapsed_s = start.elapsed().as_secs_f64();
    assert_eq!(final_cells, total);

    Row {
        engine,
        transitions: total,
        workers,
        elapsed_s,
        tps: total as f64 / elapsed_s,
        checksum,
        final_cells,
    }
}

fn parse_workers(v: &str) -> Vec<usize> {
    v.split(',')
        .filter_map(|x| x.trim().parse::<usize>().ok())
        .filter(|x| *x >= 1 && *x <= 256)
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let full = args.iter().any(|x| x == "--full");

    let mut workers = vec![1usize, 2, 4, 8, 16];
    if let Some(i) = args.iter().position(|x| x == "--workers") {
        if let Some(v) = args.get(i + 1) {
            let p = parse_workers(v);
            if !p.is_empty() {
                workers = p;
            }
        }
    }

    let sizes: Vec<u64> = if full {
        vec![100_000, 1_000_000, 5_000_000, 10_000_000]
    } else {
        vec![100_000, 1_000_000]
    };

    println!("CALIBRE GEN2 PERF-001 v0.2.0");
    println!("RAW NATIVE RUST MONETARY ENGINE");
    println!("Security: OFF");
    println!("Consensus: OFF");
    println!("Persistence: OFF");
    println!("Network: OFF");
    println!("Blocks: NONE");
    println!("DAG: NONE");
    println!();

    let mut rows = Vec::new();

    for engine in ["dense", "hash"] {
        println!("=== ENGINE: {} ===", engine.to_uppercase());

        for &n in &sizes {
            for &w in &workers {
                let r = run_case(engine, n, w);
                println!(
                    "N={:<10} workers={:<3} elapsed={:>8.5}s TPS={:>15.0} checksum={:016x}",
                    r.transitions, r.workers, r.elapsed_s, r.tps, r.checksum
                );
                rows.push(r);
            }
            println!();
        }
    }

    let file = File::create("perf001-results.csv").expect("create CSV");
    let mut out = BufWriter::new(file);
    writeln!(
        out,
        "engine,total_transitions,workers,elapsed_s,tps,checksum,final_cells"
    )
    .unwrap();

    for r in &rows {
        writeln!(
            out,
            "{},{},{},{:.9},{:.3},{:016x},{}",
            r.engine,
            r.transitions,
            r.workers,
            r.elapsed_s,
            r.tps,
            r.checksum,
            r.final_cells
        )
        .unwrap();
    }

    let hash_peak = rows
        .iter()
        .filter(|r| r.engine == "hash")
        .max_by(|a, b| a.tps.partial_cmp(&b.tps).unwrap())
        .expect("hash results");

    let dense_peak = rows
        .iter()
        .filter(|r| r.engine == "dense")
        .max_by(|a, b| a.tps.partial_cmp(&b.tps).unwrap())
        .expect("dense results");

    println!("=== DECISION ===");
    println!("DENSE UPPER-BOUND PEAK: {:.0} transitions/s", dense_peak.tps);
    println!("HASH STATE ENGINE PEAK: {:.0} transitions/s", hash_peak.tps);

    if hash_peak.tps >= 100_000.0 {
        println!("MINIMUM FLOOR: PASS (>100k)");
    } else {
        println!("MINIMUM FLOOR: FAIL (<100k)");
    }

    if hash_peak.tps >= 1_000_000.0 {
        println!("PERF-001 TARGET: PASS (>1M)");
    } else {
        println!("PERF-001 TARGET: FAIL / REDESIGN NEEDED (<1M)");
    }

    if hash_peak.tps >= 5_000_000.0 {
        println!("PERF-001 STRETCH: PASS (>5M)");
    } else {
        println!("PERF-001 STRETCH: NOT YET (<5M)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successor_preserves_shard() {
        let c = Cell {
            id: make_id(123, 77),
            value: VALUE,
            generation: 5,
        };
        assert_eq!(shard_of(successor_id(c, 9)), 77);
    }

    #[test]
    fn dense_preserves_cell_count() {
        let r = run_case("dense", 20_000, 4);
        assert_eq!(r.final_cells, 20_000);
        assert!(r.tps > 0.0);
    }

    #[test]
    fn hash_preserves_cell_count() {
        let r = run_case("hash", 20_000, 4);
        assert_eq!(r.final_cells, 20_000);
        assert!(r.tps > 0.0);
    }
}
