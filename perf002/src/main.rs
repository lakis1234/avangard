use std::collections::HashMap;
use std::env;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::{Arc, Barrier};
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
    fn finish(&self) -> u64 { self.0 }
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
fn shard_of(id: u64, shard_mask: u64) -> usize {
    (id & shard_mask) as usize
}

#[inline(always)]
fn successor_id(cell: Cell, serial: u64, shard_bits: u32, shard_mask: u64) -> u64 {
    let shard = shard_of(cell.id, shard_mask) as u64;
    let local = mix64(
        (cell.id >> shard_bits)
            ^ cell.generation.rotate_left(17)
            ^ serial.rotate_left(31)
            ^ cell.value,
    ) >> shard_bits;
    (local << shard_bits) | shard
}

fn parse_list<T: std::str::FromStr>(args: &[String], flag: &str, default: Vec<T>) -> Vec<T> {
    if let Some(i) = args.iter().position(|x| x == flag) {
        if let Some(v) = args.get(i + 1) {
            let out: Vec<T> = v.split(',').filter_map(|x| x.trim().parse::<T>().ok()).collect();
            if !out.is_empty() { return out; }
        }
    }
    default
}

fn run_case(total: u64, workers: usize, shards: usize) -> (f64, u64) {
    assert!(workers >= 1);
    assert!(shards.is_power_of_two());
    assert!(shards >= workers);

    let shard_bits = shards.trailing_zeros();
    let shard_mask = shards as u64 - 1;
    let barrier = Arc::new(Barrier::new(workers + 1));
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let owned: Vec<usize> = (w..shards).step_by(workers).collect();
            let mut maps: Vec<FastMap> = owned
                .iter()
                .map(|_| HashMap::with_capacity_and_hasher(
                    ((total as usize / shards).saturating_mul(2)).max(8),
                    BuildHasherDefault::default(),
                ))
                .collect();
            let mut ids: Vec<Vec<u64>> = owned.iter().map(|_| Vec::new()).collect();

            for serial in (w as u64..total).step_by(workers) {
                let shard = (serial as usize) & (shards - 1);
                let owner_slot = shard / workers;
                let local = serial / shards as u64 + 1;
                let id = make_id(local, shard, shard_bits);
                let cell = Cell { id, value: VALUE, generation: 0 };
                maps[owner_slot].insert(id, cell);
                ids[owner_slot].push(id);
            }

            b.wait();

            let mut checksum = 0u64;
            let mut processed = 0u64;
            for (slot, input_ids) in ids.into_iter().enumerate() {
                let map = &mut maps[slot];
                for (serial, input_id) in input_ids.into_iter().enumerate() {
                    let old = map.remove(&input_id).expect("current input missing");
                    let next = Cell {
                        id: successor_id(old, serial as u64, shard_bits, shard_mask),
                        value: old.value,
                        generation: old.generation + 1,
                    };
                    if map.insert(next.id, next).is_some() {
                        panic!("unexpected successor collision");
                    }
                    checksum ^= mix64(next.id ^ next.generation ^ next.value);
                    processed += 1;
                }
            }

            let final_cells: usize = maps.iter().map(|m| m.len()).sum();
            assert_eq!(final_cells as u64, processed);
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
    let elapsed = start.elapsed().as_secs_f64();
    assert_eq!(processed, total);
    (total as f64 / elapsed, checksum)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let full = args.iter().any(|x| x == "--full");
    let huge = args.iter().any(|x| x == "--huge");

    let workers = parse_list(&args, "--workers", vec![1usize, 2, 4, 8, 16]);
    let shards = parse_list(&args, "--shards", vec![64usize, 256, 1024, 4096]);
    let mut sizes: Vec<u64> = if full { vec![1_000_000, 5_000_000, 10_000_000] } else { vec![1_000_000] };
    if huge { sizes.push(50_000_000); }

    println!("CALIBRE GEN2 PERF-002 v0.2.0");
    println!("SHARDED NATIVE CURRENT-STATE ENGINE");
    println!("Security: OFF | Consensus: OFF | Persistence: OFF | Network: OFF");
    println!("Goal: measure shard-local ownership, cache/locality and worker scaling");
    println!();

    let mut best = 0.0f64;
    let mut best_cfg = (0u64, 0usize, 0usize);

    for &n in &sizes {
        println!("=== N={} ===", n);
        for &s in &shards {
            for &w in &workers {
                if w > s { continue; }
                let (tps, checksum) = run_case(n, w, s);
                println!("shards={:<5} workers={:<3} TPS={:>15.0} checksum={:016x}", s, w, tps, checksum);
                if tps > best {
                    best = tps;
                    best_cfg = (n, s, w);
                }
            }
        }
        println!();
    }

    println!("=== DECISION ===");
    println!("BEST SHARDED HASH TPS: {:.0}", best);
    println!("BEST CONFIG: N={} shards={} workers={}", best_cfg.0, best_cfg.1, best_cfg.2);
    println!("1M TARGET: {}", if best >= 1_000_000.0 { "PASS" } else { "FAIL" });
    println!("5M STRETCH: {}", if best >= 5_000_000.0 { "PASS" } else { "FAIL" });
    println!("20M RESEARCH TARGET: {}", if best >= 20_000_000.0 { "PASS" } else { "NOT YET" });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_preserved() {
        let shards = 256usize;
        let bits = shards.trailing_zeros();
        let mask = shards as u64 - 1;
        let c = Cell { id: make_id(123, 77, bits), value: VALUE, generation: 9 };
        assert_eq!(shard_of(successor_id(c, 5, bits, mask), mask), 77);
    }

    #[test]
    fn sharded_engine_preserves_count() {
        let (tps, _) = run_case(100_000, 4, 256);
        assert!(tps > 0.0);
    }
}
