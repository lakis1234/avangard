use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{BufWriter, Write};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Instant;

const VALUE: u64 = 100;
const HOT_TAG: u64 = 0xC411_BRE5_0000_0001u64;

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
    fn write_u64(&mut self, i: u64) { self.0 = mix64(i); }

    #[inline(always)]
    fn finish(&self) -> u64 { self.0 }
}

type FastMap = HashMap<u64, Cell, BuildHasherDefault<U64Hasher>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode { SharedAccount, IndependentReceive }

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::SharedAccount => "ACCOUNT",
            Mode::IndependentReceive => "OUTPUT",
        }
    }
}

#[derive(Default)]
struct HotAccount {
    generation: u64,
    received: u64,
}

#[derive(Clone)]
struct Row {
    mode: Mode,
    total: u64,
    shards: usize,
    workers: usize,
    hot_pct: u32,
    elapsed_s: f64,
    tps: f64,
    hot_ops: u64,
    checksum: u64,
}

#[inline(always)]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[inline(always)]
fn is_hot(serial: u64, hot_pct: u32) -> bool {
    if hot_pct == 0 { return false; }
    (mix64(serial ^ 0x9e37_79b9_7f4a_7c15) % 100) < hot_pct as u64
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

fn parse_modes(args: &[String]) -> Vec<Mode> {
    if let Some(i) = args.iter().position(|x| x == "--modes") {
        if let Some(v) = args.get(i + 1) {
            let mut out = Vec::new();
            for m in v.split(',') {
                match m.trim().to_ascii_lowercase().as_str() {
                    "account" => out.push(Mode::SharedAccount),
                    "output" => out.push(Mode::IndependentReceive),
                    _ => {}
                }
            }
            if !out.is_empty() { return out; }
        }
    }
    vec![Mode::SharedAccount, Mode::IndependentReceive]
}

fn run_case(mode: Mode, total: u64, workers: usize, shards: usize, hot_pct: u32) -> Row {
    assert!(workers >= 1);
    assert!(shards.is_power_of_two());
    assert!(shards >= workers);
    assert_eq!(shards % workers, 0);
    assert!(hot_pct <= 100);

    let shard_bits = shards.trailing_zeros();
    let shard_mask = shards as u64 - 1;
    let barrier = Arc::new(Barrier::new(workers + 1));
    let hot_account = Arc::new(Mutex::new(HotAccount::default()));
    let mut handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let b = Arc::clone(&barrier);
        let account = Arc::clone(&hot_account);
        handles.push(thread::spawn(move || {
            let owned: Vec<usize> = (w..shards).step_by(workers).collect();
            let per_shard = (total as usize / shards).saturating_add(2);
            let mut maps: Vec<FastMap> = owned
                .iter()
                .map(|_| HashMap::with_capacity_and_hasher(
                    per_shard.saturating_mul(2).max(8),
                    BuildHasherDefault::default(),
                ))
                .collect();
            let mut ids: Vec<Vec<(u64, u64)>> = owned.iter().map(|_| Vec::new()).collect();

            for serial in (w as u64..total).step_by(workers) {
                let shard = (serial as usize) & (shards - 1);
                let owner_slot = shard / workers;
                let local = serial / shards as u64 + 1;
                let id = make_id(local, shard, shard_bits);
                maps[owner_slot].insert(id, Cell { id, value: VALUE, generation: 0 });
                ids[owner_slot].push((serial, id));
            }

            b.wait();

            let mut checksum = 0u64;
            let mut processed = 0u64;
            let mut hot_ops = 0u64;

            for (slot, input_ids) in ids.into_iter().enumerate() {
                let map = &mut maps[slot];
                for (serial, input_id) in input_ids {
                    let old = map.remove(&input_id).expect("current input missing");
                    let next = Cell {
                        id: successor_id(old, serial, shard_bits, shard_mask),
                        value: old.value,
                        generation: old.generation + 1,
                    };
                    if map.insert(next.id, next).is_some() {
                        panic!("unexpected successor collision");
                    }

                    let hot = is_hot(serial, hot_pct);
                    let recipient_tag = if hot { HOT_TAG } else { mix64(serial ^ 0xA11C_E001) };
                    checksum ^= mix64(next.id ^ next.generation ^ next.value ^ recipient_tag);

                    if hot {
                        hot_ops += 1;
                        if mode == Mode::SharedAccount {
                            let mut h = account.lock().expect("hot account mutex poisoned");
                            h.generation = h.generation.wrapping_add(1);
                            h.received = h.received.wrapping_add(1);
                        } else {
                            checksum ^= mix64(serial ^ HOT_TAG ^ 0x0B1E_C700);
                        }
                    }
                    processed += 1;
                }
            }

            let final_cells: usize = maps.iter().map(|m| m.len()).sum();
            assert_eq!(final_cells as u64, processed);
            (checksum, processed, hot_ops)
        }));
    }

    let start = Instant::now();
    barrier.wait();

    let mut checksum = 0u64;
    let mut processed = 0u64;
    let mut hot_ops = 0u64;
    for h in handles {
        let (c, p, hot) = h.join().expect("worker panic");
        checksum ^= c;
        processed += p;
        hot_ops += hot;
    }
    let elapsed_s = start.elapsed().as_secs_f64();
    assert_eq!(processed, total);

    if mode == Mode::SharedAccount {
        let h = hot_account.lock().expect("hot account mutex poisoned");
        assert_eq!(h.generation, hot_ops);
        assert_eq!(h.received, hot_ops);
    }

    Row {
        mode,
        total,
        shards,
        workers,
        hot_pct,
        elapsed_s,
        tps: total as f64 / elapsed_s,
        hot_ops,
        checksum,
    }
}

fn find_row<'a>(rows: &'a [Row], mode: Mode, total: u64, shards: usize, workers: usize, hot_pct: u32) -> Option<&'a Row> {
    rows.iter().find(|r| r.mode == mode && r.total == total && r.shards == shards && r.workers == workers && r.hot_pct == hot_pct)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let full = args.iter().any(|x| x == "--full");
    let huge = args.iter().any(|x| x == "--huge");

    let workers = parse_list(&args, "--workers", vec![1usize, 2, 4, 8, 16]);
    let shards = parse_list(&args, "--shards", vec![256usize, 1024]);
    let hotspots = parse_list(&args, "--hotspots", vec![0u32, 1, 10, 50]);
    let modes = parse_modes(&args);
    let sizes: Vec<u64> = if huge {
        vec![50_000_000]
    } else if full {
        vec![10_000_000]
    } else {
        vec![1_000_000]
    };

    println!("CALIBRE GEN2 PERF-003 v0.3.0");
    println!("HOTSPOT / CONFLICT-DOMAIN SCALING");
    println!("Security: OFF | Consensus: OFF | Persistence: OFF | Network: OFF");
    println!("ACCOUNT = hot recipient mutates one shared serialized account state");
    println!("OUTPUT  = hot recipient receives independent outputs; no shared recipient mutation");
    println!();

    let mut rows = Vec::new();

    for &n in &sizes {
        println!("=== N={} ===", n);
        for &mode in &modes {
            println!("--- MODE={} ---", mode.name());
            for &hot in &hotspots {
                for &s in &shards {
                    for &w in &workers {
                        if w > s || s % w != 0 { continue; }
                        let r = run_case(mode, n, w, s, hot);
                        println!(
                            "hot={:>2}% shards={:<5} workers={:<3} TPS={:>15.0} hot_ops={:<10} checksum={:016x}",
                            hot, s, w, r.tps, r.hot_ops, r.checksum
                        );
                        rows.push(r);
                    }
                }
                println!();
            }
        }
    }

    let file = File::create("perf003-results.csv").expect("create CSV");
    let mut out = BufWriter::new(file);
    writeln!(out, "mode,total,shards,workers,hot_pct,elapsed_s,tps,hot_ops,checksum").unwrap();
    for r in &rows {
        writeln!(
            out,
            "{},{},{},{},{},{:.9},{:.3},{},{:016x}",
            r.mode.name(), r.total, r.shards, r.workers, r.hot_pct, r.elapsed_s, r.tps, r.hot_ops, r.checksum
        ).unwrap();
    }

    println!("=== DECISION ===");
    let best = rows.iter().max_by(|a, b| a.tps.partial_cmp(&b.tps).unwrap()).expect("results");
    println!("BEST TPS: {:.0} mode={} N={} hot={}%% shards={} workers={}", best.tps, best.mode.name(), best.total, best.hot_pct, best.shards, best.workers);

    let ref_total = sizes[0];
    if let (Some(o0), Some(o50)) = (
        find_row(&rows, Mode::IndependentReceive, ref_total, 1024, 8, 0),
        find_row(&rows, Mode::IndependentReceive, ref_total, 1024, 8, 50),
    ) {
        let retention = 100.0 * o50.tps / o0.tps;
        println!("OUTPUT 1024/8 HOT50 RETENTION: {:.1}%", retention);
        println!("HOT-RECEIVER INDEPENDENCE: {}", if retention >= 70.0 { "PASS" } else { "DEGRADED" });
    }
    if let (Some(a0), Some(a50), Some(o50)) = (
        find_row(&rows, Mode::SharedAccount, ref_total, 1024, 8, 0),
        find_row(&rows, Mode::SharedAccount, ref_total, 1024, 8, 50),
        find_row(&rows, Mode::IndependentReceive, ref_total, 1024, 8, 50),
    ) {
        let retention = 100.0 * a50.tps / a0.tps;
        println!("ACCOUNT 1024/8 HOT50 RETENTION: {:.1}%", retention);
        println!("OUTPUT-vs-ACCOUNT HOT50 SPEEDUP: {:.2}x", o50.tps / a50.tps);
        println!("SHARED-ACCOUNT HOTSPOT BOTTLENECK: {}", if a50.tps < o50.tps { "OBSERVED" } else { "NOT OBSERVED" });
    }
    println!("CORRECTNESS: PASS if run completed (cell count preserved; shared hot generation == hot op count)");
    println!("NETWORK TPS PROVEN: NO");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_preserved() {
        let shards = 1024usize;
        let bits = shards.trailing_zeros();
        let mask = shards as u64 - 1;
        let c = Cell { id: make_id(123, 777, bits), value: VALUE, generation: 9 };
        assert_eq!(shard_of(successor_id(c, 5, bits, mask), mask), 777);
    }

    #[test]
    fn account_hot_count_is_safe() {
        let r = run_case(Mode::SharedAccount, 100_000, 8, 256, 50);
        assert_eq!(r.total, 100_000);
        assert!(r.hot_ops > 40_000 && r.hot_ops < 60_000);
        assert!(r.tps > 0.0);
    }

    #[test]
    fn output_hot_receiver_runs_without_shared_account() {
        let r = run_case(Mode::IndependentReceive, 100_000, 8, 256, 50);
        assert_eq!(r.total, 100_000);
        assert!(r.hot_ops > 40_000 && r.hot_ops < 60_000);
        assert!(r.tps > 0.0);
    }
}
