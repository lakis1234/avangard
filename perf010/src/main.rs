use std::collections::HashMap;
use std::env;
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

const VALUE: u64 = 100;
const MAGIC: u64 = 0xCA11_BAEA_0000_0010;
const MAX_ARITY: usize = 8;
const MIN_RECORD: usize = 96;
const SERIAL_MASK: u64 = (1u64 << 48) - 1;

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
    (mix64(serial ^ 0xA11C_E001_5EED_0010) as usize) & (shards - 1)
}

#[inline(always)]
fn canonical_input_id_from_route(serial: u64, shard: usize, shard_bits: u32) -> u64 {
    make_id(serial + 1, shard, shard_bits)
}

#[inline(always)]
fn referenced_serial(tx: u64, k: usize, arity: usize, conflict_pct: u32) -> u64 {
    let own = tx * arity as u64 + k as u64;
    if conflict_pct > 0
        && tx > 0
        && k == 0
        && (mix64(tx ^ 0xC0AF_11C7_0000_0010) % 100) < conflict_pct as u64
    {
        (tx - 1) * arity as u64
    } else {
        own
    }
}

#[inline(always)]
fn output_shard(tx: u64, shards: usize) -> usize {
    (mix64(tx ^ 0x0A7B_17A5_F00D_0010) as usize) & (shards - 1)
}

#[inline(always)]
fn output_id(tx: u64, shard: usize, shard_bits: u32) -> u64 {
    make_id((1u64 << 48) + tx + 1, shard, shard_bits)
}

#[inline(always)]
fn pack_route(serial: u64, shard: usize) -> u64 {
    assert!(serial <= SERIAL_MASK);
    assert!(shard < (1usize << 16));
    ((shard as u64) << 48) | serial
}

#[inline(always)]
fn unpack_route(route: u64) -> (u64, usize) {
    (route & SERIAL_MASK, (route >> 48) as usize)
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

fn stream_count(total: u64, streams: usize, stream: usize) -> u64 {
    let base = total / streams as u64;
    let extra = total % streams as u64;
    base + if (stream as u64) < extra { 1 } else { 0 }
}

fn stream_has_range(start: u64, end: u64, streams: usize, stream: usize) -> bool {
    if start >= end {
        return false;
    }
    let m = streams as u64;
    let rem = start % m;
    let delta = (stream as u64 + m - rem) % m;
    start + delta < end
}

#[inline(always)]
fn wire_tag(tx: u64, arity: usize, declared_value: u64, inputs: &[u64; MAX_ARITY]) -> u64 {
    let mut x = mix64(tx ^ MAGIC ^ (arity as u64).rotate_left(11) ^ declared_value.rotate_left(23));
    for (k, serial) in inputs.iter().take(arity).enumerate() {
        x = mix64(x ^ serial.rotate_left(((k * 7 + 3) & 63) as u32));
    }
    x
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

struct WireSlot {
    routes: [AtomicU64; MAX_ARITY],
}

impl WireSlot {
    fn new() -> Self {
        Self {
            routes: std::array::from_fn(|_| AtomicU64::new(u64::MAX)),
        }
    }
}

#[derive(Clone)]
struct Row {
    txs: u64,
    arity: usize,
    workers: usize,
    shards: usize,
    conflict_pct: u32,
    batch_size: usize,
    streams: usize,
    record_size: usize,
    elapsed_s: f64,
    attempt_tps: f64,
    commit_tps: f64,
    committed: u64,
    aborted: u64,
    p50_us: f64,
    p95_us: f64,
    p99_us: f64,
    wire_checksum: u64,
    state_checksum: u64,
}

fn run_case(
    txs: u64,
    arity: usize,
    workers: usize,
    shards: usize,
    conflict_pct: u32,
    batch_size: usize,
    streams: usize,
    record_size: usize,
) -> Row {
    assert!(txs > 0);
    assert!((1..=MAX_ARITY).contains(&arity));
    assert!((1..=64).contains(&workers));
    assert!(shards.is_power_of_two());
    assert!(shards >= workers);
    assert!(shards < (1usize << 16));
    assert!(conflict_pct <= 100);
    assert!(batch_size >= streams);
    assert!((1..=32).contains(&streams));
    assert!((MIN_RECORD..=4096).contains(&record_size));
    assert!(txs * arity as u64 <= SERIAL_MASK);

    let shard_bits = shards.trailing_zeros();
    let total_inputs = txs * arity as u64;
    let batches = ((txs as usize) + batch_size - 1) / batch_size;

    // Canonical current state is built before timing. Every shard has exactly one owner worker.
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
        let id = canonical_input_id_from_route(serial, sid, shard_bits);
        assert!(maps_by_worker[owner][slot]
            .insert(
                id,
                Cell {
                    id,
                    value: VALUE,
                    generation: 0,
                },
            )
            .is_none());
    }

    // PERF-010 optimization: receivers compute shard/owner exactly once and publish a packed
    // route plus an 8-bit input mask for the owning execution worker. PERF-009 made every
    // execution worker scan all 8 wire inputs for every transaction and recompute routing.
    let wire_slots: Arc<Vec<WireSlot>> = Arc::new((0..txs).map(|_| WireSlot::new()).collect());
    let owner_masks: Arc<Vec<AtomicU8>> = Arc::new(
        (0..(txs as usize * workers))
            .map(|_| AtomicU8::new(0))
            .collect(),
    );
    let prepared_counts: Arc<Vec<AtomicU8>> =
        Arc::new((0..txs).map(|_| AtomicU8::new(0)).collect());
    let prepared_values: Arc<Vec<AtomicU64>> =
        Arc::new((0..txs).map(|_| AtomicU64::new(0)).collect());

    let expected_streams: Arc<Vec<usize>> = Arc::new(
        (0..batches)
            .map(|b| {
                let start = (b * batch_size) as u64;
                let end = ((b + 1) * batch_size).min(txs as usize) as u64;
                (0..streams)
                    .filter(|&s| stream_has_range(start, end, streams, s))
                    .count()
            })
            .collect(),
    );
    let stream_done: Arc<Vec<AtomicUsize>> =
        Arc::new((0..batches).map(|_| AtomicUsize::new(0)).collect());
    let (batch_ready_tx, batch_ready_rx) = mpsc::channel::<usize>();

    let phase = Arc::new(Barrier::new(workers + 1));
    let mut execution_handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let mut maps = std::mem::take(&mut maps_by_worker[w]);
        let wire_slots = Arc::clone(&wire_slots);
        let owner_masks = Arc::clone(&owner_masks);
        let prepared_counts = Arc::clone(&prepared_counts);
        let prepared_values = Arc::clone(&prepared_values);
        let phase = Arc::clone(&phase);

        execution_handles.push(thread::spawn(move || {
            let mut checksum = 0u64;
            let mut committed = 0u64;
            let mut aborted = 0u64;
            let mut outputs: FastMap = HashMap::with_capacity_and_hasher(
                (txs as usize / workers).saturating_mul(2).saturating_add(32),
                BuildHasherDefault::default(),
            );
            let approx_refs = ((batch_size * arity + workers - 1) / workers).max(16);
            let mut prepared: Vec<(usize, u64, Cell)> = Vec::with_capacity(approx_refs);

            for b in 0..batches {
                let start_tx = b * batch_size;
                let end_tx = ((b + 1) * batch_size).min(txs as usize);
                prepared.clear();

                // Released only after every TCP record in this microbatch has been decoded.
                phase.wait();

                // Owner-mask routed prepare. Each worker performs one mask load per tx, then
                // visits only the input positions that actually belong to it.
                for tx in start_tx as u64..end_tx as u64 {
                    let mut mask = owner_masks[tx as usize * workers + w].load(Ordering::Acquire);
                    while mask != 0 {
                        let k = mask.trailing_zeros() as usize;
                        mask &= mask - 1;
                        let route = wire_slots[tx as usize].routes[k].load(Ordering::Acquire);
                        assert_ne!(route, u64::MAX, "execution saw an unpublished route");
                        let (serial, sid) = unpack_route(route);
                        assert_eq!(sid % workers, w, "owner-mask route mismatch");
                        let slot = sid / workers;
                        let id = canonical_input_id_from_route(serial, sid, shard_bits);
                        if let Some(cell) = maps[slot].remove(&id) {
                            prepared_counts[tx as usize].fetch_add(1, Ordering::Relaxed);
                            prepared_values[tx as usize].fetch_add(cell.value, Ordering::Relaxed);
                            prepared.push((slot, tx, cell));
                        }
                    }
                }

                phase.wait();

                // Same fused atomic finalize path as PERF-007/PERF-009.
                for &(slot, tx, cell) in &prepared {
                    let eligible =
                        prepared_counts[tx as usize].load(Ordering::Relaxed) as usize == arity;
                    if eligible {
                        checksum ^= mix64(cell.id ^ cell.generation ^ cell.value);
                    } else if maps[slot].insert(cell.id, cell).is_some() {
                        panic!("PERF-010 rollback collision");
                    }
                }

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
                            panic!("PERF-010 output collision");
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

    // Real TCP loopback ingress. Stream setup/handshake is excluded from timing.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind PERF-010 loopback listener");
    let addr = listener.local_addr().expect("PERF-010 listener address");
    let ready = Arc::new(Barrier::new(streams * 2 + 1));
    let go = Arc::new(Barrier::new(streams * 2 + 1));

    let receiver_wire_slots = Arc::clone(&wire_slots);
    let receiver_owner_masks = Arc::clone(&owner_masks);
    let receiver_expected_streams = Arc::clone(&expected_streams);
    let receiver_stream_done = Arc::clone(&stream_done);
    let receiver_ready = Arc::clone(&ready);
    let receiver_go = Arc::clone(&go);
    let receiver_batch_tx = batch_ready_tx.clone();

    let receiver_manager = thread::spawn(move || {
        let mut receivers = Vec::with_capacity(streams);
        let mut seen = vec![false; streams];

        for _ in 0..streams {
            let (mut stream, _) = listener.accept().expect("accept PERF-010 loopback stream");
            stream.set_nodelay(true).expect("receiver TCP_NODELAY");

            let mut hello = [0u8; 8];
            stream.read_exact(&mut hello).expect("read PERF-010 stream id");
            let s = u64::from_le_bytes(hello) as usize;
            assert!(s < streams, "invalid PERF-010 stream id");
            assert!(!seen[s], "duplicate PERF-010 stream id");
            seen[s] = true;

            let wire_slots = Arc::clone(&receiver_wire_slots);
            let owner_masks = Arc::clone(&receiver_owner_masks);
            let expected_streams = Arc::clone(&receiver_expected_streams);
            let stream_done = Arc::clone(&receiver_stream_done);
            let ready = Arc::clone(&receiver_ready);
            let go = Arc::clone(&receiver_go);
            let batch_tx = receiver_batch_tx.clone();
            let expected = stream_count(txs, streams, s);

            receivers.push(thread::spawn(move || {
                let mut reader = BufReader::with_capacity(1 << 20, stream);
                let mut record = vec![0u8; record_size];
                let mut checksum = 0u64;
                let mut current_batch: Option<usize> = None;

                let mark_done = |b: usize| {
                    let done = stream_done[b].fetch_add(1, Ordering::AcqRel) + 1;
                    if done == expected_streams[b] {
                        batch_tx.send(b).expect("send PERF-010 batch-ready notification");
                    }
                };

                ready.wait();
                go.wait();

                for i in 0..expected {
                    reader.read_exact(&mut record).expect("read complete PERF-010 record");
                    let tx = u64::from_le_bytes(record[0..8].try_into().unwrap());
                    let tag = u64::from_le_bytes(record[8..16].try_into().unwrap());
                    let expected_tx = s as u64 + i * streams as u64;
                    assert_eq!(tx, expected_tx, "PERF-010 wire tx ordering mismatch");

                    let declared_value = u64::from_le_bytes(record[80..88].try_into().unwrap());
                    let declared_arity = u64::from_le_bytes(record[88..96].try_into().unwrap()) as usize;
                    assert_eq!(declared_arity, arity, "PERF-010 wire arity mismatch");
                    assert_eq!(declared_value, arity as u64 * VALUE, "PERF-010 value mismatch");

                    let mut inputs = [u64::MAX; MAX_ARITY];
                    for k in 0..arity {
                        let off = 16 + k * 8;
                        inputs[k] = u64::from_le_bytes(record[off..off + 8].try_into().unwrap());
                    }
                    assert_eq!(tag, wire_tag(tx, arity, declared_value, &inputs), "PERF-010 integrity mismatch");

                    for (k, serial) in inputs.iter().take(arity).enumerate() {
                        let sid = input_shard(*serial, shards);
                        let owner = sid % workers;
                        let route = pack_route(*serial, sid);
                        wire_slots[tx as usize].routes[k].store(route, Ordering::Release);
                        owner_masks[tx as usize * workers + owner]
                            .fetch_or(1u8 << k, Ordering::AcqRel);
                    }
                    checksum ^= mix64(tx ^ tag ^ record_size as u64);

                    let b = tx as usize / batch_size;
                    if current_batch != Some(b) {
                        if let Some(prev) = current_batch {
                            mark_done(prev);
                        }
                        current_batch = Some(b);
                    }
                }

                if let Some(last) = current_batch {
                    mark_done(last);
                }
                checksum
            }));
        }

        assert!(seen.into_iter().all(|v| v));
        let mut checksum = 0u64;
        for h in receivers {
            checksum ^= h.join().expect("PERF-010 receiver worker panic");
        }
        checksum
    });

    let mut senders = Vec::with_capacity(streams);
    for s in 0..streams {
        let ready = Arc::clone(&ready);
        let go = Arc::clone(&go);
        senders.push(thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect PERF-010 loopback stream");
            stream.set_nodelay(true).expect("sender TCP_NODELAY");
            stream
                .write_all(&(s as u64).to_le_bytes())
                .expect("write PERF-010 stream id");

            let mut writer = BufWriter::with_capacity(1 << 20, stream);
            let mut record = vec![0xA5u8; record_size];
            let count = stream_count(txs, streams, s);

            ready.wait();
            go.wait();

            for i in 0..count {
                let tx = s as u64 + i * streams as u64;
                let mut inputs = [u64::MAX; MAX_ARITY];
                for (k, slot) in inputs.iter_mut().take(arity).enumerate() {
                    *slot = referenced_serial(tx, k, arity, conflict_pct);
                    let off = 16 + k * 8;
                    record[off..off + 8].copy_from_slice(&slot.to_le_bytes());
                }
                let declared_value = arity as u64 * VALUE;
                record[80..88].copy_from_slice(&declared_value.to_le_bytes());
                record[88..96].copy_from_slice(&(arity as u64).to_le_bytes());
                let tag = wire_tag(tx, arity, declared_value, &inputs);
                record[0..8].copy_from_slice(&tx.to_le_bytes());
                record[8..16].copy_from_slice(&tag.to_le_bytes());
                writer.write_all(&record).expect("write complete PERF-010 record");
            }
            writer.flush().expect("flush PERF-010 stream");
        }));
    }

    drop(batch_ready_tx);

    ready.wait();
    let overall = Instant::now();
    go.wait();

    let mut batch_ready_flags = vec![false; batches];
    let mut batch_exec_latencies = Vec::with_capacity(batches);

    for b in 0..batches {
        while !batch_ready_flags[b] {
            let ready_batch = batch_ready_rx
                .recv()
                .expect("PERF-010 batch-ready channel closed early");
            batch_ready_flags[ready_batch] = true;
        }

        // This latency is execution-after-batch-ready, not client-to-finality/WAN latency.
        let exec_start = Instant::now();
        phase.wait();
        phase.wait();
        phase.wait();
        batch_exec_latencies.push(exec_start.elapsed());
    }

    for h in senders {
        h.join().expect("PERF-010 sender worker panic");
    }
    let wire_checksum = receiver_manager
        .join()
        .expect("PERF-010 receiver manager panic");

    let mut committed = 0u64;
    let mut aborted = 0u64;
    let mut state_checksum = 0u64;
    let mut remaining_cells = 0u64;
    let mut remaining_value = 0u128;
    let mut output_cells = 0u64;
    let mut output_value = 0u128;

    for h in execution_handles {
        let (c, a, sum, rc, rv, oc, ov) = h.join().expect("PERF-010 execution worker panic");
        committed += c;
        aborted += a;
        state_checksum ^= sum;
        remaining_cells += rc;
        remaining_value += rv;
        output_cells += oc;
        output_value += ov;
    }

    let elapsed_s = overall.elapsed().as_secs_f64();
    assert_eq!(committed + aborted, txs);
    assert_eq!(output_cells, committed);

    let final_cells = remaining_cells + output_cells;
    let expected_cells = total_inputs - committed * arity as u64 + committed;
    assert_eq!(final_cells, expected_cells);

    let total_value = remaining_value + output_value;
    let expected_value = total_inputs as u128 * VALUE as u128;
    assert_eq!(total_value, expected_value);

    Row {
        txs,
        arity,
        workers,
        shards,
        conflict_pct,
        batch_size,
        streams,
        record_size,
        elapsed_s,
        attempt_tps: txs as f64 / elapsed_s,
        commit_tps: committed as f64 / elapsed_s,
        committed,
        aborted,
        p50_us: quantile_us(&batch_exec_latencies, 0.50),
        p95_us: quantile_us(&batch_exec_latencies, 0.95),
        p99_us: quantile_us(&batch_exec_latencies, 0.99),
        wire_checksum,
        state_checksum,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let txs = parse_list(&args, "--txs", vec![1_000_000u64]);
    let arities = parse_list(&args, "--arities", vec![8usize]);
    let workers = parse_list(&args, "--workers", vec![4usize, 6, 8]);
    let shards = parse_list(&args, "--shards", vec![1024usize]);
    let conflicts = parse_list(&args, "--conflicts", vec![0u32, 10]);
    let batches = parse_list(&args, "--batches", vec![4096usize]);
    let streams = parse_list(&args, "--streams", vec![1usize, 2, 4]);
    let sizes = parse_list(&args, "--sizes", vec![128usize]);

    println!("CALIBRE GEN2 PERF-010 v1.0.0");
    println!("RECEIVER-ROUTED TCP -> OWNER-MASK -> FUSED SHARDED STATE EXECUTION");
    println!("Security: OFF | Consensus: OFF | Persistence: OFF");
    println!("Change vs PERF-009: receiver computes shard/owner once; workers visit only owned input positions");
    println!("Also sweeps worker count to expose CPU budget contention between TCP and execution");
    println!("p95 below is execution-after-batch-ready latency, NOT end-to-end/WAN finality latency");
    println!();

    let mut rows = Vec::new();
    for &n in &txs {
        for &arity in &arities {
            for &s in &shards {
                for &w in &workers {
                    for &conflict in &conflicts {
                        for &batch in &batches {
                            println!(
                                "=== TXS={} ARITY={} SHARDS={} WORKERS={} CONFLICT={}%% BATCH={} ===",
                                n, arity, s, w, conflict, batch
                            );
                            for &size in &sizes {
                                for &stream_count in &streams {
                                    let r = run_case(
                                        n,
                                        arity,
                                        w,
                                        s,
                                        conflict,
                                        batch,
                                        stream_count,
                                        size,
                                    );
                                    println!(
                                        "record={:<4}B streams={:<2} attemptTPS={:>10.0} commitTPS={:>10.0} committed={:<9} aborted={:<8} p50={:>8.1}us p95={:>8.1}us p99={:>8.1}us elapsed={:>7.3}s wire={:016x} state={:016x}",
                                        r.record_size,
                                        r.streams,
                                        r.attempt_tps,
                                        r.commit_tps,
                                        r.committed,
                                        r.aborted,
                                        r.p50_us,
                                        r.p95_us,
                                        r.p99_us,
                                        r.elapsed_s,
                                        r.wire_checksum,
                                        r.state_checksum,
                                    );
                                    rows.push(r);
                                }
                            }
                            println!();
                        }
                    }
                }
            }
        }
    }

    let best = rows
        .iter()
        .filter(|r| r.conflict_pct == 0)
        .max_by(|a, b| a.commit_tps.partial_cmp(&b.commit_tps).unwrap())
        .expect("PERF-010 results");

    println!("=== DECISION ===");
    println!(
        "BEST NO-CONFLICT INTEGRATED COMMIT TPS: {:.0} | workers={} | {} streams | {}B | batch={} | exec-p95={:.1}us",
        best.commit_tps, best.workers, best.streams, best.record_size, best.batch_size, best.p95_us
    );

    if let Some(r) = rows.iter().find(|r| {
        r.txs == 1_000_000
            && r.arity == 8
            && r.shards == 1024
            && r.workers == 8
            && r.conflict_pct == 0
            && r.batch_size == 4096
            && r.streams == 4
            && r.record_size == 128
    }) {
        println!(
            "SAME CONFIG AS PERF-009 / 8W / 4S: {:.0} committed tx/s | exec-p95={:.1}us",
            r.commit_tps, r.p95_us
        );
        println!(
            "SAME-CONFIG >3M TARGET: {}",
            if r.commit_tps >= 3_000_000.0 { "PASS" } else { "NOT YET" }
        );
    }

    let low_latency_best = rows
        .iter()
        .filter(|r| r.conflict_pct == 0 && r.p95_us <= 2_000.0)
        .max_by(|a, b| a.commit_tps.partial_cmp(&b.commit_tps).unwrap());

    if let Some(r) = low_latency_best {
        println!(
            "BEST exec-p95<=2ms: {:.0} committed tx/s | workers={} streams={} | p95={:.1}us",
            r.commit_tps, r.workers, r.streams, r.p95_us
        );
        println!("INTEGRATED >3M TARGET: {}", if r.commit_tps >= 3_000_000.0 { "PASS" } else { "NOT YET" });
        println!("INTEGRATED >4M STRETCH: {}", if r.commit_tps >= 4_000_000.0 { "PASS" } else { "NOT YET" });
        println!("INTEGRATED >5M RESEARCH TARGET: {}", if r.commit_tps >= 5_000_000.0 { "PASS" } else { "NOT YET" });
    }

    println!("WIRE-ROUTING METADATA FEEDS OWNER-LOCAL EXECUTION: YES");
    println!("WIRE ORDER/TAG + MONETARY VALUE/CELL INVARIANTS: PASS if run completed");
    println!("SIGNATURE VERIFICATION INCLUDED: NO");
    println!("DISTRIBUTED CONSENSUS/FINALITY INCLUDED: NO");
    println!("PERSISTENCE INCLUDED: NO");
    println!("PHYSICAL/WAN NETWORK TPS PROVEN: NO");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_pack_round_trip() {
        let route = pack_route(7_654_321, 1023);
        let (serial, shard) = unpack_route(route);
        assert_eq!(serial, 7_654_321);
        assert_eq!(shard, 1023);
    }

    #[test]
    fn integrated_owner_routing_no_conflict() {
        let r = run_case(20_000, 8, 4, 256, 0, 1024, 2, 128);
        assert_eq!(r.committed, 20_000);
        assert_eq!(r.aborted, 0);
        assert!(r.commit_tps > 0.0);
    }

    #[test]
    fn integrated_owner_routing_conflict_rolls_back() {
        let r = run_case(20_000, 8, 4, 256, 10, 1024, 2, 128);
        assert_eq!(r.committed + r.aborted, 20_000);
        assert!(r.aborted > 0);
        assert!(r.commit_tps > 0.0);
    }
}
