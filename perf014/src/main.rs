use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::env;
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{BufReader, BufWriter, Read, Write};
use std::mem::MaybeUninit;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

const VALUE: u64 = 100;
const MAGIC: u64 = 0xCA11_BAEE_0000_0014;
const MAX_ARITY: usize = 8;
const MIN_RECORD: usize = 96;

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
fn make_id(local: u64, shard: usize, bits: u32) -> u64 {
    (local << bits) | shard as u64
}

#[inline(always)]
fn input_shard(serial: u64, shards: usize) -> usize {
    (mix64(serial ^ 0xA11C_E001_5EED_0014) as usize) & (shards - 1)
}

#[inline(always)]
fn canonical_input_id(serial: u64, shard: usize, bits: u32) -> u64 {
    make_id(serial + 1, shard, bits)
}

#[inline(always)]
fn output_shard(tx: u64, shards: usize) -> usize {
    (mix64(tx ^ 0x0A7B_17A5_F00D_0014) as usize) & (shards - 1)
}

#[inline(always)]
fn output_id(tx: u64, shard: usize, bits: u32) -> u64 {
    make_id((1u64 << 48) + tx + 1, shard, bits)
}

#[inline(always)]
fn referenced_serial(tx: u64, k: usize, arity: usize, conflict_pct: u32) -> u64 {
    let own = tx * arity as u64 + k as u64;
    if conflict_pct > 0
        && tx > 0
        && k == 0
        && (mix64(tx ^ 0xC0AF_11C7_0000_0014) % 100) < conflict_pct as u64
    {
        (tx - 1) * arity as u64
    } else {
        own
    }
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
fn wire_tag(tx: u64, arity: usize, value: u64, inputs: &[u64; MAX_ARITY]) -> u64 {
    let mut x = mix64(tx ^ MAGIC ^ (arity as u64).rotate_left(11) ^ value.rotate_left(23));
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

#[derive(Clone, Copy)]
struct WorkItem {
    tx: u64,
    slot: usize,
    id: u64,
}

// One producer (one TCP stream) and one consumer (one execution worker) own each lane.
// Slots are append-only for the whole benchmark. The producer publishes a batch range with
// Release stores; the consumer reads it only after a coordinator start token and Acquire loads.
struct Lane {
    slots: Box<[UnsafeCell<MaybeUninit<WorkItem>>]>,
    starts: Vec<AtomicUsize>,
    ends: Vec<AtomicUsize>,
}

unsafe impl Sync for Lane {}

impl Lane {
    fn new(capacity: usize, batches: usize) -> Self {
        let slots: Vec<UnsafeCell<MaybeUninit<WorkItem>>> = (0..capacity)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect();
        Self {
            slots: slots.into_boxed_slice(),
            starts: (0..batches).map(|_| AtomicUsize::new(0)).collect(),
            ends: (0..batches).map(|_| AtomicUsize::new(0)).collect(),
        }
    }

    #[inline(always)]
    fn write(&self, index: usize, item: WorkItem) {
        assert!(index < self.slots.len(), "PERF-014 lane capacity exceeded");
        let ptr = self.slots[index].get();
        unsafe {
            (*ptr).write(item);
        }
    }

    #[inline(always)]
    fn publish(&self, batch: usize, start: usize, end: usize) {
        self.starts[batch].store(start, Ordering::Relaxed);
        self.ends[batch].store(end, Ordering::Release);
    }

    #[inline(always)]
    fn range(&self, batch: usize) -> (usize, usize) {
        let end = self.ends[batch].load(Ordering::Acquire);
        let start = self.starts[batch].load(Ordering::Relaxed);
        (start, end)
    }

    #[inline(always)]
    fn read(&self, index: usize) -> WorkItem {
        let ptr = self.slots[index].get();
        unsafe { *(*ptr).assume_init_ref() }
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
    assert!(shards.is_power_of_two() && shards >= workers);
    assert!(conflict_pct <= 100);
    assert!(batch_size >= streams);
    assert!((1..=32).contains(&streams));
    assert!((MIN_RECORD..=4096).contains(&record_size));

    let bits = shards.trailing_zeros();
    let total_inputs = txs * arity as u64;
    let batches = ((txs as usize) + batch_size - 1) / batch_size;

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
        let id = canonical_input_id(serial, sid, bits);
        assert!(maps_by_worker[owner][slot]
            .insert(id, Cell { id, value: VALUE, generation: 0 })
            .is_none());
    }

    // Exact capacities are computed outside timing only to size memory. Actual routing still comes
    // from decoded wire input references during the measured run.
    let mut lane_caps = vec![0usize; streams * workers];
    for tx in 0..txs {
        let s = tx as usize % streams;
        for k in 0..arity {
            let serial = referenced_serial(tx, k, arity, conflict_pct);
            let owner = input_shard(serial, shards) % workers;
            lane_caps[s * workers + owner] += 1;
        }
    }
    assert_eq!(lane_caps.iter().sum::<usize>(), total_inputs as usize);
    let lanes: Arc<Vec<Lane>> = Arc::new(
        lane_caps
            .iter()
            .map(|&cap| Lane::new(cap, batches))
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

    let mut start_txs = Vec::with_capacity(workers);
    let mut start_rxs = Vec::with_capacity(workers);
    for _ in 0..workers {
        let (tx, rx) = mpsc::sync_channel::<usize>(1);
        start_txs.push(tx);
        start_rxs.push(Some(rx));
    }

    let prepare_barrier = Arc::new(Barrier::new(workers));
    let (done_tx, done_rx) = mpsc::channel::<(usize, usize)>();
    let mut execution_handles = Vec::with_capacity(workers);

    for w in 0..workers {
        let start_rx = start_rxs[w].take().unwrap();
        let mut maps = std::mem::take(&mut maps_by_worker[w]);
        let lanes = Arc::clone(&lanes);
        let prepared_counts = Arc::clone(&prepared_counts);
        let prepared_values = Arc::clone(&prepared_values);
        let prepare_barrier = Arc::clone(&prepare_barrier);
        let done_tx = done_tx.clone();

        execution_handles.push(thread::spawn(move || {
            let mut checksum = 0u64;
            let mut committed = 0u64;
            let mut aborted = 0u64;
            let mut route_items_seen = 0u64;
            let mut outputs: FastMap = HashMap::with_capacity_and_hasher(
                (txs as usize / workers).saturating_mul(2).saturating_add(32),
                BuildHasherDefault::default(),
            );
            let mut prepared: Vec<(usize, u64, Cell)> = Vec::with_capacity(
                ((batch_size * arity + workers - 1) / workers).max(16),
            );

            for b in 0..batches {
                let token = start_rx.recv().expect("PERF-014 start channel closed early");
                assert_eq!(token, b, "PERF-014 unexpected start token");
                prepared.clear();

                for s in 0..streams {
                    let lane = &lanes[s * workers + w];
                    let (start, end) = lane.range(b);
                    for idx in start..end {
                        let item = lane.read(idx);
                        route_items_seen += 1;
                        if let Some(cell) = maps[item.slot].remove(&item.id) {
                            prepared_counts[item.tx as usize].fetch_add(1, Ordering::Relaxed);
                            prepared_values[item.tx as usize].fetch_add(cell.value, Ordering::Relaxed);
                            prepared.push((item.slot, item.tx, cell));
                        }
                    }
                }

                prepare_barrier.wait();

                for &(slot, tx, cell) in &prepared {
                    let eligible =
                        prepared_counts[tx as usize].load(Ordering::Relaxed) as usize == arity;
                    if eligible {
                        checksum ^= mix64(cell.id ^ cell.generation ^ cell.value);
                    } else if maps[slot].insert(cell.id, cell).is_some() {
                        panic!("PERF-014 rollback collision");
                    }
                }

                let start_tx = (b * batch_size) as u64;
                let end_tx = ((b + 1) * batch_size).min(txs as usize) as u64;
                for tx in (start_tx + w as u64..end_tx).step_by(workers) {
                    let eligible =
                        prepared_counts[tx as usize].load(Ordering::Relaxed) as usize == arity;
                    if eligible {
                        let value = prepared_values[tx as usize].load(Ordering::Relaxed);
                        assert_eq!(value, arity as u64 * VALUE);
                        let sid = output_shard(tx, shards);
                        let id = output_id(tx, sid, bits);
                        let next = Cell { id, value, generation: 1 };
                        if outputs.insert(id, next).is_some() {
                            panic!("PERF-014 output collision");
                        }
                        checksum ^= mix64(next.id ^ next.value ^ next.generation);
                        committed += 1;
                    } else {
                        aborted += 1;
                    }
                }

                done_tx.send((b, w)).expect("PERF-014 done channel closed");
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
                route_items_seen,
            )
        }));
    }
    drop(done_tx);

    let stream_done: Arc<Vec<AtomicUsize>> =
        Arc::new((0..batches).map(|_| AtomicUsize::new(0)).collect());
    let (batch_ready_tx, batch_ready_rx) = mpsc::channel::<usize>();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind PERF-014 loopback listener");
    let addr = listener.local_addr().expect("PERF-014 listener address");
    let ready = Arc::new(Barrier::new(streams * 2 + 1));
    let go = Arc::new(Barrier::new(streams * 2 + 1));

    let rr = Arc::clone(&ready);
    let rg = Arc::clone(&go);
    let rsd = Arc::clone(&stream_done);
    let res = Arc::clone(&expected_streams);
    let rbr = batch_ready_tx.clone();
    let rlanes = Arc::clone(&lanes);

    let receiver_manager = thread::spawn(move || {
        let mut receivers = Vec::with_capacity(streams);
        let mut seen = vec![false; streams];

        for _ in 0..streams {
            let (mut stream, _) = listener.accept().expect("accept PERF-014 stream");
            stream.set_nodelay(true).expect("receiver TCP_NODELAY");
            let mut hello = [0u8; 8];
            stream.read_exact(&mut hello).expect("read PERF-014 stream id");
            let s = u64::from_le_bytes(hello) as usize;
            assert!(s < streams && !seen[s]);
            seen[s] = true;

            let ready = Arc::clone(&rr);
            let go = Arc::clone(&rg);
            let stream_done = Arc::clone(&rsd);
            let expected_streams = Arc::clone(&res);
            let batch_ready_tx = rbr.clone();
            let lanes = Arc::clone(&rlanes);
            let expected = stream_count(txs, streams, s);

            receivers.push(thread::spawn(move || {
                let mut reader = BufReader::with_capacity(1 << 20, stream);
                let mut record = vec![0u8; record_size];
                let mut checksum = 0u64;
                let mut routed_inputs = 0u64;
                let mut current_batch: Option<usize> = None;
                let mut cursors = vec![0usize; workers];
                let mut batch_starts = vec![0usize; workers];

                let flush_batch = |batch: usize,
                                   cursors: &Vec<usize>,
                                   batch_starts: &mut Vec<usize>| {
                    for w in 0..workers {
                        let lane = &lanes[s * workers + w];
                        lane.publish(batch, batch_starts[w], cursors[w]);
                        batch_starts[w] = cursors[w];
                    }
                    let done = stream_done[batch].fetch_add(1, Ordering::AcqRel) + 1;
                    if done == expected_streams[batch] {
                        batch_ready_tx
                            .send(batch)
                            .expect("send PERF-014 batch-ready notification");
                    }
                };

                ready.wait();
                go.wait();

                for i in 0..expected {
                    reader.read_exact(&mut record).expect("read complete PERF-014 record");
                    let tx = u64::from_le_bytes(record[0..8].try_into().unwrap());
                    let tag = u64::from_le_bytes(record[8..16].try_into().unwrap());
                    let expected_tx = s as u64 + i * streams as u64;
                    assert_eq!(tx, expected_tx, "PERF-014 wire tx ordering mismatch");

                    let declared_value = u64::from_le_bytes(record[80..88].try_into().unwrap());
                    let declared_arity =
                        u64::from_le_bytes(record[88..96].try_into().unwrap()) as usize;
                    assert_eq!(declared_arity, arity, "PERF-014 wire arity mismatch");
                    assert_eq!(declared_value, arity as u64 * VALUE, "PERF-014 declared value mismatch");

                    let mut inputs = [u64::MAX; MAX_ARITY];
                    for k in 0..arity {
                        let off = 16 + k * 8;
                        inputs[k] = u64::from_le_bytes(record[off..off + 8].try_into().unwrap());
                    }
                    assert_eq!(tag, wire_tag(tx, arity, declared_value, &inputs), "PERF-014 integrity mismatch");

                    let b = tx as usize / batch_size;
                    if current_batch != Some(b) {
                        if let Some(prev) = current_batch {
                            flush_batch(prev, &cursors, &mut batch_starts);
                        }
                        current_batch = Some(b);
                    }

                    for serial in inputs.iter().take(arity) {
                        let sid = input_shard(*serial, shards);
                        let owner = sid % workers;
                        let slot = sid / workers;
                        let id = canonical_input_id(*serial, sid, bits);
                        let lane = &lanes[s * workers + owner];
                        let idx = cursors[owner];
                        lane.write(idx, WorkItem { tx, slot, id });
                        cursors[owner] += 1;
                        routed_inputs += 1;
                    }

                    checksum ^= mix64(tx ^ tag ^ record_size as u64);
                }

                if let Some(last) = current_batch {
                    flush_batch(last, &cursors, &mut batch_starts);
                }

                (checksum, routed_inputs)
            }));
        }

        assert!(seen.into_iter().all(|v| v));
        let mut checksum = 0u64;
        let mut routed_inputs = 0u64;
        for h in receivers {
            let (c, r) = h.join().expect("PERF-014 receiver worker panic");
            checksum ^= c;
            routed_inputs += r;
        }
        (checksum, routed_inputs)
    });

    let mut senders = Vec::with_capacity(streams);
    for s in 0..streams {
        let ready = Arc::clone(&ready);
        let go = Arc::clone(&go);
        senders.push(thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).expect("connect PERF-014 stream");
            stream.set_nodelay(true).expect("sender TCP_NODELAY");
            stream
                .write_all(&(s as u64).to_le_bytes())
                .expect("write PERF-014 stream id");

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
                writer.write_all(&record).expect("write complete PERF-014 record");
            }
            writer.flush().expect("flush PERF-014 stream");
        }));
    }

    drop(batch_ready_tx);

    ready.wait();
    let overall = Instant::now();
    go.wait();

    let mut ready_flags = vec![false; batches];
    let mut batch_latencies = Vec::with_capacity(batches);

    for b in 0..batches {
        while !ready_flags[b] {
            let rb = batch_ready_rx
                .recv()
                .expect("PERF-014 batch-ready channel closed early");
            assert!(rb < batches);
            ready_flags[rb] = true;
        }

        let exec_start = Instant::now();
        for tx in &start_txs {
            tx.send(b).expect("PERF-014 start channel closed");
        }

        let mut done = 0usize;
        while done < workers {
            let (db, _w) = done_rx.recv().expect("PERF-014 done channel closed early");
            assert_eq!(db, b, "PERF-014 worker completed unexpected batch");
            done += 1;
        }
        batch_latencies.push(exec_start.elapsed());
    }

    for h in senders {
        h.join().expect("PERF-014 sender worker panic");
    }
    let (wire_checksum, routed_inputs) = receiver_manager
        .join()
        .expect("PERF-014 receiver manager panic");
    assert_eq!(routed_inputs, total_inputs);

    drop(start_txs);

    let mut committed = 0u64;
    let mut aborted = 0u64;
    let mut state_checksum = 0u64;
    let mut remaining_cells = 0u64;
    let mut remaining_value = 0u128;
    let mut output_cells = 0u64;
    let mut output_value = 0u128;
    let mut route_items_seen = 0u64;

    for h in execution_handles {
        let (c, a, sum, rc, rv, oc, ov, routes) =
            h.join().expect("PERF-014 execution worker panic");
        committed += c;
        aborted += a;
        state_checksum ^= sum;
        remaining_cells += rc;
        remaining_value += rv;
        output_cells += oc;
        output_value += ov;
        route_items_seen += routes;
    }

    let elapsed_s = overall.elapsed().as_secs_f64();
    assert_eq!(route_items_seen, total_inputs);
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
        p50_us: quantile_us(&batch_latencies, 0.50),
        p95_us: quantile_us(&batch_latencies, 0.95),
        p99_us: quantile_us(&batch_latencies, 0.99),
        wire_checksum,
        state_checksum,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let txs = parse_list(&args, "--txs", vec![1_000_000u64]);
    let arities = parse_list(&args, "--arities", vec![8usize]);
    let workers = parse_list(&args, "--workers", vec![6usize, 7, 8]);
    let shards = parse_list(&args, "--shards", vec![1024usize]);
    let conflicts = parse_list(&args, "--conflicts", vec![0u32, 10]);
    let batches = parse_list(&args, "--batches", vec![4096usize, 6144, 8192, 12288]);
    let streams = parse_list(&args, "--streams", vec![1usize, 2]);
    let sizes = parse_list(&args, "--sizes", vec![128usize]);

    println!("CALIBRE GEN2 PERF-014 v1.4.0");
    println!("PREALLOCATED SPSC ROUTE-LANES -> OWNER-LOCAL ATOMIC ENGINE");
    println!("Security: OFF | Consensus: OFF | Persistence: OFF");
    println!("Change vs PERF-013: remove heavy routed WorkItem MPSC chunks and per-batch Vec transfer");
    println!("TCP receivers append directly into preallocated stream->worker lanes; workers read published ranges");
    println!("Lane capacity sizing is outside timing; actual route data still comes from decoded wire records");
    println!("p95 is globally batch-ready-to-all-workers-done latency, NOT end-to-end/WAN finality latency");
    println!("Target: >5M integrated committed arity-8 tx/s");
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
        .expect("PERF-014 results");

    println!("=== DECISION ===");
    println!(
        "BEST NO-CONFLICT INTEGRATED COMMIT TPS: {:.0} | workers={} streams={} batch={} | p95={:.1}us",
        best.commit_tps, best.workers, best.streams, best.batch_size, best.p95_us
    );

    let low_latency_best = rows
        .iter()
        .filter(|r| r.conflict_pct == 0 && r.p95_us <= 2_000.0)
        .max_by(|a, b| a.commit_tps.partial_cmp(&b.commit_tps).unwrap());
    if let Some(r) = low_latency_best {
        println!(
            "BEST p95<=2ms: {:.0} committed tx/s | workers={} streams={} batch={} | p95={:.1}us",
            r.commit_tps, r.workers, r.streams, r.batch_size, r.p95_us
        );
    }

    if let Some(r) = rows.iter().find(|r| {
        r.txs == 1_000_000
            && r.arity == 8
            && r.shards == 1024
            && r.workers == 7
            && r.conflict_pct == 0
            && r.batch_size == 6144
            && r.streams == 2
            && r.record_size == 128
    }) {
        println!(
            "PERF-013 LOW-LATENCY REFERENCE SHAPE / 7W / 2S / B6144: {:.0} committed tx/s | p95={:.1}us",
            r.commit_tps, r.p95_us
        );
    }

    println!(
        "INTEGRATED >5M RESEARCH TARGET: {}",
        if best.commit_tps >= 5_000_000.0 { "PASS" } else { "NOT YET" }
    );
    println!("PREALLOCATED SPSC ROUTE LANES ACTIVE: YES");
    println!("ROUTED INPUT COUNT == TXS * ARITY: PASS if run completed");
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
    fn stream_partition_and_lane_capacity() {
        let total = 100_003u64;
        let streams = 7usize;
        let sum: u64 = (0..streams).map(|s| stream_count(total, streams, s)).sum();
        assert_eq!(sum, total);
        assert!(stream_has_range(0, 4096, streams, 0));
    }

    #[test]
    fn spsc_lane_round_trip() {
        let lane = Lane::new(4, 1);
        lane.write(0, WorkItem { tx: 7, slot: 3, id: 99 });
        lane.publish(0, 0, 1);
        let (a, b) = lane.range(0);
        assert_eq!((a, b), (0, 1));
        let x = lane.read(0);
        assert_eq!(x.tx, 7);
        assert_eq!(x.slot, 3);
        assert_eq!(x.id, 99);
    }

    #[test]
    fn integrated_lane_no_conflict_preserves_value() {
        let r = run_case(20_000, 8, 4, 256, 0, 1024, 2, 128);
        assert_eq!(r.committed, 20_000);
        assert_eq!(r.aborted, 0);
        assert!(r.commit_tps > 0.0);
    }

    #[test]
    fn integrated_lane_conflict_rolls_back() {
        let r = run_case(20_000, 8, 4, 256, 10, 1024, 2, 128);
        assert_eq!(r.committed + r.aborted, 20_000);
        assert!(r.aborted > 0);
        assert!(r.commit_tps > 0.0);
    }
}
