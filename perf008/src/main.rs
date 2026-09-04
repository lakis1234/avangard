use std::env;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

const MAGIC: u64 = 0xCA11_BAE8_0000_0008;

#[inline(always)]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
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
    record_size: usize,
    streams: usize,
    elapsed_s: f64,
    tx_s: f64,
    gb_s: f64,
    checksum: u64,
}

fn stream_count(total: u64, streams: usize, stream: usize) -> u64 {
    let base = total / streams as u64;
    let extra = total % streams as u64;
    base + if (stream as u64) < extra { 1 } else { 0 }
}

fn run_case(txs: u64, record_size: usize, streams: usize) -> Row {
    assert!(txs > 0);
    assert!((16..=4096).contains(&record_size));
    assert!((1..=32).contains(&streams));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener address");

    // All sender and receiver workers rendezvous twice so connection setup is not timed.
    let ready = Arc::new(Barrier::new(streams * 2 + 1));
    let go = Arc::new(Barrier::new(streams * 2 + 1));

    let ready_accept = Arc::clone(&ready);
    let go_accept = Arc::clone(&go);
    let receiver_manager = thread::spawn(move || {
        let mut receivers = Vec::with_capacity(streams);
        for s in 0..streams {
            let (stream, _) = listener.accept().expect("accept loopback stream");
            stream.set_nodelay(true).expect("receiver TCP_NODELAY");
            let ready = Arc::clone(&ready_accept);
            let go = Arc::clone(&go_accept);
            let expected = stream_count(txs, streams, s);
            receivers.push(thread::spawn(move || {
                let mut reader = BufReader::with_capacity(1 << 20, stream);
                let mut record = vec![0u8; record_size];
                let mut checksum = 0u64;
                ready.wait();
                go.wait();

                for i in 0..expected {
                    reader.read_exact(&mut record).expect("read complete record");
                    let tx = u64::from_le_bytes(record[0..8].try_into().unwrap());
                    let tag = u64::from_le_bytes(record[8..16].try_into().unwrap());
                    let expected_tx = s as u64 + i * streams as u64;
                    assert_eq!(tx, expected_tx, "wire tx ordering mismatch");
                    assert_eq!(tag, mix64(tx ^ MAGIC), "wire record integrity mismatch");
                    checksum ^= mix64(tx ^ tag ^ record_size as u64);
                }
                checksum
            }));
        }

        let mut checksum = 0u64;
        for h in receivers {
            checksum ^= h.join().expect("receiver worker panic");
        }
        checksum
    });

    let mut senders = Vec::with_capacity(streams);
    for s in 0..streams {
        let ready = Arc::clone(&ready);
        let go = Arc::clone(&go);
        senders.push(thread::spawn(move || {
            let stream = TcpStream::connect(addr).expect("connect loopback stream");
            stream.set_nodelay(true).expect("sender TCP_NODELAY");
            let mut writer = BufWriter::with_capacity(1 << 20, stream);
            let mut record = vec![0xA5u8; record_size];
            let count = stream_count(txs, streams, s);
            ready.wait();
            go.wait();

            for i in 0..count {
                let tx = s as u64 + i * streams as u64;
                record[0..8].copy_from_slice(&tx.to_le_bytes());
                record[8..16].copy_from_slice(&mix64(tx ^ MAGIC).to_le_bytes());
                writer.write_all(&record).expect("write complete record");
            }
            writer.flush().expect("flush loopback stream");
        }));
    }

    ready.wait();
    let start = Instant::now();
    go.wait();

    for h in senders {
        h.join().expect("sender worker panic");
    }
    let checksum = receiver_manager.join().expect("receiver manager panic");
    let elapsed_s = start.elapsed().as_secs_f64();
    let tx_s = txs as f64 / elapsed_s;
    let gb_s = (txs as f64 * record_size as f64) / elapsed_s / 1_000_000_000.0;

    Row {
        txs,
        record_size,
        streams,
        elapsed_s,
        tx_s,
        gb_s,
        checksum,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let txs = parse_list(&args, "--txs", vec![1_000_000u64]);
    let sizes = parse_list(&args, "--sizes", vec![32usize, 64, 128, 256]);
    let streams = parse_list(&args, "--streams", vec![1usize, 4]);

    println!("CALIBRE GEN2 PERF-008 v0.8.0");
    println!("REAL LOOPBACK TRANSACTION-ENVELOPE INGRESS");
    println!("Transport: TCP 127.0.0.1 | integrity field checked on every record");
    println!("Security: OFF | Consensus: OFF | Persistence: OFF");
    println!("Purpose: quantify kernel/socket + binary framing/parse cost before combining with execution");
    println!("This is LOCAL LOOPBACK ingress, NOT distributed network TPS.");
    println!();

    let mut rows = Vec::new();
    for &n in &txs {
        println!("=== TXS={} ===", n);
        for &size in &sizes {
            for &s in &streams {
                let r = run_case(n, size, s);
                println!(
                    "record={:<4}B streams={:<2} tx/s={:>12.0} wire={:>6.3} GB/s elapsed={:>7.3}s checksum={:016x}",
                    r.record_size, r.streams, r.tx_s, r.gb_s, r.elapsed_s, r.checksum
                );
                rows.push(r);
            }
        }
        println!();
    }

    let best = rows
        .iter()
        .max_by(|a, b| a.tx_s.partial_cmp(&b.tx_s).unwrap())
        .expect("results");

    println!("=== DECISION ===");
    println!(
        "BEST LOOPBACK INGRESS: {:.0} tx/s | {}B records | {} streams | {:.3} GB/s",
        best.tx_s, best.record_size, best.streams, best.gb_s
    );
    for size in [32usize, 64, 128, 256] {
        if let Some(r) = rows.iter().find(|r| r.txs == 1_000_000 && r.record_size == size && r.streams == 4) {
            println!("1M / 4 STREAMS / {}B: {:.0} tx/s | {:.3} GB/s", size, r.tx_s, r.gb_s);
        }
    }
    if let Some(r) = rows.iter().find(|r| r.txs == 1_000_000 && r.record_size == 128 && r.streams == 4) {
        println!("128B ENVELOPE >5M INGRESS TARGET: {}", if r.tx_s >= 5_000_000.0 { "PASS" } else { "NOT YET" });
    }
    println!("WIRE RECORD COUNT/ORDER/INTEGRITY: PASS if run completed");
    println!("ENGINE EXECUTION INCLUDED: NO");
    println!("DISTRIBUTED NETWORK TPS PROVEN: NO");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_partition_covers_total() {
        let total = 100_003u64;
        let streams = 7usize;
        let sum: u64 = (0..streams).map(|s| stream_count(total, streams, s)).sum();
        assert_eq!(sum, total);
    }

    #[test]
    fn loopback_records_round_trip() {
        let r = run_case(20_000, 64, 2);
        assert!(r.tx_s > 0.0);
        assert_eq!(r.txs, 20_000);
    }
}
