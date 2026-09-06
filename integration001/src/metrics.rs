use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// A point-in-time copy of the wire counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireSnapshot {
    pub requests: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl WireSnapshot {
    pub fn merge(&mut self, other: Self) {
        self.requests = self.requests.saturating_add(other.requests);
        self.bytes_sent = self.bytes_sent.saturating_add(other.bytes_sent);
        self.bytes_received = self.bytes_received.saturating_add(other.bytes_received);
    }
}

/// Thread-safe counters for logical requests and application-level wire bytes.
///
/// The counters use relaxed atomics because they report measurements; they do not
/// synchronize protocol state. Take the final snapshot after worker threads stop.
#[derive(Debug, Default)]
pub struct WireCounters {
    requests: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

impl WireCounters {
    pub const fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    pub fn record_request(&self, bytes_sent: u64, bytes_received: u64) {
        saturating_atomic_add(&self.requests, 1);
        saturating_atomic_add(&self.bytes_sent, bytes_sent);
        saturating_atomic_add(&self.bytes_received, bytes_received);
    }

    pub fn increment_requests(&self) {
        saturating_atomic_add(&self.requests, 1);
    }

    pub fn add_bytes_sent(&self, bytes: u64) {
        saturating_atomic_add(&self.bytes_sent, bytes);
    }

    pub fn add_bytes_received(&self, bytes: u64) {
        saturating_atomic_add(&self.bytes_received, bytes);
    }

    pub fn snapshot(&self) -> WireSnapshot {
        WireSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }

    pub fn merge_snapshot(&self, snapshot: WireSnapshot) {
        saturating_atomic_add(&self.requests, snapshot.requests);
        saturating_atomic_add(&self.bytes_sent, snapshot.bytes_sent);
        saturating_atomic_add(&self.bytes_received, snapshot.bytes_received);
    }

    pub fn merge(&self, other: &Self) {
        self.merge_snapshot(other.snapshot());
    }
}

fn saturating_atomic_add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

/// Finite-sample latency percentiles using the nearest-rank definition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LatencySummary {
    pub samples: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

/// Return p50, p95, p99 and max for microsecond samples.
///
/// The input is not modified. Empty input has no percentile summary.
pub fn summarize_latencies(samples_us: &[u64]) -> Option<LatencySummary> {
    if samples_us.is_empty() {
        return None;
    }

    let mut sorted = samples_us.to_vec();
    sorted.sort_unstable();
    Some(LatencySummary {
        samples: u64::try_from(sorted.len()).unwrap_or(u64::MAX),
        p50_us: nearest_rank(&sorted, 50),
        p95_us: nearest_rank(&sorted, 95),
        p99_us: nearest_rank(&sorted, 99),
        max_us: *sorted.last().expect("non-empty latency sample"),
    })
}

fn nearest_rank(sorted: &[u64], percentile: usize) -> u64 {
    debug_assert!(!sorted.is_empty());
    debug_assert!((1..=100).contains(&percentile));
    let count = sorted.len();
    let rank = (count.saturating_mul(percentile).saturating_add(99)) / 100;
    sorted[rank.max(1).min(count) - 1]
}

/// Logical operations per elapsed second. A zero duration returns zero rather
/// than infinity so emitted JSON always remains valid.
pub fn throughput(count: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if count == 0 || seconds == 0.0 {
        0.0
    } else {
        count as f64 / seconds
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunMetricsSnapshot {
    pub wire: WireSnapshot,
    pub phase_samples_us: BTreeMap<String, Vec<u64>>,
}

#[derive(Debug, Default)]
struct RunMetricsInner {
    wire: WireCounters,
    phase_samples_us: Mutex<BTreeMap<String, Vec<u64>>>,
}

/// Cloneable metrics handle. Clones share counters and phase samples, so it can
/// be passed directly to networking and validator worker threads.
#[derive(Clone, Debug, Default)]
pub struct RunMetrics {
    inner: Arc<RunMetricsInner>,
}

impl RunMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_request(&self, bytes_sent: u64, bytes_received: u64) {
        self.inner.wire.record_request(bytes_sent, bytes_received);
    }

    pub fn increment_requests(&self) {
        self.inner.wire.increment_requests();
    }

    pub fn add_bytes_sent(&self, bytes: u64) {
        self.inner.wire.add_bytes_sent(bytes);
    }

    pub fn add_bytes_received(&self, bytes: u64) {
        self.inner.wire.add_bytes_received(bytes);
    }

    pub fn record_latency_us(&self, phase: impl AsRef<str>, microseconds: u64) {
        self.lock_phases()
            .entry(phase.as_ref().to_owned())
            .or_default()
            .push(microseconds);
    }

    pub fn record_latency(&self, phase: impl AsRef<str>, elapsed: Duration) {
        let microseconds = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.record_latency_us(phase, microseconds);
    }

    pub fn wire_snapshot(&self) -> WireSnapshot {
        self.inner.wire.snapshot()
    }

    pub fn phase_summary(&self, phase: &str) -> Option<LatencySummary> {
        let phases = self.lock_phases();
        phases
            .get(phase)
            .and_then(|samples| summarize_latencies(samples))
    }

    pub fn phase_summaries(&self) -> BTreeMap<String, LatencySummary> {
        self.lock_phases()
            .iter()
            .filter_map(|(phase, samples)| {
                summarize_latencies(samples).map(|summary| (phase.clone(), summary))
            })
            .collect()
    }

    pub fn snapshot(&self) -> RunMetricsSnapshot {
        RunMetricsSnapshot {
            wire: self.inner.wire.snapshot(),
            phase_samples_us: self.lock_phases().clone(),
        }
    }

    /// Merge a non-shared metrics collector into this one.
    pub fn merge(&self, other: &Self) {
        self.merge_snapshot(&other.snapshot());
    }

    pub fn merge_snapshot(&self, snapshot: &RunMetricsSnapshot) {
        self.inner.wire.merge_snapshot(snapshot.wire);
        let mut phases = self.lock_phases();
        for (phase, samples) in &snapshot.phase_samples_us {
            phases
                .entry(phase.clone())
                .or_default()
                .extend_from_slice(samples);
        }
    }

    fn lock_phases(&self) -> MutexGuard<'_, BTreeMap<String, Vec<u64>>> {
        self.inner
            .phase_samples_us
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Escape JSON string contents without adding the surrounding quotation marks.
pub fn json_escape(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control <= '\u{1f}' => {
                let value = control as u32;
                escaped.push_str("\\u00");
                escaped.push(HEX[((value >> 4) & 0x0f) as usize] as char);
                escaped.push(HEX[(value & 0x0f) as usize] as char);
            }
            other => escaped.push(other),
        }
    }
    escaped
}

/// Write a stable, compact JSON report.
///
/// Metadata, gate names, numeric metric names and latency phase names are sorted
/// lexicographically. Duplicate names use the last supplied value.
pub fn write_json<P: AsRef<Path>>(
    path: P,
    run: &RunMetrics,
    metadata: &[(&str, &str)],
    gates: &[(&str, bool)],
    numeric_metrics: &[(&str, f64)],
) -> io::Result<()> {
    let metadata: BTreeMap<&str, &str> = metadata.iter().copied().collect();
    let gates: BTreeMap<&str, bool> = gates.iter().copied().collect();
    let numeric_metrics: BTreeMap<&str, f64> = numeric_metrics.iter().copied().collect();
    if let Some((name, _)) = numeric_metrics.iter().find(|(_, value)| !value.is_finite()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("numeric metric {name:?} is not finite"),
        ));
    }

    let snapshot = run.snapshot();
    let phase_summaries: BTreeMap<String, LatencySummary> = snapshot
        .phase_samples_us
        .iter()
        .filter_map(|(phase, samples)| {
            summarize_latencies(samples).map(|summary| (phase.clone(), summary))
        })
        .collect();

    let mut json = String::new();
    json.push('{');
    push_string_map(&mut json, "metadata", &metadata);
    json.push(',');
    push_bool_map(&mut json, "gates", &gates);
    json.push(',');
    push_number_map(&mut json, "metrics", &numeric_metrics);
    json.push_str(",\"wire\":{");
    json.push_str("\"requests\":");
    json.push_str(&snapshot.wire.requests.to_string());
    json.push_str(",\"bytes_sent\":");
    json.push_str(&snapshot.wire.bytes_sent.to_string());
    json.push_str(",\"bytes_received\":");
    json.push_str(&snapshot.wire.bytes_received.to_string());
    json.push_str("},\"latency_us\":{");
    for (index, (phase, summary)) in phase_summaries.iter().enumerate() {
        if index != 0 {
            json.push(',');
        }
        push_quoted(&mut json, phase);
        json.push_str(":{");
        json.push_str("\"samples\":");
        json.push_str(&summary.samples.to_string());
        json.push_str(",\"p50\":");
        json.push_str(&summary.p50_us.to_string());
        json.push_str(",\"p95\":");
        json.push_str(&summary.p95_us.to_string());
        json.push_str(",\"p99\":");
        json.push_str(&summary.p99_us.to_string());
        json.push_str(",\"max\":");
        json.push_str(&summary.max_us.to_string());
        json.push('}');
    }
    json.push_str("}}");

    fs::write(path, json)
}

fn push_quoted(output: &mut String, value: &str) {
    output.push('"');
    output.push_str(&json_escape(value));
    output.push('"');
}

fn push_string_map(output: &mut String, name: &str, values: &BTreeMap<&str, &str>) {
    push_quoted(output, name);
    output.push_str(":{");
    for (index, (key, value)) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        push_quoted(output, key);
        output.push(':');
        push_quoted(output, value);
    }
    output.push('}');
}

fn push_bool_map(output: &mut String, name: &str, values: &BTreeMap<&str, bool>) {
    push_quoted(output, name);
    output.push_str(":{");
    for (index, (key, value)) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        push_quoted(output, key);
        output.push(':');
        output.push_str(if *value { "true" } else { "false" });
    }
    output.push('}');
}

fn push_number_map(output: &mut String, name: &str, values: &BTreeMap<&str, f64>) {
    push_quoted(output, name);
    output.push_str(":{");
    for (index, (key, value)) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        push_quoted(output, key);
        output.push(':');
        output.push_str(&value.to_string());
    }
    output.push('}');
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn wire_counters_are_shared_and_thread_safe() {
        let metrics = RunMetrics::new();
        let mut workers = Vec::new();
        for _ in 0..8 {
            let metrics = metrics.clone();
            workers.push(thread::spawn(move || {
                for _ in 0..1_000 {
                    metrics.record_request(10, 4);
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }

        assert_eq!(
            metrics.wire_snapshot(),
            WireSnapshot {
                requests: 8_000,
                bytes_sent: 80_000,
                bytes_received: 32_000,
            }
        );
    }

    #[test]
    fn snapshots_merge_without_losing_phases() {
        let first = RunMetrics::new();
        first.record_request(10, 5);
        first.record_latency_us("finality", 30);

        let second = RunMetrics::new();
        second.record_request(20, 7);
        second.record_latency_us("finality", 10);
        second.record_latency_us("reject", 9);

        first.merge(&second);
        assert_eq!(first.wire_snapshot().requests, 2);
        assert_eq!(first.wire_snapshot().bytes_sent, 30);
        assert_eq!(first.phase_summary("finality").unwrap().p50_us, 10);
        assert_eq!(first.phase_summary("reject").unwrap().max_us, 9);
    }

    #[test]
    fn finite_sample_percentiles_use_nearest_rank() {
        assert_eq!(summarize_latencies(&[]), None);
        assert_eq!(
            summarize_latencies(&[100, 1, 50, 25, 75]),
            Some(LatencySummary {
                samples: 5,
                p50_us: 50,
                p95_us: 100,
                p99_us: 100,
                max_us: 100,
            })
        );
        assert_eq!(summarize_latencies(&[1, 2, 3, 4]).unwrap().p50_us, 2);
    }

    #[test]
    fn duration_recording_and_throughput_are_finite() {
        let metrics = RunMetrics::new();
        metrics.record_latency("wire", Duration::from_micros(123));
        assert_eq!(metrics.phase_summary("wire").unwrap().max_us, 123);
        assert_eq!(throughput(250, Duration::from_secs(2)), 125.0);
        assert_eq!(throughput(250, Duration::ZERO), 0.0);
        assert_eq!(throughput(0, Duration::from_secs(1)), 0.0);
    }

    #[test]
    fn json_strings_escape_quotes_slashes_controls_and_keep_unicode() {
        assert_eq!(
            json_escape("CALIBRE \"A\"\\B\n\t\u{0001} Κ"),
            "CALIBRE \\\"A\\\"\\\\B\\n\\t\\u0001 Κ"
        );
    }

    #[test]
    fn json_output_is_compact_sorted_and_deterministic() {
        let metrics = RunMetrics::new();
        metrics.record_request(10, 5);
        metrics.record_latency_us("finality", 30);
        metrics.record_latency_us("finality", 10);
        metrics.record_latency_us("accept\"phase", 7);

        let path = temporary_path("report");
        write_json(
            &path,
            &metrics,
            &[("z", "line\n"), ("a", "quote\"")],
            &[("z", false), ("a", true)],
            &[("z", 2.0), ("a", 1.25)],
        )
        .unwrap();

        let actual = fs::read_to_string(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(
            actual,
            "{\"metadata\":{\"a\":\"quote\\\"\",\"z\":\"line\\n\"},\"gates\":{\"a\":true,\"z\":false},\"metrics\":{\"a\":1.25,\"z\":2},\"wire\":{\"requests\":1,\"bytes_sent\":10,\"bytes_received\":5},\"latency_us\":{\"accept\\\"phase\":{\"samples\":1,\"p50\":7,\"p95\":7,\"p99\":7,\"max\":7},\"finality\":{\"samples\":2,\"p50\":10,\"p95\":30,\"p99\":30,\"max\":30}}}"
        );
        assert!(!actual.contains('\n'));
    }

    #[test]
    fn json_rejects_non_finite_numbers_before_writing() {
        let path = temporary_path("non-finite");
        let result = write_json(
            &path,
            &RunMetrics::new(),
            &[],
            &[],
            &[("bad", f64::NAN)],
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(!path.exists());
    }

    fn temporary_path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "calibre-integration001-metrics-{label}-{}-{nonce}.json",
            std::process::id()
        ))
    }
}
