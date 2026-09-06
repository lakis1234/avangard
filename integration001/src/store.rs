//! Durable, append-only validator state for the integrated CALIBRE experiment.
//!
//! The node verifies signatures and certificates before calling this module.  The
//! store's job is narrower but security-critical: make that decision durable
//! before a reply can escape, reject equivocation after restart, and make
//! committee retirement terminal.

use blake3::Hasher;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

pub type Digest = [u8; 32];

pub const PHASE_PREVOTE: u8 = 1;
pub const PHASE_PRECOMMIT: u8 = 2;

const WAL_MAGIC: [u8; 8] = *b"CALINT1W";
const WAL_VERSION: u16 = 1;
const HEADER_LEN: usize = 24;
const CHECKSUM_LEN: usize = 32;
const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = MAX_SNAPSHOT_BYTES + 512;

const KIND_INITIALIZE: u8 = 1;
const KIND_ACTIVATE: u8 = 2;
const KIND_VOTE: u8 = 3;
const KIND_APPLY: u8 = 4;
const KIND_RETIRE: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    Initialized,
    Active,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistOutcome {
    Persisted,
    AlreadyPresent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub committee_hash: Digest,
    pub epoch: u64,
    pub state_root: Digest,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationRecord {
    pub handoff_hash: Digest,
    pub snapshot: Snapshot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetirementRecord {
    pub handoff_hash: Digest,
    pub next_committee: Digest,
    pub next_epoch: u64,
    pub snapshot: Snapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecommitLock {
    pub round: u64,
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedRecord {
    pub tx_digest: Digest,
    pub certificate_digest: Digest,
    pub prior_state_root: Digest,
    pub next_snapshot: Snapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct VoteKey {
    conflict_key: Digest,
    round: u64,
    phase: u8,
}

/// A validator-local WAL.  `WalStore` is deliberately not cloneable: one node
/// process owns one append handle.
pub struct WalStore {
    file: File,
    committee_hash: Digest,
    epoch: u64,
    initial_snapshot: Snapshot,
    lifecycle: Lifecycle,
    current_snapshot: Snapshot,
    activation: Option<ActivationRecord>,
    retirement: Option<RetirementRecord>,
    votes: HashMap<VoteKey, Digest>,
    locks: HashMap<Digest, PrecommitLock>,
    applied: HashMap<Digest, AppliedRecord>,
    next_sequence: u64,
    poisoned: bool,
}

impl WalStore {
    /// Opens an existing WAL or writes its one-time initialization record.
    ///
    /// A new WAL requires `genesis`.  Initialization does *not* authorize
    /// voting: the caller must separately call `activate`, including for the
    /// first committee.  This two-record transition makes a crash between
    /// provisioning and activation fail closed.  An existing retired WAL is
    /// never reinitialized, even when `genesis` is supplied again.
    pub fn open(
        path: &Path,
        expected_committee: Digest,
        expected_epoch: u64,
        genesis: Option<Snapshot>,
    ) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create WAL directory: {e}"))?;
        }

        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("read WAL: {e}")),
        };
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .map_err(|e| format!("open WAL: {e}"))?;

        if bytes.is_empty() {
            let snapshot = genesis.ok_or_else(|| {
                "empty WAL requires an explicit initialization snapshot; fail closed".to_string()
            })?;
            validate_snapshot(&snapshot, &expected_committee, expected_epoch)?;
            let payload = encode_snapshot(&snapshot)?;
            append_record(&mut file, 0, KIND_INITIALIZE, &payload)?;
            return Ok(Self {
                file,
                committee_hash: expected_committee,
                epoch: expected_epoch,
                initial_snapshot: snapshot.clone(),
                lifecycle: Lifecycle::Initialized,
                current_snapshot: snapshot,
                activation: None,
                retirement: None,
                votes: HashMap::new(),
                locks: HashMap::new(),
                applied: HashMap::new(),
                next_sequence: 1,
                poisoned: false,
            });
        }

        let replay = replay_wal(&bytes, expected_committee, expected_epoch)?;
        if let Some(provided) = genesis {
            validate_snapshot(&provided, &expected_committee, expected_epoch)?;
            if provided != replay.initial_snapshot {
                return Err("provided initialization snapshot conflicts with durable WAL; fail closed".into());
            }
        }

        Ok(Self {
            file,
            committee_hash: expected_committee,
            epoch: expected_epoch,
            initial_snapshot: replay.initial_snapshot,
            lifecycle: replay.lifecycle,
            current_snapshot: replay.current_snapshot,
            activation: replay.activation,
            retirement: replay.retirement,
            votes: replay.votes,
            locks: replay.locks,
            applied: replay.applied,
            next_sequence: replay.next_sequence,
            poisoned: false,
        })
    }

    pub fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
    }

    pub fn committee_hash(&self) -> Digest {
        self.committee_hash
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn initial_snapshot(&self) -> &Snapshot {
        &self.initial_snapshot
    }

    pub fn current_snapshot(&self) -> &Snapshot {
        &self.current_snapshot
    }

    pub fn activation(&self) -> Option<&ActivationRecord> {
        self.activation.as_ref()
    }

    pub fn retirement(&self) -> Option<&RetirementRecord> {
        self.retirement.as_ref()
    }

    pub fn vote_digest(&self, conflict_key: Digest, round: u64, phase: u8) -> Option<Digest> {
        self.votes
            .get(&VoteKey { conflict_key, round, phase })
            .copied()
    }

    pub fn precommit_lock(&self, conflict_key: Digest) -> Option<PrecommitLock> {
        self.locks.get(&conflict_key).copied()
    }

    pub fn applied_record(&self, tx_digest: Digest) -> Option<&AppliedRecord> {
        self.applied.get(&tx_digest)
    }

    pub fn applied_count(&self) -> usize {
        self.applied.len()
    }

    pub fn wal_records(&self) -> u64 {
        self.next_sequence
    }

    pub fn wal_bytes(&self) -> Result<u64, String> {
        self.file
            .metadata()
            .map(|m| m.len())
            .map_err(|e| format!("read WAL metadata: {e}"))
    }

    /// Activates this committee from an exact handoff/snapshot pair.
    pub fn activate(
        &mut self,
        handoff_hash: Digest,
        snapshot: Snapshot,
    ) -> Result<PersistOutcome, String> {
        self.ensure_healthy()?;
        validate_snapshot(&snapshot, &self.committee_hash, self.epoch)?;

        match self.lifecycle {
            Lifecycle::Initialized => {
                // Initialization is only provisioning.  Activation may bind a
                // handoff hash, but it may not silently replace provisioned
                // state.
                if snapshot != self.current_snapshot {
                    return Err("activation snapshot conflicts with initialized snapshot".into());
                }
            }
            Lifecycle::Active => {
                let existing = self
                    .activation
                    .as_ref()
                    .ok_or_else(|| "active WAL is missing its activation record; fail closed".to_string())?;
                if existing.handoff_hash == handoff_hash && existing.snapshot == snapshot {
                    return Ok(PersistOutcome::AlreadyPresent);
                }
                return Err("conflicting committee activation rejected".into());
            }
            Lifecycle::Retired => {
                return Err("retired committee cannot be activated or resurrected".into());
            }
        }

        let mut payload = Vec::new();
        put_digest(&mut payload, &handoff_hash);
        payload.extend_from_slice(&encode_snapshot(&snapshot)?);
        self.append(KIND_ACTIVATE, &payload)?;
        self.lifecycle = Lifecycle::Active;
        self.current_snapshot = snapshot.clone();
        self.activation = Some(ActivationRecord { handoff_hash, snapshot });
        Ok(PersistOutcome::Persisted)
    }

    /// Durably records a phase vote before the signed vote is returned.
    ///
    /// There can be only one digest for a committee/conflict/round/phase.  A
    /// precommit lock is monotonic: lower rounds and conflicting digests are
    /// rejected.  This conservative experiment never unlocks to a conflicting
    /// digest; a future liveness protocol would need an explicit verified
    /// higher-round unlock certificate in this API.
    pub fn persist_vote(
        &mut self,
        conflict_key: Digest,
        round: u64,
        phase: u8,
        digest: Digest,
    ) -> Result<PersistOutcome, String> {
        self.ensure_active("vote")?;
        validate_phase(phase)?;
        let key = VoteKey { conflict_key, round, phase };
        if let Some(existing) = self.votes.get(&key) {
            return if existing == &digest {
                Ok(PersistOutcome::AlreadyPresent)
            } else {
                Err("conflicting same-round phase vote rejected".into())
            };
        }

        if let Some(lock) = self.locks.get(&conflict_key) {
            if round < lock.round {
                return Err("vote below durable precommit-lock round rejected".into());
            }
            if digest != lock.digest {
                return Err("vote conflicting with durable precommit lock rejected".into());
            }
        }

        let mut payload = Vec::with_capacity(73);
        put_digest(&mut payload, &conflict_key);
        put_u64(&mut payload, round);
        payload.push(phase);
        put_digest(&mut payload, &digest);
        self.append(KIND_VOTE, &payload)?;
        self.votes.insert(key, digest);
        if phase == PHASE_PRECOMMIT {
            self.locks.insert(conflict_key, PrecommitLock { round, digest });
        }
        Ok(PersistOutcome::Persisted)
    }

    /// Advances the persisted state after the node server has verified a
    /// certificate.  The certificate digest is mandatory audit evidence; the
    /// store does not accept a bare state replacement API.
    pub fn apply_verified(
        &mut self,
        tx_digest: Digest,
        certificate_digest: Digest,
        next_snapshot: Snapshot,
    ) -> Result<PersistOutcome, String> {
        self.ensure_healthy()?;
        validate_snapshot(&next_snapshot, &self.committee_hash, self.epoch)?;
        if is_zero(&tx_digest) || is_zero(&certificate_digest) {
            return Err("verified apply requires nonzero transaction and certificate digests".into());
        }

        if let Some(existing) = self.applied.get(&tx_digest) {
            if existing.certificate_digest == certificate_digest
                && existing.next_snapshot == next_snapshot
            {
                return Ok(PersistOutcome::AlreadyPresent);
            }
            return Err("transaction digest was already applied with different certified state".into());
        }
        if self.lifecycle != Lifecycle::Active {
            return Err("new certified state can only be applied by an active committee".into());
        }
        if next_snapshot.state_root == self.current_snapshot.state_root {
            return Err("certified apply did not advance the state root".into());
        }

        let prior_state_root = self.current_snapshot.state_root;
        let mut payload = Vec::new();
        put_digest(&mut payload, &tx_digest);
        put_digest(&mut payload, &certificate_digest);
        put_digest(&mut payload, &prior_state_root);
        payload.extend_from_slice(&encode_snapshot(&next_snapshot)?);
        self.append(KIND_APPLY, &payload)?;
        let applied = AppliedRecord {
            tx_digest,
            certificate_digest,
            prior_state_root,
            next_snapshot: next_snapshot.clone(),
        };
        self.applied.insert(tx_digest, applied);
        self.current_snapshot = next_snapshot;
        Ok(PersistOutcome::Persisted)
    }

    /// Makes the current committee terminal and persists the exact state that
    /// the handoff certified.  No later vote, apply, or activation can follow.
    pub fn retire(
        &mut self,
        handoff_hash: Digest,
        next_committee: Digest,
        next_epoch: u64,
        state_root: Digest,
    ) -> Result<PersistOutcome, String> {
        self.ensure_healthy()?;
        if self.lifecycle == Lifecycle::Retired {
            let existing = self
                .retirement
                .as_ref()
                .ok_or_else(|| "retired WAL is missing its retirement record; fail closed".to_string())?;
            if existing.handoff_hash == handoff_hash
                && existing.next_committee == next_committee
                && existing.next_epoch == next_epoch
                && existing.snapshot.state_root == state_root
            {
                return Ok(PersistOutcome::AlreadyPresent);
            }
            return Err("conflicting committee retirement rejected".into());
        }
        if self.lifecycle != Lifecycle::Active {
            return Err("only an active committee can retire".into());
        }
        let required_next = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| "epoch overflow during retirement".to_string())?;
        if next_epoch != required_next {
            return Err("retirement must hand off to the direct next epoch".into());
        }
        if next_committee == self.committee_hash {
            return Err("retirement must hand off to a distinct committee".into());
        }
        if state_root != self.current_snapshot.state_root {
            return Err("retirement state root does not match durable current state".into());
        }
        if is_zero(&handoff_hash) {
            return Err("retirement requires a nonzero handoff digest".into());
        }

        let snapshot = self.current_snapshot.clone();
        let mut payload = Vec::new();
        put_digest(&mut payload, &handoff_hash);
        put_digest(&mut payload, &next_committee);
        put_u64(&mut payload, next_epoch);
        payload.extend_from_slice(&encode_snapshot(&snapshot)?);
        self.append(KIND_RETIRE, &payload)?;
        self.lifecycle = Lifecycle::Retired;
        self.retirement = Some(RetirementRecord {
            handoff_hash,
            next_committee,
            next_epoch,
            snapshot,
        });
        Ok(PersistOutcome::Persisted)
    }

    fn ensure_healthy(&self) -> Result<(), String> {
        if self.poisoned {
            Err("WAL append previously failed; process must restart and rescan fail closed".into())
        } else {
            Ok(())
        }
    }

    fn ensure_active(&self, operation: &str) -> Result<(), String> {
        self.ensure_healthy()?;
        match self.lifecycle {
            Lifecycle::Active => Ok(()),
            Lifecycle::Initialized => Err(format!("committee is initialized but not active; {operation} rejected")),
            Lifecycle::Retired => Err(format!("committee is retired; {operation} rejected")),
        }
    }

    fn append(&mut self, kind: u8, payload: &[u8]) -> Result<(), String> {
        match append_record(&mut self.file, self.next_sequence, kind, payload) {
            Ok(()) => {
                self.next_sequence = self
                    .next_sequence
                    .checked_add(1)
                    .ok_or_else(|| "WAL sequence exhausted".to_string())?;
                Ok(())
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
}

struct ReplayState {
    initial_snapshot: Snapshot,
    lifecycle: Lifecycle,
    current_snapshot: Snapshot,
    activation: Option<ActivationRecord>,
    retirement: Option<RetirementRecord>,
    votes: HashMap<VoteKey, Digest>,
    locks: HashMap<Digest, PrecommitLock>,
    applied: HashMap<Digest, AppliedRecord>,
    next_sequence: u64,
}

fn replay_wal(
    bytes: &[u8],
    expected_committee: Digest,
    expected_epoch: u64,
) -> Result<ReplayState, String> {
    let mut offset = 0usize;
    let mut sequence = 0u64;
    let mut state: Option<ReplayState> = None;

    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < HEADER_LEN + CHECKSUM_LEN {
            return Err("incomplete WAL record; fail closed".into());
        }
        let header = &bytes[offset..offset + HEADER_LEN];
        if header[0..8] != WAL_MAGIC {
            return Err("bad WAL magic; fail closed".into());
        }
        let version = u16::from_le_bytes([header[8], header[9]]);
        if version != WAL_VERSION {
            return Err("unsupported WAL version; fail closed".into());
        }
        let kind = header[10];
        if header[11] != 0 {
            return Err("nonzero WAL reserved byte; fail closed".into());
        }
        let payload_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err("WAL payload exceeds safety limit; fail closed".into());
        }
        let record_sequence = u64::from_le_bytes(header[16..24].try_into().unwrap());
        if record_sequence != sequence {
            return Err("non-contiguous WAL sequence; fail closed".into());
        }
        let record_len = HEADER_LEN
            .checked_add(payload_len)
            .and_then(|n| n.checked_add(CHECKSUM_LEN))
            .ok_or_else(|| "WAL record length overflow; fail closed".to_string())?;
        if record_len > remaining {
            return Err("incomplete WAL record; fail closed".into());
        }
        let payload_start = offset + HEADER_LEN;
        let payload_end = payload_start + payload_len;
        let payload = &bytes[payload_start..payload_end];
        let checksum = &bytes[payload_end..payload_end + CHECKSUM_LEN];
        if checksum != wal_checksum(header, payload) {
            return Err("WAL checksum mismatch; fail closed".into());
        }

        if kind == KIND_INITIALIZE {
            if sequence != 0 || state.is_some() {
                return Err("duplicate or misplaced initialization record; fail closed".into());
            }
            let snapshot = decode_snapshot_exact(payload)?;
            validate_snapshot(&snapshot, &expected_committee, expected_epoch)?;
            state = Some(ReplayState {
                initial_snapshot: snapshot.clone(),
                lifecycle: Lifecycle::Initialized,
                current_snapshot: snapshot,
                activation: None,
                retirement: None,
                votes: HashMap::new(),
                locks: HashMap::new(),
                applied: HashMap::new(),
                next_sequence: 1,
            });
        } else {
            let replay = state
                .as_mut()
                .ok_or_else(|| "WAL does not begin with initialization; fail closed".to_string())?;
            replay_record(replay, kind, payload, expected_committee, expected_epoch)?;
        }

        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| "WAL sequence overflow; fail closed".to_string())?;
        offset += record_len;
    }

    let mut state = state.ok_or_else(|| "WAL has no initialization record; fail closed".to_string())?;
    state.next_sequence = sequence;
    Ok(state)
}

fn replay_record(
    state: &mut ReplayState,
    kind: u8,
    payload: &[u8],
    expected_committee: Digest,
    expected_epoch: u64,
) -> Result<(), String> {
    if state.lifecycle == Lifecycle::Retired {
        return Err("record follows terminal retirement; fail closed".into());
    }

    let mut input = payload;
    match kind {
        KIND_ACTIVATE => {
            if state.lifecycle != Lifecycle::Initialized || state.activation.is_some() {
                return Err("duplicate or misplaced activation; fail closed".into());
            }
            let handoff_hash = take_digest(&mut input)?;
            let snapshot = decode_snapshot(&mut input)?;
            finish(input)?;
            validate_snapshot(&snapshot, &expected_committee, expected_epoch)?;
            if snapshot != state.current_snapshot {
                return Err("activation changed initialized state; fail closed".into());
            }
            state.lifecycle = Lifecycle::Active;
            state.current_snapshot = snapshot.clone();
            state.activation = Some(ActivationRecord { handoff_hash, snapshot });
        }
        KIND_VOTE => {
            require_active(state, "vote record")?;
            let conflict_key = take_digest(&mut input)?;
            let round = take_u64(&mut input)?;
            let phase = take_u8(&mut input)?;
            let digest = take_digest(&mut input)?;
            finish(input)?;
            validate_phase(phase)?;
            let key = VoteKey { conflict_key, round, phase };
            if let Some(old) = state.votes.get(&key) {
                if old != &digest {
                    return Err("conflicting durable same-round phase vote; fail closed".into());
                }
                return Err("duplicate vote WAL record; fail closed".into());
            }
            if let Some(lock) = state.locks.get(&conflict_key) {
                if round < lock.round {
                    return Err("vote below durable precommit-lock round in WAL; fail closed".into());
                }
                if digest != lock.digest {
                    return Err("vote conflicts with durable precommit lock in WAL; fail closed".into());
                }
            }
            state.votes.insert(key, digest);
            if phase == PHASE_PRECOMMIT {
                state.locks.insert(conflict_key, PrecommitLock { round, digest });
            }
        }
        KIND_APPLY => {
            require_active(state, "apply record")?;
            let tx_digest = take_digest(&mut input)?;
            let certificate_digest = take_digest(&mut input)?;
            let prior_state_root = take_digest(&mut input)?;
            let next_snapshot = decode_snapshot(&mut input)?;
            finish(input)?;
            validate_snapshot(&next_snapshot, &expected_committee, expected_epoch)?;
            if is_zero(&tx_digest) || is_zero(&certificate_digest) {
                return Err("apply WAL record has zero transaction/certificate digest; fail closed".into());
            }
            if state.applied.contains_key(&tx_digest) {
                return Err("duplicate applied transaction WAL record; fail closed".into());
            }
            if prior_state_root != state.current_snapshot.state_root {
                return Err("applied state lineage does not match prior root; fail closed".into());
            }
            if next_snapshot.state_root == prior_state_root {
                return Err("applied WAL record did not advance state root; fail closed".into());
            }
            let applied = AppliedRecord {
                tx_digest,
                certificate_digest,
                prior_state_root,
                next_snapshot: next_snapshot.clone(),
            };
            state.applied.insert(tx_digest, applied);
            state.current_snapshot = next_snapshot;
        }
        KIND_RETIRE => {
            require_active(state, "retirement record")?;
            let handoff_hash = take_digest(&mut input)?;
            let next_committee = take_digest(&mut input)?;
            let next_epoch = take_u64(&mut input)?;
            let snapshot = decode_snapshot(&mut input)?;
            finish(input)?;
            if is_zero(&handoff_hash) {
                return Err("retirement WAL record has zero handoff digest; fail closed".into());
            }
            if next_committee == expected_committee {
                return Err("retirement WAL retains same committee; fail closed".into());
            }
            if next_epoch != expected_epoch.checked_add(1).ok_or("epoch overflow in WAL")? {
                return Err("retirement WAL skips the direct next epoch; fail closed".into());
            }
            if snapshot != state.current_snapshot {
                return Err("retirement snapshot does not equal durable state; fail closed".into());
            }
            state.lifecycle = Lifecycle::Retired;
            state.retirement = Some(RetirementRecord {
                handoff_hash,
                next_committee,
                next_epoch,
                snapshot,
            });
        }
        KIND_INITIALIZE => {
            return Err("duplicate initialization record; fail closed".into());
        }
        _ => return Err("unknown WAL record kind; fail closed".into()),
    }
    Ok(())
}

fn require_active(state: &ReplayState, record: &str) -> Result<(), String> {
    if state.lifecycle == Lifecycle::Active {
        Ok(())
    } else {
        Err(format!("{record} while committee was not active; fail closed"))
    }
}

fn append_record(file: &mut File, sequence: u64, kind: u8, payload: &[u8]) -> Result<(), String> {
    if payload.len() > MAX_PAYLOAD_BYTES || payload.len() > u32::MAX as usize {
        return Err("WAL payload exceeds safety limit".into());
    }
    let mut header = [0u8; HEADER_LEN];
    header[0..8].copy_from_slice(&WAL_MAGIC);
    header[8..10].copy_from_slice(&WAL_VERSION.to_le_bytes());
    header[10] = kind;
    header[11] = 0;
    header[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    header[16..24].copy_from_slice(&sequence.to_le_bytes());
    let checksum = wal_checksum(&header, payload);

    file.write_all(&header).map_err(|e| format!("append WAL header: {e}"))?;
    file.write_all(payload).map_err(|e| format!("append WAL payload: {e}"))?;
    file.write_all(&checksum).map_err(|e| format!("append WAL checksum: {e}"))?;
    // A successful method return means the decision is past the OS durability
    // boundary used by this experiment.
    file.sync_all().map_err(|e| format!("sync WAL before success: {e}"))
}

fn wal_checksum(header: &[u8], payload: &[u8]) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(b"CALIBRE_INTEGRATION001_APPEND_ONLY_WAL_CHECKSUM_V1");
    hasher.update(header);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn encode_snapshot(snapshot: &Snapshot) -> Result<Vec<u8>, String> {
    if snapshot.bytes.len() > MAX_SNAPSHOT_BYTES || snapshot.bytes.len() > u32::MAX as usize {
        return Err("snapshot exceeds safety limit".into());
    }
    let mut out = Vec::with_capacity(76 + snapshot.bytes.len());
    put_digest(&mut out, &snapshot.committee_hash);
    put_u64(&mut out, snapshot.epoch);
    put_digest(&mut out, &snapshot.state_root);
    put_u32(&mut out, snapshot.bytes.len() as u32);
    out.extend_from_slice(&snapshot.bytes);
    Ok(out)
}

fn decode_snapshot_exact(payload: &[u8]) -> Result<Snapshot, String> {
    let mut input = payload;
    let snapshot = decode_snapshot(&mut input)?;
    finish(input)?;
    Ok(snapshot)
}

fn decode_snapshot(input: &mut &[u8]) -> Result<Snapshot, String> {
    let committee_hash = take_digest(input)?;
    let epoch = take_u64(input)?;
    let state_root = take_digest(input)?;
    let len = take_u32(input)? as usize;
    if len > MAX_SNAPSHOT_BYTES {
        return Err("snapshot in WAL exceeds safety limit; fail closed".into());
    }
    let bytes = take(input, len)?.to_vec();
    Ok(Snapshot { committee_hash, epoch, state_root, bytes })
}

fn validate_snapshot(snapshot: &Snapshot, committee: &Digest, epoch: u64) -> Result<(), String> {
    if &snapshot.committee_hash != committee {
        return Err("snapshot committee does not match this WAL".into());
    }
    if snapshot.epoch != epoch {
        return Err("snapshot epoch does not match this WAL".into());
    }
    if snapshot.bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err("snapshot exceeds safety limit".into());
    }
    Ok(())
}

fn validate_phase(phase: u8) -> Result<(), String> {
    if phase == PHASE_PREVOTE || phase == PHASE_PRECOMMIT {
        Ok(())
    } else {
        Err("unknown vote phase".into())
    }
}

fn is_zero(digest: &Digest) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

fn put_digest(out: &mut Vec<u8>, value: &Digest) {
    out.extend_from_slice(value);
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], String> {
    if input.len() < len {
        return Err("truncated WAL payload; fail closed".into());
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}

fn take_u8(input: &mut &[u8]) -> Result<u8, String> {
    Ok(take(input, 1)?[0])
}

fn take_u32(input: &mut &[u8]) -> Result<u32, String> {
    let raw: [u8; 4] = take(input, 4)?
        .try_into()
        .map_err(|_| "invalid u32 in WAL payload".to_string())?;
    Ok(u32::from_le_bytes(raw))
}

fn take_u64(input: &mut &[u8]) -> Result<u64, String> {
    let raw: [u8; 8] = take(input, 8)?
        .try_into()
        .map_err(|_| "invalid u64 in WAL payload".to_string())?;
    Ok(u64::from_le_bytes(raw))
}

fn take_digest(input: &mut &[u8]) -> Result<Digest, String> {
    take(input, 32)?
        .try_into()
        .map_err(|_| "invalid digest in WAL payload".to_string())
}

fn finish(input: &[u8]) -> Result<(), String> {
    if input.is_empty() {
        Ok(())
    } else {
        Err("trailing bytes in WAL payload; fail closed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TestDir {
        path: std::path::PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "calibre-integration001-store-{label}-{}-{now}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn wal(&self, name: &str) -> std::path::PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn snapshot(committee: Digest, epoch: u64, root: u8, payload: &[u8]) -> Snapshot {
        Snapshot {
            committee_hash: committee,
            epoch,
            state_root: [root; 32],
            bytes: payload.to_vec(),
        }
    }

    fn active_store(path: &Path) -> WalStore {
        let committee = [1; 32];
        let genesis = snapshot(committee, 7, 2, b"genesis");
        let mut store = WalStore::open(path, committee, 7, Some(genesis.clone())).unwrap();
        assert_eq!(store.lifecycle(), Lifecycle::Initialized);
        assert_eq!(store.activate([3; 32], genesis).unwrap(), PersistOutcome::Persisted);
        store
    }

    #[test]
    fn lifecycle_votes_apply_retire_and_restart() {
        let dir = TestDir::new("lifecycle");
        let path = dir.wal("node.wal");
        let committee = [1; 32];
        let next_committee = [9; 32];
        let conflict = [4; 32];
        let mut store = active_store(&path);

        assert_eq!(
            store.persist_vote(conflict, 11, PHASE_PREVOTE, [5; 32]).unwrap(),
            PersistOutcome::Persisted
        );
        assert_eq!(
            store.persist_vote(conflict, 11, PHASE_PRECOMMIT, [5; 32]).unwrap(),
            PersistOutcome::Persisted
        );
        let next = snapshot(committee, 7, 6, b"after-certified-payment");
        assert_eq!(
            store.apply_verified([7; 32], [8; 32], next.clone()).unwrap(),
            PersistOutcome::Persisted
        );
        assert_eq!(
            store.retire([10; 32], next_committee, 8, next.state_root).unwrap(),
            PersistOutcome::Persisted
        );
        assert_eq!(store.lifecycle(), Lifecycle::Retired);
        drop(store);

        let reopened = WalStore::open(&path, committee, 7, None).unwrap();
        assert_eq!(reopened.lifecycle(), Lifecycle::Retired);
        assert_eq!(reopened.current_snapshot(), &next);
        assert_eq!(reopened.precommit_lock(conflict).unwrap().digest, [5; 32]);
        assert!(reopened.applied_record([7; 32]).is_some());
        assert_eq!(reopened.retirement().unwrap().next_committee, next_committee);
    }

    #[test]
    fn vote_choice_and_precommit_lock_are_durable_and_monotonic() {
        let dir = TestDir::new("votes");
        let path = dir.wal("node.wal");
        let conflict = [21; 32];
        let digest = [22; 32];
        let mut store = active_store(&path);
        assert_eq!(
            store.persist_vote(conflict, 5, PHASE_PRECOMMIT, digest).unwrap(),
            PersistOutcome::Persisted
        );
        assert_eq!(
            store.persist_vote(conflict, 5, PHASE_PRECOMMIT, digest).unwrap(),
            PersistOutcome::AlreadyPresent
        );
        assert!(store.persist_vote(conflict, 5, PHASE_PRECOMMIT, [23; 32]).is_err());
        assert!(store.persist_vote(conflict, 4, PHASE_PREVOTE, digest).is_err());
        assert!(store.persist_vote(conflict, 6, PHASE_PREVOTE, [23; 32]).is_err());
        assert_eq!(
            store.persist_vote(conflict, 6, PHASE_PRECOMMIT, digest).unwrap(),
            PersistOutcome::Persisted
        );
        drop(store);

        let reopened = WalStore::open(&path, [1; 32], 7, None).unwrap();
        assert_eq!(
            reopened.precommit_lock(conflict),
            Some(PrecommitLock { round: 6, digest })
        );
    }

    #[test]
    fn verified_apply_is_idempotent_but_bare_or_conflicting_advance_fails() {
        let dir = TestDir::new("apply");
        let path = dir.wal("node.wal");
        let mut store = active_store(&path);
        let next = snapshot([1; 32], 7, 31, b"certified-state");
        assert!(store.apply_verified([0; 32], [30; 32], next.clone()).is_err());
        assert!(store.apply_verified([29; 32], [0; 32], next.clone()).is_err());
        assert_eq!(
            store.apply_verified([29; 32], [30; 32], next.clone()).unwrap(),
            PersistOutcome::Persisted
        );
        assert_eq!(
            store.apply_verified([29; 32], [30; 32], next.clone()).unwrap(),
            PersistOutcome::AlreadyPresent
        );
        assert!(store
            .apply_verified([29; 32], [30; 32], snapshot([1; 32], 7, 32, b"fork"))
            .is_err());
        assert!(store.apply_verified([33; 32], [34; 32], next).is_err());
    }

    #[test]
    fn retirement_is_terminal_and_cannot_resurrect_genesis() {
        let dir = TestDir::new("terminal");
        let path = dir.wal("node.wal");
        let committee = [1; 32];
        let mut store = active_store(&path);
        let root = store.current_snapshot().state_root;
        assert_eq!(
            store.retire([40; 32], [41; 32], 8, root).unwrap(),
            PersistOutcome::Persisted
        );
        assert_eq!(
            store.retire([40; 32], [41; 32], 8, root).unwrap(),
            PersistOutcome::AlreadyPresent
        );
        assert!(store.persist_vote([42; 32], 1, PHASE_PREVOTE, [43; 32]).is_err());
        assert!(store
            .activate([44; 32], snapshot(committee, 7, 2, b"genesis"))
            .is_err());
        drop(store);

        let supplied_genesis = snapshot(committee, 7, 2, b"genesis");
        let reopened = WalStore::open(&path, committee, 7, Some(supplied_genesis)).unwrap();
        assert_eq!(reopened.lifecycle(), Lifecycle::Retired);
    }

    #[test]
    fn torn_and_checksum_mutated_wals_fail_closed() {
        let dir = TestDir::new("damage");
        let good_path = dir.wal("good.wal");
        let store = active_store(&good_path);
        drop(store);
        let good = fs::read(&good_path).unwrap();

        let torn_path = dir.wal("torn.wal");
        let mut torn = good.clone();
        torn.pop();
        fs::write(&torn_path, torn).unwrap();
        let torn_error = WalStore::open(&torn_path, [1; 32], 7, None)
            .err()
            .unwrap();
        assert!(torn_error.contains("incomplete"));

        let corrupt_path = dir.wal("corrupt.wal");
        let mut corrupt = good;
        corrupt[HEADER_LEN + 1] ^= 0x80;
        fs::write(&corrupt_path, corrupt).unwrap();
        let corrupt_error = WalStore::open(&corrupt_path, [1; 32], 7, None)
            .err()
            .unwrap();
        assert!(corrupt_error.contains("checksum"));
    }

    #[test]
    fn initialization_and_activation_are_separate_fail_closed_steps() {
        let dir = TestDir::new("initialization");
        let path = dir.wal("node.wal");
        let committee = [50; 32];
        let genesis = snapshot(committee, 12, 51, b"provisioned");
        let mut store = WalStore::open(&path, committee, 12, Some(genesis.clone())).unwrap();
        assert_eq!(store.lifecycle(), Lifecycle::Initialized);
        assert!(store.persist_vote([52; 32], 1, PHASE_PREVOTE, [53; 32]).is_err());
        drop(store);

        let mut reopened = WalStore::open(&path, committee, 12, None).unwrap();
        assert_eq!(reopened.lifecycle(), Lifecycle::Initialized);
        assert_eq!(
            reopened.activate([54; 32], genesis.clone()).unwrap(),
            PersistOutcome::Persisted
        );
        assert_eq!(
            reopened.activate([54; 32], genesis).unwrap(),
            PersistOutcome::AlreadyPresent
        );
    }
}
