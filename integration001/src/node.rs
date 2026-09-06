//! Real loopback validator process for the bounded INTEGRATION-001 live gate.
//!
//! Each child owns one signing key, one TCP listener, and one append-only WAL.
//! Honest votes are synced to the WAL before their signatures leave the
//! process.  Byzantine fixture nodes are intentionally allowed to sign an
//! arbitrary request statement, but they never bypass validation in the state
//! application path; two malicious shares cannot make an invalid transfer a
//! valid five-share certificate.

use crate::model::{
    ApplyOutcome, CommitteeManifest, Digest, Proposal, Qc, State, Tx, UserAuth,
    committee_hash, conflict_key, lab_committee, lab_validator_key, qc_digest, sign_vote,
    intent_hash, validate_cell, verify_proposal, verify_qc, PHASE_PRECOMMIT, PHASE_PREVOTE,
};
use crate::store::{Lifecycle, PersistOutcome, Snapshot, WalStore};
use crate::wire::{
    MAX_FRAME_LEN, Request, Response, decode_request, decode_state, encode_qc, encode_response,
    encode_state, read_frame, write_frame,
};
use blake3::Hasher;
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const REJECT_BAD_FRAME: u16 = 1;
pub const REJECT_BAD_REQUEST: u16 = 2;
pub const REJECT_INVALID_PROPOSAL: u16 = 10;
pub const REJECT_INPUT_NOT_LIVE: u16 = 11;
pub const REJECT_INVALID_PREVOTE_QC: u16 = 12;
pub const REJECT_LOCAL_PREVOTE_MISSING: u16 = 13;
pub const REJECT_DURABLE_LOCK: u16 = 14;
pub const REJECT_SIGNING: u16 = 15;
pub const REJECT_INVALID_FINALITY: u16 = 20;
pub const REJECT_STATE_APPLY: u16 = 21;
pub const REJECT_STATE_PERSIST: u16 = 22;
pub const REJECT_QUERY: u16 = 30;

const NODE_ARG_COUNT: usize = 6;
const IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeConfig {
    epoch: u64,
    index: u8,
    port: u16,
    wal_path: PathBuf,
    snapshot_path: PathBuf,
    byzantine: bool,
}

impl NodeConfig {
    /// Parses the six positional arguments following the internal `--node`
    /// discriminator:
    ///
    /// `<epoch> <index> <port> <wal-path> <initial-state-path> <0|1>`.
    fn parse(args: &[String]) -> Result<Self, String> {
        if args.len() != NODE_ARG_COUNT {
            return Err(format!(
                "internal node mode requires exactly {NODE_ARG_COUNT} arguments"
            ));
        }
        let epoch = parse_nonzero::<u64>(&args[0], "epoch")?;
        let index = args[1]
            .parse::<u8>()
            .map_err(|_| "node index is not a u8".to_string())?;
        if index as usize >= crate::model::N {
            return Err("node index is not a committee member".into());
        }
        let port = parse_nonzero::<u16>(&args[2], "port")?;
        if args[3].is_empty() || args[4].is_empty() {
            return Err("WAL and initial-state paths must be nonempty".into());
        }
        let wal_path = PathBuf::from(&args[3]);
        let snapshot_path = PathBuf::from(&args[4]);
        if wal_path == snapshot_path {
            return Err("WAL and initial-state paths must be distinct".into());
        }
        let byzantine = match args[5].as_str() {
            "0" => false,
            "1" => true,
            _ => return Err("Byzantine marker must be exactly 0 or 1".into()),
        };
        Ok(Self {
            epoch,
            index,
            port,
            wal_path,
            snapshot_path,
            byzantine,
        })
    }
}

fn parse_nonzero<T>(raw: &str, label: &str) -> Result<T, String>
where
    T: std::str::FromStr + Default + PartialEq,
{
    let value = raw
        .parse::<T>()
        .map_err(|_| format!("{label} is not a valid integer"))?;
    if value == T::default() {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug)]
struct NodeRejection {
    code: u16,
}

impl NodeRejection {
    const fn new(code: u16) -> Self {
        Self { code }
    }
}

struct NodeServer {
    index: u8,
    byzantine: bool,
    committee_hash: Digest,
    manifest: CommitteeManifest,
    signing_key: SigningKey,
    state: State,
    store: WalStore,
}

impl NodeServer {
    fn open(config: &NodeConfig) -> Result<Self, String> {
        let manifest = lab_committee(config.epoch);
        let committee_hash = committee_hash(&manifest)?;
        let signing_key = lab_validator_key(config.epoch, config.index as usize);
        let member = manifest
            .members
            .get(config.index as usize)
            .ok_or("node index missing from fixture committee")?;
        if member.index != config.index
            || member.public_key != signing_key.verifying_key().to_bytes()
        {
            return Err("fixture key does not match node committee slot".into());
        }

        let initial_bytes = read_bounded_snapshot(&config.snapshot_path)?;
        let initial_state = decode_state(&initial_bytes)
            .map_err(|error| format!("decode initial state: {error}"))?;
        validate_state_shape(&initial_state)?;
        validate_pure_genesis(&initial_state)?;
        let initial_snapshot = Snapshot {
            committee_hash,
            epoch: config.epoch,
            state_root: initial_state.root(),
            bytes: initial_bytes,
        };

        let mut store = WalStore::open(
            &config.wal_path,
            committee_hash,
            config.epoch,
            Some(initial_snapshot.clone()),
        )?;
        if store.lifecycle() == Lifecycle::Initialized {
            store.activate(
                genesis_activation_digest(
                    committee_hash,
                    config.epoch,
                    initial_snapshot.state_root,
                ),
                initial_snapshot,
            )?;
        }

        let durable = store.current_snapshot();
        let state = decode_state(&durable.bytes)
            .map_err(|error| format!("decode durable state: {error}"))?;
        validate_state_shape(&state)?;
        if durable.committee_hash != committee_hash
            || durable.epoch != config.epoch
            || durable.state_root != state.root()
        {
            return Err("durable state wrapper does not match canonical state bytes".into());
        }
        reconcile_state_with_wal(&state, &store)?;

        Ok(Self {
            index: config.index,
            byzantine: config.byzantine,
            committee_hash,
            manifest,
            signing_key,
            state,
            store,
        })
    }

    fn handle(&mut self, request: Request) -> Result<(Response, bool), NodeRejection> {
        match request {
            Request::Ping => Ok((
                Response::Pong {
                    index: self.index,
                    epoch: self.manifest.epoch,
                    committee_hash: self.committee_hash,
                },
                false,
            )),
            Request::Prevote(proposal) => self.prevote(proposal).map(|vote| {
                (Response::Vote(vote), false)
            }),
            Request::Precommit {
                proposal,
                prevote_qc,
            } => self.precommit(proposal, prevote_qc).map(|vote| {
                (Response::Vote(vote), false)
            }),
            Request::Apply {
                tx,
                auth,
                prevote_qc,
                finality_qc,
            } => self
                .apply(tx, auth, prevote_qc, finality_qc)
                .map(|(state_root, idempotent)| {
                    (
                        Response::Applied {
                            state_root,
                            idempotent,
                        },
                        false,
                    )
                }),
            Request::QueryState => {
                let snapshot_bytes = u64::try_from(self.store.current_snapshot().bytes.len())
                    .map_err(|_| NodeRejection::new(REJECT_QUERY))?;
                let wal_bytes = self
                    .store
                    .wal_bytes()
                    .map_err(|_| NodeRejection::new(REJECT_QUERY))?;
                Ok((
                    Response::State {
                        state_root: self.state.root(),
                        snapshot_bytes,
                        wal_bytes,
                        lifecycle: self.store.lifecycle(),
                    },
                    false,
                ))
            }
        }
    }

    fn prevote(&mut self, proposal: Proposal) -> Result<crate::model::Vote, NodeRejection> {
        let conflict = conflict_key(proposal.tx.input.reference);
        if self.byzantine {
            // The two fixture adversaries can sign a malformed proposal or both
            // sides of a conflict.  Their valid validator signatures still
            // carry only two distinct committee identities.
            return sign_vote(
                &self.manifest,
                PHASE_PREVOTE,
                proposal.round,
                conflict,
                proposal.intent,
                [0; 32],
                self.index,
                &self.signing_key,
            )
            .map_err(|_| NodeRejection::new(REJECT_SIGNING));
        }

        self.validate_live_proposal(&proposal)?;
        self.store
            .persist_vote(conflict, proposal.round, PHASE_PREVOTE, proposal.intent)
            .map_err(|_| NodeRejection::new(REJECT_DURABLE_LOCK))?;
        sign_vote(
            &self.manifest,
            PHASE_PREVOTE,
            proposal.round,
            conflict,
            proposal.intent,
            [0; 32],
            self.index,
            &self.signing_key,
        )
        .map_err(|_| NodeRejection::new(REJECT_SIGNING))
    }

    fn precommit(
        &mut self,
        proposal: Proposal,
        prevote_qc: Qc,
    ) -> Result<crate::model::Vote, NodeRejection> {
        let conflict = conflict_key(proposal.tx.input.reference);
        let prevote_qc_digest = if self.byzantine {
            // Cooperate with a valid QC so Byzantine shares can participate
            // in the ordinary path; otherwise bind the exact malformed bytes
            // while continuing to model an arbitrary signer.
            match qc_digest(&prevote_qc, &self.manifest) {
                Ok(digest) => digest,
                Err(_) => adversarial_qc_digest(&prevote_qc)
                    .map_err(|_| NodeRejection::new(REJECT_SIGNING))?,
            }
        } else {
            self.validate_live_proposal(&proposal)?;
            verify_qc(
                &prevote_qc,
                &self.manifest,
                PHASE_PREVOTE,
                proposal.round,
                conflict,
                proposal.intent,
                None,
            )
            .map_err(|_| NodeRejection::new(REJECT_INVALID_PREVOTE_QC))?;
            let digest = qc_digest(&prevote_qc, &self.manifest)
                .map_err(|_| NodeRejection::new(REJECT_INVALID_PREVOTE_QC))?;
            if self.store.vote_digest(conflict, proposal.round, PHASE_PREVOTE)
                != Some(proposal.intent)
            {
                return Err(NodeRejection::new(REJECT_LOCAL_PREVOTE_MISSING));
            }
            self.store
                .persist_vote(conflict, proposal.round, PHASE_PRECOMMIT, proposal.intent)
                .map_err(|_| NodeRejection::new(REJECT_DURABLE_LOCK))?;
            digest
        };

        sign_vote(
            &self.manifest,
            PHASE_PRECOMMIT,
            proposal.round,
            conflict,
            proposal.intent,
            prevote_qc_digest,
            self.index,
            &self.signing_key,
        )
        .map_err(|_| NodeRejection::new(REJECT_SIGNING))
    }

    fn validate_live_proposal(&self, proposal: &Proposal) -> Result<(), NodeRejection> {
        verify_proposal(proposal, &self.manifest)
            .map_err(|_| NodeRejection::new(REJECT_INVALID_PROPOSAL))?;
        if self.state.live_cell(proposal.tx.input.reference) != Some(&proposal.tx.input) {
            return Err(NodeRejection::new(REJECT_INPUT_NOT_LIVE));
        }
        Ok(())
    }

    fn apply(
        &mut self,
        tx: Tx,
        auth: UserAuth,
        prevote_qc: Qc,
        finality_qc: Qc,
    ) -> Result<(Digest, bool), NodeRejection> {
        // `State::apply_finalized` revalidates transaction structure, owner
        // authorization, exact live input, five unique member signatures, and
        // the complete PRECOMMIT statement.  We additionally verify the
        // supplied PREVOTE QC and its exact digest link from every PRECOMMIT,
        // making the certificate self-contained at the state boundary.
        // Byzantine mode never bypasses this verifier/state boundary.
        self.verify_finality_chain(&tx, &prevote_qc, &finality_qc)?;
        let mut next = self.state.clone();
        match next
            .apply_finalized(
                &tx,
                &auth,
                &prevote_qc,
                &finality_qc,
                &self.manifest,
            )
            .map_err(|_| NodeRejection::new(REJECT_INVALID_FINALITY))?
        {
            ApplyOutcome::AlreadyApplied(_) => Ok((self.state.root(), true)),
            ApplyOutcome::Applied(receipt) => {
                validate_state_shape(&next)
                    .map_err(|_| NodeRejection::new(REJECT_STATE_APPLY))?;
                let bytes = encode_state(&next)
                    .map_err(|_| NodeRejection::new(REJECT_STATE_APPLY))?;
                let next_snapshot = Snapshot {
                    committee_hash: self.committee_hash,
                    epoch: self.manifest.epoch,
                    state_root: next.root(),
                    bytes,
                };
                match self
                    .store
                    .apply_verified(
                        receipt.intent,
                        receipt.certificate_digest,
                        next_snapshot,
                    )
                    .map_err(|_| NodeRejection::new(REJECT_STATE_PERSIST))?
                {
                    PersistOutcome::Persisted => {
                        self.state = next;
                        Ok((self.state.root(), false))
                    }
                    PersistOutcome::AlreadyPresent => {
                        // This can only follow a matching durable application.
                        // Keep memory synchronized with the bytes just checked.
                        self.state = next;
                        Ok((self.state.root(), true))
                    }
                }
            }
        }
    }

    fn verify_finality_chain(
        &self,
        tx: &Tx,
        prevote_qc: &Qc,
        finality_qc: &Qc,
    ) -> Result<(), NodeRejection> {
        let intent = intent_hash(tx)
            .map_err(|_| NodeRejection::new(REJECT_INVALID_FINALITY))?;
        let conflict = conflict_key(tx.input.reference);
        let round = prevote_qc
            .votes
            .first()
            .ok_or_else(|| NodeRejection::new(REJECT_INVALID_FINALITY))?
            .round;
        verify_qc(
            prevote_qc,
            &self.manifest,
            PHASE_PREVOTE,
            round,
            conflict,
            intent,
            None,
        )
        .map_err(|_| NodeRejection::new(REJECT_INVALID_FINALITY))?;
        let prevote_digest = qc_digest(prevote_qc, &self.manifest)
            .map_err(|_| NodeRejection::new(REJECT_INVALID_FINALITY))?;
        verify_qc(
            finality_qc,
            &self.manifest,
            PHASE_PRECOMMIT,
            round,
            conflict,
            intent,
            Some(prevote_digest),
        )
        .map_err(|_| NodeRejection::new(REJECT_INVALID_FINALITY))
    }
}

fn read_bounded_snapshot(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("inspect initial state: {error}"))?;
    let max = u64::try_from(MAX_FRAME_LEN).expect("wire bound fits u64");
    if metadata.len() > max {
        return Err(format!("initial state exceeds {MAX_FRAME_LEN} bytes"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(|error| format!("open initial state: {error}"))?
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read initial state: {error}"))?;
    if bytes.len() > MAX_FRAME_LEN {
        return Err(format!("initial state exceeds {MAX_FRAME_LEN} bytes"));
    }
    Ok(bytes)
}

fn validate_state_shape(state: &State) -> Result<(), String> {
    state.validate()?;
    let mut referenced_ids = BTreeSet::new();
    for (reference, cell) in &state.live {
        if reference != &cell.reference {
            return Err("state live-map key does not match embedded cell".into());
        }
        validate_cell(cell)?;
        if !referenced_ids.insert(reference.id) {
            return Err("two state references share one identifier".into());
        }
        if !state.known_ids.contains(&reference.id) {
            return Err("live cell identifier is absent from known-id set".into());
        }
        if state.spent_by.contains_key(reference) {
            return Err("cell is both live and spent".into());
        }
    }
    for (reference, spending_intent) in &state.spent_by {
        if !referenced_ids.insert(reference.id) {
            return Err("live/spent references share one identifier".into());
        }
        if !state.known_ids.contains(&reference.id) {
            return Err("spent cell identifier is absent from known-id set".into());
        }
        if !state.applied.contains_key(spending_intent) {
            return Err("spent-by intent has no applied receipt".into());
        }
    }
    if referenced_ids != state.known_ids {
        return Err("known-id set does not exactly match live and spent state".into());
    }
    let mut receipt_outputs = BTreeSet::new();
    for (intent, receipt) in &state.applied {
        if intent != &receipt.intent {
            return Err("applied receipt map key does not match intent".into());
        }
        if receipt.certificate_digest == [0; 32] {
            return Err("applied receipt has a zero certificate digest".into());
        }
        if receipt.output_refs.is_empty() {
            return Err("applied receipt has no materialized outputs".into());
        }
        for reference in &receipt.output_refs {
            if !receipt_outputs.insert(reference.id) {
                return Err("applied receipts repeat an output identifier".into());
            }
            if !state.live.contains_key(reference) && !state.spent_by.contains_key(reference) {
                return Err("applied output is absent from live/spent state".into());
            }
        }
    }
    Ok(())
}

fn validate_pure_genesis(state: &State) -> Result<(), String> {
    if !state.spent_by.is_empty() || !state.applied.is_empty() {
        return Err("initial-state file must be a pure unspent genesis snapshot".into());
    }
    if state.known_ids.len() != state.live.len() {
        return Err("pure genesis known-id count does not equal live-cell count".into());
    }
    Ok(())
}

fn reconcile_state_with_wal(state: &State, store: &WalStore) -> Result<(), String> {
    if state.applied.len() != store.applied_count() {
        return Err("durable state and WAL disagree on applied transaction count".into());
    }
    for (intent, receipt) in &state.applied {
        let durable = store
            .applied_record(*intent)
            .ok_or("durable state receipt is absent from WAL")?;
        if durable.certificate_digest != receipt.certificate_digest {
            return Err("durable state and WAL disagree on certificate digest".into());
        }
    }
    Ok(())
}

fn genesis_activation_digest(
    committee_hash: Digest,
    epoch: u64,
    state_root: Digest,
) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(b"CALIBRE_INTEGRATION001_GENESIS_ACTIVATION_V1");
    hasher.update(&committee_hash);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&state_root);
    *hasher.finalize().as_bytes()
}

/// Byzantine nodes may bind a PRECOMMIT to malformed QC bytes.  Honest nodes
/// never use this path, and the application verifier still requires a valid
/// five-share PREVOTE/PRECOMMIT chain.
fn adversarial_qc_digest(qc: &Qc) -> Result<Digest, String> {
    let bytes = encode_qc(qc)?;
    let mut hasher = Hasher::new();
    hasher.update(b"CALIBRE_INTEGRATION001_ADVERSARIAL_QC_BYTES_V1");
    hasher.update(&bytes);
    let mut digest = *hasher.finalize().as_bytes();
    if digest == [0; 32] {
        // `sign_vote` requires a nonzero PRECOMMIT justification.  The
        // deterministic substitution keeps even this astronomically unlikely
        // edge case explicit and non-ambiguous.
        digest[0] = 1;
    }
    Ok(digest)
}

fn send_response(stream: &mut TcpStream, response: &Response) -> Result<(), String> {
    let payload = encode_response(response)?;
    write_frame(stream, &payload)
}

fn configure_stream(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set node read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set node write timeout: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("set node TCP_NODELAY: {error}"))
}

fn serve_connection(server: &mut NodeServer, stream: &mut TcpStream) -> bool {
    if configure_stream(stream).is_err() {
        return false;
    }
    let payload = match read_frame(stream) {
        Ok(payload) => payload,
        Err(_) => {
            let _ = send_response(
                stream,
                &Response::Rejected {
                    code: REJECT_BAD_FRAME,
                },
            );
            return false;
        }
    };
    let request = match decode_request(&payload) {
        Ok(request) => request,
        Err(_) => {
            let _ = send_response(
                stream,
                &Response::Rejected {
                    code: REJECT_BAD_REQUEST,
                },
            );
            return false;
        }
    };
    let (response, shutdown) = match server.handle(request) {
        Ok(value) => value,
        Err(rejection) => (
            Response::Rejected {
                code: rejection.code,
            },
            false,
        ),
    };
    let _ = send_response(stream, &response);
    shutdown
}

/// Runs one internal child-node process.
///
/// `args` must be the slice after `--node`; this interface is intentionally
/// internal to the integration binary and rejects any malformed/extra field.
pub fn run_node_from_args(args: &[String]) -> Result<(), String> {
    let config = NodeConfig::parse(args)?;
    let listener = TcpListener::bind(("127.0.0.1", config.port))
        .map_err(|error| format!("bind node {}: {error}", config.index))?;
    let mut server = NodeServer::open(&config)?;
    println!(
        "CALIBRE_NODE_READY index={} epoch={} port={} byzantine={}",
        config.index, config.epoch, config.port, config.byzantine
    );
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        if serve_connection(&mut server, &mut stream) {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn child_arguments_are_exact_and_bounded() {
        let config = NodeConfig::parse(&strings(&[
            "100",
            "6",
            "4242",
            "node.wal",
            "initial.state",
            "1",
        ]))
        .unwrap();
        assert_eq!(config.epoch, 100);
        assert_eq!(config.index, 6);
        assert_eq!(config.port, 4242);
        assert!(config.byzantine);

        for bad in [
            strings(&[]),
            strings(&["0", "0", "1", "w", "s", "0"]),
            strings(&["1", "7", "1", "w", "s", "0"]),
            strings(&["1", "0", "0", "w", "s", "0"]),
            strings(&["1", "0", "1", "w", "w", "0"]),
            strings(&["1", "0", "1", "w", "s", "true"]),
            strings(&["1", "0", "1", "w", "s", "0", "extra"]),
        ] {
            assert!(NodeConfig::parse(&bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn malformed_state_shape_is_rejected() {
        let owner = crate::model::lab_user_key(1)
            .verifying_key()
            .to_bytes();
        let cell = crate::model::make_genesis_cell(1, 100, owner);
        let mut state = State::from_cells(vec![cell.clone()]).unwrap();
        state.known_ids.clear();
        assert!(validate_state_shape(&state).is_err());

        let mut state = State::from_cells(vec![cell]).unwrap();
        state.live.values_mut().next().unwrap().amount += 1;
        assert!(validate_state_shape(&state).is_err());
    }

    #[test]
    fn activation_digest_binds_epoch_committee_and_state() {
        let base = genesis_activation_digest([1; 32], 7, [2; 32]);
        assert_ne!(base, genesis_activation_digest([3; 32], 7, [2; 32]));
        assert_ne!(base, genesis_activation_digest([1; 32], 8, [2; 32]));
        assert_ne!(base, genesis_activation_digest([1; 32], 7, [4; 32]));
    }
}
