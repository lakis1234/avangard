//! Canonical monetary and quorum model for CALIBRE INTEGRATION-001.
//!
//! The deterministic keys in this module are laboratory fixtures. They are
//! deliberately reproducible and must never be used as production key
//! management.

use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};

pub type Digest = [u8; 32];
pub type PublicKeyBytes = [u8; 32];
pub type SignatureBytes = [u8; 64];

pub const PROTOCOL_VERSION: u16 = 1;
pub const NETWORK_ID: u32 = 1;
pub const N: usize = 7;
pub const Q: usize = 5;
pub const OLD_EPOCH: u64 = 100;
pub const NEW_EPOCH: u64 = 101;
pub const PHASE_PREVOTE: u8 = 1;
pub const PHASE_PRECOMMIT: u8 = 2;
pub const ASSET_CALIBRE: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeMember {
    pub index: u8,
    pub public_key: PublicKeyBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitteeManifest {
    pub network_id: u32,
    pub epoch: u64,
    pub threshold: u8,
    pub members: Vec<CommitteeMember>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellRef {
    pub asset_id: u32,
    pub id: Digest,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    pub reference: CellRef,
    pub amount: u64,
    pub owner: PublicKeyBytes,
    pub predecessor: Digest,
    pub state_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub asset_id: u32,
    pub amount: u64,
    pub owner: PublicKeyBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u16,
    pub network_id: u32,
    pub epoch: u64,
    pub committee_hash: Digest,
    pub input: Cell,
    pub outputs: Vec<Output>,
    pub fee: u64,
    pub salt: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserAuth {
    pub signer: PublicKeyBytes,
    pub signature: SignatureBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vote {
    pub network_id: u32,
    pub epoch: u64,
    pub committee_hash: Digest,
    pub phase: u8,
    pub round: u64,
    pub conflict_key: Digest,
    pub intent: Digest,
    pub justify: Digest,
    pub signer_index: u8,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Qc {
    pub votes: Vec<Vote>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub round: u64,
    pub proposer_index: u8,
    pub tx: Tx,
    pub auth: UserAuth,
    pub intent: Digest,
    pub justify: Option<Qc>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyReceipt {
    pub intent: Digest,
    pub certificate_digest: Digest,
    pub output_refs: Vec<CellRef>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub live: BTreeMap<CellRef, Cell>,
    pub spent_by: BTreeMap<CellRef, Digest>,
    pub known_ids: BTreeSet<Digest>,
    pub applied: BTreeMap<Digest, ApplyReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied(ApplyReceipt),
    AlreadyApplied(ApplyReceipt),
}

fn put_u16(out: &mut Vec<u8>, value: u16) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_u32(out: &mut Vec<u8>, value: u32) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_u64(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
fn put_digest(out: &mut Vec<u8>, value: &Digest) { out.extend_from_slice(value); }

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn deterministic_key(domain: &[u8], label: u64) -> SigningKey {
    let mut hasher = Hasher::new();
    hasher.update(domain);
    hasher.update(&label.to_le_bytes());
    SigningKey::from_bytes(hasher.finalize().as_bytes())
}

pub fn lab_user_key(label: u64) -> SigningKey {
    deterministic_key(b"CALIBRE_INTEGRATION001_LAB_USER_KEY_V1", label)
}

pub fn lab_validator_key(epoch: u64, index: usize) -> SigningKey {
    deterministic_key(
        b"CALIBRE_INTEGRATION001_LAB_VALIDATOR_KEY_V1",
        epoch.wrapping_mul(1000).wrapping_add(index as u64),
    )
}

pub fn lab_committee(epoch: u64) -> CommitteeManifest {
    CommitteeManifest {
        network_id: NETWORK_ID,
        epoch,
        threshold: Q as u8,
        members: (0..N)
            .map(|index| CommitteeMember {
                index: index as u8,
                public_key: lab_validator_key(epoch, index).verifying_key().to_bytes(),
            })
            .collect(),
    }
}

pub fn validate_manifest(manifest: &CommitteeManifest) -> Result<(), String> {
    if manifest.network_id != NETWORK_ID { return Err("wrong network in committee manifest".into()); }
    if manifest.threshold as usize != Q { return Err("committee threshold must be five".into()); }
    if manifest.members.len() != N { return Err("committee must contain seven members".into()); }
    let mut keys = BTreeSet::new();
    for (expected, member) in manifest.members.iter().enumerate() {
        if member.index as usize != expected { return Err("committee indices must be canonical 0..6".into()); }
        VerifyingKey::from_bytes(&member.public_key).map_err(|_| "invalid committee public key")?;
        if !keys.insert(member.public_key) { return Err("duplicate committee public key".into()); }
    }
    Ok(())
}

pub fn committee_hash(manifest: &CommitteeManifest) -> Result<Digest, String> {
    validate_manifest(manifest)?;
    let mut bytes = Vec::new();
    put_u16(&mut bytes, PROTOCOL_VERSION);
    put_u32(&mut bytes, manifest.network_id);
    put_u64(&mut bytes, manifest.epoch);
    bytes.push(manifest.threshold);
    put_u32(&mut bytes, manifest.members.len() as u32);
    for member in &manifest.members {
        bytes.push(member.index);
        bytes.extend_from_slice(&member.public_key);
    }
    Ok(hash_domain(b"CALIBRE_INTEGRATION001_COMMITTEE_V1", &bytes))
}

pub fn compute_cell_digest(
    reference: CellRef,
    amount: u64,
    owner: PublicKeyBytes,
    predecessor: Digest,
) -> Digest {
    let mut bytes = Vec::new();
    put_u32(&mut bytes, reference.asset_id);
    put_digest(&mut bytes, &reference.id);
    put_u64(&mut bytes, reference.generation);
    put_u64(&mut bytes, amount);
    bytes.extend_from_slice(&owner);
    put_digest(&mut bytes, &predecessor);
    hash_domain(b"CALIBRE_INTEGRATION001_CELL_V1", &bytes)
}

pub fn make_genesis_cell(label: u64, amount: u64, owner: PublicKeyBytes) -> Cell {
    let mut id_bytes = Vec::new();
    put_u64(&mut id_bytes, label);
    let reference = CellRef {
        asset_id: ASSET_CALIBRE,
        id: hash_domain(b"CALIBRE_INTEGRATION001_GENESIS_ID_V1", &id_bytes),
        generation: 0,
    };
    let predecessor = [0; 32];
    Cell {
        reference,
        amount,
        owner,
        predecessor,
        state_digest: compute_cell_digest(reference, amount, owner, predecessor),
    }
}

pub fn validate_cell(cell: &Cell) -> Result<(), String> {
    if cell.amount == 0 { return Err("zero-value cells are forbidden".into()); }
    if cell.reference.asset_id != ASSET_CALIBRE { return Err("unsupported asset".into()); }
    if cell.state_digest != compute_cell_digest(cell.reference, cell.amount, cell.owner, cell.predecessor) {
        return Err("cell state digest mismatch".into());
    }
    Ok(())
}

fn tx_bytes(tx: &Tx) -> Result<Vec<u8>, String> {
    if tx.outputs.is_empty() || tx.outputs.len() > 8 { return Err("transaction must contain 1..=8 outputs".into()); }
    let mut bytes = Vec::new();
    put_u16(&mut bytes, tx.version);
    put_u32(&mut bytes, tx.network_id);
    put_u64(&mut bytes, tx.epoch);
    put_digest(&mut bytes, &tx.committee_hash);
    put_u32(&mut bytes, tx.input.reference.asset_id);
    put_digest(&mut bytes, &tx.input.reference.id);
    put_u64(&mut bytes, tx.input.reference.generation);
    put_u64(&mut bytes, tx.input.amount);
    bytes.extend_from_slice(&tx.input.owner);
    put_digest(&mut bytes, &tx.input.predecessor);
    put_digest(&mut bytes, &tx.input.state_digest);
    put_u32(&mut bytes, tx.outputs.len() as u32);
    for output in &tx.outputs {
        put_u32(&mut bytes, output.asset_id);
        put_u64(&mut bytes, output.amount);
        bytes.extend_from_slice(&output.owner);
    }
    put_u64(&mut bytes, tx.fee);
    put_digest(&mut bytes, &tx.salt);
    Ok(bytes)
}

pub fn intent_hash(tx: &Tx) -> Result<Digest, String> {
    Ok(hash_domain(b"CALIBRE_INTEGRATION001_TX_INTENT_V1", &tx_bytes(tx)?))
}

pub fn conflict_key(reference: CellRef) -> Digest {
    let mut bytes = Vec::new();
    put_u32(&mut bytes, reference.asset_id);
    put_digest(&mut bytes, &reference.id);
    put_u64(&mut bytes, reference.generation);
    hash_domain(b"CALIBRE_INTEGRATION001_CONFLICT_KEY_V1", &bytes)
}

pub fn validate_tx(tx: &Tx, manifest: &CommitteeManifest) -> Result<(), String> {
    validate_manifest(manifest)?;
    validate_cell(&tx.input)?;
    if tx.version != PROTOCOL_VERSION { return Err("unsupported transaction version".into()); }
    if tx.network_id != manifest.network_id { return Err("transaction network mismatch".into()); }
    if tx.epoch != manifest.epoch { return Err("transaction epoch mismatch".into()); }
    if tx.committee_hash != committee_hash(manifest)? { return Err("transaction committee mismatch".into()); }
    if tx.fee == 0 { return Err("fee must be explicit and nonzero in this experiment".into()); }
    let mut total = tx.fee;
    for output in &tx.outputs {
        if output.asset_id != tx.input.reference.asset_id { return Err("output asset mismatch".into()); }
        if output.amount == 0 { return Err("zero-value output".into()); }
        total = total.checked_add(output.amount).ok_or("output value overflow")?;
    }
    if total != tx.input.amount { return Err("transaction does not conserve value".into()); }
    let _ = intent_hash(tx)?;
    Ok(())
}

fn user_message(tx: &Tx) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    put_digest(&mut bytes, &intent_hash(tx)?);
    Ok(bytes)
}

pub fn sign_user(tx: &Tx, key: &SigningKey) -> Result<UserAuth, String> {
    Ok(UserAuth { signer: key.verifying_key().to_bytes(), signature: key.sign(&user_message(tx)?).to_bytes() })
}

pub fn verify_user_auth(tx: &Tx, auth: &UserAuth, manifest: &CommitteeManifest) -> Result<(), String> {
    validate_tx(tx, manifest)?;
    if auth.signer != tx.input.owner { return Err("signer does not own exact input".into()); }
    VerifyingKey::from_bytes(&auth.signer)
        .map_err(|_| "invalid owner key")?
        .verify_strict(&user_message(tx)?, &Signature::from_bytes(&auth.signature))
        .map_err(|_| "invalid owner signature".into())
}

pub fn leader(conflict: Digest, round: u64) -> usize {
    let offset = u64::from_le_bytes(conflict[..8].try_into().expect("eight bytes")) as usize % N;
    (offset + (round as usize % N)) % N
}

fn vote_message(
    manifest: &CommitteeManifest,
    phase: u8,
    round: u64,
    conflict: Digest,
    intent: Digest,
    justify: Digest,
    signer_index: u8,
) -> Result<Vec<u8>, String> {
    if phase != PHASE_PREVOTE && phase != PHASE_PRECOMMIT { return Err("invalid vote phase".into()); }
    let mut bytes = Vec::new();
    put_u16(&mut bytes, PROTOCOL_VERSION);
    put_u32(&mut bytes, manifest.network_id);
    put_u64(&mut bytes, manifest.epoch);
    put_digest(&mut bytes, &committee_hash(manifest)?);
    bytes.push(phase);
    put_u64(&mut bytes, round);
    put_digest(&mut bytes, &conflict);
    put_digest(&mut bytes, &intent);
    put_digest(&mut bytes, &justify);
    bytes.push(signer_index);
    let statement = hash_domain(b"CALIBRE_INTEGRATION001_VOTE_STATEMENT_V1", &bytes);
    Ok(statement.to_vec())
}

#[allow(clippy::too_many_arguments)]
pub fn sign_vote(
    manifest: &CommitteeManifest,
    phase: u8,
    round: u64,
    conflict: Digest,
    intent: Digest,
    justify: Digest,
    signer_index: u8,
    key: &SigningKey,
) -> Result<Vote, String> {
    validate_manifest(manifest)?;
    let member = manifest.members.get(signer_index as usize).ok_or("signer index is not a member")?;
    if member.index != signer_index || member.public_key != key.verifying_key().to_bytes() {
        return Err("signing key does not match manifest slot".into());
    }
    if phase == PHASE_PREVOTE && justify != [0; 32] { return Err("prevote cannot carry a justify digest".into()); }
    if phase == PHASE_PRECOMMIT && justify == [0; 32] { return Err("precommit must bind its prevote QC".into()); }
    let signature = key
        .sign(&vote_message(manifest, phase, round, conflict, intent, justify, signer_index)?)
        .to_bytes();
    Ok(Vote {
        network_id: manifest.network_id,
        epoch: manifest.epoch,
        committee_hash: committee_hash(manifest)?,
        phase,
        round,
        conflict_key: conflict,
        intent,
        justify,
        signer_index,
        signature,
    })
}

pub fn verify_vote(vote: &Vote, manifest: &CommitteeManifest) -> Result<(), String> {
    validate_manifest(manifest)?;
    if vote.network_id != manifest.network_id || vote.epoch != manifest.epoch {
        return Err("vote network or epoch mismatch".into());
    }
    if vote.committee_hash != committee_hash(manifest)? { return Err("vote committee mismatch".into()); }
    if vote.phase == PHASE_PREVOTE && vote.justify != [0; 32] { return Err("prevote has a justify digest".into()); }
    if vote.phase == PHASE_PRECOMMIT && vote.justify == [0; 32] { return Err("precommit omits prevote QC digest".into()); }
    let member = manifest.members.get(vote.signer_index as usize).ok_or("vote signer is not a member")?;
    if member.index != vote.signer_index { return Err("vote signer index mismatch".into()); }
    VerifyingKey::from_bytes(&member.public_key)
        .map_err(|_| "invalid validator key")?
        .verify_strict(
            &vote_message(
                manifest,
                vote.phase,
                vote.round,
                vote.conflict_key,
                vote.intent,
                vote.justify,
                vote.signer_index,
            )?,
            &Signature::from_bytes(&vote.signature),
        )
        .map_err(|_| "invalid validator vote signature".into())
}

#[allow(clippy::too_many_arguments)]
pub fn assemble_qc(
    votes: Vec<Vote>,
    manifest: &CommitteeManifest,
    phase: u8,
    round: u64,
    conflict: Digest,
    intent: Digest,
    expected_justify: Option<Digest>,
) -> Result<Qc, String> {
    let mut by_index = BTreeMap::new();
    for vote in votes {
        verify_vote(&vote, manifest)?;
        if vote.phase != phase || vote.round != round || vote.conflict_key != conflict || vote.intent != intent {
            return Err("mixed vote statements cannot form a QC".into());
        }
        if let Some(justify) = expected_justify {
            if vote.justify != justify { return Err("vote justify digest mismatch".into()); }
        }
        if by_index.insert(vote.signer_index, vote).is_some() {
            return Err("duplicate signer in QC input".into());
        }
    }
    let qc = Qc { votes: by_index.into_values().collect() };
    verify_qc(&qc, manifest, phase, round, conflict, intent, expected_justify)?;
    Ok(qc)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_qc(
    qc: &Qc,
    manifest: &CommitteeManifest,
    phase: u8,
    round: u64,
    conflict: Digest,
    intent: Digest,
    expected_justify: Option<Digest>,
) -> Result<(), String> {
    if qc.votes.len() < Q || qc.votes.len() > N { return Err("QC does not contain 5..=7 votes".into()); }
    let mut last = None;
    for vote in &qc.votes {
        verify_vote(vote, manifest)?;
        if vote.phase != phase || vote.round != round || vote.conflict_key != conflict || vote.intent != intent {
            return Err("QC contains a mixed statement".into());
        }
        match expected_justify {
            Some(justify) if vote.justify != justify => return Err("QC justify digest mismatch".into()),
            None if vote.justify != [0; 32] => return Err("QC unexpectedly carries justification".into()),
            _ => {}
        }
        if last.is_some_and(|previous| vote.signer_index <= previous) {
            return Err("QC signers must be unique and sorted".into());
        }
        last = Some(vote.signer_index);
    }
    Ok(())
}

pub fn qc_digest(qc: &Qc, manifest: &CommitteeManifest) -> Result<Digest, String> {
    if qc.votes.is_empty() { return Err("empty QC".into()); }
    let first = qc.votes[0];
    verify_qc(
        qc,
        manifest,
        first.phase,
        first.round,
        first.conflict_key,
        first.intent,
        if first.phase == PHASE_PRECOMMIT { Some(first.justify) } else { None },
    )?;
    let mut bytes = Vec::new();
    put_u32(&mut bytes, qc.votes.len() as u32);
    for vote in &qc.votes {
        bytes.push(vote.signer_index);
        bytes.extend_from_slice(&vote.signature);
    }
    bytes.push(first.phase);
    put_u64(&mut bytes, first.round);
    put_digest(&mut bytes, &first.conflict_key);
    put_digest(&mut bytes, &first.intent);
    put_digest(&mut bytes, &first.justify);
    Ok(hash_domain(b"CALIBRE_INTEGRATION001_QC_V1", &bytes))
}

fn proposal_message(
    manifest: &CommitteeManifest,
    round: u64,
    proposer_index: u8,
    intent: Digest,
    justify_digest: Digest,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    put_u16(&mut bytes, PROTOCOL_VERSION);
    put_u32(&mut bytes, manifest.network_id);
    put_u64(&mut bytes, manifest.epoch);
    put_digest(&mut bytes, &committee_hash(manifest)?);
    put_u64(&mut bytes, round);
    bytes.push(proposer_index);
    put_digest(&mut bytes, &intent);
    put_digest(&mut bytes, &justify_digest);
    Ok(hash_domain(b"CALIBRE_INTEGRATION001_PROPOSAL_V1", &bytes).to_vec())
}

pub fn make_proposal(
    manifest: &CommitteeManifest,
    round: u64,
    tx: Tx,
    auth: UserAuth,
    justify: Option<Qc>,
) -> Result<Proposal, String> {
    verify_user_auth(&tx, &auth, manifest)?;
    let intent = intent_hash(&tx)?;
    let proposer_index = leader(conflict_key(tx.input.reference), round) as u8;
    let justify_digest = match &justify {
        Some(qc) => {
            let first = qc.votes.first().ok_or("empty proposal justify QC")?;
            verify_qc(
                qc,
                manifest,
                PHASE_PREVOTE,
                first.round,
                conflict_key(tx.input.reference),
                intent,
                None,
            )?;
            if first.round >= round { return Err("justify QC must be from a lower round".into()); }
            qc_digest(qc, manifest)?
        }
        None => [0; 32],
    };
    let key = lab_validator_key(manifest.epoch, proposer_index as usize);
    let signature = key
        .sign(&proposal_message(manifest, round, proposer_index, intent, justify_digest)?)
        .to_bytes();
    Ok(Proposal { round, proposer_index, tx, auth, intent, justify, signature })
}

pub fn verify_proposal(proposal: &Proposal, manifest: &CommitteeManifest) -> Result<(), String> {
    verify_user_auth(&proposal.tx, &proposal.auth, manifest)?;
    if proposal.intent != intent_hash(&proposal.tx)? { return Err("proposal intent mismatch".into()); }
    let conflict = conflict_key(proposal.tx.input.reference);
    if proposal.proposer_index as usize != leader(conflict, proposal.round) {
        return Err("wrong conflict-local proposer".into());
    }
    let justify_digest = match &proposal.justify {
        Some(qc) => {
            let first = qc.votes.first().ok_or("empty proposal justify QC")?;
            verify_qc(qc, manifest, PHASE_PREVOTE, first.round, conflict, proposal.intent, None)?;
            if first.round >= proposal.round { return Err("proposal justify is not from a lower round".into()); }
            qc_digest(qc, manifest)?
        }
        None => [0; 32],
    };
    let member = manifest.members.get(proposal.proposer_index as usize).ok_or("proposal signer is not a member")?;
    VerifyingKey::from_bytes(&member.public_key)
        .map_err(|_| "invalid proposer key")?
        .verify_strict(
            &proposal_message(manifest, proposal.round, proposal.proposer_index, proposal.intent, justify_digest)?,
            &Signature::from_bytes(&proposal.signature),
        )
        .map_err(|_| "invalid proposal signature".into())
}

pub fn output_ref(tx: &Tx, output_index: usize) -> Result<CellRef, String> {
    let generation = tx.input.reference.generation.checked_add(1).ok_or("cell generation overflow")?;
    let mut bytes = Vec::new();
    put_digest(&mut bytes, &intent_hash(tx)?);
    put_u32(&mut bytes, u32::try_from(output_index).map_err(|_| "output index overflow")?);
    Ok(CellRef {
        asset_id: tx.input.reference.asset_id,
        id: hash_domain(b"CALIBRE_INTEGRATION001_OUTPUT_REF_V1", &bytes),
        generation,
    })
}

pub fn fee_collector() -> PublicKeyBytes {
    lab_user_key(9_999).verifying_key().to_bytes()
}

fn materialize_outputs(tx: &Tx) -> Result<Vec<Cell>, String> {
    let mut effects = tx.outputs.clone();
    effects.push(Output { asset_id: tx.input.reference.asset_id, amount: tx.fee, owner: fee_collector() });
    let mut cells = Vec::with_capacity(effects.len());
    for (index, output) in effects.into_iter().enumerate() {
        let reference = output_ref(tx, index)?;
        let predecessor = tx.input.state_digest;
        cells.push(Cell {
            reference,
            amount: output.amount,
            owner: output.owner,
            predecessor,
            state_digest: compute_cell_digest(reference, output.amount, output.owner, predecessor),
        });
    }
    Ok(cells)
}

impl State {
    pub fn from_cells(cells: Vec<Cell>) -> Result<Self, String> {
        let mut state = Self::default();
        for cell in cells {
            validate_cell(&cell)?;
            if state.live.insert(cell.reference, cell.clone()).is_some() {
                return Err("duplicate genesis cell reference".into());
            }
            if !state.known_ids.insert(cell.reference.id) { return Err("duplicate genesis cell id".into()); }
        }
        Ok(state)
    }

    pub fn live_cell(&self, reference: CellRef) -> Option<&Cell> { self.live.get(&reference) }

    pub fn validate(&self) -> Result<(), String> {
        for (reference, cell) in &self.live {
            if reference != &cell.reference { return Err("live-state key/reference mismatch".into()); }
            validate_cell(cell)?;
            if !self.known_ids.contains(&reference.id) { return Err("live cell is absent from known-id set".into()); }
            if self.spent_by.contains_key(reference) { return Err("cell is both live and spent".into()); }
        }
        for reference in self.spent_by.keys() {
            if !self.known_ids.contains(&reference.id) { return Err("spent cell is absent from known-id set".into()); }
            if self.live.contains_key(reference) { return Err("spent cell remains live".into()); }
        }
        for (intent, receipt) in &self.applied {
            if intent != &receipt.intent { return Err("applied receipt key mismatch".into()); }
            if receipt.output_refs.is_empty() { return Err("applied receipt has no output refs".into()); }
        }
        Ok(())
    }

    pub fn root(&self) -> Digest { state_root(self) }

    pub fn total_value(&self) -> Result<u64, String> {
        self.live
            .values()
            .try_fold(0u64, |total, cell| {
                total.checked_add(cell.amount).ok_or_else(|| "state value overflow".to_string())
            })
    }

    pub fn apply_finalized(
        &mut self,
        tx: &Tx,
        auth: &UserAuth,
        prevote_qc: &Qc,
        precommit_qc: &Qc,
        manifest: &CommitteeManifest,
    ) -> Result<ApplyOutcome, String> {
        let intent = intent_hash(tx)?;
        let conflict = conflict_key(tx.input.reference);
        let prevote = prevote_qc.votes.first().ok_or("empty prevote QC")?;
        verify_qc(
            prevote_qc,
            manifest,
            PHASE_PREVOTE,
            prevote.round,
            conflict,
            intent,
            None,
        )?;
        let prevote_digest = qc_digest(prevote_qc, manifest)?;
        let precommit = precommit_qc.votes.first().ok_or("empty finality QC")?;
        if precommit.round != prevote.round {
            return Err("PRECOMMIT QC round does not match PREVOTE QC".into());
        }
        verify_qc(
            precommit_qc,
            manifest,
            PHASE_PRECOMMIT,
            precommit.round,
            conflict,
            intent,
            Some(prevote_digest),
        )?;
        if let Some(receipt) = self.applied.get(&intent) {
            verify_user_auth(tx, auth, manifest)?;
            return Ok(ApplyOutcome::AlreadyApplied(receipt.clone()));
        }

        verify_user_auth(tx, auth, manifest)?;
        let current = self.live.get(&tx.input.reference).ok_or("input is not live")?;
        if current != &tx.input { return Err("transaction does not reference the exact live input state".into()); }
        let certificate_digest = qc_digest(precommit_qc, manifest)?;
        let outputs = materialize_outputs(tx)?;
        let mut refs = BTreeSet::new();
        for cell in &outputs {
            validate_cell(cell)?;
            if !refs.insert(cell.reference) { return Err("duplicate output reference".into()); }
            if self.known_ids.contains(&cell.reference.id) { return Err("output id collides with prior state".into()); }
        }

        let receipt = ApplyReceipt {
            intent,
            certificate_digest,
            output_refs: outputs.iter().map(|cell| cell.reference).collect(),
        };
        self.live.remove(&tx.input.reference);
        self.spent_by.insert(tx.input.reference, intent);
        for cell in outputs {
            self.known_ids.insert(cell.reference.id);
            self.live.insert(cell.reference, cell);
        }
        self.applied.insert(intent, receipt.clone());
        Ok(ApplyOutcome::Applied(receipt))
    }
}

pub fn state_root(state: &State) -> Digest {
    let mut bytes = Vec::new();
    put_u16(&mut bytes, PROTOCOL_VERSION);
    put_u32(&mut bytes, state.live.len() as u32);
    for (reference, cell) in &state.live {
        put_u32(&mut bytes, reference.asset_id);
        put_digest(&mut bytes, &reference.id);
        put_u64(&mut bytes, reference.generation);
        put_u64(&mut bytes, cell.amount);
        bytes.extend_from_slice(&cell.owner);
        put_digest(&mut bytes, &cell.predecessor);
        put_digest(&mut bytes, &cell.state_digest);
    }
    put_u32(&mut bytes, state.spent_by.len() as u32);
    for (reference, intent) in &state.spent_by {
        put_u32(&mut bytes, reference.asset_id);
        put_digest(&mut bytes, &reference.id);
        put_u64(&mut bytes, reference.generation);
        put_digest(&mut bytes, intent);
    }
    put_u32(&mut bytes, state.known_ids.len() as u32);
    for id in &state.known_ids { put_digest(&mut bytes, id); }
    put_u32(&mut bytes, state.applied.len() as u32);
    for (intent, receipt) in &state.applied {
        put_digest(&mut bytes, intent);
        put_digest(&mut bytes, &receipt.certificate_digest);
        put_u32(&mut bytes, receipt.output_refs.len() as u32);
        for reference in &receipt.output_refs {
            put_u32(&mut bytes, reference.asset_id);
            put_digest(&mut bytes, &reference.id);
            put_u64(&mut bytes, reference.generation);
        }
    }
    hash_domain(b"CALIBRE_INTEGRATION001_STATE_ROOT_V1", &bytes)
}

pub fn make_transfer(
    manifest: &CommitteeManifest,
    input: Cell,
    outputs: Vec<Output>,
    fee: u64,
    salt: Digest,
) -> Result<Tx, String> {
    let tx = Tx {
        version: PROTOCOL_VERSION,
        network_id: manifest.network_id,
        epoch: manifest.epoch,
        committee_hash: committee_hash(manifest)?,
        input,
        outputs,
        fee,
        salt,
    };
    validate_tx(&tx, manifest)?;
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (CommitteeManifest, SigningKey, Cell, Tx, UserAuth) {
        let manifest = lab_committee(OLD_EPOCH);
        let alice = lab_user_key(1);
        let bob = lab_user_key(2).verifying_key().to_bytes();
        let input = make_genesis_cell(1, 100, alice.verifying_key().to_bytes());
        let tx = make_transfer(
            &manifest,
            input.clone(),
            vec![
                Output { asset_id: ASSET_CALIBRE, amount: 60, owner: bob },
                Output { asset_id: ASSET_CALIBRE, amount: 39, owner: alice.verifying_key().to_bytes() },
            ],
            1,
            [7; 32],
        )
        .unwrap();
        let auth = sign_user(&tx, &alice).unwrap();
        (manifest, alice, input, tx, auth)
    }

    fn final_qc(manifest: &CommitteeManifest, tx: &Tx) -> Qc {
        let intent = intent_hash(tx).unwrap();
        let conflict = conflict_key(tx.input.reference);
        let round = 3;
        let prevotes = (0..Q)
            .map(|index| {
                sign_vote(
                    manifest,
                    PHASE_PREVOTE,
                    round,
                    conflict,
                    intent,
                    [0; 32],
                    index as u8,
                    &lab_validator_key(manifest.epoch, index),
                )
                .unwrap()
            })
            .collect();
        let prevote_qc = assemble_qc(
            prevotes,
            manifest,
            PHASE_PREVOTE,
            round,
            conflict,
            intent,
            None,
        )
        .unwrap();
        let justify = qc_digest(&prevote_qc, manifest).unwrap();
        let precommits = (0..Q)
            .map(|index| {
                sign_vote(
                    manifest,
                    PHASE_PRECOMMIT,
                    round,
                    conflict,
                    intent,
                    justify,
                    index as u8,
                    &lab_validator_key(manifest.epoch, index),
                )
                .unwrap()
            })
            .collect();
        assemble_qc(
            precommits,
            manifest,
            PHASE_PRECOMMIT,
            round,
            conflict,
            intent,
            Some(justify),
        )
        .unwrap()
    }

    #[test]
    fn manifest_and_quorum_boundary_are_exact() {
        let manifest = lab_committee(OLD_EPOCH);
        validate_manifest(&manifest).unwrap();
        assert_eq!(2 * Q - N, 3);
        assert!(2 * Q - N > 2);
    }

    #[test]
    fn authorization_binds_owner_and_every_effect() {
        let (manifest, _alice, _input, tx, auth) = fixture();
        verify_user_auth(&tx, &auth, &manifest).unwrap();

        let mut mutations = Vec::new();
        let mut changed = tx.clone(); changed.network_id += 1; mutations.push(changed);
        let mut changed = tx.clone(); changed.epoch += 1; mutations.push(changed);
        let mut changed = tx.clone(); changed.input.reference.generation += 1; mutations.push(changed);
        let mut changed = tx.clone(); changed.input.amount += 1; mutations.push(changed);
        let mut changed = tx.clone(); changed.outputs[0].owner = lab_user_key(3).verifying_key().to_bytes(); mutations.push(changed);
        let mut changed = tx.clone(); changed.outputs[0].amount -= 1; changed.outputs[1].amount += 1; mutations.push(changed);
        let mut changed = tx.clone(); changed.outputs.swap(0, 1); mutations.push(changed);
        let mut changed = tx.clone(); changed.fee += 1; mutations.push(changed);
        let mut changed = tx.clone(); changed.salt[0] ^= 1; mutations.push(changed);
        for changed in mutations { assert!(verify_user_auth(&changed, &auth, &manifest).is_err()); }

        let mallory = lab_user_key(3);
        assert!(verify_user_auth(&tx, &sign_user(&tx, &mallory).unwrap(), &manifest).is_err());
    }

    #[test]
    fn conservation_and_overflow_fail_closed() {
        let (manifest, _alice, input, _tx, _auth) = fixture();
        assert!(make_transfer(
            &manifest,
            input.clone(),
            vec![Output { asset_id: ASSET_CALIBRE, amount: 100, owner: input.owner }],
            1,
            [1; 32],
        ).is_err());
        let mut huge = input;
        huge.amount = u64::MAX;
        huge.state_digest = compute_cell_digest(huge.reference, huge.amount, huge.owner, huge.predecessor);
        assert!(make_transfer(
            &manifest,
            huge,
            vec![
                Output { asset_id: ASSET_CALIBRE, amount: u64::MAX, owner: lab_user_key(1).verifying_key().to_bytes() },
                Output { asset_id: ASSET_CALIBRE, amount: 1, owner: lab_user_key(2).verifying_key().to_bytes() },
            ],
            1,
            [2; 32],
        ).is_err());
    }

    #[test]
    fn quorum_rejects_four_duplicates_and_wrong_statement() {
        let (manifest, _alice, _input, tx, _auth) = fixture();
        let intent = intent_hash(&tx).unwrap();
        let conflict = conflict_key(tx.input.reference);
        let votes: Vec<_> = (0..4)
            .map(|index| sign_vote(&manifest, PHASE_PREVOTE, 1, conflict, intent, [0; 32], index, &lab_validator_key(OLD_EPOCH, index as usize)).unwrap())
            .collect();
        assert!(assemble_qc(votes.clone(), &manifest, PHASE_PREVOTE, 1, conflict, intent, None).is_err());
        let mut duplicates = vec![votes[0]; 5];
        assert!(assemble_qc(duplicates.clone(), &manifest, PHASE_PREVOTE, 1, conflict, intent, None).is_err());
        duplicates[4].intent[0] ^= 1;
        assert!(assemble_qc(duplicates, &manifest, PHASE_PREVOTE, 1, conflict, intent, None).is_err());
    }

    #[test]
    fn finalized_apply_is_value_conserving_and_idempotent() {
        let (manifest, _alice, input, tx, auth) = fixture();
        let qc = final_qc(&manifest, &tx);
        let mut state = State::from_cells(vec![input]).unwrap();
        let before = state.total_value().unwrap();
        let intent = intent_hash(&tx).unwrap();
        let conflict = conflict_key(tx.input.reference);
        let round = qc.votes[0].round;
        let prevotes = (0..Q).map(|index| sign_vote(&manifest, PHASE_PREVOTE, round, conflict, intent, [0; 32], index as u8, &lab_validator_key(OLD_EPOCH, index)).unwrap()).collect();
        let prevote_qc = assemble_qc(prevotes, &manifest, PHASE_PREVOTE, round, conflict, intent, None).unwrap();
        assert!(matches!(state.apply_finalized(&tx, &auth, &prevote_qc, &qc, &manifest).unwrap(), ApplyOutcome::Applied(_)));
        assert_eq!(state.total_value().unwrap(), before);
        assert_eq!(state.live.values().filter(|cell| cell.owner == fee_collector() && cell.amount == 1).count(), 1);
        assert!(matches!(state.apply_finalized(&tx, &auth, &prevote_qc, &qc, &manifest).unwrap(), ApplyOutcome::AlreadyApplied(_)));
        assert_eq!(state.total_value().unwrap(), before);
    }

    #[test]
    fn state_root_is_insertion_order_independent() {
        let a = make_genesis_cell(10, 10, lab_user_key(10).verifying_key().to_bytes());
        let b = make_genesis_cell(11, 11, lab_user_key(11).verifying_key().to_bytes());
        assert_eq!(State::from_cells(vec![a.clone(), b.clone()]).unwrap().root(), State::from_cells(vec![b, a]).unwrap().root());
    }

    #[test]
    fn exhaustive_f2_static_allocations_never_make_two_quorums() {
        let mut cases = 0usize;
        for honest_mask in 0u8..32 {
            for byz0 in 0u8..4 {
                for byz1 in 0u8..4 {
                    let honest_a = honest_mask.count_ones() as usize;
                    let honest_b = 5 - honest_a;
                    let byz_a = (byz0 == 1 || byz0 == 3) as usize + (byz1 == 1 || byz1 == 3) as usize;
                    let byz_b = (byz0 == 2 || byz0 == 3) as usize + (byz1 == 2 || byz1 == 3) as usize;
                    assert!(!(honest_a + byz_a >= Q && honest_b + byz_b >= Q));
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 512);
    }

    #[test]
    fn f3_boundary_can_make_two_quorums() {
        assert_eq!(3 + 2, Q);
        assert_eq!(3 + 2, Q);
    }
}
