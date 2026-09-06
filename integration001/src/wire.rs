use crate::model::{
    ApplyReceipt, Cell, CellRef, CommitteeManifest, CommitteeMember, Output, Proposal, Qc, State,
    Tx, UserAuth, Vote, N, PHASE_PRECOMMIT, PHASE_PREVOTE,
};
use crate::store::Lifecycle;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpStream;

pub const MAX_FRAME_LEN: usize = 1024 * 1024;
pub const MAX_COLLECTION_LEN: usize = 2048;
pub const MAX_OUTPUTS: usize = 8;
pub const MAX_RECEIPT_OUTPUTS: usize = MAX_OUTPUTS + 1;
pub const MAX_VOTES: usize = N;

pub type WireResult<T> = Result<T, String>;

#[derive(Debug, Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self::default()
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn fixed<const N: usize>(&mut self, value: &[u8; N]) {
        self.bytes.extend_from_slice(value);
    }

    fn count(&mut self, count: usize, label: &str) -> WireResult<()> {
        self.bounded_count(count, MAX_COLLECTION_LEN, label)
    }

    fn bounded_count(&mut self, count: usize, max: usize, label: &str) -> WireResult<()> {
        if count > max {
            return Err(format!("{label} count exceeds {max}"));
        }
        let count = u32::try_from(count).map_err(|_| format!("{label} count does not fit u32"))?;
        self.u32(count);
        Ok(())
    }

    fn finish(self) -> WireResult<Vec<u8>> {
        if self.bytes.len() > MAX_FRAME_LEN {
            return Err(format!("encoded payload exceeds {MAX_FRAME_LEN} bytes"));
        }
        Ok(self.bytes)
    }
}

#[derive(Debug)]
struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> WireResult<Self> {
        if bytes.len() > MAX_FRAME_LEN {
            return Err(format!("payload exceeds {MAX_FRAME_LEN} bytes"));
        }
        Ok(Self { bytes, offset: 0 })
    }

    fn take(&mut self, len: usize, label: &str) -> WireResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| format!("{label} length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| format!("truncated {label}"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self, label: &str) -> WireResult<u8> {
        Ok(self.take(1, label)?[0])
    }

    fn bool(&mut self, label: &str) -> WireResult<bool> {
        match self.u8(label)? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(format!("invalid {label} boolean value {value}")),
        }
    }

    fn u16(&mut self, label: &str) -> WireResult<u16> {
        Ok(u16::from_le_bytes(
            self.take(2, label)?.try_into().expect("fixed width"),
        ))
    }

    fn u32(&mut self, label: &str) -> WireResult<u32> {
        Ok(u32::from_le_bytes(
            self.take(4, label)?.try_into().expect("fixed width"),
        ))
    }

    fn u64(&mut self, label: &str) -> WireResult<u64> {
        Ok(u64::from_le_bytes(
            self.take(8, label)?.try_into().expect("fixed width"),
        ))
    }

    fn fixed<const N: usize>(&mut self, label: &str) -> WireResult<[u8; N]> {
        Ok(self.take(N, label)?.try_into().expect("fixed width"))
    }

    fn count(&mut self, label: &str) -> WireResult<usize> {
        self.bounded_count(MAX_COLLECTION_LEN, label)
    }

    fn bounded_count(&mut self, max: usize, label: &str) -> WireResult<usize> {
        let count = usize::try_from(self.u32(label)?)
            .map_err(|_| format!("{label} count does not fit usize"))?;
        if count > max {
            return Err(format!("{label} count exceeds {max}"));
        }
        Ok(count)
    }

    fn finish(self) -> WireResult<()> {
        if self.offset != self.bytes.len() {
            return Err(format!(
                "trailing bytes: consumed {}, payload has {}",
                self.offset,
                self.bytes.len()
            ));
        }
        Ok(())
    }
}

fn write_frame_to<W: Write>(writer: &mut W, payload: &[u8]) -> WireResult<()> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(format!("outgoing frame exceeds {MAX_FRAME_LEN} bytes"));
    }
    let len = u32::try_from(payload.len()).map_err(|_| "frame length does not fit u32")?;
    writer
        .write_all(&len.to_be_bytes())
        .map_err(|error| format!("write frame header: {error}"))?;
    writer
        .write_all(payload)
        .map_err(|error| format!("write frame payload: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("flush frame: {error}"))
}

fn read_frame_from<R: Read>(reader: &mut R) -> WireResult<Vec<u8>> {
    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|error| format!("read frame header: {error}"))?;
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_LEN {
        return Err(format!("incoming frame exceeds {MAX_FRAME_LEN} bytes"));
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .map_err(|error| format!("read frame payload: {error}"))?;
    Ok(payload)
}

pub fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> WireResult<()> {
    write_frame_to(stream, payload)
}

pub fn read_frame(stream: &mut TcpStream) -> WireResult<Vec<u8>> {
    read_frame_from(stream)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Ping,
    Prevote(Proposal),
    Precommit {
        proposal: Proposal,
        prevote_qc: Qc,
    },
    Apply {
        tx: Tx,
        auth: UserAuth,
        prevote_qc: Qc,
        finality_qc: Qc,
    },
    QueryState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    Pong {
        index: u8,
        epoch: u64,
        committee_hash: [u8; 32],
    },
    Vote(Vote),
    Applied {
        state_root: [u8; 32],
        idempotent: bool,
    },
    State {
        state_root: [u8; 32],
        snapshot_bytes: u64,
        wal_bytes: u64,
        lifecycle: Lifecycle,
    },
    Rejected {
        code: u16,
    },
}

const REQUEST_PING: u8 = 1;
const REQUEST_PREVOTE: u8 = 2;
const REQUEST_PRECOMMIT: u8 = 3;
const REQUEST_APPLY: u8 = 4;
const REQUEST_QUERY_STATE: u8 = 5;

const RESPONSE_PONG: u8 = 1;
const RESPONSE_VOTE: u8 = 2;
const RESPONSE_APPLIED: u8 = 3;
const RESPONSE_STATE: u8 = 4;
const RESPONSE_REJECTED: u8 = 6;

fn put_phase(encoder: &mut Encoder, phase: u8) -> WireResult<()> {
    if phase != PHASE_PREVOTE && phase != PHASE_PRECOMMIT {
        return Err(format!("invalid vote phase {phase}"));
    }
    encoder.u8(phase);
    Ok(())
}

fn take_phase(decoder: &mut Decoder<'_>) -> WireResult<u8> {
    let phase = decoder.u8("vote phase")?;
    if phase != PHASE_PREVOTE && phase != PHASE_PRECOMMIT {
        return Err(format!("invalid vote phase {phase}"));
    }
    Ok(phase)
}

fn put_committee_member(encoder: &mut Encoder, member: &CommitteeMember) {
    encoder.u8(member.index);
    encoder.fixed(&member.public_key);
}

fn take_committee_member(decoder: &mut Decoder<'_>) -> WireResult<CommitteeMember> {
    Ok(CommitteeMember {
        index: decoder.u8("committee member index")?,
        public_key: decoder.fixed("committee member public key")?,
    })
}

fn put_committee_manifest(
    encoder: &mut Encoder,
    manifest: &CommitteeManifest,
) -> WireResult<()> {
    encoder.u32(manifest.network_id);
    encoder.u64(manifest.epoch);
    encoder.u8(manifest.threshold);
    encoder.bounded_count(manifest.members.len(), N, "committee members")?;
    for member in &manifest.members {
        put_committee_member(encoder, member);
    }
    Ok(())
}

fn take_committee_manifest(decoder: &mut Decoder<'_>) -> WireResult<CommitteeManifest> {
    let network_id = decoder.u32("committee network")?;
    let epoch = decoder.u64("committee epoch")?;
    let threshold = decoder.u8("committee threshold")?;
    let count = decoder.bounded_count(N, "committee members")?;
    let mut members = Vec::with_capacity(count);
    let mut indices = BTreeSet::new();
    for _ in 0..count {
        let member = take_committee_member(decoder)?;
        if !indices.insert(member.index) {
            return Err("duplicate committee member index".into());
        }
        members.push(member);
    }
    Ok(CommitteeManifest {
        network_id,
        epoch,
        threshold,
        members,
    })
}

fn put_cell_ref(encoder: &mut Encoder, reference: &CellRef) {
    encoder.u32(reference.asset_id);
    encoder.fixed(&reference.id);
    encoder.u64(reference.generation);
}

fn take_cell_ref(decoder: &mut Decoder<'_>) -> WireResult<CellRef> {
    Ok(CellRef {
        asset_id: decoder.u32("cell asset")?,
        id: decoder.fixed("cell id")?,
        generation: decoder.u64("cell generation")?,
    })
}

fn put_cell(encoder: &mut Encoder, cell: &Cell) {
    put_cell_ref(encoder, &cell.reference);
    encoder.u64(cell.amount);
    encoder.fixed(&cell.owner);
    encoder.fixed(&cell.predecessor);
    encoder.fixed(&cell.state_digest);
}

fn take_cell(decoder: &mut Decoder<'_>) -> WireResult<Cell> {
    Ok(Cell {
        reference: take_cell_ref(decoder)?,
        amount: decoder.u64("cell amount")?,
        owner: decoder.fixed("cell owner")?,
        predecessor: decoder.fixed("cell predecessor")?,
        state_digest: decoder.fixed("cell state digest")?,
    })
}

fn put_output(encoder: &mut Encoder, output: &Output) {
    encoder.u32(output.asset_id);
    encoder.u64(output.amount);
    encoder.fixed(&output.owner);
}

fn take_output(decoder: &mut Decoder<'_>) -> WireResult<Output> {
    Ok(Output {
        asset_id: decoder.u32("output asset")?,
        amount: decoder.u64("output amount")?,
        owner: decoder.fixed("output owner")?,
    })
}

fn put_tx(encoder: &mut Encoder, tx: &Tx) -> WireResult<()> {
    encoder.u16(tx.version);
    encoder.u32(tx.network_id);
    encoder.u64(tx.epoch);
    encoder.fixed(&tx.committee_hash);
    put_cell(encoder, &tx.input);
    if tx.outputs.is_empty() {
        return Err("transaction output count must be nonzero".into());
    }
    encoder.bounded_count(tx.outputs.len(), MAX_OUTPUTS, "transaction outputs")?;
    for output in &tx.outputs {
        put_output(encoder, output);
    }
    encoder.u64(tx.fee);
    encoder.fixed(&tx.salt);
    Ok(())
}

fn take_tx(decoder: &mut Decoder<'_>) -> WireResult<Tx> {
    let version = decoder.u16("transaction version")?;
    let network_id = decoder.u32("transaction network")?;
    let epoch = decoder.u64("transaction epoch")?;
    let committee_hash = decoder.fixed("transaction committee hash")?;
    let input = take_cell(decoder)?;
    let count = decoder.bounded_count(MAX_OUTPUTS, "transaction outputs")?;
    if count == 0 {
        return Err("transaction output count must be nonzero".into());
    }
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        outputs.push(take_output(decoder)?);
    }
    Ok(Tx {
        version,
        network_id,
        epoch,
        committee_hash,
        input,
        outputs,
        fee: decoder.u64("transaction fee")?,
        salt: decoder.fixed("transaction salt")?,
    })
}

fn put_user_auth(encoder: &mut Encoder, auth: &UserAuth) {
    encoder.fixed(&auth.signer);
    encoder.fixed(&auth.signature);
}

fn take_user_auth(decoder: &mut Decoder<'_>) -> WireResult<UserAuth> {
    Ok(UserAuth {
        signer: decoder.fixed("authorization signer")?,
        signature: decoder.fixed("authorization signature")?,
    })
}

fn put_vote(encoder: &mut Encoder, vote: &Vote) -> WireResult<()> {
    encoder.u32(vote.network_id);
    encoder.u64(vote.epoch);
    encoder.fixed(&vote.committee_hash);
    put_phase(encoder, vote.phase)?;
    encoder.u64(vote.round);
    encoder.fixed(&vote.conflict_key);
    encoder.fixed(&vote.intent);
    encoder.fixed(&vote.justify);
    encoder.u8(vote.signer_index);
    encoder.fixed(&vote.signature);
    Ok(())
}

fn take_vote(decoder: &mut Decoder<'_>) -> WireResult<Vote> {
    Ok(Vote {
        network_id: decoder.u32("vote network")?,
        epoch: decoder.u64("vote epoch")?,
        committee_hash: decoder.fixed("vote committee hash")?,
        phase: take_phase(decoder)?,
        round: decoder.u64("vote round")?,
        conflict_key: decoder.fixed("vote conflict key")?,
        intent: decoder.fixed("vote intent")?,
        justify: decoder.fixed("vote justification")?,
        signer_index: decoder.u8("vote signer index")?,
        signature: decoder.fixed("vote signature")?,
    })
}

fn put_qc(encoder: &mut Encoder, qc: &Qc) -> WireResult<()> {
    if qc.votes.is_empty() {
        return Err("QC vote count must be nonzero".into());
    }
    encoder.bounded_count(qc.votes.len(), MAX_VOTES, "QC votes")?;
    for vote in &qc.votes {
        put_vote(encoder, vote)?;
    }
    Ok(())
}

fn take_qc(decoder: &mut Decoder<'_>) -> WireResult<Qc> {
    let count = decoder.bounded_count(MAX_VOTES, "QC votes")?;
    if count == 0 {
        return Err("QC vote count must be nonzero".into());
    }
    let mut votes = Vec::with_capacity(count);
    for _ in 0..count {
        votes.push(take_vote(decoder)?);
    }
    Ok(Qc { votes })
}

fn put_proposal(encoder: &mut Encoder, proposal: &Proposal) -> WireResult<()> {
    encoder.u64(proposal.round);
    encoder.u8(proposal.proposer_index);
    put_tx(encoder, &proposal.tx)?;
    put_user_auth(encoder, &proposal.auth);
    encoder.fixed(&proposal.intent);
    encoder.bool(proposal.justify.is_some());
    if let Some(qc) = &proposal.justify {
        put_qc(encoder, qc)?;
    }
    encoder.fixed(&proposal.signature);
    Ok(())
}

fn take_proposal(decoder: &mut Decoder<'_>) -> WireResult<Proposal> {
    let round = decoder.u64("proposal round")?;
    let proposer_index = decoder.u8("proposal proposer index")?;
    let tx = take_tx(decoder)?;
    let auth = take_user_auth(decoder)?;
    let intent = decoder.fixed("proposal intent")?;
    let justify = if decoder.bool("proposal justification presence")? {
        Some(take_qc(decoder)?)
    } else {
        None
    };
    Ok(Proposal {
        round,
        proposer_index,
        tx,
        auth,
        intent,
        justify,
        signature: decoder.fixed("proposal signature")?,
    })
}

fn put_apply_receipt(encoder: &mut Encoder, receipt: &ApplyReceipt) -> WireResult<()> {
    encoder.fixed(&receipt.intent);
    encoder.fixed(&receipt.certificate_digest);
    encoder.bounded_count(receipt.output_refs.len(), MAX_RECEIPT_OUTPUTS, "receipt output refs")?;
    for reference in &receipt.output_refs {
        put_cell_ref(encoder, reference);
    }
    Ok(())
}

fn take_apply_receipt(decoder: &mut Decoder<'_>) -> WireResult<ApplyReceipt> {
    let intent = decoder.fixed("receipt intent")?;
    let certificate_digest = decoder.fixed("receipt certificate digest")?;
    let count = decoder.bounded_count(MAX_RECEIPT_OUTPUTS, "receipt output refs")?;
    let mut output_refs = Vec::with_capacity(count);
    for _ in 0..count {
        output_refs.push(take_cell_ref(decoder)?);
    }
    Ok(ApplyReceipt {
        intent,
        certificate_digest,
        output_refs,
    })
}

fn put_state(encoder: &mut Encoder, state: &State) -> WireResult<()> {
    encoder.count(state.live.len(), "live cells")?;
    for (reference, cell) in &state.live {
        if reference != &cell.reference {
            return Err("live-cell map key does not match embedded reference".into());
        }
        put_cell(encoder, cell);
    }

    encoder.count(state.spent_by.len(), "spent cells")?;
    for (reference, intent) in &state.spent_by {
        put_cell_ref(encoder, reference);
        encoder.fixed(intent);
    }

    encoder.count(state.known_ids.len(), "known cell ids")?;
    for id in &state.known_ids {
        encoder.fixed(id);
    }

    encoder.count(state.applied.len(), "applied receipts")?;
    for (intent, receipt) in &state.applied {
        if intent != &receipt.intent {
            return Err("applied-receipt map key does not match embedded intent".into());
        }
        put_apply_receipt(encoder, receipt)?;
    }
    Ok(())
}

fn take_state(decoder: &mut Decoder<'_>) -> WireResult<State> {
    let live_count = decoder.count("live cells")?;
    let mut live = BTreeMap::new();
    for _ in 0..live_count {
        let cell = take_cell(decoder)?;
        if live.insert(cell.reference, cell).is_some() {
            return Err("duplicate live cell reference".into());
        }
    }

    let spent_count = decoder.count("spent cells")?;
    let mut spent_by = BTreeMap::new();
    for _ in 0..spent_count {
        let reference = take_cell_ref(decoder)?;
        let intent = decoder.fixed("spent-by intent")?;
        if spent_by.insert(reference, intent).is_some() {
            return Err("duplicate spent cell reference".into());
        }
    }

    let known_count = decoder.count("known cell ids")?;
    let mut known_ids = BTreeSet::new();
    for _ in 0..known_count {
        if !known_ids.insert(decoder.fixed("known cell id")?) {
            return Err("duplicate known cell id".into());
        }
    }

    let applied_count = decoder.count("applied receipts")?;
    let mut applied = BTreeMap::new();
    for _ in 0..applied_count {
        let receipt = take_apply_receipt(decoder)?;
        if applied.insert(receipt.intent, receipt).is_some() {
            return Err("duplicate applied receipt intent".into());
        }
    }

    Ok(State {
        live,
        spent_by,
        known_ids,
        applied,
    })
}

pub fn encode_committee_manifest(manifest: &CommitteeManifest) -> WireResult<Vec<u8>> {
    let mut encoder = Encoder::new();
    put_committee_manifest(&mut encoder, manifest)?;
    encoder.finish()
}

pub fn decode_committee_manifest(bytes: &[u8]) -> WireResult<CommitteeManifest> {
    let mut decoder = Decoder::new(bytes)?;
    let value = take_committee_manifest(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}

macro_rules! exact_codec {
    ($encode:ident, $decode:ident, $ty:ty, $put:ident, $take:ident) => {
        pub fn $encode(value: &$ty) -> WireResult<Vec<u8>> {
            let mut encoder = Encoder::new();
            $put(&mut encoder, value)?;
            encoder.finish()
        }

        pub fn $decode(bytes: &[u8]) -> WireResult<$ty> {
            let mut decoder = Decoder::new(bytes)?;
            let value = $take(&mut decoder)?;
            decoder.finish()?;
            Ok(value)
        }
    };
}

fn put_cell_ref_result(encoder: &mut Encoder, value: &CellRef) -> WireResult<()> {
    put_cell_ref(encoder, value);
    Ok(())
}
fn put_cell_result(encoder: &mut Encoder, value: &Cell) -> WireResult<()> {
    put_cell(encoder, value);
    Ok(())
}
fn put_tx_result(encoder: &mut Encoder, value: &Tx) -> WireResult<()> {
    put_tx(encoder, value)
}
fn put_user_auth_result(encoder: &mut Encoder, value: &UserAuth) -> WireResult<()> {
    put_user_auth(encoder, value);
    Ok(())
}
fn put_vote_result(encoder: &mut Encoder, value: &Vote) -> WireResult<()> {
    put_vote(encoder, value)
}

exact_codec!(encode_cell_ref, decode_cell_ref, CellRef, put_cell_ref_result, take_cell_ref);
exact_codec!(encode_cell, decode_cell, Cell, put_cell_result, take_cell);
exact_codec!(encode_tx, decode_tx, Tx, put_tx_result, take_tx);
exact_codec!(
    encode_user_auth,
    decode_user_auth,
    UserAuth,
    put_user_auth_result,
    take_user_auth
);
exact_codec!(encode_vote, decode_vote, Vote, put_vote_result, take_vote);
exact_codec!(encode_qc, decode_qc, Qc, put_qc, take_qc);
exact_codec!(
    encode_proposal,
    decode_proposal,
    Proposal,
    put_proposal,
    take_proposal
);
exact_codec!(
    encode_state,
    decode_state,
    State,
    put_state,
    take_state
);

pub fn encode_state_snapshot(cells: &[Cell]) -> WireResult<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder.count(cells.len(), "snapshot cells")?;
    let mut references = BTreeSet::new();
    for cell in cells {
        if !references.insert(cell.reference) {
            return Err("duplicate snapshot cell reference".into());
        }
        put_cell(&mut encoder, cell);
    }
    encoder.finish()
}

pub fn decode_state_snapshot(bytes: &[u8]) -> WireResult<Vec<Cell>> {
    let mut decoder = Decoder::new(bytes)?;
    let count = decoder.count("snapshot cells")?;
    let mut cells = Vec::with_capacity(count);
    let mut references = BTreeSet::new();
    for _ in 0..count {
        let cell = take_cell(&mut decoder)?;
        if !references.insert(cell.reference) {
            return Err("duplicate snapshot cell reference".into());
        }
        cells.push(cell);
    }
    decoder.finish()?;
    Ok(cells)
}

pub fn encode_request(request: &Request) -> WireResult<Vec<u8>> {
    let mut encoder = Encoder::new();
    match request {
        Request::Ping => encoder.u8(REQUEST_PING),
        Request::Prevote(proposal) => {
            encoder.u8(REQUEST_PREVOTE);
            put_proposal(&mut encoder, proposal)?;
        }
        Request::Precommit {
            proposal,
            prevote_qc,
        } => {
            encoder.u8(REQUEST_PRECOMMIT);
            put_proposal(&mut encoder, proposal)?;
            put_qc(&mut encoder, prevote_qc)?;
        }
        Request::Apply {
            tx,
            auth,
            prevote_qc,
            finality_qc,
        } => {
            encoder.u8(REQUEST_APPLY);
            put_tx(&mut encoder, tx)?;
            put_user_auth(&mut encoder, auth);
            put_qc(&mut encoder, prevote_qc)?;
            put_qc(&mut encoder, finality_qc)?;
        }
        Request::QueryState => encoder.u8(REQUEST_QUERY_STATE),
    }
    encoder.finish()
}

pub fn decode_request(bytes: &[u8]) -> WireResult<Request> {
    let mut decoder = Decoder::new(bytes)?;
    let request = match decoder.u8("request tag")? {
        REQUEST_PING => Request::Ping,
        REQUEST_PREVOTE => Request::Prevote(take_proposal(&mut decoder)?),
        REQUEST_PRECOMMIT => Request::Precommit {
            proposal: take_proposal(&mut decoder)?,
            prevote_qc: take_qc(&mut decoder)?,
        },
        REQUEST_APPLY => Request::Apply {
            tx: take_tx(&mut decoder)?,
            auth: take_user_auth(&mut decoder)?,
            prevote_qc: take_qc(&mut decoder)?,
            finality_qc: take_qc(&mut decoder)?,
        },
        REQUEST_QUERY_STATE => Request::QueryState,
        tag => return Err(format!("invalid request tag {tag}")),
    };
    decoder.finish()?;
    Ok(request)
}

fn put_lifecycle(encoder: &mut Encoder, lifecycle: Lifecycle) {
    encoder.u8(match lifecycle {
        Lifecycle::Initialized => 1,
        Lifecycle::Active => 2,
        Lifecycle::Retired => 3,
    });
}

fn take_lifecycle(decoder: &mut Decoder<'_>) -> WireResult<Lifecycle> {
    match decoder.u8("lifecycle")? {
        1 => Ok(Lifecycle::Initialized),
        2 => Ok(Lifecycle::Active),
        3 => Ok(Lifecycle::Retired),
        value => Err(format!("invalid lifecycle value {value}")),
    }
}

pub fn encode_response(response: &Response) -> WireResult<Vec<u8>> {
    let mut encoder = Encoder::new();
    match response {
        Response::Pong {
            index,
            epoch,
            committee_hash,
        } => {
            encoder.u8(RESPONSE_PONG);
            encoder.u8(*index);
            encoder.u64(*epoch);
            encoder.fixed(committee_hash);
        }
        Response::Vote(vote) => {
            encoder.u8(RESPONSE_VOTE);
            put_vote(&mut encoder, vote)?;
        }
        Response::Applied {
            state_root,
            idempotent,
        } => {
            encoder.u8(RESPONSE_APPLIED);
            encoder.fixed(state_root);
            encoder.bool(*idempotent);
        }
        Response::State {
            state_root,
            snapshot_bytes,
            wal_bytes,
            lifecycle,
        } => {
            encoder.u8(RESPONSE_STATE);
            encoder.fixed(state_root);
            encoder.u64(*snapshot_bytes);
            encoder.u64(*wal_bytes);
            put_lifecycle(&mut encoder, *lifecycle);
        }
        Response::Rejected { code } => {
            encoder.u8(RESPONSE_REJECTED);
            encoder.u16(*code);
        }
    }
    encoder.finish()
}

pub fn decode_response(bytes: &[u8]) -> WireResult<Response> {
    let mut decoder = Decoder::new(bytes)?;
    let response = match decoder.u8("response tag")? {
        RESPONSE_PONG => Response::Pong {
            index: decoder.u8("validator index")?,
            epoch: decoder.u64("validator epoch")?,
            committee_hash: decoder.fixed("validator committee hash")?,
        },
        RESPONSE_VOTE => Response::Vote(take_vote(&mut decoder)?),
        RESPONSE_APPLIED => Response::Applied {
            state_root: decoder.fixed("applied state root")?,
            idempotent: decoder.bool("idempotent")?,
        },
        RESPONSE_STATE => Response::State {
            state_root: decoder.fixed("state root")?,
            snapshot_bytes: decoder.u64("snapshot byte count")?,
            wal_bytes: decoder.u64("WAL byte count")?,
            lifecycle: take_lifecycle(&mut decoder)?,
        },
        RESPONSE_REJECTED => Response::Rejected {
            code: decoder.u16("rejection code")?,
        },
        tag => return Err(format!("invalid response tag {tag}")),
    };
    decoder.finish()?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;
    use std::thread;

    fn sample_cell(seed: u8) -> Cell {
        Cell {
            reference: CellRef {
                asset_id: 1,
                id: [seed; 32],
                generation: u64::from(seed),
            },
            amount: 100,
            owner: [seed.wrapping_add(1); 32],
            predecessor: [seed.wrapping_add(2); 32],
            state_digest: [seed.wrapping_add(3); 32],
        }
    }

    fn sample_tx() -> Tx {
        Tx {
            version: 1,
            network_id: 1,
            epoch: 100,
            committee_hash: [4; 32],
            input: sample_cell(5),
            outputs: vec![
                Output {
                    asset_id: 1,
                    amount: 60,
                    owner: [6; 32],
                },
                Output {
                    asset_id: 1,
                    amount: 39,
                    owner: [7; 32],
                },
            ],
            fee: 1,
            salt: [8; 32],
        }
    }

    fn sample_auth() -> UserAuth {
        UserAuth {
            signer: [9; 32],
            signature: [10; 64],
        }
    }

    fn sample_vote(phase: u8, signer_index: u8) -> Vote {
        Vote {
            network_id: 1,
            epoch: 100,
            committee_hash: [11; 32],
            phase,
            round: 3,
            conflict_key: [12; 32],
            intent: [13; 32],
            justify: [14; 32],
            signer_index,
            signature: [15u8.wrapping_add(signer_index); 64],
        }
    }

    fn sample_qc(phase: u8) -> Qc {
        Qc {
            votes: (0..5).map(|index| sample_vote(phase, index)).collect(),
        }
    }

    fn sample_proposal() -> Proposal {
        Proposal {
            round: 4,
            proposer_index: 2,
            tx: sample_tx(),
            auth: sample_auth(),
            intent: [16; 32],
            justify: Some(sample_qc(PHASE_PRECOMMIT)),
            signature: [17; 64],
        }
    }

    fn sample_state() -> State {
        let cell = sample_cell(18);
        let spent = sample_cell(19).reference;
        let receipt = ApplyReceipt {
            intent: [20; 32],
            certificate_digest: [21; 32],
            output_refs: vec![cell.reference],
        };
        State {
            live: BTreeMap::from([(cell.reference, cell.clone())]),
            spent_by: BTreeMap::from([(spent, [22; 32])]),
            known_ids: BTreeSet::from([cell.reference.id, spent.id]),
            applied: BTreeMap::from([(receipt.intent, receipt)]),
        }
    }

    #[test]
    fn primitive_round_trip_is_little_endian_and_exact() {
        let mut encoder = Encoder::new();
        encoder.u8(7);
        encoder.bool(true);
        encoder.u16(0x1234);
        encoder.u32(0x1234_5678);
        encoder.u64(0x0123_4567_89ab_cdef);
        encoder.fixed(&[9u8; 32]);
        let bytes = encoder.finish().unwrap();
        assert_eq!(&bytes[2..4], &[0x34, 0x12]);
        assert_eq!(&bytes[4..8], &[0x78, 0x56, 0x34, 0x12]);

        let mut decoder = Decoder::new(&bytes).unwrap();
        assert_eq!(decoder.u8("tag").unwrap(), 7);
        assert!(decoder.bool("enabled").unwrap());
        assert_eq!(decoder.u16("short").unwrap(), 0x1234);
        assert_eq!(decoder.u32("word").unwrap(), 0x1234_5678);
        assert_eq!(decoder.u64("long").unwrap(), 0x0123_4567_89ab_cdef);
        assert_eq!(decoder.fixed::<32>("digest").unwrap(), [9u8; 32]);
        decoder.finish().unwrap();
    }

    #[test]
    fn invalid_boolean_and_trailing_bytes_fail_closed() {
        let mut bad_bool = Decoder::new(&[2]).unwrap();
        assert!(bad_bool.bool("flag").unwrap_err().contains("invalid"));

        let mut trailing = Decoder::new(&[1, 0xff]).unwrap();
        assert_eq!(trailing.u8("tag").unwrap(), 1);
        assert!(trailing.finish().unwrap_err().contains("trailing"));
    }

    #[test]
    fn bounded_counts_fail_before_allocation() {
        let count = (MAX_COLLECTION_LEN as u32 + 1).to_le_bytes();
        let mut decoder = Decoder::new(&count).unwrap();
        assert!(decoder.count("shares").unwrap_err().contains("exceeds"));

        let mut encoder = Encoder::new();
        assert!(encoder.count(MAX_COLLECTION_LEN + 1, "shares").is_err());
    }

    #[test]
    fn frame_round_trip_uses_big_endian_length() {
        let mut bytes = Vec::new();
        write_frame_to(&mut bytes, b"CALIBRE").unwrap();
        assert_eq!(&bytes[..4], &[0, 0, 0, 7]);
        assert_eq!(read_frame_from(&mut Cursor::new(bytes)).unwrap(), b"CALIBRE");
    }

    #[test]
    fn public_frame_api_round_trips_over_real_tcp() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_frame(&mut stream).unwrap();
            assert_eq!(request, b"request");
            write_frame(&mut stream, b"response").unwrap();
        });

        let mut client = TcpStream::connect(address).unwrap();
        write_frame(&mut client, b"request").unwrap();
        assert_eq!(read_frame(&mut client).unwrap(), b"response");
        server.join().unwrap();
    }

    #[test]
    fn oversized_outgoing_and_incoming_frames_fail_closed() {
        let mut sink = Vec::new();
        assert!(write_frame_to(&mut sink, &vec![0u8; MAX_FRAME_LEN + 1]).is_err());

        let declared = u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_be_bytes();
        let error = read_frame_from(&mut Cursor::new(declared)).unwrap_err();
        assert!(error.contains("incoming frame exceeds"));
    }

    #[test]
    fn truncated_frame_fails_closed() {
        let bytes = [0, 0, 0, 4, 1, 2, 3];
        assert!(read_frame_from(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn every_core_type_round_trips_exactly() {
        let manifest = CommitteeManifest {
            network_id: 1,
            epoch: 100,
            threshold: 5,
            members: (0..7)
                .map(|index| CommitteeMember {
                    index,
                    public_key: [index.wrapping_add(1); 32],
                })
                .collect(),
        };
        assert_eq!(
            decode_committee_manifest(&encode_committee_manifest(&manifest).unwrap()).unwrap(),
            manifest
        );

        let cell = sample_cell(1);
        assert_eq!(decode_cell_ref(&encode_cell_ref(&cell.reference).unwrap()).unwrap(), cell.reference);
        assert_eq!(decode_cell(&encode_cell(&cell).unwrap()).unwrap(), cell);

        let tx = sample_tx();
        assert_eq!(decode_tx(&encode_tx(&tx).unwrap()).unwrap(), tx);
        let auth = sample_auth();
        assert_eq!(decode_user_auth(&encode_user_auth(&auth).unwrap()).unwrap(), auth);
        let vote = sample_vote(PHASE_PREVOTE, 0);
        assert_eq!(decode_vote(&encode_vote(&vote).unwrap()).unwrap(), vote);
        let qc = sample_qc(PHASE_PRECOMMIT);
        assert_eq!(decode_qc(&encode_qc(&qc).unwrap()).unwrap(), qc);
        let proposal = sample_proposal();
        assert_eq!(decode_proposal(&encode_proposal(&proposal).unwrap()).unwrap(), proposal);
        let state = sample_state();
        assert_eq!(decode_state(&encode_state(&state).unwrap()).unwrap(), state);

        let snapshot = vec![sample_cell(30), sample_cell(31)];
        assert_eq!(
            decode_state_snapshot(&encode_state_snapshot(&snapshot).unwrap()).unwrap(),
            snapshot
        );
    }

    #[test]
    fn request_and_response_variants_round_trip() {
        let proposal = sample_proposal();
        let prevote_qc = sample_qc(PHASE_PREVOTE);
        let finality_qc = sample_qc(PHASE_PRECOMMIT);
        let requests = vec![
            Request::Ping,
            Request::Prevote(proposal.clone()),
            Request::Precommit {
                proposal: proposal.clone(),
                prevote_qc: prevote_qc.clone(),
            },
            Request::Apply {
                tx: proposal.tx.clone(),
                auth: proposal.auth,
                prevote_qc: prevote_qc.clone(),
                finality_qc,
            },
            Request::QueryState,
        ];
        for request in requests {
            assert_eq!(decode_request(&encode_request(&request).unwrap()).unwrap(), request);
        }

        let responses = vec![
            Response::Pong {
                index: 3,
                epoch: 100,
                committee_hash: [32; 32],
            },
            Response::Vote(sample_vote(PHASE_PREVOTE, 3)),
            Response::Applied {
                state_root: [33; 32],
                idempotent: true,
            },
            Response::State {
                state_root: [34; 32],
                snapshot_bytes: 1234,
                wal_bytes: 4321,
                lifecycle: Lifecycle::Active,
            },
            Response::Rejected { code: 7 },
        ];
        for response in responses {
            assert_eq!(decode_response(&encode_response(&response).unwrap()).unwrap(), response);
        }
    }

    #[test]
    fn bad_tags_phases_booleans_and_lifecycles_fail_closed() {
        assert!(decode_request(&[0xff]).unwrap_err().contains("request tag"));
        assert!(decode_response(&[0xff]).unwrap_err().contains("response tag"));

        let mut vote = encode_vote(&sample_vote(PHASE_PREVOTE, 0)).unwrap();
        vote[44] = 0xff;
        assert!(decode_vote(&vote).unwrap_err().contains("vote phase"));

        let mut applied = encode_response(&Response::Applied {
            state_root: [1; 32],
            idempotent: false,
        })
        .unwrap();
        applied[33] = 2;
        assert!(decode_response(&applied).unwrap_err().contains("boolean"));

        let mut state = encode_response(&Response::State {
            state_root: [1; 32],
            snapshot_bytes: 1,
            wal_bytes: 2,
            lifecycle: Lifecycle::Active,
        })
        .unwrap();
        state[49] = 9;
        assert!(decode_response(&state).unwrap_err().contains("lifecycle"));
    }

    #[test]
    fn type_decoders_reject_oversize_counts_and_trailing_bytes() {
        let mut manifest = encode_committee_manifest(&CommitteeManifest {
            network_id: 1,
            epoch: 100,
            threshold: 5,
            members: Vec::new(),
        })
        .unwrap();
        manifest[13..17].copy_from_slice(&8u32.to_le_bytes());
        assert!(decode_committee_manifest(&manifest).unwrap_err().contains("exceeds"));

        let mut tx = encode_tx(&sample_tx()).unwrap();
        tx[194..198].copy_from_slice(&9u32.to_le_bytes());
        assert!(decode_tx(&tx).unwrap_err().contains("outputs count exceeds"));

        let mut exact = encode_cell_ref(&sample_cell(1).reference).unwrap();
        exact.push(0);
        assert!(decode_cell_ref(&exact).unwrap_err().contains("trailing"));
    }

    #[test]
    fn duplicate_snapshot_and_state_keys_are_rejected() {
        let cell = sample_cell(40);
        assert!(encode_state_snapshot(&[cell.clone(), cell.clone()]).is_err());

        let mut malformed = sample_state();
        let key = *malformed.live.keys().next().unwrap();
        malformed.live.get_mut(&key).unwrap().reference = sample_cell(41).reference;
        assert!(encode_state(&malformed).unwrap_err().contains("map key"));
    }
}
