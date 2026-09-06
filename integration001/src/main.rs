use calibre_integration001::config::{
    ControllerConfig, MAX_BENCH_COUNT, parse_controller_args,
};
use calibre_integration001::metrics::{RunMetrics, throughput, write_json};
use calibre_integration001::node::{REJECT_DURABLE_LOCK, REJECT_INVALID_PROPOSAL};
use calibre_integration001::model::{
    ApplyOutcome, Cell, CommitteeManifest, Digest, Output, PHASE_PRECOMMIT, PHASE_PREVOTE, Q,
    Qc, State, Tx, UserAuth, Vote, assemble_qc, committee_hash, conflict_key, fee_collector,
    intent_hash, lab_committee, lab_user_key, lab_validator_key, make_genesis_cell, make_proposal,
    make_transfer, qc_digest, sign_user, sign_vote, verify_qc, verify_user_auth, verify_vote, N,
    NETWORK_ID, OLD_EPOCH, PROTOCOL_VERSION,
};
use calibre_integration001::wire::{
    Request, Response, decode_response, encode_request, encode_state, read_frame, write_frame,
};
use blake3::Hasher;
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const VALIDATOR_COUNT: usize = 7;
const RPC_TIMEOUT: Duration = Duration::from_secs(120);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(8);
const LAB_SEED: u64 = 0xc411_b2e5_2026_0001;
const ALICE_KEY_LABEL: u64 = 1;
const BOB_KEY_LABEL: u64 = 2;
const CHARLIE_KEY_LABEL: u64 = 3;
const MALLORY_KEY_LABEL: u64 = 4;
const BENCH_OWNER_KEY_LABEL: u64 = 10;
const PHASE_A_GATES: [&str; 16] = [
    "B01", "B02", "B03", "B04", "B05", "B06", "B07", "B08", "B09", "B10", "B11",
    "B12", "B13", "B29", "B30-A", "B31-A",
];
const PHASE_B_NOT_IMPLEMENTED: [&str; 17] = [
    "B14", "B15", "B16", "B17", "B18", "B19", "B20", "B21", "B22", "B23", "B24",
    "B25", "B26", "B27", "B28", "B30-B", "B31-B",
];
const MEASURED_FIELDS: &str = "gate outcomes,clean-run count,validator topology,owner-auth rejections,field-mutation rejections,quorum-negative rejections,live-transaction finality proof-chain counts,diagnostic QC counts,zero hard-failure counters,client-submit-to-QC latency,independent-transfer throughput,framed TCP requests/bytes,canonical state totals/state root,snapshot bytes,WAL bytes,total wall time,executable BLAKE3";
const NOT_MEASURED_FIELDS: &str = "CPU,peak RSS,per-fsync latency,restart duration,packet loss,kernel TCP bytes,physical power-loss durability,WAN latency,physical multi-machine behavior";

#[derive(Clone)]
struct LabFixture {
    manifest: CommitteeManifest,
    genesis: State,
    alice: SigningKey,
    bob: [u8; 32],
    charlie: [u8; 32],
    mallory: SigningKey,
    bench_owner: SigningKey,
    main_input: Cell,
    negative_inputs: Vec<Cell>,
    bench_inputs: Vec<Cell>,
}

#[derive(Clone, Debug)]
struct FinalizedTransfer {
    tx: Tx,
    auth: UserAuth,
    prevote_qc: Qc,
    qc: Qc,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QuerySummary {
    state_root: Digest,
    snapshot_bytes: u64,
    wal_bytes: u64,
}

#[derive(Clone, Debug)]
struct PhaseARunOutcome {
    final_root: Digest,
    genesis_root: Digest,
    genesis_total: u64,
    final_total: u64,
    bench_elapsed: Duration,
    bench_completed: usize,
    invalid_owner_votes: u64,
    invalid_owner_rejections: u64,
    mutation_count: usize,
    qc_negative_count: usize,
    max_snapshot_bytes: u64,
    max_wal_bytes: u64,
    model_cases: u64,
    split_bob_votes: usize,
    split_charlie_votes: usize,
    post_restart_conflict_votes: usize,
    post_restart_lock_rejections: usize,
    conflicting_precommit_rejections: usize,
    loser_live_outputs: usize,
    decision_vector: Vec<u64>,
}

type StartGate = Arc<(Mutex<bool>, Condvar)>;

fn new_start_gate() -> StartGate {
    Arc::new((Mutex::new(false), Condvar::new()))
}

fn wait_for_start(gate: &StartGate) -> Result<(), String> {
    let (lock, ready) = &**gate;
    let mut started = lock
        .lock()
        .map_err(|_| "concurrent start gate mutex was poisoned".to_string())?;
    while !*started {
        started = ready
            .wait(started)
            .map_err(|_| "concurrent start gate mutex was poisoned while waiting".to_string())?;
    }
    Ok(())
}

fn release_start(gate: &StartGate) {
    let (lock, ready) = &**gate;
    // A failed worker must not strand its peers. Recovering a poisoned guard is
    // safe here because the only protected value is the one-way start flag.
    let mut started = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    *started = true;
    ready.notify_all();
}

fn labelled_digest(domain: &[u8], label: u64) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(domain);
    hasher.update(&label.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(count.saturating_mul(2));
    for byte in bytes.iter().take(count) {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn source_commit() -> &'static str {
    match option_env!("CALIBRE_SOURCE_COMMIT") {
        Some(value) if !value.is_empty() => value,
        _ => "UNAVAILABLE_NOT_INJECTED_AT_COMPILE_TIME",
    }
}

fn invocation_argv() -> String {
    format!("{:?}", std::env::args().collect::<Vec<_>>())
}

fn executable_audit_identity() -> Result<(String, String), String> {
    let path = std::env::current_exe()
        .map_err(|error| format!("locate running executable for B30-A: {error}"))?;
    let bytes = fs::read(&path)
        .map_err(|error| format!("read running executable for B30-A hash: {error}"))?;
    let digest = blake3::hash(&bytes);
    Ok((
        path.to_string_lossy().into_owned(),
        hex_prefix(digest.as_bytes(), 32),
    ))
}

fn build_fixture(bench_count: usize) -> Result<LabFixture, String> {
    let manifest = lab_committee(OLD_EPOCH);
    let alice = lab_user_key(ALICE_KEY_LABEL);
    let bob = lab_user_key(BOB_KEY_LABEL).verifying_key().to_bytes();
    let charlie = lab_user_key(CHARLIE_KEY_LABEL).verifying_key().to_bytes();
    let mallory = lab_user_key(MALLORY_KEY_LABEL);
    let bench_owner = lab_user_key(BENCH_OWNER_KEY_LABEL);
    let main_input = make_genesis_cell(1, 100, alice.verifying_key().to_bytes());
    let negative_inputs = (0..3)
        .map(|index| {
            make_genesis_cell(
                10 + index,
                100,
                alice.verifying_key().to_bytes(),
            )
        })
        .collect::<Vec<_>>();
    let bench_inputs = (0..bench_count)
        .map(|index| {
            make_genesis_cell(
                1_000 + index as u64,
                10,
                bench_owner.verifying_key().to_bytes(),
            )
        })
        .collect::<Vec<_>>();
    let mut cells = vec![main_input.clone()];
    cells.extend(negative_inputs.iter().cloned());
    cells.extend(bench_inputs.iter().cloned());
    let genesis = State::from_cells(cells)?;
    Ok(LabFixture {
        manifest,
        genesis,
        alice,
        bob,
        charlie,
        mallory,
        bench_owner,
        main_input,
        negative_inputs,
        bench_inputs,
    })
}

fn make_single_recipient_transfer(
    manifest: &CommitteeManifest,
    input: Cell,
    recipient: [u8; 32],
    amount: u64,
    fee: u64,
    salt_label: u64,
) -> Result<Tx, String> {
    make_transfer(
        manifest,
        input,
        vec![Output {
            asset_id: calibre_integration001::model::ASSET_CALIBRE,
            amount,
            owner: recipient,
        }],
        fee,
        labelled_digest(b"CALIBRE_INTEGRATION001_LAB_SALT_V1", salt_label),
    )
}

fn make_main_transfer(
    fixture: &LabFixture,
    recipient: [u8; 32],
    salt_label: u64,
) -> Result<(Tx, UserAuth), String> {
    let tx = make_transfer(
        &fixture.manifest,
        fixture.main_input.clone(),
        vec![
            Output {
                asset_id: fixture.main_input.reference.asset_id,
                amount: 60,
                owner: recipient,
            },
            Output {
                asset_id: fixture.main_input.reference.asset_id,
                amount: 39,
                owner: fixture.alice.verifying_key().to_bytes(),
            },
        ],
        1,
        labelled_digest(b"CALIBRE_INTEGRATION001_MAIN_SALT_V1", salt_label),
    )?;
    let auth = sign_user(&tx, &fixture.alice)?;
    Ok((tx, auth))
}

fn exhaustive_conflict_safety_cases() -> Result<u64, String> {
    let mut cases = 0u64;
    for honest_choices in 0u8..32 {
        for byzantine_zero in 0u8..4 {
            for byzantine_one in 0u8..4 {
                let honest_a = honest_choices.count_ones() as usize;
                let honest_b = 5usize.saturating_sub(honest_a);
                let byzantine_a = (byzantine_zero & 1 != 0) as usize
                    + (byzantine_one & 1 != 0) as usize;
                let byzantine_b = (byzantine_zero & 2 != 0) as usize
                    + (byzantine_one & 2 != 0) as usize;
                if honest_a + byzantine_a >= 5 && honest_b + byzantine_b >= 5 {
                    return Err(format!(
                        "dual quorum in abstract case honest={honest_choices:05b} byzantine={byzantine_zero},{byzantine_one}"
                    ));
                }
                cases = cases.saturating_add(1);
            }
        }
    }
    if cases != 512 {
        return Err(format!("abstract conflict model ran {cases} cases instead of 512"));
    }
    Ok(cases)
}

fn deterministic_permutation(count: usize, mut state: u64) -> Vec<usize> {
    let mut values: Vec<usize> = (0..count).collect();
    for upper in (1..count).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let selected = (state as usize) % (upper + 1);
        values.swap(upper, selected);
    }
    values
}

fn signed_field_mutations_rejected(
    tx: &Tx,
    auth: &UserAuth,
    manifest: &CommitteeManifest,
) -> Result<usize, String> {
    let mut mutations = Vec::new();

    let mut recipient = tx.clone();
    recipient.outputs[0].owner[0] ^= 1;
    mutations.push(("recipient", recipient));

    let mut version = tx.clone();
    version.version = version.version.wrapping_add(1);
    mutations.push(("protocol version", version));

    let mut amount = tx.clone();
    amount.outputs[0].amount += 1;
    amount.outputs[1].amount -= 1;
    mutations.push(("amount", amount));

    let mut fee = tx.clone();
    fee.fee += 1;
    fee.outputs[1].amount -= 1;
    mutations.push(("fee", fee));

    let mut input_id = tx.clone();
    input_id.input.reference.id[0] ^= 1;
    mutations.push(("input identity", input_id));

    let mut input_generation = tx.clone();
    input_generation.input.reference.generation += 1;
    mutations.push(("input generation", input_generation));

    let mut input_state = tx.clone();
    input_state.input.state_digest[0] ^= 1;
    mutations.push(("input state digest", input_state));

    let mut input_owner = tx.clone();
    input_owner.input.owner[0] ^= 1;
    mutations.push(("input owner", input_owner));

    let mut predecessor = tx.clone();
    predecessor.input.predecessor[0] ^= 1;
    mutations.push(("input predecessor", predecessor));

    let mut asset = tx.clone();
    asset.outputs[0].asset_id = asset.outputs[0].asset_id.wrapping_add(1);
    mutations.push(("asset", asset));

    let mut network = tx.clone();
    network.network_id = network.network_id.wrapping_add(1);
    mutations.push(("network", network));

    let mut epoch = tx.clone();
    epoch.epoch = epoch.epoch.wrapping_add(1);
    mutations.push(("committee generation", epoch));

    let mut committee = tx.clone();
    committee.committee_hash[0] ^= 1;
    mutations.push(("committee identity", committee));

    let mut effects = tx.clone();
    effects.outputs.swap(0, 1);
    mutations.push(("ordered output effects", effects));

    let mut salt = tx.clone();
    salt.salt[0] ^= 1;
    mutations.push(("transaction salt", salt));

    for (name, mutated) in &mutations {
        if verify_user_auth(mutated, auth, manifest).is_ok() {
            return Err(format!("owner authorization survived signed-field mutation: {name}"));
        }
    }
    Ok(mutations.len())
}

fn conservation_negatives_rejected(
    fixture: &LabFixture,
    base: &Tx,
) -> Result<(), String> {
    let mut hidden_mint = base.clone();
    hidden_mint.outputs[0].amount += 1;
    if calibre_integration001::model::validate_tx(&hidden_mint, &fixture.manifest).is_ok() {
        return Err("hidden mint transaction passed conservation".into());
    }

    let mut missing_value = base.clone();
    missing_value.outputs[0].amount -= 1;
    if calibre_integration001::model::validate_tx(&missing_value, &fixture.manifest).is_ok() {
        return Err("missing-value transaction passed conservation".into());
    }

    let mut overflow = base.clone();
    overflow.outputs[0].amount = u64::MAX;
    if calibre_integration001::model::validate_tx(&overflow, &fixture.manifest).is_ok() {
        return Err("overflowing transaction passed conservation".into());
    }

    let mut zero_fee = base.clone();
    zero_fee.outputs[1].amount += zero_fee.fee;
    zero_fee.fee = 0;
    if calibre_integration001::model::validate_tx(&zero_fee, &fixture.manifest).is_ok() {
        return Err("zero/implicit fee transaction was accepted".into());
    }
    Ok(())
}

fn request_vote(
    ports: &[u16],
    index: usize,
    request: &Request,
    metrics: &RunMetrics,
) -> Result<Option<Vote>, String> {
    let port = *ports
        .get(index)
        .ok_or_else(|| format!("no port for validator {index}"))?;
    match rpc(port, request, metrics)? {
        Response::Vote(vote) if vote.signer_index as usize == index => Ok(Some(vote)),
        Response::Vote(vote) => Err(format!(
            "validator {index} returned vote for signer {}",
            vote.signer_index
        )),
        Response::Rejected { .. } => Ok(None),
        other => Err(format!(
            "validator {index} returned unexpected vote response: {other:?}"
        )),
    }
}

fn collect_votes(
    ports: &[u16],
    indices: &[usize],
    request: &Request,
    metrics: &RunMetrics,
) -> Result<Vec<Vote>, String> {
    let mut votes = Vec::new();
    for &index in indices {
        if let Some(vote) = request_vote(ports, index, request, metrics)? {
            votes.push(vote);
        }
    }
    Ok(votes)
}

fn verify_observed_votes(
    votes: &[Vote],
    manifest: &CommitteeManifest,
    phase: u8,
    round: u64,
    conflict: Digest,
    intent: Digest,
) -> Result<(), String> {
    let mut signers = BTreeSet::new();
    for vote in votes {
        verify_vote(vote, manifest)?;
        if vote.phase != phase
            || vote.round != round
            || vote.conflict_key != conflict
            || vote.intent != intent
        {
            return Err("observed vote does not match the requested statement".into());
        }
        if !signers.insert(vote.signer_index) {
            return Err("observed vote set contains a duplicate signer".into());
        }
    }
    Ok(())
}

fn fixture_finality_chain(
    manifest: &CommitteeManifest,
    tx: &Tx,
    round: u64,
    signer_indices: &[usize],
) -> Result<(Qc, Qc), String> {
    let conflict = conflict_key(tx.input.reference);
    let intent = intent_hash(tx)?;
    let prevotes = signer_indices
        .iter()
        .copied()
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
        })
        .collect::<Result<Vec<_>, _>>()?;
    let prevote_qc = assemble_qc(
        prevotes,
        manifest,
        PHASE_PREVOTE,
        round,
        conflict,
        intent,
        None,
    )?;
    let prevote_digest = qc_digest(&prevote_qc, manifest)?;
    let precommits = signer_indices
        .iter()
        .copied()
        .map(|index| {
            sign_vote(
                manifest,
                PHASE_PRECOMMIT,
                round,
                conflict,
                intent,
                prevote_digest,
                index as u8,
                &lab_validator_key(manifest.epoch, index),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let precommit_qc = assemble_qc(
        precommits,
        manifest,
        PHASE_PRECOMMIT,
        round,
        conflict,
        intent,
        Some(prevote_digest),
    )?;
    Ok((prevote_qc, precommit_qc))
}

fn finalize_transfer(
    ports: &[u16],
    manifest: &CommitteeManifest,
    tx: Tx,
    auth: UserAuth,
    round: u64,
    metrics: &RunMetrics,
) -> Result<FinalizedTransfer, String> {
    let started = Instant::now();
    let proposal = make_proposal(manifest, round, tx.clone(), auth, None)?;
    let conflict = conflict_key(tx.input.reference);
    let intent = intent_hash(&tx)?;
    let honest = [2usize, 3, 4, 5, 6];
    let prevotes = collect_votes(
        ports,
        &honest,
        &Request::Prevote(proposal.clone()),
        metrics,
    )?;
    let prevote_qc = assemble_qc(
        prevotes,
        manifest,
        PHASE_PREVOTE,
        round,
        conflict,
        intent,
        None,
    )?;
    let prevote_digest = qc_digest(&prevote_qc, manifest)?;
    let retained_prevote_qc = prevote_qc.clone();
    let precommits = collect_votes(
        ports,
        &honest,
        &Request::Precommit {
            proposal,
            prevote_qc,
        },
        metrics,
    )?;
    let qc = assemble_qc(
        precommits,
        manifest,
        PHASE_PRECOMMIT,
        round,
        conflict,
        intent,
        Some(prevote_digest),
    )?;
    metrics.record_latency("client_submit_to_qc", started.elapsed());
    Ok(FinalizedTransfer {
        tx,
        auth,
        prevote_qc: retained_prevote_qc,
        qc,
    })
}

fn apply_to_validator(
    port: u16,
    finalized: &FinalizedTransfer,
    metrics: &RunMetrics,
) -> Result<(Digest, bool), String> {
    match rpc(
        port,
        &Request::Apply {
            tx: finalized.tx.clone(),
            auth: finalized.auth,
            prevote_qc: finalized.prevote_qc.clone(),
            finality_qc: finalized.qc.clone(),
        },
        metrics,
    )? {
        Response::Applied {
            state_root,
            idempotent,
        } => Ok((state_root, idempotent)),
        Response::Rejected { code } => Err(format!("validator rejected valid apply with code {code}")),
        other => Err(format!("unexpected apply response: {other:?}")),
    }
}

fn query_validator(port: u16, metrics: &RunMetrics) -> Result<QuerySummary, String> {
    match rpc(port, &Request::QueryState, metrics)? {
        Response::State {
            state_root,
            snapshot_bytes,
            wal_bytes,
            lifecycle: calibre_integration001::store::Lifecycle::Active,
        } => Ok(QuerySummary {
            state_root,
            snapshot_bytes,
            wal_bytes,
        }),
        Response::State { lifecycle, .. } => {
            Err(format!("validator is not active while queried: {lifecycle:?}"))
        }
        other => Err(format!("unexpected state response: {other:?}")),
    }
}

fn live_owner_authorization_negatives(
    fixture: &LabFixture,
    ports: &[u16],
    metrics: &RunMetrics,
) -> Result<(u64, u64), String> {
    let mut total_votes = 0u64;
    let mut total_rejections = 0u64;
    for (case_index, input) in fixture.negative_inputs.iter().enumerate() {
        let tx = make_single_recipient_transfer(
            &fixture.manifest,
            input.clone(),
            fixture.bob,
            99,
            1,
            10_000 + case_index as u64,
        )?;
        let valid_auth = sign_user(&tx, &fixture.alice)?;
        let mut proposal = make_proposal(
            &fixture.manifest,
            40 + case_index as u64,
            tx.clone(),
            valid_auth,
            None,
        )?;
        match case_index {
            0 => proposal.auth.signature = [0; 64],
            1 => proposal.auth = sign_user(&tx, &fixture.mallory)?,
            2 => proposal.auth.signature[0] ^= 1,
            _ => return Err("unexpected owner-negative case index".into()),
        }

        let request = Request::Prevote(proposal.clone());
        let mut votes = Vec::new();
        let mut case_rejections = 0usize;
        for index in 0..N {
            match rpc(ports[index], &request, metrics)? {
                Response::Vote(vote) if vote.signer_index as usize == index && index < 2 => {
                    votes.push(vote);
                }
                Response::Vote(vote) => {
                    return Err(format!(
                        "validator {index} unexpectedly signed invalid owner case {case_index} as signer {}",
                        vote.signer_index
                    ));
                }
                Response::Rejected { code }
                    if index >= 2 && code == REJECT_INVALID_PROPOSAL =>
                {
                    case_rejections += 1;
                }
                Response::Rejected { code } => {
                    return Err(format!(
                        "validator {index} returned ambiguous owner-negative rejection code {code} in case {case_index}"
                    ));
                }
                other => {
                    return Err(format!(
                        "validator {index} returned unexpected owner-negative response in case {case_index}: {other:?}"
                    ));
                }
            }
        }
        if case_rejections != 5 {
            return Err(format!(
                "owner-negative case {case_index} produced {case_rejections}/5 exact honest rejections"
            ));
        }
        verify_observed_votes(
            &votes,
            &fixture.manifest,
            PHASE_PREVOTE,
            proposal.round,
            conflict_key(tx.input.reference),
            intent_hash(&tx)?,
        )?;
        let mut signers = BTreeSet::new();
        for vote in &votes {
            verify_vote(vote, &fixture.manifest)?;
            if vote.signer_index >= 2 {
                return Err(format!(
                    "honest validator {} signed invalid owner authorization case {case_index}",
                    vote.signer_index
                ));
            }
            signers.insert(vote.signer_index);
        }
        if signers.len() > 2 {
            return Err(format!(
                "invalid owner authorization case {case_index} obtained {} unique shares",
                signers.len()
            ));
        }
        let intent = intent_hash(&tx)?;
        if assemble_qc(
            votes,
            &fixture.manifest,
            PHASE_PREVOTE,
            proposal.round,
            conflict_key(tx.input.reference),
            intent,
            None,
        )
        .is_ok()
        {
            return Err(format!(
                "invalid owner authorization case {case_index} formed a quorum"
            ));
        }
        total_votes = total_votes.saturating_add(signers.len() as u64);
        total_rejections = total_rejections.saturating_add(case_rejections as u64);
    }
    Ok((total_votes, total_rejections))
}

fn quorum_negative_matrix(
    finalized: &FinalizedTransfer,
    manifest: &CommitteeManifest,
) -> Result<usize, String> {
    let first = *finalized
        .qc
        .votes
        .first()
        .ok_or("finality QC unexpectedly empty")?;
    let conflict = conflict_key(finalized.tx.input.reference);
    let intent = intent_hash(&finalized.tx)?;
    verify_qc(
        &finalized.qc,
        manifest,
        PHASE_PRECOMMIT,
        first.round,
        conflict,
        intent,
        Some(first.justify),
    )?;

    let mut bad_cases = Vec::new();
    bad_cases.push(("four shares", Qc { votes: finalized.qc.votes[..4].to_vec() }));
    bad_cases.push(("duplicate identities", Qc { votes: vec![first; 5] }));

    let mut non_member = finalized.qc.clone();
    non_member.votes[0].signer_index = N as u8;
    bad_cases.push(("non-member", non_member));

    let mut wrong_committee = finalized.qc.clone();
    wrong_committee.votes[0].committee_hash[0] ^= 1;
    bad_cases.push(("wrong committee", wrong_committee));

    let mut wrong_generation = finalized.qc.clone();
    wrong_generation.votes[0].epoch = wrong_generation.votes[0].epoch.wrapping_add(1);
    bad_cases.push(("wrong generation", wrong_generation));

    let mut altered_payload = finalized.qc.clone();
    altered_payload.votes[0].intent[0] ^= 1;
    bad_cases.push(("altered payload", altered_payload));

    let mut invalid_signature = finalized.qc.clone();
    invalid_signature.votes[0].signature[0] ^= 1;
    bad_cases.push(("invalid signature", invalid_signature));

    for (name, qc) in &bad_cases {
        if verify_qc(
            qc,
            manifest,
            PHASE_PRECOMMIT,
            first.round,
            conflict,
            intent,
            Some(first.justify),
        )
        .is_ok()
        {
            return Err(format!("quorum verifier accepted {name}"));
        }
    }
    Ok(bad_cases.len())
}

fn make_bench_transfers(fixture: &LabFixture) -> Result<Vec<(Tx, UserAuth)>, String> {
    fixture
        .bench_inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let recipient = lab_user_key(1_000 + index as u64)
                .verifying_key()
                .to_bytes();
            let tx = make_single_recipient_transfer(
                &fixture.manifest,
                input.clone(),
                recipient,
                9,
                1,
                20_000 + index as u64,
            )?;
            let auth = sign_user(&tx, &fixture.bench_owner)?;
            Ok((tx, auth))
        })
        .collect()
}

fn finalize_bench_concurrently(
    ports: &[u16],
    manifest: &CommitteeManifest,
    transfers: Vec<(Tx, UserAuth)>,
    metrics: &RunMetrics,
) -> Result<(Vec<FinalizedTransfer>, Duration), String> {
    let count = transfers.len();
    let start_gate = new_start_gate();
    thread::scope(|scope| -> Result<_, String> {
        let mut handles = Vec::with_capacity(count);
        for (index, (tx, auth)) in transfers.into_iter().enumerate() {
            let worker_gate = Arc::clone(&start_gate);
            let manifest = manifest.clone();
            let metrics = metrics.clone();
            let worker = thread::Builder::new()
                .name(format!("calibre-finalize-{index}"))
                .spawn_scoped(scope, move || {
                    wait_for_start(&worker_gate)?;
                    finalize_transfer(
                        ports,
                        &manifest,
                        tx,
                        auth,
                        100 + index as u64,
                        &metrics,
                    )
                });
            match worker {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    release_start(&start_gate);
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(format!(
                        "spawn benchmark client thread {index}: {error}"
                    ));
                }
            }
        }
        let started = Instant::now();
        release_start(&start_gate);
        let mut finalized = Vec::with_capacity(count);
        for (index, handle) in handles.into_iter().enumerate() {
            let result = handle
                .join()
                .map_err(|_| format!("benchmark client thread {index} panicked"))??;
            finalized.push(result);
        }
        Ok((finalized, started.elapsed()))
    })
}

fn apply_in_order(
    starting_state: &State,
    finalized: &[FinalizedTransfer],
    order: &[usize],
    manifest: &CommitteeManifest,
) -> Result<State, String> {
    let mut state = starting_state.clone();
    for &index in order {
        let transfer = finalized
            .get(index)
            .ok_or_else(|| format!("schedule contains invalid transfer index {index}"))?;
        match state.apply_finalized(
            &transfer.tx,
            &transfer.auth,
            &transfer.prevote_qc,
            &transfer.qc,
            manifest,
        )? {
            ApplyOutcome::Applied(_) => {}
            ApplyOutcome::AlreadyApplied(_) => {
                return Err(format!("fresh schedule repeated transfer index {index}"));
            }
        }
    }
    Ok(state)
}

fn apply_bench_to_live_nodes(
    ports: &[u16],
    finalized: &[FinalizedTransfer],
    schedules: &[Vec<usize>],
    metrics: &RunMetrics,
) -> Result<(), String> {
    if schedules.len() != ports.len() {
        return Err("live schedule count does not match validator count".into());
    }
    let finalized = Arc::new(finalized.to_vec());
    let mut handles = Vec::with_capacity(ports.len());
    for (index, (&port, order)) in ports.iter().zip(schedules).enumerate() {
        let finalized = Arc::clone(&finalized);
        let order = order.clone();
        let metrics = metrics.clone();
        let spawn = thread::Builder::new()
            .name(format!("calibre-apply-{index}"))
            .spawn(move || -> Result<(), String> {
                for transfer_index in order {
                    let transfer = finalized.get(transfer_index).ok_or_else(|| {
                        format!("validator {index} schedule has invalid index {transfer_index}")
                    })?;
                    let (_, idempotent) = apply_to_validator(port, transfer, &metrics)?;
                    if idempotent {
                        return Err(format!(
                            "validator {index} treated first benchmark apply {transfer_index} as duplicate"
                        ));
                    }
                }
                Ok(())
            });
        match spawn {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                for handle in handles {
                    let _ = handle.join();
                }
                return Err(format!("spawn apply worker {index}: {error}"));
            }
        }
    }
    for (index, handle) in handles.into_iter().enumerate() {
        handle
            .join()
            .map_err(|_| format!("validator apply thread {index} panicked"))??;
    }
    Ok(())
}

#[derive(Debug)]
struct ValidatorProcess {
    index: usize,
    port: u16,
    wal_path: PathBuf,
    byzantine: bool,
    child: Option<Child>,
}

#[derive(Debug)]
struct Cluster {
    exe: PathBuf,
    epoch: u64,
    committee_hash: [u8; 32],
    snapshot_path: PathBuf,
    root: PathBuf,
    nodes: Vec<ValidatorProcess>,
    metrics: RunMetrics,
    cleaned: bool,
}

fn unique_temp_root() -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock before UNIX epoch: {error}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!(
        "calibre-integration001-{}-{nanos}",
        std::process::id()
    )))
}

fn reserve_loopback_ports(count: usize) -> Result<Vec<u16>, String> {
    let mut reservations = Vec::with_capacity(count);
    for _ in 0..count {
        reservations.push(
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .map_err(|error| format!("reserve loopback port: {error}"))?,
        );
    }
    let ports = reservations
        .iter()
        .map(|listener| {
            listener
                .local_addr()
                .map(|address| address.port())
                .map_err(|error| format!("read reserved port: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    drop(reservations);
    Ok(ports)
}

fn rpc_raw(port: u16, payload: &[u8], metrics: &RunMetrics) -> Result<Vec<u8>, String> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, RPC_TIMEOUT)
        .map_err(|error| format!("connect 127.0.0.1:{port}: {error}"))?;
    stream
        .set_read_timeout(Some(RPC_TIMEOUT))
        .map_err(|error| format!("set read timeout for 127.0.0.1:{port}: {error}"))?;
    stream
        .set_write_timeout(Some(RPC_TIMEOUT))
        .map_err(|error| format!("set write timeout for 127.0.0.1:{port}: {error}"))?;
    write_frame(&mut stream, payload)?;
    let response = read_frame(&mut stream)?;
    metrics.record_request(
        u64::try_from(payload.len().saturating_add(4)).unwrap_or(u64::MAX),
        u64::try_from(response.len().saturating_add(4)).unwrap_or(u64::MAX),
    );
    Ok(response)
}

fn rpc(port: u16, request: &Request, metrics: &RunMetrics) -> Result<Response, String> {
    let payload = encode_request(request)?;
    decode_response(&rpc_raw(port, &payload, metrics)?)
}

fn require_expected_pong(
    response: Response,
    index: usize,
    epoch: u64,
    committee_hash: [u8; 32],
) -> Result<(), String> {
    match response {
        Response::Pong {
            index: actual_index,
            epoch: actual_epoch,
            committee_hash: actual_committee,
        } if actual_index as usize == index
            && actual_epoch == epoch
            && actual_committee == committee_hash => Ok(()),
        other => Err(format!(
            "validator {index} returned wrong identity-bound readiness response: {other:?}"
        )),
    }
}

impl Cluster {
    fn start(
        epoch: u64,
        committee_hash: [u8; 32],
        snapshot_bytes: &[u8],
        metrics: RunMetrics,
    ) -> Result<Self, String> {
        let exe = std::env::current_exe().map_err(|error| format!("locate executable: {error}"))?;
        let ports = reserve_loopback_ports(VALIDATOR_COUNT)?;
        let root = unique_temp_root()?;
        fs::create_dir_all(&root)
            .map_err(|error| format!("create validator state directory: {error}"))?;
        let snapshot_path = root.join("genesis.snapshot");
        if let Err(error) = fs::write(&snapshot_path, snapshot_bytes) {
            let _ = fs::remove_dir_all(&root);
            return Err(format!("write validator genesis snapshot: {error}"));
        }
        let mut cluster = Self {
            exe,
            epoch,
            committee_hash,
            snapshot_path,
            root,
            nodes: Vec::with_capacity(VALIDATOR_COUNT),
            metrics,
            cleaned: false,
        };

        for (index, port) in ports.into_iter().enumerate() {
            cluster.spawn_node(index, port, index < 2)?;
        }
        Ok(cluster)
    }

    fn spawn_node(
        &mut self,
        index: usize,
        port: u16,
        byzantine: bool,
    ) -> Result<(), String> {
        let wal_path = self.root.join(format!("validator-{index}.wal"));
        let mut child = Command::new(&self.exe)
            .arg("--node")
            .arg(self.epoch.to_string())
            .arg(index.to_string())
            .arg(port.to_string())
            .arg(&wal_path)
            .arg(&self.snapshot_path)
            .arg(if byzantine { "1" } else { "0" })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("spawn validator {index}: {error}"))?;

        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("poll validator {index} during startup: {error}"))?
            {
                return Err(format!("validator {index} exited before readiness: {status}"));
            }
            if let Ok(response) = rpc(port, &Request::Ping, &RunMetrics::new()) {
                if require_expected_pong(response, index, self.epoch, self.committee_hash).is_ok() {
                    break;
                }
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("validator {index} did not answer Ping before timeout"));
            }
            thread::sleep(Duration::from_millis(20));
        }

        self.nodes.push(ValidatorProcess {
            index,
            port,
            wal_path,
            byzantine,
            child: Some(child),
        });
        Ok(())
    }

    fn ports(&self) -> Vec<u16> {
        self.nodes.iter().map(|node| node.port).collect()
    }

    fn restart(&mut self, index: usize) -> Result<u16, String> {
        let position = self
            .nodes
            .iter()
            .position(|node| node.index == index)
            .ok_or_else(|| format!("unknown validator index {index}"))?;
        if let Some(mut child) = self.nodes[position].child.take() {
            child
                .kill()
                .map_err(|error| format!("kill validator {index}: {error}"))?;
            child
                .wait()
                .map_err(|error| format!("wait for killed validator {index}: {error}"))?;
        }
        let port = reserve_loopback_ports(1)?
            .into_iter()
            .next()
            .ok_or("port reservation returned no port")?;
        let wal_path = self.nodes[position].wal_path.clone();
        let byzantine = self.nodes[position].byzantine;

        let mut child = Command::new(&self.exe)
            .arg("--node")
            .arg(self.epoch.to_string())
            .arg(index.to_string())
            .arg(port.to_string())
            .arg(&wal_path)
            .arg(&self.snapshot_path)
            .arg(if byzantine { "1" } else { "0" })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("restart validator {index}: {error}"))?;
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("poll restarted validator {index}: {error}"))?
            {
                return Err(format!("validator {index} exited during restart: {status}"));
            }
            if let Ok(response) = rpc(port, &Request::Ping, &RunMetrics::new()) {
                if require_expected_pong(
                    response,
                    index,
                    self.epoch,
                    self.committee_hash,
                )
                .is_ok()
                {
                    break;
                }
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("restarted validator {index} did not answer Ping"));
            }
            thread::sleep(Duration::from_millis(20));
        }
        self.nodes[position].port = port;
        self.nodes[position].child = Some(child);
        Ok(port)
    }

    fn shutdown_and_cleanup(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        for node in &mut self.nodes {
            let Some(mut child) = node.child.take() else {
                errors.push(format!("validator {} missing child handle", node.index));
                continue;
            };
            match child.try_wait() {
                Ok(Some(status)) => errors.push(format!(
                    "validator {} exited before controller cleanup: {status}",
                    node.index
                )),
                Ok(None) => {
                    if let Err(error) = child.kill() {
                        errors.push(format!("kill validator {}: {error}", node.index));
                    }
                    if let Err(error) = child.wait() {
                        errors.push(format!("reap validator {}: {error}", node.index));
                    }
                }
                Err(error) => errors.push(format!("poll validator {}: {error}", node.index)),
            }
        }
        if errors.is_empty() {
            fs::remove_dir_all(&self.root)
                .map_err(|error| format!("remove test-owned validator state: {error}"))?;
            self.cleaned = true;
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        for node in &mut self.nodes {
            if let Some(mut child) = node.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        if !self.cleaned {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn run_phase_a_once(
    config: &ControllerConfig,
    metrics: RunMetrics,
    run_label: &str,
) -> Result<PhaseARunOutcome, String> {
    let fixture = build_fixture(config.bench_count)?;
    let manifest_hash = committee_hash(&fixture.manifest)?;
    if N != VALIDATOR_COUNT || Q != 5 || fixture.manifest.members.len() != 7 {
        return Err("topology preflight is not N=7/Q=5".into());
    }
    let genesis_total = fixture.genesis.total_value()?;
    let snapshot_bytes = encode_state(&fixture.genesis)?;
    let mut cluster = Cluster::start(OLD_EPOCH, manifest_hash, &snapshot_bytes, metrics.clone())?;
    if cluster.nodes.len() != 7 || cluster.nodes.iter().filter(|node| node.byzantine).count() != 2 {
        return Err("live topology did not create exactly seven nodes with two Byzantine fixtures".into());
    }
    let mut ports = cluster.ports();

    println!("CALIBRE INTEGRATION-001 v0.1.0");
    println!("CLEAN REPEATABILITY RUN: {run_label}");
    println!("PHASE A — BOUNDED LOCAL MONETARY INTEGRATION");
    println!("Seven separate validator OS processes; real 127.0.0.1 TCP; N=7 Q=5 f<=2");
    println!("TPM: NOT USED");
    println!("NO BLOCKCHAIN / NO UNIVERSAL TRANSACTION ORDER FOR INDEPENDENT PAYMENTS");

    let (invalid_owner_votes, invalid_owner_rejections) =
        live_owner_authorization_negatives(&fixture, &ports, &metrics)?;
    println!("LIVE UNSIGNED / WRONG-OWNER / MALFORMED AUTHORIZATION: AT MOST 2/7 SHARES -> PASS");

    let (bob_tx, bob_auth) = make_main_transfer(&fixture, fixture.bob, 1)?;
    let (charlie_tx, charlie_auth) = make_main_transfer(&fixture, fixture.charlie, 2)?;
    let mutation_count = signed_field_mutations_rejected(&bob_tx, &bob_auth, &fixture.manifest)?;
    conservation_negatives_rejected(&fixture, &bob_tx)?;
    println!("OWNER SIGNATURE BINDS {mutation_count} TESTED FIELDS; CONSERVATION/OVERFLOW NEGATIVES REJECTED -> PASS");

    let bob_round_one = make_proposal(
        &fixture.manifest,
        1,
        bob_tx.clone(),
        bob_auth,
        None,
    )?;
    let charlie_round_one = make_proposal(
        &fixture.manifest,
        1,
        charlie_tx.clone(),
        charlie_auth,
        None,
    )?;
    let split_gate = new_start_gate();
    let (split_bob, split_charlie) = thread::scope(|scope| -> Result<_, String> {
        let bob_gate = Arc::clone(&split_gate);
        let bob_ports = &ports;
        let bob_metrics = &metrics;
        let bob_request = Request::Prevote(bob_round_one);
        let bob_worker = thread::Builder::new()
            .name("calibre-conflict-bob".into())
            .spawn_scoped(scope, move || {
                wait_for_start(&bob_gate)?;
                collect_votes(bob_ports, &[2, 3, 4], &bob_request, bob_metrics)
            })
            .map_err(|error| format!("spawn Bob conflict-delivery thread: {error}"))?;
        let charlie_gate = Arc::clone(&split_gate);
        let charlie_ports = &ports;
        let charlie_metrics = &metrics;
        let charlie_request = Request::Prevote(charlie_round_one);
        let charlie_worker = match thread::Builder::new()
            .name("calibre-conflict-charlie".into())
            .spawn_scoped(scope, move || {
                wait_for_start(&charlie_gate)?;
                collect_votes(
                    charlie_ports,
                    &[5, 6],
                    &charlie_request,
                    charlie_metrics,
                )
            }) {
            Ok(worker) => worker,
            Err(error) => {
                release_start(&split_gate);
                let _ = bob_worker.join();
                return Err(format!("spawn Charlie conflict-delivery thread: {error}"));
            }
        };
        release_start(&split_gate);
        let bob = bob_worker
            .join()
            .map_err(|_| "Bob conflict-delivery thread panicked".to_string())??;
        let charlie = charlie_worker
            .join()
            .map_err(|_| "Charlie conflict-delivery thread panicked".to_string())??;
        Ok((bob, charlie))
    })?;
    let main_conflict = conflict_key(fixture.main_input.reference);
    let bob_intent = intent_hash(&bob_tx)?;
    let charlie_intent = intent_hash(&charlie_tx)?;
    verify_observed_votes(
        &split_bob,
        &fixture.manifest,
        PHASE_PREVOTE,
        1,
        main_conflict,
        bob_intent,
    )?;
    verify_observed_votes(
        &split_charlie,
        &fixture.manifest,
        PHASE_PREVOTE,
        1,
        main_conflict,
        charlie_intent,
    )?;
    if split_bob.len() != 3 || split_charlie.len() != 2 {
        return Err(format!(
            "tentative honest split was {}/{} instead of 3/2",
            split_bob.len(),
            split_charlie.len()
        ));
    }
    println!("ROUND 1 CONCURRENT ALICE DOUBLE-SPEND: HONEST PREVOTES SPLIT BOB 3 / CHARLIE 2; NO QC -> OBSERVED");

    let bob_finalized = finalize_transfer(
        &ports,
        &fixture.manifest,
        bob_tx.clone(),
        bob_auth,
        2,
        &metrics,
    )?;
    let qc_negative_count = quorum_negative_matrix(&bob_finalized, &fixture.manifest)?;
    if bob_finalized.qc.votes.len() != Q {
        return Err("Bob finality certificate is not exactly 5-of-7".into());
    }
    println!("ROUND 2 HEALTHY HONEST QUORUM: BOB GETS 5/7 PRECOMMIT QC -> PASS");

    let (alternate_prevote_qc, alternate_precommit_qc) = fixture_finality_chain(
        &fixture.manifest,
        &bob_tx,
        2,
        &[0, 1, 2, 3, 4],
    )?;
    if qc_digest(&alternate_precommit_qc, &fixture.manifest)?
        == qc_digest(&bob_finalized.qc, &fixture.manifest)?
    {
        return Err("different signer subsets unexpectedly produced one QC digest".into());
    }
    let mut original_qc_state = fixture.genesis.clone();
    let mut alternate_qc_state = fixture.genesis.clone();
    original_qc_state.apply_finalized(
        &bob_tx,
        &bob_auth,
        &bob_finalized.prevote_qc,
        &bob_finalized.qc,
        &fixture.manifest,
    )?;
    alternate_qc_state.apply_finalized(
        &bob_tx,
        &bob_auth,
        &alternate_prevote_qc,
        &alternate_precommit_qc,
        &fixture.manifest,
    )?;
    if original_qc_state.root() != alternate_qc_state.root()
        || original_qc_state.live != alternate_qc_state.live
        || original_qc_state.spent_by != alternate_qc_state.spent_by
    {
        return Err("same intent with different valid QC subsets diverged semantic state".into());
    }
    println!("SAME BOB INTENT / TWO DIFFERENT VALID 5-OF-7 QC SUBSETS: SEMANTIC STATE ROOT MATCHES -> PASS");

    // Build a cryptographically valid opposing PREVOTE QC with laboratory
    // fixture keys, then send it to the two honest nodes that really recorded
    // Charlie PREVOTEs in round 1. Both have since durably PRECOMMIT-locked Bob
    // in round 2, so the old opposing PRECOMMIT must be rejected specifically
    // at the durable-lock boundary.
    let charlie_round_one_attack = make_proposal(
        &fixture.manifest,
        1,
        charlie_tx.clone(),
        charlie_auth,
        None,
    )?;
    let synthetic_charlie_prevotes = (0..Q)
        .map(|index| {
            sign_vote(
                &fixture.manifest,
                PHASE_PREVOTE,
                1,
                main_conflict,
                charlie_intent,
                [0; 32],
                index as u8,
                &lab_validator_key(OLD_EPOCH, index),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let synthetic_charlie_prevote_qc = assemble_qc(
        synthetic_charlie_prevotes,
        &fixture.manifest,
        PHASE_PREVOTE,
        1,
        main_conflict,
        charlie_intent,
        None,
    )?;
    let conflicting_precommit = Request::Precommit {
        proposal: charlie_round_one_attack,
        prevote_qc: synthetic_charlie_prevote_qc,
    };
    let mut conflicting_precommit_rejections = 0usize;
    for index in [5usize, 6] {
        match rpc(ports[index], &conflicting_precommit, &metrics)? {
            Response::Rejected { code } if code == REJECT_DURABLE_LOCK => {
                conflicting_precommit_rejections += 1;
            }
            other => {
                return Err(format!(
                    "honest validator {index} did not reject opposing PRECOMMIT at durable-lock boundary: {other:?}"
                ));
            }
        }
    }
    if conflicting_precommit_rejections != 2 {
        return Err("opposing PRECOMMIT durable-lock rejection count was not 2/2".into());
    }
    println!("WHITE-BOX SYNTHETIC OPPOSING ROUND-1 PREVOTE QC AFTER BOB LOCK: HONEST NODES 5,6 REJECT CHARLIE PRECOMMIT AT DURABLE LOCK 2/2 -> PASS");

    ports[2] = cluster.restart(2)?;
    let charlie_round_three = make_proposal(
        &fixture.manifest,
        3,
        charlie_tx.clone(),
        charlie_auth,
        None,
    )?;
    let charlie_after_lock_request = Request::Prevote(charlie_round_three);
    let mut charlie_after_lock = Vec::new();
    let mut post_restart_lock_rejections = 0usize;
    for index in 0..N {
        match rpc(ports[index], &charlie_after_lock_request, &metrics)? {
            Response::Vote(vote) if vote.signer_index as usize == index => {
                charlie_after_lock.push(vote);
            }
            Response::Vote(vote) => {
                return Err(format!(
                    "validator {index} returned post-restart vote for signer {}",
                    vote.signer_index
                ));
            }
            Response::Rejected { code }
                if index >= 2 && code == REJECT_DURABLE_LOCK =>
            {
                post_restart_lock_rejections += 1;
            }
            Response::Rejected { code } => {
                return Err(format!(
                    "validator {index} returned ambiguous post-restart conflict rejection code {code}"
                ));
            }
            other => {
                return Err(format!(
                    "validator {index} returned unexpected post-restart response: {other:?}"
                ));
            }
        }
    }
    verify_observed_votes(
        &charlie_after_lock,
        &fixture.manifest,
        PHASE_PREVOTE,
        3,
        main_conflict,
        charlie_intent,
    )?;
    if charlie_after_lock.len() != 2
        || charlie_after_lock.iter().any(|vote| vote.signer_index >= 2)
        || post_restart_lock_rejections != 5
    {
        return Err(format!(
            "post-lock Charlie conflict obtained unexpected shares/rejections: shares={:?} durable_lock_rejections={post_restart_lock_rejections}",
            charlie_after_lock
                .iter()
                .map(|vote| vote.signer_index)
                .collect::<Vec<_>>()
        ));
    }
    println!("ONE HONEST PROCESS KILL/RESTART: ALL FIVE HONEST NODES RETURN EXACT DURABLE-LOCK REJECTION; CHARLIE REMAINS 2/7 -> PASS SMOKE (NOT PHASE B)");

    let mut controller_state = fixture.genesis.clone();
    let bob_receipt = match controller_state.apply_finalized(
        &bob_finalized.tx,
        &bob_finalized.auth,
        &bob_finalized.prevote_qc,
        &bob_finalized.qc,
        &fixture.manifest,
    )? {
        ApplyOutcome::Applied(receipt) => receipt,
        ApplyOutcome::AlreadyApplied(_) => return Err("first controller Bob apply was duplicate".into()),
    };
    if bob_receipt.output_refs.len() != 3 {
        return Err("Bob transfer did not create recipient/change/fee cells".into());
    }
    let bob_cell = controller_state.live_cell(bob_receipt.output_refs[0]).ok_or("Bob output absent")?;
    let change_cell = controller_state.live_cell(bob_receipt.output_refs[1]).ok_or("Alice change absent")?;
    let fee_cell = controller_state.live_cell(bob_receipt.output_refs[2]).ok_or("fee output absent")?;
    if bob_cell.amount != 60 || bob_cell.owner != fixture.bob
        || change_cell.amount != 39 || change_cell.owner != fixture.alice.verifying_key().to_bytes()
        || fee_cell.amount != 1 || fee_cell.owner != fee_collector()
        || controller_state.total_value()? != genesis_total
        || controller_state.live.values().any(|cell| cell.owner == fixture.charlie)
    {
        return Err("Bob/Alice/fee outputs, conservation, or loser absence invariant failed".into());
    }

    for &port in &ports {
        let (_, duplicate) = apply_to_validator(port, &bob_finalized, &metrics)?;
        if duplicate { return Err("first live Bob apply was marked duplicate".into()); }
    }
    let duplicate_receipt = match controller_state.apply_finalized(
        &bob_finalized.tx,
        &bob_finalized.auth,
        &bob_finalized.prevote_qc,
        &bob_finalized.qc,
        &fixture.manifest,
    )? {
        ApplyOutcome::AlreadyApplied(receipt) => receipt,
        ApplyOutcome::Applied(_) => return Err("duplicate controller apply advanced state twice".into()),
    };
    if duplicate_receipt != bob_receipt {
        return Err("duplicate controller apply changed receipt".into());
    }
    for &port in &ports {
        let (_, duplicate) = apply_to_validator(port, &bob_finalized, &metrics)?;
        if !duplicate { return Err("duplicate live Bob apply advanced state twice".into()); }
    }
    println!("100 -> BOB 60 + ALICE 39 + FEE 1; DUPLICATE APPLY IDEMPOTENT; CHARLIE OUTPUT ABSENT -> PASS");

    let before_bench = controller_state.clone();
    let transfers = make_bench_transfers(&fixture)?;
    let (bench_finalized, bench_elapsed) = finalize_bench_concurrently(
        &ports,
        &fixture.manifest,
        transfers,
        &metrics,
    )?;
    if bench_finalized.len() != config.bench_count {
        return Err("not all independent transfers finalized".into());
    }
    let forward: Vec<usize> = (0..config.bench_count).collect();
    let reverse: Vec<usize> = forward.iter().rev().copied().collect();
    let shuffled = deterministic_permutation(config.bench_count, LAB_SEED);
    let forward_state = apply_in_order(&before_bench, &bench_finalized, &forward, &fixture.manifest)?;
    let reverse_state = apply_in_order(&before_bench, &bench_finalized, &reverse, &fixture.manifest)?;
    let shuffled_state = apply_in_order(&before_bench, &bench_finalized, &shuffled, &fixture.manifest)?;
    if forward_state.root() != reverse_state.root()
        || forward_state.root() != shuffled_state.root()
        || forward_state.total_value()? != genesis_total
    {
        return Err("independent transfer schedules did not converge".into());
    }
    let live_schedules = (0..N)
        .map(|index| match index % 3 {
            0 => forward.clone(),
            1 => reverse.clone(),
            _ => shuffled.clone(),
        })
        .collect::<Vec<_>>();
    apply_bench_to_live_nodes(&ports, &bench_finalized, &live_schedules, &metrics)?;

    let expected_root = forward_state.root();
    let mut max_snapshot_bytes = 0u64;
    let mut max_wal_bytes = 0u64;
    for &port in &ports {
        let query = query_validator(port, &metrics)?;
        if query.state_root != expected_root {
            return Err("live validator roots failed to converge across local schedules".into());
        }
        max_snapshot_bytes = max_snapshot_bytes.max(query.snapshot_bytes);
        max_wal_bytes = max_wal_bytes.max(query.wal_bytes);
    }
    let model_cases = exhaustive_conflict_safety_cases()?;
    println!("{} INDEPENDENT TRANSFERS: 5-HONEST QC EACH; FORWARD/REVERSE/SHUFFLED ROOTS CONVERGE -> PASS", config.bench_count);
    println!("EXHAUSTIVE F<=2 ABSTRACT CONFLICT CASES: {model_cases}/512, DUAL QC=0 -> PASS");

    cluster.shutdown_and_cleanup()?;
    println!("CLEAN REPEATABILITY RUN {run_label}: CORE GATES COMPLETE; FINAL DECISION DEFERRED");
    Ok(PhaseARunOutcome {
        final_root: expected_root,
        genesis_root: fixture.genesis.root(),
        genesis_total,
        final_total: forward_state.total_value()?,
        bench_elapsed,
        bench_completed: bench_finalized.len(),
        invalid_owner_votes,
        invalid_owner_rejections,
        mutation_count,
        qc_negative_count,
        max_snapshot_bytes,
        max_wal_bytes,
        model_cases,
        split_bob_votes: split_bob.len(),
        split_charlie_votes: split_charlie.len(),
        post_restart_conflict_votes: charlie_after_lock.len(),
        post_restart_lock_rejections,
        conflicting_precommit_rejections,
        loser_live_outputs: forward_state
            .live
            .values()
            .filter(|cell| cell.owner == fixture.charlie)
            .count(),
        decision_vector: vec![
            invalid_owner_votes,
            invalid_owner_rejections,
            split_bob.len() as u64,
            split_charlie.len() as u64,
            bob_finalized.qc.votes.len() as u64,
            conflicting_precommit_rejections as u64,
            charlie_after_lock.len() as u64,
            post_restart_lock_rejections as u64,
            mutation_count as u64,
            qc_negative_count as u64,
            bench_finalized.len() as u64,
            model_cases,
            genesis_total,
            forward_state.total_value()?,
        ],
    })
}

fn run_controller(config: ControllerConfig) -> Result<(), String> {
    let overall_started = Instant::now();
    let metrics = RunMetrics::new();
    let first = run_phase_a_once(&config, metrics.clone(), "1/2")?;
    let second = run_phase_a_once(&config, metrics.clone(), "2/2")?;
    if first.final_root != second.final_root
        || first.genesis_root != second.genesis_root
        || first.decision_vector != second.decision_vector
    {
        return Err("clean repeatability runs produced different root or safety decisions".into());
    }

    let audit_count_executed = config.bench_count == MAX_BENCH_COUNT;
    let all_gates = PHASE_A_GATES
        .iter()
        .map(|gate| (*gate, *gate != "B11" || audit_count_executed))
        .collect::<Vec<_>>();
    let passed_gate_count = all_gates.iter().filter(|(_, passed)| *passed).count();
    let phase_a_status = if audit_count_executed { "PASS" } else { "INCONCLUSIVE" };
    let b11_status = if audit_count_executed {
        "PASS"
    } else {
        "NOT_RUN_AT_AUDIT_COUNT"
    };
    let elapsed = overall_started.elapsed();
    let bench_tps = throughput(second.bench_completed as u64, second.bench_elapsed);
    let wire = metrics.wire_snapshot();
    let latency_samples = metrics
        .phase_summary("client_submit_to_qc")
        .map_or(0, |summary| summary.samples);
    let finality_proof_chains_per_run = 1u64.saturating_add(second.bench_completed as u64);
    let finality_proof_chains_total = finality_proof_chains_per_run.saturating_mul(2);
    let qc_shares_per_run = finality_proof_chains_per_run.saturating_mul(Q as u64);
    let expected_latency_samples = finality_proof_chains_total;
    if latency_samples != expected_latency_samples {
        return Err(format!(
            "B30-A latency sample count mismatch: observed {latency_samples}, expected {expected_latency_samples}"
        ));
    }
    if first.bench_completed != config.bench_count
        || second.bench_completed != config.bench_count
        || first.genesis_total != first.final_total
        || second.genesis_total != second.final_total
        || first.loser_live_outputs != 0
        || second.loser_live_outputs != 0
        || first.conflicting_precommit_rejections != 2
        || second.conflicting_precommit_rejections != 2
        || first.post_restart_lock_rejections != 5
        || second.post_restart_lock_rejections != 5
    {
        return Err("B30-A run-count, conservation, or loser-output evidence is inconsistent".into());
    }
    let (executable_path, executable_blake3) = executable_audit_identity()?;
    let invocation = invocation_argv();
    let source_commit = source_commit();
    let source_commit_status = if source_commit == "UNAVAILABLE_NOT_INJECTED_AT_COMPILE_TIME" {
        "UNAVAILABLE_NOT_INJECTED_AT_COMPILE_TIME"
    } else {
        "AVAILABLE_COMPILE_TIME"
    };
    let implemented_gates = PHASE_A_GATES.join(",");
    let phase_b_not_implemented_gates = PHASE_B_NOT_IMPLEMENTED.join(",");
    let manifest = lab_committee(OLD_EPOCH);
    let committee_hash_text = hex_prefix(&committee_hash(&manifest)?, 32);
    let validator_fingerprints = manifest
        .members
        .iter()
        .map(|member| format!("{}:{}", member.index, hex_prefix(&member.public_key, 8)))
        .collect::<Vec<_>>()
        .join(",");
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let phase_a_gate_statuses = all_gates
        .iter()
        .map(|(gate, passed)| {
            if *gate == "B08" {
                format!("{gate}:SAFETY_PASS_EQUIVOCATION_LIVENESS_NOT_GUARANTEED")
            } else if *gate == "B11" {
                format!("{gate}:{b11_status}")
            } else {
                format!("{gate}:{}", if *passed { "PASS" } else { "NOT_RUN" })
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    let phase_b_gate_statuses = PHASE_B_NOT_IMPLEMENTED
        .iter()
        .map(|gate| format!("{gate}:NOT_IMPLEMENTED"))
        .collect::<Vec<_>>()
        .join(",");

    if let Some(path) = &config.evidence_path {
        let bench_count_text = config.bench_count.to_string();
        let elapsed_text = elapsed.as_millis().to_string();
        let protocol_version_text = PROTOCOL_VERSION.to_string();
        let network_id_text = NETWORK_ID.to_string();
        let seed_text = format!("0x{LAB_SEED:016x}");
        let genesis_root_text = hex_prefix(&second.genesis_root, 32);
        let final_root_text = hex_prefix(&second.final_root, 32);
        let metadata = [
            ("experiment", "CALIBRE INTEGRATION-001"),
            ("phase", "A"),
            ("phase_a_status", phase_a_status),
            ("full_campaign", "NOT_IMPLEMENTED_NOT_RUN"),
            ("topology", "7_processes_127.0.0.1_Q5_f2"),
            ("platform", platform.as_str()),
            ("bench_count", bench_count_text.as_str()),
            ("elapsed_ms", elapsed_text.as_str()),
            ("acceptance_order", "conflict_local_no_blocks_no_universal_order"),
            ("protocol_version", protocol_version_text.as_str()),
            ("network_id", network_id_text.as_str()),
            ("seed", seed_text.as_str()),
            ("source_commit", source_commit),
            ("source_commit_status", source_commit_status),
            ("executable_path", executable_path.as_str()),
            ("executable_blake3", executable_blake3.as_str()),
            ("invocation_argv", invocation.as_str()),
            ("clean_initial_state_root", genesis_root_text.as_str()),
            ("final_state_root", final_root_text.as_str()),
            ("committee_hash", committee_hash_text.as_str()),
            ("validator_key_fingerprints", validator_fingerprints.as_str()),
            ("phase_a_implemented_gates", implemented_gates.as_str()),
            ("phase_a_gate_statuses", phase_a_gate_statuses.as_str()),
            ("b08_status", "SAFETY_PASS_EQUIVOCATION_LIVENESS_NOT_GUARANTEED"),
            ("b11_status", b11_status),
            ("phase_b_gate_statuses", phase_b_gate_statuses.as_str()),
            ("phase_b_not_implemented_gates", phase_b_not_implemented_gates.as_str()),
            ("measured_fields", MEASURED_FIELDS),
            ("not_measured_fields", NOT_MEASURED_FIELDS),
            ("healthy_finality_signers", "HONEST_INDICES_2_3_4_5_6_NO_BYZANTINE_COOPERATION"),
            ("b10_opposing_prevote_qc", "SYNTHETIC_WHITE_BOX_VALID_LAB_FIXTURE_INJECTION_NOT_AN_OBSERVED_ADVERSARY_QC"),
            ("restart_fault_observed", "HONEST_NODE_2_KILLED_RESTARTED_NEW_PORT_LOCK_RECOVERED"),
            ("cleanup", "TWO_TEST_OWNED_ROOTS_REMOVED_ALL_CHILDREN_REAPED"),
        ];
        let numeric = [
            ("live_transaction_finality_proof_chains_per_run", finality_proof_chains_per_run as f64),
            ("live_transaction_finality_proof_chains_total", finality_proof_chains_total as f64),
            ("live_transaction_precommit_qcs_per_run", finality_proof_chains_per_run as f64),
            ("live_transaction_precommit_qcs_total", finality_proof_chains_total as f64),
            ("live_transaction_prevote_qcs_per_run", finality_proof_chains_per_run as f64),
            ("live_transaction_prevote_qcs_total", finality_proof_chains_total as f64),
            ("live_transaction_qc_shares_per_phase_per_run", qc_shares_per_run as f64),
            ("unique_certified_intents_per_run", finality_proof_chains_per_run as f64),
            ("diagnostic_same_intent_alternate_finality_chains_per_run", 1.0),
            ("white_box_opposing_prevote_qc_injections_per_run", 1.0),
            ("accepted_transactions_per_run", (1 + second.bench_completed) as f64),
            ("abstract_conflict_cases_per_run", second.model_cases as f64),
            ("bench_completed_per_run", second.bench_completed as f64),
            ("bench_finality_elapsed_ms_second_run", second.bench_elapsed.as_secs_f64() * 1_000.0),
            ("bench_finality_proof_chains_per_second", bench_tps),
            ("byzantine_validators", 2.0),
            ("client_submit_to_qc_samples", latency_samples as f64),
            ("clean_repeatability_runs", 2.0),
            ("phase_a_gate_count", PHASE_A_GATES.len() as f64),
            ("phase_a_passed_gate_count", passed_gate_count as f64),
            ("conservation_final_total", second.final_total as f64),
            ("conservation_genesis_total", second.genesis_total as f64),
            ("main_input_value", 100.0),
            ("main_recipient_value", 60.0),
            ("main_change_value", 39.0),
            ("main_fee_value", 1.0),
            ("invalid_owner_cases_per_run", 3.0),
            ("invalid_owner_rejections_per_run", second.invalid_owner_rejections as f64),
            ("invalid_owner_votes_per_run", second.invalid_owner_votes as f64),
            ("signed_field_mutation_rejections_per_run", second.mutation_count as f64),
            ("conservation_negative_rejections_per_run", 4.0),
            ("quorum_negative_rejections_per_run", second.qc_negative_count as f64),
            ("duplicate_controller_apply_checks_per_run", 1.0),
            ("duplicate_live_validator_apply_checks_per_run", 7.0),
            ("unauthorized_finality_proof_chains", 0.0),
            ("dual_conflicting_finality_proof_chains", 0.0),
            ("different_valid_qc_subset_state_root_matches", 1.0),
            ("loser_live_outputs", second.loser_live_outputs as f64),
            ("live_conflict_bob_round1_prevotes", second.split_bob_votes as f64),
            ("live_conflict_charlie_round1_prevotes", second.split_charlie_votes as f64),
            ("opposing_precommit_durable_lock_rejections", second.conflicting_precommit_rejections as f64),
            ("post_restart_charlie_prevotes", second.post_restart_conflict_votes as f64),
            ("post_restart_durable_lock_rejections", second.post_restart_lock_rejections as f64),
            ("max_snapshot_bytes", first.max_snapshot_bytes.max(second.max_snapshot_bytes) as f64),
            ("max_wal_bytes", first.max_wal_bytes.max(second.max_wal_bytes) as f64),
            ("quorum_negative_cases_per_run", second.qc_negative_count as f64),
            ("signed_field_mutations_per_run", second.mutation_count as f64),
            ("validator_processes_per_run", 7.0),
        ];
        write_json(path, &metrics, &metadata, &all_gates, &numeric)
            .map_err(|error| format!("write Phase A evidence JSON: {error}"))?;
        println!("EVIDENCE JSON: {}", path.display());
    } else {
        println!("EVIDENCE JSON: NOT REQUESTED (use --evidence <path>)");
    }

    println!();
    println!("=== INTEGRATION-001 PHASE A GATES ===");
    for gate in PHASE_A_GATES {
        if gate == "B08" {
            println!("{gate}=PASS — SAFETY PASS / EQUIVOCATION LIVENESS NOT GUARANTEED");
        } else if gate == "B11" {
            println!("{gate}={b11_status} — REQUESTED_PER_RUN={}", config.bench_count);
        } else {
            println!("{gate}=PASS");
        }
    }
    println!("AUDIT_ID SOURCE_COMMIT={source_commit} SOURCE_COMMIT_STATUS={source_commit_status} EXECUTABLE_BLAKE3={executable_blake3} PLATFORM={platform}");
    println!("RUN_CONFIG PROTOCOL_VERSION={PROTOCOL_VERSION} NETWORK_ID={NETWORK_ID} EPOCH={OLD_EPOCH} N={N} Q={Q} F=2 SEED=0x{LAB_SEED:016x}");
    println!("ROOTS GENESIS={} FINAL={} COMMITTEE={}", hex_prefix(&second.genesis_root, 32), hex_prefix(&second.final_root, 32), committee_hash_text);
    println!("COUNTS PHASE_A_GATES_PASSED={passed_gate_count}/{} LIVE_TRANSACTION_FINALITY_CHAINS_PER_RUN={finality_proof_chains_per_run} UNIQUE_CERTIFIED_INTENTS_PER_RUN={finality_proof_chains_per_run} LIVE_TRANSACTION_PREVOTE_QCS_PER_RUN={finality_proof_chains_per_run} LIVE_TRANSACTION_PRECOMMIT_QCS_PER_RUN={finality_proof_chains_per_run} DIAGNOSTIC_ALTERNATE_SAME_INTENT_CHAINS_PER_RUN=1 WHITE_BOX_OPPOSING_PREVOTE_QC_INJECTIONS_PER_RUN=1 UNAUTHORIZED_FINALITY=0 DUAL_CONFLICT_FINALITY=0", PHASE_A_GATES.len());
    println!("NEGATIVES_PER_RUN OWNER_CASES=3 OWNER_HONEST_REJECTIONS={} SIGNED_FIELD_MUTATIONS={} CONSERVATION_CASES=4 QUORUM_CASES={}", second.invalid_owner_rejections, second.mutation_count, second.qc_negative_count);
    println!("CONFLICT_OBSERVED_PER_RUN ROUND1_BOB_PREVOTES={} ROUND1_CHARLIE_PREVOTES={} OPPOSING_PRECOMMIT_DURABLE_LOCK_REJECTIONS={} POST_RESTART_CHARLIE_PREVOTES={} POST_RESTART_DURABLE_LOCK_REJECTIONS={} LOSER_LIVE_OUTPUTS={}", second.split_bob_votes, second.split_charlie_votes, second.conflicting_precommit_rejections, second.post_restart_conflict_votes, second.post_restart_lock_rejections, second.loser_live_outputs);
    println!("CONSERVATION GENESIS_TOTAL={} FINAL_TOTAL={} RESULT=PASS", second.genesis_total, second.final_total);
    println!("PERSISTENCE MAX_SNAPSHOT_BYTES={} MAX_WAL_BYTES={}", first.max_snapshot_bytes.max(second.max_snapshot_bytes), first.max_wal_bytes.max(second.max_wal_bytes));
    println!("ELAPSED_TOTAL_MS={} INVOCATION={invocation}", elapsed.as_millis());
    println!("CLIENT_SUBMIT_TO_QC_P50_US={}", metrics.phase_summary("client_submit_to_qc").map_or(0, |value| value.p50_us));
    println!("BENCH_REQUESTED_PER_RUN={} BENCH_COMPLETED_PER_RUN={} BENCH_FINALITY_QC_TPS_SECOND_RUN={bench_tps:.2}", config.bench_count, second.bench_completed);
    println!("FRAMED_TCP_REQUESTS={} BYTES_SENT={} BYTES_RECEIVED={}", wire.requests, wire.bytes_sent, wire.bytes_received);
    println!("CLEAN_REPEATABILITY_RUNS=2 ROOT_AND_SAFETY_DECISIONS_MATCH=PASS");
    println!("MEASURED_FIELDS={MEASURED_FIELDS}");
    println!("NOT_MEASURED_FIELDS={NOT_MEASURED_FIELDS}");
    println!("SINGLE_PROCESS_RESTART_SMOKE=PASS; EXHAUSTIVE_CRASH_CAMPAIGN=NOT_IMPLEMENTED");
    println!("PHASE_B_GATES={phase_b_gate_statuses}");
    if audit_count_executed {
        println!("CALIBRE INTEGRATION-001 PHASE A: PASS");
    } else {
        println!("CALIBRE INTEGRATION-001 PHASE A: INCONCLUSIVE — B11 AUDIT COUNT {MAX_BENCH_COUNT} NOT RUN");
    }
    println!("CALIBRE INTEGRATION-001 FULL CAMPAIGN: NOT IMPLEMENTED / NOT RUN");
    Ok(())
}

fn program_main() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--node") {
        return calibre_integration001::node::run_node_from_args(&args[2..]);
    }
    let config = parse_controller_args(&args[1..])?;
    run_controller(config)
}

fn main() {
    if let Err(error) = program_main() {
        eprintln!("CALIBRE INTEGRATION-001 ERROR: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserves_seven_distinct_loopback_ports() {
        let ports = reserve_loopback_ports(VALIDATOR_COUNT).unwrap();
        let mut unique = ports.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ports.len(), VALIDATOR_COUNT);
        assert_eq!(unique.len(), VALIDATOR_COUNT);
    }

    #[test]
    fn exhaustive_f_two_model_has_no_dual_quorum() {
        assert_eq!(exhaustive_conflict_safety_cases().unwrap(), 512);
    }

    #[test]
    fn deterministic_schedule_is_a_permutation() {
        let first = deterministic_permutation(128, 0xc411_b2e5_2026_0001);
        let second = deterministic_permutation(128, 0xc411_b2e5_2026_0001);
        assert_eq!(first, second);
        let mut sorted = first;
        sorted.sort_unstable();
        assert_eq!(sorted, (0..128).collect::<Vec<_>>());
    }
}
