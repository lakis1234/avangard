use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use std::collections::HashSet;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const N: usize = 7;
const Q: usize = 5;
const OLD_GENERATION: u64 = 70;
const CURRENT_GENERATION: u64 = 71;
const COIN_ID: u64 = 18_000_001;

const OP_PING: u8 = 0;
const OP_COMBINED_SHARE: u8 = 1;
const OP_SHUTDOWN: u8 = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StateRef {
    coin_id: u64,
    generation: u64,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FreshnessRequest {
    epoch: u64,
    state: StateRef,
    nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct CombinedShare {
    index: usize,
    monetary_signature: [u8; 64],
    nv_name: [u8; 32],
    nv_generation: u64,
    attestation_signature: [u8; 64],
}

#[derive(Clone, Copy, Debug)]
struct MonotonicGeneration {
    value: u64,
}

impl MonotonicGeneration {
    fn new(value: u64) -> Self {
        Self { value }
    }

    fn advance_to(&mut self, next: u64) -> bool {
        if next <= self.value {
            return false;
        }
        self.value = next;
        true
    }
}

fn deterministic_key(domain: &[u8], label: u64) -> SigningKey {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(&label.to_le_bytes());
    SigningKey::from_bytes(h.finalize().as_bytes())
}

fn committee_key(generation: u64, index: usize) -> SigningKey {
    deterministic_key(
        b"CALIBRE_SEC018_COMMITTEE_KEY_MODEL_V1",
        generation.wrapping_mul(1000).wrapping_add(index as u64),
    )
}

fn attestation_key(index: usize) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC018_PINNED_AK_MODEL_V1", index as u64)
}

fn pinned_nv_name(index: usize) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC018_PINNED_NV_NAME_MODEL_V1");
    h.update(&(index as u64).to_le_bytes());
    h.update(attestation_key(index).verifying_key().as_bytes());
    *h.finalize().as_bytes()
}

fn state(generation: u64, label: &[u8]) -> StateRef {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC018_MONETARY_STATE_V1");
    h.update(&COIN_ID.to_le_bytes());
    h.update(&generation.to_le_bytes());
    h.update(label);
    StateRef { coin_id: COIN_ID, generation, digest: *h.finalize().as_bytes() }
}

fn fresh_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
fn labelled_nonce(label: &[u8]) -> [u8; 32] {
    *blake3::hash(label).as_bytes()
}

fn monetary_message(request: &FreshnessRequest, index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(b"CALIBRE_SEC018_MONETARY_FRESHNESS_V1");
    out.extend_from_slice(&request.epoch.to_le_bytes());
    out.extend_from_slice(&request.state.coin_id.to_le_bytes());
    out.extend_from_slice(&request.state.generation.to_le_bytes());
    out.extend_from_slice(&request.state.digest);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out
}

fn qualifying_data(request: &FreshnessRequest) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC018_NV_QUALIFYING_DATA_V1");
    h.update(&request.epoch.to_le_bytes());
    h.update(&request.state.coin_id.to_le_bytes());
    h.update(&request.state.generation.to_le_bytes());
    h.update(&request.state.digest);
    h.update(&request.nonce);
    *h.finalize().as_bytes()
}

fn attestation_message(
    index: usize,
    nv_name: &[u8; 32],
    nv_generation: u64,
    qualifying: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(144);
    out.extend_from_slice(b"CALIBRE_SEC018_NV_CERTIFY_MODEL_V1");
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out.extend_from_slice(nv_name);
    out.extend_from_slice(&nv_generation.to_le_bytes());
    out.extend_from_slice(qualifying);
    out
}

fn make_combined_share(
    index: usize,
    device_nv_generation: u64,
    request: &FreshnessRequest,
) -> CombinedShare {
    let monetary_signature = committee_key(request.state.generation, index)
        .sign(&monetary_message(request, index))
        .to_bytes();
    let nv_name = pinned_nv_name(index);
    let attestation_signature = attestation_key(index)
        .sign(&attestation_message(
            index,
            &nv_name,
            device_nv_generation,
            &qualifying_data(request),
        ))
        .to_bytes();
    CombinedShare {
        index,
        monetary_signature,
        nv_name,
        nv_generation: device_nv_generation,
        attestation_signature,
    }
}

fn verify_combined_share(request: &FreshnessRequest, share: &CombinedShare) -> bool {
    if share.index >= N
        || share.nv_name != pinned_nv_name(share.index)
        || share.nv_generation != request.state.generation
    {
        return false;
    }

    let monetary_ok = committee_key(request.state.generation, share.index)
        .verifying_key()
        .verify_strict(
            &monetary_message(request, share.index),
            &Signature::from_bytes(&share.monetary_signature),
        )
        .is_ok();
    if !monetary_ok {
        return false;
    }

    attestation_key(share.index)
        .verifying_key()
        .verify_strict(
            &attestation_message(
                share.index,
                &share.nv_name,
                share.nv_generation,
                &qualifying_data(request),
            ),
            &Signature::from_bytes(&share.attestation_signature),
        )
        .is_ok()
}

fn accepted_indices(request: &FreshnessRequest, shares: &[CombinedShare]) -> HashSet<usize> {
    shares
        .iter()
        .filter(|share| verify_combined_share(request, share))
        .map(|share| share.index)
        .collect()
}

fn verify_certificate(request: &FreshnessRequest, shares: &[CombinedShare]) -> bool {
    accepted_indices(request, shares).len() >= Q
}

fn write_u64(stream: &mut impl Write, value: u64) -> std::io::Result<()> {
    stream.write_all(&value.to_le_bytes())
}

fn read_u64(stream: &mut impl Read) -> std::io::Result<u64> {
    let mut bytes = [0u8; 8];
    stream.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_array<const SIZE: usize>(stream: &mut impl Read) -> std::io::Result<[u8; SIZE]> {
    let mut bytes = [0u8; SIZE];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn write_request(stream: &mut impl Write, request: &FreshnessRequest) -> std::io::Result<()> {
    write_u64(stream, request.epoch)?;
    write_u64(stream, request.state.coin_id)?;
    write_u64(stream, request.state.generation)?;
    stream.write_all(&request.state.digest)?;
    stream.write_all(&request.nonce)
}

fn read_request(stream: &mut impl Read) -> std::io::Result<FreshnessRequest> {
    Ok(FreshnessRequest {
        epoch: read_u64(stream)?,
        state: StateRef {
            coin_id: read_u64(stream)?,
            generation: read_u64(stream)?,
            digest: read_array(stream)?,
        },
        nonce: read_array(stream)?,
    })
}

fn run_node(index: usize, port: u16, nv_generation: u64) -> Result<(), String> {
    if index >= N {
        return Err("node index outside committee".into());
    }
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    for incoming in listener.incoming() {
        let mut stream = incoming.map_err(|e| e.to_string())?;
        let mut opcode = [0u8; 1];
        stream.read_exact(&mut opcode).map_err(|e| e.to_string())?;
        match opcode[0] {
            OP_PING => stream.write_all(&[1]).map_err(|e| e.to_string())?,
            OP_COMBINED_SHARE => {
                let request = read_request(&mut stream).map_err(|e| e.to_string())?;
                let share = make_combined_share(index, nv_generation, &request);
                stream.write_all(&[1, index as u8]).map_err(|e| e.to_string())?;
                stream.write_all(&share.monetary_signature).map_err(|e| e.to_string())?;
                stream.write_all(&share.nv_name).map_err(|e| e.to_string())?;
                write_u64(&mut stream, share.nv_generation).map_err(|e| e.to_string())?;
                stream.write_all(&share.attestation_signature).map_err(|e| e.to_string())?;
            }
            OP_SHUTDOWN => break,
            _ => return Err("unknown SEC-018 opcode".into()),
        }
    }
    Ok(())
}

fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    Ok(listener.local_addr().map_err(|e| e.to_string())?.port())
}

fn connect(port: u16) -> Option<TcpStream> {
    let stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(1))).ok()?;
    Some(stream)
}

struct NodeProc {
    index: usize,
    port: u16,
    child: Child,
}

impl NodeProc {
    fn spawn(exe: &std::path::Path, index: usize, nv_generation: u64) -> Result<Self, String> {
        let port = free_port()?;
        let mut child = Command::new(exe)
            .arg("--node")
            .arg(index.to_string())
            .arg(port.to_string())
            .arg(nv_generation.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn node {index}: {e}"))?;

        for _ in 0..100 {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                return Err(format!("node {index} exited during startup with {status}"));
            }
            if let Some(mut stream) = connect(port) {
                if stream.write_all(&[OP_PING]).is_ok() {
                    let mut status = [0u8; 1];
                    if stream.read_exact(&mut status).is_ok() && status[0] == 1 {
                        return Ok(Self { index, port, child });
                    }
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
        Err(format!("node {index} did not become ready"))
    }

    fn stop(&mut self) {
        if let Some(mut stream) = connect(self.port) {
            let _ = stream.write_all(&[OP_SHUTDOWN]);
        }
        for _ in 0..40 {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        self.stop();
    }
}

fn rpc_combined_share(node: &NodeProc, request: &FreshnessRequest) -> Option<CombinedShare> {
    let mut stream = connect(node.port)?;
    stream.write_all(&[OP_COMBINED_SHARE]).ok()?;
    write_request(&mut stream, request).ok()?;
    let status = read_array::<2>(&mut stream).ok()?;
    if status[0] != 1 || status[1] as usize != node.index {
        return None;
    }
    Some(CombinedShare {
        index: status[1] as usize,
        monetary_signature: read_array(&mut stream).ok()?,
        nv_name: read_array(&mut stream).ok()?,
        nv_generation: read_u64(&mut stream).ok()?,
        attestation_signature: read_array(&mut stream).ok()?,
    })
}

fn collect(nodes: &[NodeProc], request: &FreshnessRequest) -> Vec<CombinedShare> {
    nodes
        .iter()
        .filter_map(|node| rpc_combined_share(node, request))
        .collect()
}

fn spawn_committee(exe: &std::path::Path, generations: &[u64; N]) -> Result<Vec<NodeProc>, String> {
    let mut nodes = Vec::with_capacity(N);
    for (index, generation) in generations.iter().copied().enumerate() {
        nodes.push(NodeProc::spawn(exe, index, generation)?);
    }
    Ok(nodes)
}

fn stop_committee(nodes: &mut [NodeProc]) {
    for node in nodes {
        node.stop();
    }
}

fn controller() -> Result<(), String> {
    let exe = env::current_exe().map_err(|e| e.to_string())?;
    println!("CALIBRE SECURITY SEC-018 v0.18.0");
    println!("ATTESTED MONOTONIC GENERATION PROTOCOL GATE / PRE-OPENED OLD-SIGNING-HANDLE ATTACK");
    println!("N=7 Q=5; retired generation 70; active generation 71");
    println!("Seven separate OS processes use real 127.0.0.1 TCP sockets on one physical host");
    println!("All seven old monetary-signing handles remain deliberately usable after retirement");
    println!("Global blockchain / universal transaction order: NOT USED");
    println!("IMPORTANT: software protocol model only; live TPM NV_Increment / NV_Certify / AK properties are NOT tested");
    println!("TPM clear / PCR / NV / hierarchy / BitLocker / existing-key modification: NONE");
    println!();

    let old_state = state(OLD_GENERATION, b"GENERATION-70-STATE");
    let current_state = state(CURRENT_GENERATION, b"GENERATION-71-STATE");

    let mut abstract_counter = MonotonicGeneration::new(OLD_GENERATION);
    if !abstract_counter.advance_to(CURRENT_GENERATION)
        || abstract_counter.advance_to(OLD_GENERATION)
    {
        return Err("abstract monotonic generation rule failed".into());
    }
    println!("ABSTRACT MONOTONIC RULE: 70->71 ACCEPTED; 71->70 REJECTED -> MODEL PASS");

    let baseline_request = FreshnessRequest {
        epoch: OLD_GENERATION,
        state: old_state,
        nonce: fresh_nonce(),
    };
    let mut nodes = spawn_committee(&exe, &[OLD_GENERATION; N])?;
    let baseline = collect(&nodes, &baseline_request);
    let baseline_count = accepted_indices(&baseline_request, &baseline).len();
    if baseline_count != N || !verify_certificate(&baseline_request, &baseline) {
        return Err(format!("pre-retirement baseline produced {baseline_count}/7"));
    }
    println!("PRE-RETIREMENT GENERATION-70 COMBINED FRESHNESS: 7/7 -> BASELINE PASS");
    stop_committee(&mut nodes);

    let post_generations = [
        CURRENT_GENERATION,
        CURRENT_GENERATION,
        CURRENT_GENERATION,
        CURRENT_GENERATION,
        CURRENT_GENERATION,
        OLD_GENERATION,
        OLD_GENERATION,
    ];
    let mut nodes = spawn_committee(&exe, &post_generations)?;

    let stale_request = FreshnessRequest {
        epoch: OLD_GENERATION,
        state: old_state,
        nonce: fresh_nonce(),
    };
    let stale = collect(&nodes, &stale_request);
    if stale.len() != N {
        return Err(format!("expected seven raw old-handle responses, got {}", stale.len()));
    }
    let stale_count = accepted_indices(&stale_request, &stale).len();
    if stale_count != 2 || verify_certificate(&stale_request, &stale) {
        return Err(format!("stale combined-certificate boundary was {stale_count}/7"));
    }
    println!("POST-RETIREMENT RAW OLD-HANDLE SIGNATURES: 7/7 STILL AVAILABLE -> SEC-017 ATTACK CAPABILITY PRESERVED");
    println!("POST-RETIREMENT OLD STATE + MATCHING GENERATION ATTESTATION: {stale_count}/7 <5 -> STALE QUORUM REJECTED: PASS IN MODEL");

    let current_request = FreshnessRequest {
        epoch: CURRENT_GENERATION,
        state: current_state,
        nonce: fresh_nonce(),
    };
    let current = collect(&nodes, &current_request);
    let current_count = accepted_indices(&current_request, &current).len();
    if current_count != Q || !verify_certificate(&current_request, &current) {
        return Err(format!("current combined certificate produced {current_count}/7"));
    }
    println!("CURRENT GENERATION-71 COMBINED FRESHNESS: {current_count}/7 -> QUORUM PASS");

    let replay_request = FreshnessRequest { nonce: fresh_nonce(), ..baseline_request };
    let replay_count = accepted_indices(&replay_request, &baseline).len();
    if replay_count != 0 || verify_certificate(&replay_request, &baseline) {
        return Err(format!("old nonce-bound certificate replay accepted {replay_count}/7"));
    }
    println!("OLD NV-PROOF + MONETARY-SIGNATURE REPLAY UNDER NEW CLIENT NONCE: 0/7 -> REJECTED: PASS");

    if verify_combined_share(&stale_request, &stale[0]) {
        return Err("generation-71 attestation mixed with generation-70 state was accepted".into());
    }
    println!("OLD MONETARY SIGNATURE MIXED WITH CURRENT GENERATION-71 ATTESTATION: REJECTED -> PASS");

    let mut wrong_name = current[0];
    wrong_name.nv_name[0] ^= 1;
    if verify_combined_share(&current_request, &wrong_name) {
        return Err("wrong NV Name was accepted".into());
    }
    println!("WRONG / REDEFINED NV-INDEX NAME: PIN MISMATCH -> REJECTED: PASS");

    let rollback_request = FreshnessRequest {
        epoch: OLD_GENERATION,
        state: old_state,
        nonce: fresh_nonce(),
    };
    let rollback = collect(&nodes, &rollback_request);
    let rollback_count = accepted_indices(&rollback_request, &rollback).len();
    if rollback_count != 2 || verify_certificate(&rollback_request, &rollback) {
        return Err(format!("application rollback accepted {rollback_count}/7"));
    }
    println!("RESTORED GENERATION-70 APPLICATION STATE WHILE HONEST MODELED NV REMAINS 71: {rollback_count}/7 <5 -> REJECTED: PASS IN MODEL");

    let boundary_request = FreshnessRequest {
        epoch: OLD_GENERATION,
        state: old_state,
        nonce: fresh_nonce(),
    };
    let mut boundary = Vec::new();
    for index in [0usize, 1, 2] {
        boundary.push(make_combined_share(index, OLD_GENERATION, &boundary_request));
    }
    for index in [5usize, 6] {
        boundary.push(
            rpc_combined_share(&nodes[index], &boundary_request)
                .ok_or_else(|| format!("Byzantine node {index} did not answer boundary request"))?,
        );
    }
    let boundary_count = accepted_indices(&boundary_request, &boundary).len();
    if boundary_count != Q || !verify_certificate(&boundary_request, &boundary) {
        return Err(format!("expected compromised-attestation-key boundary, got {boundary_count}/7"));
    }
    println!("THREE COMPROMISED PINNED ATTESTATION KEYS + TWO BYZANTINE GENERATION-70 DEVICES: {boundary_count}/7 STALE QUORUM -> ATTACK WITNESS CONFIRMED");

    stop_committee(&mut nodes);
    println!();
    println!("=== SEC-018 DECISION ===");
    println!("EXPERIMENT_EXECUTION=PASS");
    println!("OLD_PREOPENED_SIGNING_HANDLES_WITHOUT_MATCHING_GENERATION_ATTESTATION=REJECTED_2_OF_7_IN_TESTED_MODEL");
    println!("CURRENT_GENERATION_COMBINED_FRESHNESS=ACCEPTED_5_OF_7_IN_TESTED_MODEL");
    println!("OLD_NONCE_BOUND_ATTESTATION_REPLAY=REJECTED");
    println!("APPLICATION_STATE_ROLLBACK_WITHOUT_MODELED_NV_ROLLBACK=REJECTED_2_OF_7");
    println!("THREE_PINNED_ATTESTATION_KEYS_COMPROMISED=STALE_5_OF_7_ATTACK_CONFIRMED");
    println!("LIVE_TPM_NV_MONOTONICITY_NV_CERTIFY_AND_AK_PROPERTIES=NOT_TESTED");
    println!("TPM_CLEAR_PCR_NV_HIERARCHY_BITLOCKER_EXISTING_KEYS_MODIFIED=NO");
    println!("PHYSICAL_MULTI_MACHINE_WAN=NOT_YET");
    println!("GLOBAL_BLOCKCHAIN_OR_UNIVERSAL_ORDER_USED=NO");
    Ok(())
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let result = match args.get(1).map(String::as_str) {
        Some("--node") if args.len() == 5 => {
            let index = args[2].parse::<usize>().map_err(|e| e.to_string());
            let port = args[3].parse::<u16>().map_err(|e| e.to_string());
            let generation = args[4].parse::<u64>().map_err(|e| e.to_string());
            match (index, port, generation) {
                (Ok(index), Ok(port), Ok(generation)) => run_node(index, port, generation),
                (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => Err(e),
            }
        }
        Some("--node") => Err("usage: --node <index> <port> <nv-generation>".into()),
        None => controller(),
        Some(_) => Err("usage: calibre-sec018 [--node <index> <port> <nv-generation>]".into()),
    };
    if let Err(error) = result {
        eprintln!("SEC-018 ERROR: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> FreshnessRequest {
        FreshnessRequest {
            epoch: OLD_GENERATION,
            state: state(OLD_GENERATION, b"TEST"),
            nonce: labelled_nonce(b"SEC018-TEST-NONCE"),
        }
    }

    #[test]
    fn five_unique_combined_shares_pass_four_fail() {
        let request = request();
        let four = (0..4)
            .map(|index| make_combined_share(index, OLD_GENERATION, &request))
            .collect::<Vec<_>>();
        assert!(!verify_certificate(&request, &four));
        let five = (0..5)
            .map(|index| make_combined_share(index, OLD_GENERATION, &request))
            .collect::<Vec<_>>();
        assert!(verify_certificate(&request, &five));
    }

    #[test]
    fn duplicate_index_does_not_inflate_quorum() {
        let request = request();
        let share = make_combined_share(0, OLD_GENERATION, &request);
        assert!(!verify_certificate(&request, &[share; Q]));
    }

    #[test]
    fn client_nonce_and_state_are_bound() {
        let request = request();
        let share = make_combined_share(0, OLD_GENERATION, &request);
        let changed_nonce = FreshnessRequest { nonce: labelled_nonce(b"OTHER"), ..request };
        let changed_state = FreshnessRequest {
            state: state(OLD_GENERATION, b"OTHER-STATE"),
            ..request
        };
        assert!(verify_combined_share(&request, &share));
        assert!(!verify_combined_share(&changed_nonce, &share));
        assert!(!verify_combined_share(&changed_state, &share));
    }

    #[test]
    fn attested_generation_must_equal_state_generation() {
        let request = request();
        let share = make_combined_share(0, CURRENT_GENERATION, &request);
        assert!(!verify_combined_share(&request, &share));
    }

    #[test]
    fn pinned_nv_name_is_required() {
        let request = request();
        let mut share = make_combined_share(0, OLD_GENERATION, &request);
        share.nv_name[31] ^= 1;
        assert!(!verify_combined_share(&request, &share));
    }

    #[test]
    fn abstract_monotonic_generation_rejects_decrease_and_repeat() {
        let mut generation = MonotonicGeneration::new(OLD_GENERATION);
        assert!(generation.advance_to(CURRENT_GENERATION));
        assert!(!generation.advance_to(OLD_GENERATION));
        assert!(!generation.advance_to(CURRENT_GENERATION));
        assert_eq!(generation.value, CURRENT_GENERATION);
    }

    #[test]
    fn compromised_attestation_key_boundary_forms_five() {
        let request = request();
        let shares = [0usize, 1, 2, 5, 6]
            .into_iter()
            .map(|index| make_combined_share(index, OLD_GENERATION, &request))
            .collect::<Vec<_>>();
        assert_eq!(accepted_indices(&request, &shares).len(), Q);
        assert!(verify_certificate(&request, &shares));
    }
}
