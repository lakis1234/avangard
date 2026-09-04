use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};

const NETWORK_ID: u32 = 1;
const MAX_INPUTS: usize = 8;
const CELL_VALUE: u64 = 100;
const CERT_EPOCH: u64 = 2;
const N: usize = 7;
const Q: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cell {
    id: u64,
    value: u64,
    generation: u64,
    owner: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct InputRef {
    id: u64,
    generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SpendTx {
    network_id: u32,
    tx_id: u64,
    inputs: Vec<InputRef>,
    output_id: u64,
    recipient: [u8; 32],
    output_value: u64,
    expiry: u64,
}

#[derive(Clone, Copy, Debug)]
struct UserAuthorization {
    signer: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Copy, Debug)]
struct VerifiedSpend {
    tx_digest: [u8; 32],
    user_signer: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
struct CertifierShare {
    certifier: [u8; 32],
    tx_digest: [u8; 32],
    user_signer: [u8; 32],
    epoch: u64,
    signature: [u8; 64],
}

#[derive(Clone, Debug)]
struct ThresholdCertificate {
    tx_digest: [u8; 32],
    user_signer: [u8; 32],
    epoch: u64,
    shares: Vec<CertifierShare>,
}

struct CertifierNode {
    sk: SigningKey,
    byzantine: bool,
    locks: HashMap<InputRef, [u8; 32]>,
}

#[derive(Clone)]
struct CoreState {
    active: HashMap<u64, Cell>,
    committee: Vec<[u8; 32]>,
    threshold: usize,
}

fn deterministic_key(label: u64) -> SigningKey {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC002_DETERMINISTIC_KEY_V1");
    h.update(&label.to_le_bytes());
    SigningKey::from_bytes(h.finalize().as_bytes())
}

fn canonical_user_message(tx: &SpendTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + tx.inputs.len() * 16);
    out.extend_from_slice(b"CALIBRE_SEC002_USER_SPEND_V1");
    out.extend_from_slice(&tx.network_id.to_le_bytes());
    out.extend_from_slice(&tx.tx_id.to_le_bytes());
    out.extend_from_slice(&(tx.inputs.len() as u64).to_le_bytes());
    for input in &tx.inputs {
        out.extend_from_slice(&input.id.to_le_bytes());
        out.extend_from_slice(&input.generation.to_le_bytes());
    }
    out.extend_from_slice(&tx.output_id.to_le_bytes());
    out.extend_from_slice(&tx.recipient);
    out.extend_from_slice(&tx.output_value.to_le_bytes());
    out.extend_from_slice(&tx.expiry.to_le_bytes());
    out
}

fn tx_commitment(tx: &SpendTx, signer: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC002_AUTHORIZED_TX_COMMITMENT_V1");
    h.update(&canonical_user_message(tx));
    h.update(signer);
    *h.finalize().as_bytes()
}

fn share_message(tx_digest: &[u8; 32], user_signer: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC002_THRESHOLD_SHARE_V1");
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(tx_digest);
    out.extend_from_slice(user_signer);
    out
}

fn sign_user_spend(tx: &SpendTx, sk: &SigningKey) -> UserAuthorization {
    UserAuthorization {
        signer: sk.verifying_key().to_bytes(),
        signature: sk.sign(&canonical_user_message(tx)).to_bytes(),
    }
}

fn verify_user_authorization(
    tx: &SpendTx,
    auth: &UserAuthorization,
    cells: &HashMap<u64, Cell>,
) -> Result<VerifiedSpend, String> {
    if tx.network_id != NETWORK_ID {
        return Err("wrong network/domain".into());
    }
    if tx.inputs.is_empty() || tx.inputs.len() > MAX_INPUTS {
        return Err("invalid input count".into());
    }

    let vk = VerifyingKey::from_bytes(&auth.signer).map_err(|_| "invalid user public key")?;
    let sig = Signature::from_bytes(&auth.signature);
    vk.verify_strict(&canonical_user_message(tx), &sig)
        .map_err(|_| "user signature rejected")?;

    let mut seen = HashSet::with_capacity(tx.inputs.len());
    let mut total = 0u64;
    for input in &tx.inputs {
        if !seen.insert(*input) {
            return Err("duplicate input".into());
        }
        let cell = cells
            .get(&input.id)
            .ok_or_else(|| format!("input {} not active", input.id))?;
        if cell.generation != input.generation {
            return Err(format!("input {} generation mismatch", input.id));
        }
        if cell.owner != auth.signer {
            return Err(format!("input {} owner mismatch", input.id));
        }
        total = total
            .checked_add(cell.value)
            .ok_or_else(|| "input value overflow".to_string())?;
    }

    if total != tx.output_value {
        return Err(format!(
            "value conservation mismatch: inputs={} output={}",
            total, tx.output_value
        ));
    }

    Ok(VerifiedSpend {
        tx_digest: tx_commitment(tx, &auth.signer),
        user_signer: auth.signer,
    })
}

impl CertifierNode {
    fn new(index: usize, byzantine: bool) -> Self {
        Self {
            sk: deterministic_key(100 + index as u64),
            byzantine,
            locks: HashMap::new(),
        }
    }

    fn public(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }

    fn make_share(&self, verified: VerifiedSpend) -> CertifierShare {
        CertifierShare {
            certifier: self.public(),
            tx_digest: verified.tx_digest,
            user_signer: verified.user_signer,
            epoch: CERT_EPOCH,
            signature: self
                .sk
                .sign(&share_message(
                    &verified.tx_digest,
                    &verified.user_signer,
                    CERT_EPOCH,
                ))
                .to_bytes(),
        }
    }

    fn authorize_and_sign(
        &mut self,
        tx: &SpendTx,
        auth: &UserAuthorization,
        cells: &HashMap<u64, Cell>,
    ) -> Result<CertifierShare, String> {
        let verified = verify_user_authorization(tx, auth, cells)?;

        if !self.byzantine {
            for input in &tx.inputs {
                if let Some(existing) = self.locks.get(input) {
                    if existing != &verified.tx_digest {
                        return Err(format!(
                            "honest certifier conflict lock for input {} generation {}",
                            input.id, input.generation
                        ));
                    }
                }
            }
            for input in &tx.inputs {
                self.locks.insert(*input, verified.tx_digest);
            }
        }

        Ok(self.make_share(verified))
    }

    // Attack helper: a Byzantine certifier may lie that ownership verification succeeded.
    fn sign_raw_claim(
        &self,
        tx: &SpendTx,
        claimed_user: [u8; 32],
    ) -> Result<CertifierShare, String> {
        if !self.byzantine {
            return Err("honest certifier refuses raw unverified claim".into());
        }
        Ok(self.make_share(VerifiedSpend {
            tx_digest: tx_commitment(tx, &claimed_user),
            user_signer: claimed_user,
        }))
    }
}

fn committee_with_f_byzantine(f: usize) -> Vec<CertifierNode> {
    assert!(f <= N);
    (0..N)
        .map(|i| CertifierNode::new(i, i < f))
        .collect()
}

fn committee_keys(nodes: &[CertifierNode]) -> Vec<[u8; 32]> {
    nodes.iter().map(CertifierNode::public).collect()
}

fn certificate_from(shares: Vec<CertifierShare>) -> ThresholdCertificate {
    assert!(!shares.is_empty());
    ThresholdCertificate {
        tx_digest: shares[0].tx_digest,
        user_signer: shares[0].user_signer,
        epoch: shares[0].epoch,
        shares,
    }
}

impl CoreState {
    fn new(cells: HashMap<u64, Cell>, committee: Vec<[u8; 32]>, threshold: usize) -> Self {
        Self {
            active: cells,
            committee,
            threshold,
        }
    }

    fn verify_threshold_certificate(
        &self,
        tx: &SpendTx,
        cert: &ThresholdCertificate,
    ) -> Result<(), String> {
        if cert.epoch != CERT_EPOCH {
            return Err("certificate epoch mismatch".into());
        }
        if tx_commitment(tx, &cert.user_signer) != cert.tx_digest {
            return Err("threshold certificate does not bind exact transaction".into());
        }

        let trusted: HashSet<[u8; 32]> = self.committee.iter().copied().collect();
        let mut unique = HashSet::new();
        for share in &cert.shares {
            if share.epoch != cert.epoch
                || share.tx_digest != cert.tx_digest
                || share.user_signer != cert.user_signer
            {
                return Err("share/certificate mismatch".into());
            }
            if !trusted.contains(&share.certifier) {
                return Err("share from untrusted certifier".into());
            }
            if !unique.insert(share.certifier) {
                continue;
            }
            let vk = VerifyingKey::from_bytes(&share.certifier)
                .map_err(|_| "invalid certifier public key")?;
            let sig = Signature::from_bytes(&share.signature);
            vk.verify_strict(
                &share_message(&share.tx_digest, &share.user_signer, share.epoch),
                &sig,
            )
            .map_err(|_| "threshold share signature rejected")?;
        }

        if unique.len() < self.threshold {
            return Err(format!(
                "insufficient threshold shares: have {} need {}",
                unique.len(), self.threshold
            ));
        }
        Ok(())
    }

    fn apply_certified_spend(
        &mut self,
        tx: &SpendTx,
        cert: &ThresholdCertificate,
    ) -> Result<Cell, String> {
        if tx.network_id != NETWORK_ID {
            return Err("core wrong network/domain".into());
        }
        self.verify_threshold_certificate(tx, cert)?;

        if tx.inputs.is_empty() || tx.inputs.len() > MAX_INPUTS {
            return Err("core invalid input count".into());
        }
        if self.active.contains_key(&tx.output_id) {
            return Err("output id already active".into());
        }

        let mut seen = HashSet::with_capacity(tx.inputs.len());
        let mut total = 0u64;
        for input in &tx.inputs {
            if !seen.insert(*input) {
                return Err("core duplicate input".into());
            }
            let cell = self
                .active
                .get(&input.id)
                .ok_or_else(|| format!("core input {} already spent/not active", input.id))?;
            if cell.generation != input.generation {
                return Err(format!("core input {} generation mismatch", input.id));
            }
            total = total
                .checked_add(cell.value)
                .ok_or_else(|| "core input value overflow".to_string())?;
        }
        if total != tx.output_value {
            return Err("core value conservation mismatch".into());
        }

        for input in &tx.inputs {
            self.active.remove(&input.id);
        }
        let output = Cell {
            id: tx.output_id,
            value: tx.output_value,
            generation: 0,
            owner: tx.recipient,
        };
        self.active.insert(output.id, output.clone());
        Ok(output)
    }
}

fn alice_cells(alice: [u8; 32]) -> HashMap<u64, Cell> {
    (0..MAX_INPUTS)
        .map(|i| {
            let id = 1_000 + i as u64;
            (
                id,
                Cell {
                    id,
                    value: CELL_VALUE,
                    generation: 7,
                    owner: alice,
                },
            )
        })
        .collect()
}

fn spend_to(recipient: [u8; 32], tx_id: u64, output_id: u64) -> SpendTx {
    SpendTx {
        network_id: NETWORK_ID,
        tx_id,
        inputs: (0..MAX_INPUTS)
            .map(|i| InputRef {
                id: 1_000 + i as u64,
                generation: 7,
            })
            .collect(),
        output_id,
        recipient,
        output_value: CELL_VALUE * MAX_INPUTS as u64,
        expiry: 2_000_000_000,
    }
}

fn collect_valid_shares(
    nodes: &mut [CertifierNode],
    indices: &[usize],
    tx: &SpendTx,
    auth: &UserAuthorization,
    cells: &HashMap<u64, Cell>,
) -> Vec<CertifierShare> {
    let mut out = Vec::new();
    for &i in indices {
        if let Ok(share) = nodes[i].authorize_and_sign(tx, auth, cells) {
            out.push(share);
        }
    }
    out
}

fn dual_quorum_exists_by_partition(n: usize, q: usize, f: usize) -> bool {
    let honest = n - f;
    let assignments = 3usize.pow(honest as u32);
    for mut code in 0..assignments {
        let mut a = f;
        let mut b = f;
        for _ in 0..honest {
            match code % 3 {
                1 => a += 1,
                2 => b += 1,
                _ => {}
            }
            code /= 3;
        }
        if a >= q && b >= q {
            return true;
        }
    }
    false
}

fn main() {
    let alice_sk = deterministic_key(1);
    let bob_sk = deterministic_key(2);
    let mallory_sk = deterministic_key(3);
    let alice = alice_sk.verifying_key().to_bytes();
    let bob = bob_sk.verifying_key().to_bytes();
    let mallory = mallory_sk.verifying_key().to_bytes();
    let cells = alice_cells(alice);

    println!("CALIBRE SECURITY SEC-002 v0.2.0");
    println!("5-OF-7 THRESHOLD AUTHORIZATION + CONFLICT-LOCK QUORUM BOUNDARY");
    println!("Purpose: remove the SEC-001 single-certifier theft authority and test conflicting-successor Byzantine safety");
    println!("N={} Q={} quorum intersection={} | honest certifier rule: one digest per input-generation per epoch", N, Q, 2 * Q - N);
    println!("Performance target: NONE - security phase; frozen PERF result remains separate");
    println!();

    // Normal valid owner-authorized spend.
    let tx = spend_to(bob, 42, 9_000);
    let auth = sign_user_spend(&tx, &alice_sk);
    let mut nodes = committee_with_f_byzantine(0);
    let committee = committee_keys(&nodes);
    let shares = collect_valid_shares(&mut nodes, &[0, 1, 2, 3, 4], &tx, &auth, &cells);
    assert_eq!(shares.len(), Q);
    let cert = certificate_from(shares);
    let mut core = CoreState::new(cells.clone(), committee, Q);
    let output = core
        .apply_certified_spend(&tx, &cert)
        .expect("SEC-002 valid threshold spend should commit");
    assert_eq!(output.owner, bob);
    println!("VALID ALICE -> BOB WITH 5-OF-7 CERTIFIER SHARES: PASS");

    // Two Byzantine certifiers cannot fabricate a threshold certificate for Mallory.
    let forged_tx = spend_to(mallory, 43, 9_001);
    let mallory_auth = sign_user_spend(&forged_tx, &mallory_sk);
    assert!(verify_user_authorization(&forged_tx, &mallory_auth, &cells).is_err());
    let nodes_f2 = committee_with_f_byzantine(2);
    let committee_f2 = committee_keys(&nodes_f2);
    let forged_shares = vec![
        nodes_f2[0].sign_raw_claim(&forged_tx, mallory).unwrap(),
        nodes_f2[1].sign_raw_claim(&forged_tx, mallory).unwrap(),
    ];
    let forged_cert = certificate_from(forged_shares);
    let forge_core = CoreState::new(cells.clone(), committee_f2.clone(), Q);
    assert!(forge_core
        .verify_threshold_certificate(&forged_tx, &forged_cert)
        .is_err());
    println!("UNAUTHORIZED MALLORY FORGERY WITH 2 BYZANTINE CERTIFIERS: REJECTED");

    // f=2: one valid quorum can form, but a conflicting second quorum cannot.
    let tx_a = spend_to(bob, 50, 9_100);
    let tx_b = spend_to(mallory, 51, 9_101);
    let auth_a = sign_user_spend(&tx_a, &alice_sk);
    let auth_b = sign_user_spend(&tx_b, &alice_sk);
    let mut f2_nodes = committee_with_f_byzantine(2);
    let a_shares = collect_valid_shares(&mut f2_nodes, &[0, 1, 2, 3, 4], &tx_a, &auth_a, &cells);
    let b_shares = collect_valid_shares(&mut f2_nodes, &[0, 1, 5, 6, 2], &tx_b, &auth_b, &cells);
    assert_eq!(a_shares.len(), 5);
    assert_eq!(b_shares.len(), 4);
    assert!(!dual_quorum_exists_by_partition(N, Q, 2));
    println!("F=2 CONFLICTING ALICE-SIGNED SUCCESSORS: SECOND 5-OF-7 QUORUM IMPOSSIBLE");

    // f=3 boundary: three Byzantine sign both; four honest split 2+2, creating two 5-share certs.
    let mut f3_nodes = committee_with_f_byzantine(3);
    let f3_committee = committee_keys(&f3_nodes);
    let a2 = collect_valid_shares(&mut f3_nodes, &[0, 1, 2, 3, 4], &tx_a, &auth_a, &cells);
    let b2 = collect_valid_shares(&mut f3_nodes, &[0, 1, 2, 5, 6], &tx_b, &auth_b, &cells);
    assert_eq!(a2.len(), 5);
    assert_eq!(b2.len(), 5);
    assert!(dual_quorum_exists_by_partition(N, Q, 3));
    let cert_a = certificate_from(a2);
    let cert_b = certificate_from(b2);
    let mut replica_a = CoreState::new(cells.clone(), f3_committee.clone(), Q);
    let mut replica_b = CoreState::new(cells.clone(), f3_committee, Q);
    let out_a = replica_a.apply_certified_spend(&tx_a, &cert_a).unwrap();
    let out_b = replica_b.apply_certified_spend(&tx_b, &cert_b).unwrap();
    assert_eq!(out_a.owner, bob);
    assert_eq!(out_b.owner, mallory);
    println!("F=3 PARTITIONED CONFLICT RACE: TWO VALID 5-OF-7 CERTIFICATES -> ATTACK CONFIRMED AT BOUNDARY");
    println!();

    println!("=== SEC-002 DECISION ===");
    println!("SINGLE CERTIFIER THEFT AUTHORITY REMOVED: PASS");
    println!("OWNER-AUTHORIZATION INDEPENDENTLY CHECKED BY HONEST CERTIFIERS: PASS");
    println!("5-OF-7 UNIQUE REAL ED25519 CERTIFIER SHARES VERIFIED BY CORE: PASS");
    println!("BELOW-THRESHOLD UNAUTHORIZED FORGERY WITH F=2: REJECTED");
    println!("CONFLICTING-SUCCESSOR SAFETY WITH F<=2 UNDER ONE-DIGEST HONEST LOCK RULE: PASS");
    println!("F=3 DUAL-CERTIFICATE SAFETY: FAIL - ATTACK CONFIRMED / EXPECTED QUORUM BOUNDARY");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("PERSISTENT CRASH-SAFE HONEST LOCKS: NOT YET");
    println!("PHYSICAL MULTI-MACHINE / WAN PARTITION TEST: NOT YET");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (SigningKey, SigningKey, SigningKey, HashMap<u64, Cell>) {
        let alice_sk = deterministic_key(1);
        let bob_sk = deterministic_key(2);
        let mallory_sk = deterministic_key(3);
        let cells = alice_cells(alice_sk.verifying_key().to_bytes());
        (alice_sk, bob_sk, mallory_sk, cells)
    }

    #[test]
    fn valid_five_of_seven_owner_spend_commits() {
        let (alice_sk, bob_sk, _, cells) = fixture();
        let tx = spend_to(bob_sk.verifying_key().to_bytes(), 1, 9000);
        let auth = sign_user_spend(&tx, &alice_sk);
        let mut nodes = committee_with_f_byzantine(0);
        let committee = committee_keys(&nodes);
        let shares = collect_valid_shares(&mut nodes, &[0, 1, 2, 3, 4], &tx, &auth, &cells);
        let cert = certificate_from(shares);
        let mut core = CoreState::new(cells, committee, Q);
        assert!(core.apply_certified_spend(&tx, &cert).is_ok());
    }

    #[test]
    fn two_byzantine_cannot_forge_unauthorized_owner() {
        let (_, _, mallory_sk, cells) = fixture();
        let mallory = mallory_sk.verifying_key().to_bytes();
        let tx = spend_to(mallory, 2, 9001);
        let nodes = committee_with_f_byzantine(2);
        let cert = certificate_from(vec![
            nodes[0].sign_raw_claim(&tx, mallory).unwrap(),
            nodes[1].sign_raw_claim(&tx, mallory).unwrap(),
        ]);
        let core = CoreState::new(cells, committee_keys(&nodes), Q);
        assert!(core.verify_threshold_certificate(&tx, &cert).is_err());
    }

    #[test]
    fn duplicate_share_cannot_inflate_threshold() {
        let (alice_sk, bob_sk, _, cells) = fixture();
        let tx = spend_to(bob_sk.verifying_key().to_bytes(), 3, 9002);
        let auth = sign_user_spend(&tx, &alice_sk);
        let mut nodes = committee_with_f_byzantine(0);
        let one = nodes[0].authorize_and_sign(&tx, &auth, &cells).unwrap();
        let cert = certificate_from(vec![one, one, one, one, one]);
        let core = CoreState::new(cells, committee_keys(&nodes), Q);
        assert!(core.verify_threshold_certificate(&tx, &cert).is_err());
    }

    #[test]
    fn exact_transaction_tamper_is_rejected() {
        let (alice_sk, bob_sk, mallory_sk, cells) = fixture();
        let tx = spend_to(bob_sk.verifying_key().to_bytes(), 4, 9003);
        let auth = sign_user_spend(&tx, &alice_sk);
        let mut nodes = committee_with_f_byzantine(0);
        let shares = collect_valid_shares(&mut nodes, &[0, 1, 2, 3, 4], &tx, &auth, &cells);
        let cert = certificate_from(shares);
        let mut modified = tx.clone();
        modified.recipient = mallory_sk.verifying_key().to_bytes();
        let core = CoreState::new(cells, committee_keys(&nodes), Q);
        assert!(core.verify_threshold_certificate(&modified, &cert).is_err());
    }

    #[test]
    fn f2_cannot_form_two_conflicting_quorums() {
        assert!(!dual_quorum_exists_by_partition(N, Q, 2));
    }

    #[test]
    fn f3_can_form_two_conflicting_quorums() {
        assert!(dual_quorum_exists_by_partition(N, Q, 3));
    }

    #[test]
    fn f3_real_dual_certificates_commit_on_partitioned_replicas() {
        let (alice_sk, bob_sk, mallory_sk, cells) = fixture();
        let tx_a = spend_to(bob_sk.verifying_key().to_bytes(), 5, 9100);
        let tx_b = spend_to(mallory_sk.verifying_key().to_bytes(), 6, 9101);
        let auth_a = sign_user_spend(&tx_a, &alice_sk);
        let auth_b = sign_user_spend(&tx_b, &alice_sk);
        let mut nodes = committee_with_f_byzantine(3);
        let committee = committee_keys(&nodes);
        let a = collect_valid_shares(&mut nodes, &[0, 1, 2, 3, 4], &tx_a, &auth_a, &cells);
        let b = collect_valid_shares(&mut nodes, &[0, 1, 2, 5, 6], &tx_b, &auth_b, &cells);
        assert_eq!(a.len(), Q);
        assert_eq!(b.len(), Q);
        let mut core_a = CoreState::new(cells.clone(), committee.clone(), Q);
        let mut core_b = CoreState::new(cells, committee, Q);
        assert!(core_a.apply_certified_spend(&tx_a, &certificate_from(a)).is_ok());
        assert!(core_b.apply_certified_spend(&tx_b, &certificate_from(b)).is_ok());
    }
}
