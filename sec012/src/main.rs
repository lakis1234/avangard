use std::collections::HashSet;

const N: usize = 7;
const Q: usize = 5;
const F_TARGET: usize = 2;
const H: usize = 5;
const ADVERSARIAL_ROUNDS: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Digest {
    A,
    B,
}

impl Digest {
    fn idx(self) -> u16 {
        match self {
            Digest::A => 0,
            Digest::B => 1,
        }
    }

    fn other(self) -> Self {
        match self {
            Digest::A => Digest::B,
            Digest::B => Digest::A,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Lock {
    round: u8,
    digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct State {
    locks: [Option<Lock>; H],
    prevote_qc_mask: u16,
    finality: Option<Digest>,
}

impl State {
    fn genesis() -> Self {
        Self {
            locks: [None; H],
            prevote_qc_mask: 0,
            finality: None,
        }
    }
}

#[derive(Default, Debug)]
struct Stats {
    transitions: u64,
    qc_branches: u64,
    no_qc_branches: u64,
    partial_lock_branches: u64,
    full_honest_lock_branches: u64,
    finality_branches: u64,
    safety_violations: u64,
    recovery_failures: u64,
    checked_terminal_states: u64,
    max_recovery_rounds: u8,
}

fn qc_bit(round: u8, digest: Digest) -> u16 {
    1u16 << ((round as u16) * 2 + digest.idx())
}

fn has_prevote_qc(state: &State, round: u8, digest: Digest) -> bool {
    state.prevote_qc_mask & qc_bit(round, digest) != 0
}

fn highest_qc_round(state: &State, digest: Digest, before_round: u8) -> Option<u8> {
    (0..before_round)
        .rev()
        .find(|r| has_prevote_qc(state, *r, digest))
}

fn highest_qc_any(state: &State, before_round: u8) -> Option<(u8, Digest)> {
    let mut best: Option<(u8, Digest)> = None;
    for round in 0..before_round {
        for digest in [Digest::A, Digest::B] {
            if has_prevote_qc(state, round, digest) {
                match best {
                    None => best = Some((round, digest)),
                    Some((old_round, _)) if round > old_round => best = Some((round, digest)),
                    _ => {}
                }
            }
        }
    }
    best
}

fn preferred_digest(state: &State, before_round: u8) -> Digest {
    highest_qc_any(state, before_round)
        .map(|(_, d)| d)
        .unwrap_or(Digest::A)
}

fn can_prevote(lock: Option<Lock>, digest: Digest, justify_round: Option<u8>) -> bool {
    match lock {
        None => true,
        Some(l) if l.digest == digest => true,
        Some(l) => justify_round.map(|r| r > l.round).unwrap_or(false),
    }
}

fn honest_can_prevote_count(state: &State, round: u8, digest: Digest) -> usize {
    let justify = highest_qc_round(state, digest, round);
    state
        .locks
        .iter()
        .filter(|lock| can_prevote(**lock, digest, justify))
        .count()
}

fn leader(offset: usize, round: u8) -> usize {
    (offset + round as usize) % N
}

fn leader_is_byzantine(offset: usize, round: u8) -> bool {
    leader(offset, round) < F_TARGET
}

fn apply_precommit_delivery(
    state: &State,
    round: u8,
    digest: Digest,
    delivery_mask: u8,
    finality_exists: bool,
    stats: &mut Stats,
) -> Option<State> {
    let mut next = state.clone();
    next.prevote_qc_mask |= qc_bit(round, digest);

    let mut honest_precommits = 0usize;
    for i in 0..H {
        if delivery_mask & (1 << i) != 0 {
            honest_precommits += 1;
            next.locks[i] = Some(Lock { round, digest });
        }
    }

    if honest_precommits > 0 && honest_precommits < H {
        stats.partial_lock_branches += 1;
    }
    if honest_precommits == H {
        stats.full_honest_lock_branches += 1;
    }

    if finality_exists {
        stats.finality_branches += 1;
        match next.finality {
            None => next.finality = Some(digest),
            Some(existing) if existing == digest => {}
            Some(_) => {
                stats.safety_violations += 1;
                return None;
            }
        }
    }

    Some(next)
}

fn expand_round(state: &State, offset: usize, round: u8, stats: &mut Stats) -> HashSet<State> {
    let mut out = HashSet::new();

    // Any round may fail to assemble a QC because messages are delayed or withheld.
    out.insert(state.clone());
    stats.no_qc_branches += 1;
    stats.transitions += 1;

    let candidates: Vec<Digest> = if leader_is_byzantine(offset, round) {
        // Byzantine leader may equivocate and separately attempt A or B.
        vec![Digest::A, Digest::B]
    } else {
        // Honest leader follows the highest known conflict-local QC; if none exists,
        // the deterministic canonical candidate is A.
        vec![preferred_digest(state, round)]
    };

    for digest in candidates {
        let honest_prevoters = honest_can_prevote_count(state, round, digest);

        // With f<=2 and Q=5, a Byzantine adversary can complete a PREVOTE QC only
        // if at least three honest certifiers can legally PREVOTE this digest.
        if honest_prevoters < Q - F_TARGET {
            continue;
        }

        stats.qc_branches += 1;

        // Once a valid PREVOTE QC exists, the adversary may deliver it to any subset
        // of honest certifiers before the round changes. Receipt causes a durable
        // PRECOMMIT lock for that digest/round.
        for mask in 0u8..(1u8 << H) {
            let honest_precommits = mask.count_ones() as usize;

            // Branch where Byzantine PRECOMMIT shares are withheld. If all five honest
            // PRECOMMIT, a 5-of-7 QC exists without Byzantine help and finality is unavoidable.
            let must_finalize = honest_precommits >= Q;
            if let Some(next) = apply_precommit_delivery(
                state,
                round,
                digest,
                mask,
                must_finalize,
                stats,
            ) {
                out.insert(next);
                stats.transitions += 1;
            }

            // If at least three honest PRECOMMITs exist, two Byzantine shares can complete
            // a 5-of-7 PRECOMMIT QC. Explore that adversarial branch as well.
            if honest_precommits >= Q - F_TARGET && !must_finalize {
                if let Some(next) = apply_precommit_delivery(
                    state,
                    round,
                    digest,
                    mask,
                    true,
                    stats,
                ) {
                    out.insert(next);
                    stats.transitions += 1;
                }
            }
        }
    }

    out
}

fn recover_after_gst(state: &State, offset: usize, start_round: u8) -> Option<(Digest, u8)> {
    if let Some(d) = state.finality {
        return Some((d, 0));
    }

    // After GST/network heal, Byzantine leaders may remain silent. Rotating leaders
    // guarantee an honest leader within at most seven rounds. An honest leader carries
    // the highest known PREVOTE QC; if none exists it proposes canonical A.
    for step in 0..N as u8 {
        let round = start_round + step;
        if leader_is_byzantine(offset, round) {
            continue;
        }

        let digest = preferred_digest(state, round);
        let justify = highest_qc_round(state, digest, round);
        let all_honest_can_vote = state
            .locks
            .iter()
            .all(|lock| can_prevote(*lock, digest, justify));

        if all_honest_can_vote {
            // Five honest PREVOTEs create the PREVOTE QC without Byzantine help.
            // Delivering it to all five gives five honest PRECOMMITs and finality.
            return Some((digest, step + 1));
        }
    }

    None
}

fn run_offset(offset: usize, stats: &mut Stats) -> HashSet<State> {
    let mut states = HashSet::from([State::genesis()]);

    for round in 0..ADVERSARIAL_ROUNDS {
        let mut next = HashSet::new();
        for state in &states {
            next.extend(expand_round(state, offset, round, stats));
        }
        states = next;
    }

    for state in &states {
        stats.checked_terminal_states += 1;
        match recover_after_gst(state, offset, ADVERSARIAL_ROUNDS) {
            Some((_digest, rounds)) => {
                stats.max_recovery_rounds = stats.max_recovery_rounds.max(rounds);
            }
            None => stats.recovery_failures += 1,
        }
    }

    states
}

fn f3_boundary_witness() -> bool {
    // With N=7,Q=5,f=3, three Byzantine certifiers can sign both A and B.
    // Two honest certifiers can join A and two different honest certifiers can join B:
    // 3 Byzantine + 2 honest = 5 for each conflicting certificate.
    let byzantine_overlap = 3usize;
    let honest_for_a = 2usize;
    let honest_for_b = 2usize;
    byzantine_overlap + honest_for_a >= Q && byzantine_overlap + honest_for_b >= Q
}

fn main() {
    println!("CALIBRE SECURITY SEC-012 v0.12.0");
    println!("BOUNDED EXHAUSTIVE CONFLICT-LOCAL QC/ROUND-CHANGE STATE MODEL");
    println!("N=7 Q=5 target f<=2; five honest + two Byzantine certifiers");
    println!("Bound: {ADVERSARIAL_ROUNDS} adversarial conflict-local rounds, then <=7 healed-network leader-rotation rounds");
    println!("Model abstraction: signatures are assumed unforgeable; durable same-round non-equivocation and QC-lock persistence are imported from SEC-011");
    println!("Global blockchain / universal transaction order: NOT USED");
    println!();

    let mut stats = Stats::default();
    let mut union_states = HashSet::new();

    for offset in 0..N {
        let states = run_offset(offset, &mut stats);
        println!(
            "LEADER OFFSET {offset}: {} unique states reachable after {ADVERSARIAL_ROUNDS} adversarial rounds",
            states.len()
        );
        union_states.extend(states);
    }

    println!();
    println!("=== SEC-012 BOUNDED MODEL SUMMARY ===");
    println!("UNIQUE TERMINAL STATES ACROSS ALL LEADER OFFSETS: {}", union_states.len());
    println!("STATE TRANSITIONS EXPLORED: {}", stats.transitions);
    println!("PREVOTE-QC BRANCHES EXPLORED: {}", stats.qc_branches);
    println!("NO-QC / DELAY-WITHHOLD BRANCHES EXPLORED: {}", stats.no_qc_branches);
    println!("PARTIAL HONEST QC-LOCK DELIVERY BRANCHES: {}", stats.partial_lock_branches);
    println!("FULL FIVE-HONEST QC-LOCK DELIVERY BRANCHES: {}", stats.full_honest_lock_branches);
    println!("PRECOMMIT FINALITY BRANCHES EXPLORED: {}", stats.finality_branches);
    println!("CONFLICTING DUAL-FINALITY STATES FOUND WITH f<=2: {}", stats.safety_violations);
    println!("POST-HEAL RECOVERY FAILURES FROM CHECKED TERMINAL STATES: {}", stats.recovery_failures);
    println!("MAX HEALED-NETWORK ROUNDS TO AN HONEST LEADER THAT CAN FINALIZE: {}", stats.max_recovery_rounds);
    println!("F=3 TWO-CONFLICTING-5-OF-7 BOUNDARY WITNESS EXISTS: {}", if f3_boundary_witness() { "YES" } else { "NO" });
    println!();

    println!("=== SEC-012 DECISION ===");
    if stats.safety_violations == 0 {
        println!("BOUNDED EXHAUSTIVE f<=2 CONFLICT-SAFETY CHECK: PASS WITHIN MODELED ROUND/STATE BOUND");
    } else {
        println!("BOUNDED EXHAUSTIVE f<=2 CONFLICT-SAFETY CHECK: FAIL - DUAL FINALITY REACHABLE");
    }
    if stats.recovery_failures == 0 {
        println!("POST-HEAL CONFLICT-LOCAL LEADER-ROTATION RECOVERY: PASS FROM ALL MODELED TERMINAL STATES");
    } else {
        println!("POST-HEAL CONFLICT-LOCAL LEADER-ROTATION RECOVERY: FAIL IN ONE OR MORE MODELED STATES");
    }
    println!("F=3 SAFETY BOUNDARY: DUAL 5-OF-7 CERTIFICATES MATHEMATICALLY REACHABLE / EXPECTED");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("FORMAL UNBOUNDED BYZANTINE CONSENSUS PROOF: NOT CLAIMED");
    println!("PHYSICAL MULTI-MACHINE / WAN: NOT TESTED BY THIS MODEL");

    if stats.safety_violations != 0 || stats.recovery_failures != 0 || !f3_boundary_witness() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_intersection_is_three() {
        assert_eq!(Q + Q - N, 3);
        assert!(Q + Q - N > F_TARGET);
    }

    #[test]
    fn f3_boundary_can_make_two_q5_certificates() {
        assert!(f3_boundary_witness());
    }

    #[test]
    fn conflicting_lock_requires_higher_justify_qc() {
        let lock = Some(Lock {
            round: 2,
            digest: Digest::A,
        });
        assert!(!can_prevote(lock, Digest::B, None));
        assert!(!can_prevote(lock, Digest::B, Some(2)));
        assert!(can_prevote(lock, Digest::B, Some(3)));
        assert!(can_prevote(lock, Digest::A, None));
    }

    #[test]
    fn leader_rotation_covers_all_seven() {
        for offset in 0..N {
            let leaders: HashSet<_> = (0..N as u8).map(|r| leader(offset, r)).collect();
            assert_eq!(leaders.len(), N);
        }
    }

    #[test]
    fn same_round_two_conflicting_qcs_need_six_honest_votes_under_f2() {
        // Each 5-of-7 QC with only two Byzantine nodes needs at least three honest votes.
        // Honest certifiers do not same-round equivocate, so two conflicting QCs would
        // require at least 3+3=6 honest votes, but only five honest certifiers exist.
        assert!(2 * (Q - F_TARGET) > H);
    }

    #[test]
    fn digest_other_is_inverse() {
        assert_eq!(Digest::A.other(), Digest::B);
        assert_eq!(Digest::B.other(), Digest::A);
    }
}
