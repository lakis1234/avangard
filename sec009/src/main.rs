use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const NETWORK_ID: u32 = 1;
const N: usize = 7;
const Q: usize = 5;
const F_TARGET: usize = 2;
const PHASE_PREVOTE: u8 = 1;
const PHASE_PRECOMMIT: u8 = 2;
const OP_PING: u8 = 0;
const OP_PREVOTE: u8 = 1;
const OP_PRECOMMIT: u8 = 2;
const OP_SHUTDOWN: u8 = 255;
const WAL_MAGIC: [u8; 8] = *b"CAL009LK";
const WAL_RECORD: usize = 96;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct InputRef {
    id: u64,
    generation: u64,
}

#[derive(Clone, Debug)]
struct SpendTx {
    input: InputRef,
    tx_id: u64,
    recipient: [u8; 32],
    value: u64,
}

#[derive(Clone, Copy, Debug)]
struct UserAuth {
    signer: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Copy, Debug)]
struct Vote {
    index: usize,
    phase: u8,
    round: u64,
    input: InputRef,
    digest: [u8; 32],
    signature: [u8; 64],
}

#[derive(Clone, Debug)]
struct Qc {
    votes: Vec<Vote>,
}

#[derive(Clone, Debug)]
struct Proposal {
    round: u64,
    proposer: usize,
    tx: SpendTx,
    auth: UserAuth,
    digest: [u8; 32],
    justify: Option<Qc>,
    signature: [u8; 64],
}

fn deterministic_key(domain: &[u8], label: u64) -> SigningKey {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(&label.to_le_bytes());
    SigningKey::from_bytes(h.finalize().as_bytes())
}

fn user_key(label: u64) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC009_USER_KEY_V1", label)
}

fn certifier_key(index: usize) -> SigningKey {
    deterministic_key(b"CALIBRE_SEC009_CERTIFIER_KEY_V1", 100 + index as u64)
}

fn user_message(tx: &SpendTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC009_USER_SPEND_V1");
    out.extend_from_slice(&NETWORK_ID.to_le_bytes());
    out.extend_from_slice(&tx.input.id.to_le_bytes());
    out.extend_from_slice(&tx.input.generation.to_le_bytes());
    out.extend_from_slice(&tx.tx_id.to_le_bytes());
    out.extend_from_slice(&tx.recipient);
    out.extend_from_slice(&tx.value.to_le_bytes());
    out
}

fn digest_for(tx: &SpendTx, signer: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC009_AUTHORIZED_TX_V1");
    h.update(&user_message(tx));
    h.update(signer);
    *h.finalize().as_bytes()
}

fn sign_user(tx: &SpendTx, sk: &SigningKey) -> UserAuth {
    UserAuth {
        signer: sk.verifying_key().to_bytes(),
        signature: sk.sign(&user_message(tx)).to_bytes(),
    }
}

fn verify_user(tx: &SpendTx, auth: &UserAuth, digest: &[u8; 32]) -> Result<(), String> {
    let alice = user_key(1).verifying_key().to_bytes();
    if auth.signer != alice {
        return Err("owner mismatch".into());
    }
    if tx.value != 800 {
        return Err("value mismatch".into());
    }
    let vk = VerifyingKey::from_bytes(&auth.signer).map_err(|_| "bad user key")?;
    vk.verify_strict(&user_message(tx), &Signature::from_bytes(&auth.signature))
        .map_err(|_| "bad user signature")?;
    if &digest_for(tx, &auth.signer) != digest {
        return Err("digest mismatch".into());
    }
    Ok(())
}

fn leader(input: InputRef, round: u64) -> usize {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC009_CONFLICT_LEADER_V1");
    h.update(&input.id.to_le_bytes());
    h.update(&input.generation.to_le_bytes());
    h.update(&round.to_le_bytes());
    (u64::from_le_bytes(h.finalize().as_bytes()[0..8].try_into().unwrap()) as usize) % N
}

fn proposal_message(round: u64, proposer: usize, input: InputRef, digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC009_PROPOSAL_V1");
    out.extend_from_slice(&round.to_le_bytes());
    out.extend_from_slice(&(proposer as u64).to_le_bytes());
    out.extend_from_slice(&input.id.to_le_bytes());
    out.extend_from_slice(&input.generation.to_le_bytes());
    out.extend_from_slice(digest);
    out
}

fn vote_message(phase: u8, round: u64, input: InputRef, digest: &[u8; 32], index: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(b"CALIBRE_SEC009_VOTE_V1");
    out.push(phase);
    out.extend_from_slice(&round.to_le_bytes());
    out.extend_from_slice(&input.id.to_le_bytes());
    out.extend_from_slice(&input.generation.to_le_bytes());
    out.extend_from_slice(&(index as u64).to_le_bytes());
    out.extend_from_slice(digest);
    out
}

fn verify_vote(v: &Vote) -> bool {
    if v.index >= N || (v.phase != PHASE_PREVOTE && v.phase != PHASE_PRECOMMIT) {
        return false;
    }
    certifier_key(v.index)
        .verifying_key()
        .verify_strict(
            &vote_message(v.phase, v.round, v.input, &v.digest, v.index),
            &Signature::from_bytes(&v.signature),
        )
        .is_ok()
}

fn verify_qc(qc: &Qc, phase: u8, round: u64, input: InputRef, digest: &[u8; 32]) -> bool {
    let mut unique = HashSet::new();
    for v in &qc.votes {
        if v.phase != phase || v.round != round || v.input != input || &v.digest != digest || !verify_vote(v) {
            return false;
        }
        unique.insert(v.index);
    }
    unique.len() >= Q
}

fn make_qc(votes: Vec<Vote>, phase: u8, round: u64, input: InputRef, digest: &[u8; 32]) -> Result<Qc, String> {
    let mut unique = HashMap::new();
    for v in votes {
        if v.phase == phase && v.round == round && v.input == input && &v.digest == digest && verify_vote(&v) {
            unique.entry(v.index).or_insert(v);
        }
    }
    let qc = Qc { votes: unique.into_values().collect() };
    if verify_qc(&qc, phase, round, input, digest) {
        Ok(qc)
    } else {
        Err(format!("QC threshold not reached: {}/{}", qc.votes.len(), Q))
    }
}

fn checksum(prefix: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"CALIBRE_SEC009_LOCK_WAL_CHECKSUM_V1");
    h.update(prefix);
    *h.finalize().as_bytes()
}

fn encode_lock(input: InputRef, round: u64, digest: [u8; 32]) -> [u8; WAL_RECORD] {
    let mut out = [0u8; WAL_RECORD];
    out[0..8].copy_from_slice(&WAL_MAGIC);
    out[8..16].copy_from_slice(&input.id.to_le_bytes());
    out[16..24].copy_from_slice(&input.generation.to_le_bytes());
    out[24..32].copy_from_slice(&round.to_le_bytes());
    out[32..64].copy_from_slice(&digest);
    let c = checksum(&out[..64]);
    out[64..96].copy_from_slice(&c);
    out
}

fn decode_lock(rec: &[u8]) -> Result<(InputRef, u64, [u8; 32]), String> {
    if rec.len() != WAL_RECORD || rec[0..8] != WAL_MAGIC {
        return Err("bad lock WAL record".into());
    }
    if rec[64..96] != checksum(&rec[..64]) {
        return Err("lock WAL checksum mismatch".into());
    }
    let input = InputRef {
        id: u64::from_le_bytes(rec[8..16].try_into().unwrap()),
        generation: u64::from_le_bytes(rec[16..24].try_into().unwrap()),
    };
    let round = u64::from_le_bytes(rec[24..32].try_into().unwrap());
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&rec[32..64]);
    Ok((input, round, digest))
}

struct LockStore {
    file: File,
    locks: HashMap<InputRef, (u64, [u8; 32])>,
}

impl LockStore {
    fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut file = OpenOptions::new().read(true).write(true).create(true).open(path).map_err(|e| e.to_string())?;
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        if bytes.len() % WAL_RECORD != 0 {
            return Err("incomplete lock WAL record; fail closed".into());
        }
        let mut locks = HashMap::new();
        for rec in bytes.chunks_exact(WAL_RECORD) {
            let (input, round, digest) = decode_lock(rec)?;
            match locks.get(&input) {
                Some((old_round, old_digest)) if *old_round > round => {}
                Some((old_round, old_digest)) if *old_round == round && old_digest != &digest => {
                    return Err("conflicting locks at same round; fail closed".into());
                }
                _ => {
                    locks.insert(input, (round, digest));
                }
            }
        }
        file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        Ok(Self { file, locks })
    }

    fn get(&self, input: InputRef) -> Option<(u64, [u8; 32])> {
        self.locks.get(&input).copied()
    }

    fn persist_lock(&mut self, input: InputRef, round: u64, digest: [u8; 32]) -> Result<(), String> {
        if let Some((old_round, old_digest)) = self.get(input) {
            if old_round > round {
                return Err("attempted lower-round lock".into());
            }
            if old_round == round && old_digest != digest {
                return Err("attempted conflicting same-round lock".into());
            }
            if old_round == round && old_digest == digest {
                return Ok(());
            }
        }
        self.file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        self.file.write_all(&encode_lock(input, round, digest)).map_err(|e| e.to_string())?;
        self.file.sync_all().map_err(|e| e.to_string())?;
        self.locks.insert(input, (round, digest));
        Ok(())
    }
}

fn write_u64(s: &mut TcpStream, v: u64) -> Result<(), String> { s.write_all(&v.to_le_bytes()).map_err(|e| e.to_string()) }
fn read_u64(s: &mut TcpStream) -> Result<u64, String> { let mut b=[0u8;8]; s.read_exact(&mut b).map_err(|e|e.to_string())?; Ok(u64::from_le_bytes(b)) }
fn write_bytes(s: &mut TcpStream, b: &[u8]) -> Result<(), String> { s.write_all(b).map_err(|e| e.to_string()) }
fn read_arr32(s: &mut TcpStream) -> Result<[u8;32], String> { let mut b=[0u8;32]; s.read_exact(&mut b).map_err(|e|e.to_string())?; Ok(b) }
fn read_arr64(s: &mut TcpStream) -> Result<[u8;64], String> { let mut b=[0u8;64]; s.read_exact(&mut b).map_err(|e|e.to_string())?; Ok(b) }

fn write_vote(s: &mut TcpStream, v: &Vote) -> Result<(), String> {
    write_bytes(s, &[v.index as u8, v.phase])?;
    write_u64(s, v.round)?;
    write_u64(s, v.input.id)?;
    write_u64(s, v.input.generation)?;
    write_bytes(s, &v.digest)?;
    write_bytes(s, &v.signature)
}

fn read_vote(s: &mut TcpStream) -> Result<Vote, String> {
    let mut h=[0u8;2]; s.read_exact(&mut h).map_err(|e|e.to_string())?;
    Ok(Vote { index:h[0] as usize, phase:h[1], round:read_u64(s)?, input:InputRef{id:read_u64(s)?,generation:read_u64(s)?}, digest:read_arr32(s)?, signature:read_arr64(s)? })
}

fn write_qc(s: &mut TcpStream, qc: &Option<Qc>) -> Result<(), String> {
    match qc {
        None => write_bytes(s, &[0]),
        Some(q) => {
            write_bytes(s, &[1])?;
            write_u64(s, q.votes.len() as u64)?;
            for v in &q.votes { write_vote(s, v)?; }
            Ok(())
        }
    }
}

fn read_qc(s: &mut TcpStream) -> Result<Option<Qc>, String> {
    let mut p=[0u8;1]; s.read_exact(&mut p).map_err(|e|e.to_string())?;
    if p[0]==0 { return Ok(None); }
    let n=read_u64(s)? as usize;
    if n > N { return Err("oversized QC".into()); }
    let mut votes=Vec::with_capacity(n);
    for _ in 0..n { votes.push(read_vote(s)?); }
    Ok(Some(Qc{votes}))
}

fn write_tx_auth_digest(s: &mut TcpStream, tx: &SpendTx, auth: &UserAuth, digest: &[u8;32]) -> Result<(), String> {
    write_u64(s, tx.input.id)?; write_u64(s, tx.input.generation)?; write_u64(s, tx.tx_id)?;
    write_bytes(s, &tx.recipient)?; write_u64(s, tx.value)?; write_bytes(s, &auth.signer)?; write_bytes(s, &auth.signature)?; write_bytes(s, digest)
}

fn read_tx_auth_digest(s: &mut TcpStream) -> Result<(SpendTx,UserAuth,[u8;32]),String> {
    let input=InputRef{id:read_u64(s)?,generation:read_u64(s)?};
    let tx_id=read_u64(s)?; let recipient=read_arr32(s)?; let value=read_u64(s)?; let signer=read_arr32(s)?; let signature=read_arr64(s)?; let digest=read_arr32(s)?;
    Ok((SpendTx{input,tx_id,recipient,value},UserAuth{signer,signature},digest))
}

fn run_node(index: usize, port: u16, wal: PathBuf, byzantine: bool) -> Result<(), String> {
    let listener=TcpListener::bind(("127.0.0.1",port)).map_err(|e|format!("bind node {index}: {e}"))?;
    let mut store=LockStore::open(&wal)?;
    let sk=certifier_key(index);
    let mut prevoted: HashMap<(InputRef,u64),[u8;32]> = HashMap::new();
    let mut precommitted: HashMap<(InputRef,u64),[u8;32]> = HashMap::new();

    for conn in listener.incoming() {
        let mut s=match conn { Ok(v)=>v, Err(_)=>continue };
        let mut op=[0u8;1]; if s.read_exact(&mut op).is_err(){continue;}
        if op[0]==OP_PING { let _=s.write_all(&[0xAA]); continue; }
        if op[0]==OP_SHUTDOWN { let _=s.write_all(&[0x55]); break; }

        if op[0]==OP_PREVOTE {
            let round=read_u64(&mut s)?; let mut pb=[0u8;1]; s.read_exact(&mut pb).map_err(|e|e.to_string())?; let proposer=pb[0] as usize;
            let (tx,auth,digest)=read_tx_auth_digest(&mut s)?; let proposal_sig=read_arr64(&mut s)?; let justify=read_qc(&mut s)?;
            if verify_user(&tx,&auth,&digest).is_err() || proposer!=leader(tx.input,round) || proposer>=N {
                let _=s.write_all(&[0]); continue;
            }
            let pmsg=proposal_message(round,proposer,tx.input,&digest);
            if certifier_key(proposer).verifying_key().verify_strict(&pmsg,&Signature::from_bytes(&proposal_sig)).is_err() { let _=s.write_all(&[0]); continue; }

            if !byzantine {
                if let Some(existing)=prevoted.get(&(tx.input,round)) { if existing!=&digest { let _=s.write_all(&[0]); continue; } }
                if let Some((locked_round,locked_digest))=store.get(tx.input) {
                    if locked_digest!=digest {
                        let safe = justify.as_ref().map(|q| {
                            if q.votes.is_empty(){return false;}
                            let qr=q.votes[0].round;
                            qr > locked_round && qr < round && verify_qc(q,PHASE_PREVOTE,qr,tx.input,&digest)
                        }).unwrap_or(false);
                        if !safe { let _=s.write_all(&[0]); continue; }
                    }
                }
                prevoted.insert((tx.input,round),digest);
            }
            let vote=Vote{index,phase:PHASE_PREVOTE,round,input:tx.input,digest,signature:sk.sign(&vote_message(PHASE_PREVOTE,round,tx.input,&digest,index)).to_bytes()};
            s.write_all(&[1]).map_err(|e|e.to_string())?; write_vote(&mut s,&vote)?;
            continue;
        }

        if op[0]==OP_PRECOMMIT {
            let round=read_u64(&mut s)?; let (tx,auth,digest)=read_tx_auth_digest(&mut s)?; let qc=match read_qc(&mut s)? {Some(q)=>q,None=>{let _=s.write_all(&[0]);continue;}};
            if verify_user(&tx,&auth,&digest).is_err() || !verify_qc(&qc,PHASE_PREVOTE,round,tx.input,&digest) { let _=s.write_all(&[0]); continue; }
            if !byzantine {
                if let Some(existing)=precommitted.get(&(tx.input,round)) { if existing!=&digest { let _=s.write_all(&[0]); continue; } }
                if let Some((locked_round,locked_digest))=store.get(tx.input) {
                    if locked_digest!=digest && round<=locked_round { let _=s.write_all(&[0]); continue; }
                }
                store.persist_lock(tx.input,round,digest)?;
                precommitted.insert((tx.input,round),digest);
            }
            let vote=Vote{index,phase:PHASE_PRECOMMIT,round,input:tx.input,digest,signature:sk.sign(&vote_message(PHASE_PRECOMMIT,round,tx.input,&digest,index)).to_bytes()};
            s.write_all(&[1]).map_err(|e|e.to_string())?; write_vote(&mut s,&vote)?;
            continue;
        }
        let _=s.write_all(&[0]);
    }
    Ok(())
}

fn free_port() -> Result<u16,String> { let l=TcpListener::bind(("127.0.0.1",0)).map_err(|e|e.to_string())?; Ok(l.local_addr().map_err(|e|e.to_string())?.port()) }

struct NodeProc { port:u16, child:Child }
impl NodeProc {
    fn spawn(exe:&Path,index:usize,wal:PathBuf,byzantine:bool)->Result<Self,String>{
        let port=free_port()?;
        let child=Command::new(exe).arg("--node").arg(index.to_string()).arg(port.to_string()).arg(wal).arg(if byzantine{"1"}else{"0"}).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e|e.to_string())?;
        let mut n=Self{port,child}; n.wait_ready()?; Ok(n)
    }
    fn wait_ready(&mut self)->Result<(),String>{ for _ in 0..400 { if let Ok(mut s)=TcpStream::connect(("127.0.0.1",self.port)){ let _=s.write_all(&[OP_PING]); let mut b=[0u8;1]; if s.read_exact(&mut b).is_ok() && b[0]==0xAA{return Ok(());} } thread::sleep(Duration::from_millis(5)); } Err("node not ready".into()) }
    fn stop(&mut self){ if let Ok(mut s)=TcpStream::connect(("127.0.0.1",self.port)){let _=s.write_all(&[OP_SHUTDOWN]);} let _=self.child.wait(); }
}

fn make_pair(trial:u64)->(SpendTx,UserAuth,[u8;32],SpendTx,UserAuth,[u8;32]){
    let alice=user_key(1); let bob=user_key(2).verifying_key().to_bytes(); let mallory=user_key(3).verifying_key().to_bytes();
    let input=InputRef{id:9_000_000+trial,generation:9};
    let a=SpendTx{input,tx_id:90_000_000+trial*2,recipient:bob,value:800}; let b=SpendTx{input,tx_id:90_000_001+trial*2,recipient:mallory,value:800};
    let aa=sign_user(&a,&alice); let ba=sign_user(&b,&alice); let ad=digest_for(&a,&aa.signer); let bd=digest_for(&b,&ba.signer); (a,aa,ad,b,ba,bd)
}

fn build_proposal(round:u64,tx:&SpendTx,auth:&UserAuth,digest:[u8;32],justify:Option<Qc>)->Proposal{
    let proposer=leader(tx.input,round); let signature=certifier_key(proposer).sign(&proposal_message(round,proposer,tx.input,&digest)).to_bytes();
    Proposal{round,proposer,tx:tx.clone(),auth:*auth,digest,justify,signature}
}

fn request_prevote(port:u16,p:&Proposal)->Result<Option<Vote>,String>{
    let addr:SocketAddr=format!("127.0.0.1:{port}").parse().unwrap(); let mut s=match TcpStream::connect_timeout(&addr,Duration::from_millis(1000)){Ok(v)=>v,Err(_)=>return Ok(None)};
    s.set_read_timeout(Some(Duration::from_millis(1000))).ok(); s.set_write_timeout(Some(Duration::from_millis(1000))).ok();
    write_bytes(&mut s,&[OP_PREVOTE])?; write_u64(&mut s,p.round)?; write_bytes(&mut s,&[p.proposer as u8])?; write_tx_auth_digest(&mut s,&p.tx,&p.auth,&p.digest)?; write_bytes(&mut s,&p.signature)?; write_qc(&mut s,&p.justify)?;
    let mut st=[0u8;1]; if s.read_exact(&mut st).is_err() || st[0]==0{return Ok(None);} let v=read_vote(&mut s)?; Ok(if verify_vote(&v){Some(v)}else{None})
}

fn request_precommit(port:u16,tx:&SpendTx,auth:&UserAuth,digest:[u8;32],round:u64,qc:&Qc)->Result<Option<Vote>,String>{
    let addr:SocketAddr=format!("127.0.0.1:{port}").parse().unwrap(); let mut s=match TcpStream::connect_timeout(&addr,Duration::from_millis(1000)){Ok(v)=>v,Err(_)=>return Ok(None)};
    s.set_read_timeout(Some(Duration::from_millis(1000))).ok(); s.set_write_timeout(Some(Duration::from_millis(1000))).ok();
    write_bytes(&mut s,&[OP_PRECOMMIT])?; write_u64(&mut s,round)?; write_tx_auth_digest(&mut s,tx,auth,&digest)?; write_qc(&mut s,&Some(qc.clone()))?;
    let mut st=[0u8;1]; if s.read_exact(&mut st).is_err() || st[0]==0{return Ok(None);} let v=read_vote(&mut s)?; Ok(if verify_vote(&v){Some(v)}else{None})
}

fn collect_prevotes(nodes:&[NodeProc],p:&Proposal,indices:&[usize])->Result<Vec<Vote>,String>{ let mut out=Vec::new(); for &i in indices { if let Some(v)=request_prevote(nodes[i].port,p)? {out.push(v);} } Ok(out) }
fn collect_precommits(nodes:&[NodeProc],tx:&SpendTx,auth:&UserAuth,digest:[u8;32],round:u64,qc:&Qc,indices:&[usize])->Result<Vec<Vote>,String>{ let mut out=Vec::new(); for &i in indices { if let Some(v)=request_precommit(nodes[i].port,tx,auth,digest,round,qc)? {out.push(v);} } Ok(out) }

fn next_round_with_leader(input:InputRef,start:u64,allowed:&HashSet<usize>)->u64{ let mut r=start; loop{ if allowed.contains(&leader(input,r)){return r;} r+=1; } }

fn controller()->Result<(),String>{
    let exe=env::current_exe().map_err(|e|e.to_string())?; let root=env::temp_dir().join(format!("calibre-sec009-{}",std::process::id())); let _=fs::remove_dir_all(&root); fs::create_dir_all(&root).map_err(|e|e.to_string())?;
    let byz:HashSet<usize>=[0usize,1].into_iter().collect(); let honest:Vec<usize>=(0..N).filter(|i|!byz.contains(i)).collect();
    let mut nodes=Vec::new(); for i in 0..N { nodes.push(NodeProc::spawn(&exe,i,root.join(format!("node-{i}.wal")),byz.contains(&i))?); }

    println!("CALIBRE SECURITY SEC-009 v0.9.0");
    println!("CONFLICT-LOCAL ROUND CHANGE / QC LOCKING / DEADLOCK RECOVERY");
    println!("N=7 Q=5 target f<=2; seven separate OS processes over real 127.0.0.1 TCP");
    println!("Global blockchain / universal transaction order: NOT USED");
    println!("Safety lock is created only after a 5-of-7 PREVOTE QC; a first-seen vote alone is NOT a permanent lock.");
    println!();

    // Scenario 1: reproduce the SEC-008 3/2 split as tentative PREVOTEs, then recover in a new conflict-local round.
    let (a,aa,ad,b,ba,bd)=make_pair(1);
    let r0=next_round_with_leader(a.input,0,&honest.iter().copied().collect());
    let pa0=build_proposal(r0,&a,&aa,ad,None); let pb0=build_proposal(r0,&b,&ba,bd,None);
    let va=collect_prevotes(&nodes,&pa0,&honest[0..3])?; let vb=collect_prevotes(&nodes,&pb0,&honest[3..5])?;
    if va.len()!=3 || vb.len()!=2 { return Err(format!("3/2 split setup failed: A={} B={}",va.len(),vb.len())); }
    println!("ROUND {r0}: HONEST TENTATIVE PREVOTE SPLIT A=3/7 B=2/7, BYZANTINE WITHHOLD -> NO QC / NO SAFETY LOCK");
    let r1=next_round_with_leader(a.input,r0+1,&honest.iter().copied().collect());
    let (win_tx,win_auth,win_digest,lose_digest)=if ad<=bd{(&a,&aa,ad,bd)}else{(&b,&ba,bd,ad)};
    let p1=build_proposal(r1,win_tx,win_auth,win_digest,None); let pv1=collect_prevotes(&nodes,&p1,&honest)?; let qpv1=make_qc(pv1,PHASE_PREVOTE,r1,a.input,&win_digest)?;
    let pc1=collect_precommits(&nodes,win_tx,win_auth,win_digest,r1,&qpv1,&honest)?; let qpc1=make_qc(pc1,PHASE_PRECOMMIT,r1,a.input,&win_digest)?;
    println!("ROUND {r1}: HONEST PROPOSER + DETERMINISTIC CONFLICT WINNER -> PREVOTE QC {}/7, PRECOMMIT QC {}/7 -> DEADLOCK RESOLVED: PASS",qpv1.votes.len(),qpc1.votes.len());

    // A later Byzantine proposer cannot overturn the finalized/locked value without a higher valid QC.
    let mut byz_round=r1+1; while !byz.contains(&leader(a.input,byz_round)){byz_round+=1;}
    let lose_tx=if lose_digest==ad{&a}else{&b}; let lose_auth=if lose_digest==ad{&aa}else{&ba}; let evil=build_proposal(byz_round,lose_tx,lose_auth,lose_digest,None);
    let evil_honest=collect_prevotes(&nodes,&evil,&honest)?; let evil_byz=collect_prevotes(&nodes,&evil,&[0,1])?;
    if !evil_honest.is_empty() || evil_byz.len()>2 { return Err("locked-value safety attack behaved unexpectedly".into()); }
    println!("HIGHER ROUND BYZANTINE CONFLICT PROPOSAL WITHOUT JUSTIFY QC: HONEST VOTES=0, BYZANTINE VOTES={} -> CONFLICT CANNOT REACH 5/7: PASS",evil_byz.len());

    // Scenario 2: a PREVOTE QC is formed, but only three honest precommit before interruption. Next round carries the QC and completes.
    let (c,ca,cd,_d,_da,_dd)=make_pair(2); let rc0=next_round_with_leader(c.input,0,&honest.iter().copied().collect()); let pc0=build_proposal(rc0,&c,&ca,cd,None);
    let pvc0=collect_prevotes(&nodes,&pc0,&honest)?; let qvc0=make_qc(pvc0,PHASE_PREVOTE,rc0,c.input,&cd)?;
    let partial=collect_precommits(&nodes,&c,&ca,cd,rc0,&qvc0,&honest[0..3])?; if partial.len()!=3{return Err("partial lock setup failed".into());}
    let rc1=next_round_with_leader(c.input,rc0+1,&honest.iter().copied().collect()); let pc1=build_proposal(rc1,&c,&ca,cd,Some(qvc0.clone()));
    let pvc1=collect_prevotes(&nodes,&pc1,&honest)?; let qvc1=make_qc(pvc1,PHASE_PREVOTE,rc1,c.input,&cd)?; let pcc1=collect_precommits(&nodes,&c,&ca,cd,rc1,&qvc1,&honest)?; let qcc1=make_qc(pcc1,PHASE_PRECOMMIT,rc1,c.input,&cd)?;
    println!("PARTIAL PRECOMMIT LOCK (3 HONEST) + ROUND CHANGE WITH PRIOR QC: NEXT ROUND FINALIZES {}/7 -> PASS",qcc1.votes.len());

    // Scenario 3: logical partition with only four reachable nodes cannot finalize; after heal, a fresh round finalizes.
    let (e,ea,ed,_f,_fa,_fd)=make_pair(3); let re0=next_round_with_leader(e.input,0,&honest.iter().copied().collect()); let pe0=build_proposal(re0,&e,&ea,ed,None);
    let four=[0usize,2,3,4]; let p4=collect_prevotes(&nodes,&pe0,&four)?; if p4.len()>=Q{return Err("4-node partition unexpectedly reached quorum".into());}
    println!("4/3 LOGICAL PARTITION: REACHABLE PREVOTES={}/7 -> NO QC / SAFETY HOLDS / LIVENESS PAUSES",p4.len());
    let re1=next_round_with_leader(e.input,re0+1,&honest.iter().copied().collect()); let pe1=build_proposal(re1,&e,&ea,ed,None); let pve1=collect_prevotes(&nodes,&pe1,&honest)?; let qve1=make_qc(pve1,PHASE_PREVOTE,re1,e.input,&ed)?; let pce1=collect_precommits(&nodes,&e,&ea,ed,re1,&qve1,&honest)?; let qce1=make_qc(pce1,PHASE_PRECOMMIT,re1,e.input,&ed)?;
    println!("PARTITION HEALED + NEW CONFLICT-LOCAL ROUND: FINALIZES {}/7 -> LIVENESS RECOVERS: PASS",qce1.votes.len());

    // Expected f=3 boundary: three Byzantine voters can bridge two disjoint honest pairs in one equivocated round.
    for n in &mut nodes { n.stop(); } let _=fs::remove_dir_all(&root);
    let root2=env::temp_dir().join(format!("calibre-sec009-f3-{}",std::process::id())); let _=fs::remove_dir_all(&root2); fs::create_dir_all(&root2).map_err(|e|e.to_string())?;
    let byz3:HashSet<usize>=[0usize,1,2].into_iter().collect(); let mut n3=Vec::new(); for i in 0..N { n3.push(NodeProc::spawn(&exe,i,root2.join(format!("node-{i}.wal")),byz3.contains(&i))?); }
    let (g,ga,gd,h,ha,hd)=make_pair(4); let allowed=byz3.clone(); let rf=next_round_with_leader(g.input,0,&allowed); let pg=build_proposal(rf,&g,&ga,gd,None); let ph=build_proposal(rf,&h,&ha,hd,None);
    let mut vg=collect_prevotes(&n3,&pg,&[0,1,2,3,4])?; let vh=collect_prevotes(&n3,&ph,&[0,1,2,5,6])?; let qg=make_qc(vg.drain(..).collect(),PHASE_PREVOTE,rf,g.input,&gd)?; let qh=make_qc(vh,PHASE_PREVOTE,rf,h.input,&hd)?;
    let cg=collect_precommits(&n3,&g,&ga,gd,rf,&qg,&[0,1,2,3,4])?; let ch=collect_precommits(&n3,&h,&ha,hd,rf,&qh,&[0,1,2,5,6])?; let fqg=make_qc(cg,PHASE_PRECOMMIT,rf,g.input,&gd)?; let fqh=make_qc(ch,PHASE_PRECOMMIT,rf,h.input,&hd)?;
    println!("F=3 EXPECTED BOUNDARY: EQUIVOCATING BYZANTINE LEADER + 3 BYZANTINE VOTERS PRODUCE TWO PRECOMMIT QCs {}/7 AND {}/7 -> ATTACK CONFIRMED",fqg.votes.len(),fqh.votes.len());
    for n in &mut n3 { n.stop(); } let _=fs::remove_dir_all(&root2);

    println!(); println!("=== SEC-009 DECISION ===");
    println!("SEC-008 3/2 FIRST-SEEN DEADLOCK RESOLVED BY CONFLICT-LOCAL ROUND CHANGE: PASS");
    println!("FIRST-SEEN PREVOTE IS TENTATIVE; SAFETY LOCK REQUIRES 5-OF-7 PREVOTE QC: IMPLEMENTED");
    println!("FINALITY REQUIRES 5-OF-7 PRECOMMIT QC AFTER NODES HAVE SEEN A VALID PREVOTE QC: IMPLEMENTED");
    println!("LOCKED HONEST NODES REJECT CONFLICTING HIGHER-ROUND PROPOSAL WITHOUT VALID HIGHER JUSTIFICATION: PASS");
    println!("PARTIAL LOCK + QC-CARRYING ROUND CHANGE RECOVERS LIVENESS: PASS");
    println!("4/3 PARTITION SAFETY + POST-HEAL LIVENESS RECOVERY: PASS IN TESTED SCHEDULE");
    println!("F=3 SAFETY: FAIL AT EXPECTED 5-OF-7 QUORUM BOUNDARY / ATTACK CONFIRMED");
    println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");
    println!("PHYSICAL MULTI-MACHINE / WAN: NOT YET");
    println!("ARBITRARY ASYNCHRONOUS LIVENESS / FORMAL PROOF / PRODUCTION CONSENSUS: NOT PROVEN");
    Ok(())
}

fn main(){
    let args:Vec<String>=env::args().collect();
    let r=if args.get(1).map(String::as_str)==Some("--node") {
        if args.len()!=6 { Err("node usage: --node <index> <port> <wal> <byzantine 0|1>".into()) } else {
            match (args[2].parse::<usize>(),args[3].parse::<u16>()) { (Ok(i),Ok(p))=>run_node(i,p,PathBuf::from(&args[4]),args[5]=="1"), (Err(e),_)=>Err(e.to_string()), (_,Err(e))=>Err(e.to_string()) }
        }
    } else { controller() };
    if let Err(e)=r { eprintln!("SEC-009 ERROR: {e}"); std::process::exit(1); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn quorum_intersection_is_three(){assert_eq!(Q+Q-N,3);assert!(Q+Q-N>F_TARGET);}
    #[test] fn conflicting_digests_differ(){let(a,aa,ad,b,ba,bd)=make_pair(77);assert_eq!(a.input,b.input);assert_eq!(aa.signer,ba.signer);assert_ne!(ad,bd);}
    #[test] fn lock_record_round_trip(){let i=InputRef{id:7,generation:9};let d=[3u8;32];let r=encode_lock(i,4,d);let(ii,rr,dd)=decode_lock(&r).unwrap();assert_eq!(i,ii);assert_eq!(4,rr);assert_eq!(d,dd);}
    #[test] fn five_unique_votes_make_qc(){let input=InputRef{id:55,generation:1};let d=[8u8;32];let round=2;let mut votes=Vec::new();for i in 0..5{let sk=certifier_key(i);votes.push(Vote{index:i,phase:PHASE_PREVOTE,round,input,digest:d,signature:sk.sign(&vote_message(PHASE_PREVOTE,round,input,&d,i)).to_bytes()});}assert!(make_qc(votes,PHASE_PREVOTE,round,input,&d).is_ok());}
}
