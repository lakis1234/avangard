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
const BYZ: [usize; 2] = [0, 1];
const HONEST: [usize; 5] = [2, 3, 4, 5, 6];
const PHASE_PREVOTE: u8 = 1;
const PHASE_PRECOMMIT: u8 = 2;
const OP_PING: u8 = 0;
const OP_PREVOTE: u8 = 1;
const OP_PRECOMMIT: u8 = 2;
const OP_SHUTDOWN: u8 = 255;
const WAL_MAGIC: [u8; 8] = *b"CAL010ST";
const WAL_RECORD: usize = 104;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct InputRef { id: u64, generation: u64 }

#[derive(Clone, Debug)]
struct SpendTx { input: InputRef, tx_id: u64, recipient: [u8; 32], value: u64 }

#[derive(Clone, Copy, Debug)]
struct UserAuth { signer: [u8; 32], signature: [u8; 64] }

#[derive(Clone, Copy, Debug)]
struct Vote { index: usize, phase: u8, round: u64, input: InputRef, digest: [u8; 32], signature: [u8; 64] }

#[derive(Clone, Debug)]
struct Qc { votes: Vec<Vote> }

#[derive(Clone, Debug)]
struct Proposal { round: u64, proposer: usize, tx: SpendTx, auth: UserAuth, digest: [u8; 32], justify: Option<Qc>, signature: [u8; 64] }

fn deterministic_key(domain: &[u8], label: u64) -> SigningKey {
    let mut h = Hasher::new(); h.update(domain); h.update(&label.to_le_bytes()); SigningKey::from_bytes(h.finalize().as_bytes())
}
fn user_key(label: u64) -> SigningKey { deterministic_key(b"CALIBRE_SEC010_USER_KEY_V1", label) }
fn certifier_key(index: usize) -> SigningKey { deterministic_key(b"CALIBRE_SEC010_CERTIFIER_KEY_V1", 100 + index as u64) }

fn user_message(tx: &SpendTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"CALIBRE_SEC010_USER_SPEND_V1");
    out.extend_from_slice(&NETWORK_ID.to_le_bytes()); out.extend_from_slice(&tx.input.id.to_le_bytes()); out.extend_from_slice(&tx.input.generation.to_le_bytes());
    out.extend_from_slice(&tx.tx_id.to_le_bytes()); out.extend_from_slice(&tx.recipient); out.extend_from_slice(&tx.value.to_le_bytes()); out
}
fn digest_for(tx: &SpendTx, signer: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new(); h.update(b"CALIBRE_SEC010_AUTHORIZED_TX_V1"); h.update(&user_message(tx)); h.update(signer); *h.finalize().as_bytes()
}
fn sign_user(tx: &SpendTx, sk: &SigningKey) -> UserAuth { UserAuth { signer: sk.verifying_key().to_bytes(), signature: sk.sign(&user_message(tx)).to_bytes() } }
fn verify_user(tx: &SpendTx, auth: &UserAuth, digest: &[u8; 32]) -> Result<(), String> {
    let alice = user_key(1).verifying_key().to_bytes(); if auth.signer != alice { return Err("owner mismatch".into()); } if tx.value != 800 { return Err("value mismatch".into()); }
    let vk = VerifyingKey::from_bytes(&auth.signer).map_err(|_| "bad user key")?; vk.verify_strict(&user_message(tx), &Signature::from_bytes(&auth.signature)).map_err(|_| "bad user signature")?;
    if &digest_for(tx, &auth.signer) != digest { return Err("digest mismatch".into()); } Ok(())
}

fn leader_offset(input: InputRef) -> usize {
    let mut h=Hasher::new(); h.update(b"CALIBRE_SEC010_LEADER_OFFSET_V1"); h.update(&input.id.to_le_bytes()); h.update(&input.generation.to_le_bytes());
    (u64::from_le_bytes(h.finalize().as_bytes()[0..8].try_into().unwrap()) as usize) % N
}
fn leader(input: InputRef, round: u64) -> usize { (leader_offset(input) + round as usize) % N }

fn qc_summary(qc:&Option<Qc>)->(u64,[u8;32]) { match qc { None=>(u64::MAX,[0u8;32]), Some(q) if !q.votes.is_empty()=>(q.votes[0].round,q.votes[0].digest), _=>(u64::MAX,[0u8;32]) } }
fn proposal_message(round:u64,proposer:usize,input:InputRef,digest:&[u8;32],justify:&Option<Qc>)->Vec<u8>{
    let mut out=Vec::with_capacity(128); out.extend_from_slice(b"CALIBRE_SEC010_PROPOSAL_V1"); out.extend_from_slice(&round.to_le_bytes()); out.extend_from_slice(&(proposer as u64).to_le_bytes());
    out.extend_from_slice(&input.id.to_le_bytes()); out.extend_from_slice(&input.generation.to_le_bytes()); out.extend_from_slice(digest); let(jr,jd)=qc_summary(justify); out.extend_from_slice(&jr.to_le_bytes()); out.extend_from_slice(&jd); out
}
fn vote_message(phase:u8,round:u64,input:InputRef,digest:&[u8;32],index:usize)->Vec<u8>{
    let mut out=Vec::with_capacity(96); out.extend_from_slice(b"CALIBRE_SEC010_VOTE_V1"); out.push(phase); out.extend_from_slice(&round.to_le_bytes()); out.extend_from_slice(&input.id.to_le_bytes());
    out.extend_from_slice(&input.generation.to_le_bytes()); out.extend_from_slice(&(index as u64).to_le_bytes()); out.extend_from_slice(digest); out
}
fn verify_vote(v:&Vote)->bool{
    if v.index>=N || (v.phase!=PHASE_PREVOTE && v.phase!=PHASE_PRECOMMIT){return false;}
    certifier_key(v.index).verifying_key().verify_strict(&vote_message(v.phase,v.round,v.input,&v.digest,v.index),&Signature::from_bytes(&v.signature)).is_ok()
}
fn verify_qc_any(qc:&Qc,phase:u8)->bool{
    if qc.votes.is_empty(){return false;} let f=qc.votes[0]; let mut unique=HashSet::new();
    for v in &qc.votes { if v.phase!=phase || v.round!=f.round || v.input!=f.input || v.digest!=f.digest || !verify_vote(v){return false;} unique.insert(v.index); }
    unique.len()>=Q
}
fn verify_qc(qc:&Qc,phase:u8,round:u64,input:InputRef,digest:&[u8;32])->bool{ verify_qc_any(qc,phase) && qc.votes[0].round==round && qc.votes[0].input==input && &qc.votes[0].digest==digest }
fn make_qc(votes:Vec<Vote>,phase:u8,round:u64,input:InputRef,digest:&[u8;32])->Option<Qc>{
    let mut by_index=HashMap::new(); for v in votes { if v.phase==phase && v.round==round && v.input==input && &v.digest==digest && verify_vote(&v){by_index.entry(v.index).or_insert(v);} }
    let qc=Qc{votes:by_index.into_values().collect()}; if verify_qc(&qc,phase,round,input,digest){Some(qc)}else{None}
}

fn make_pair(trial:u64)->(SpendTx,UserAuth,[u8;32],SpendTx,UserAuth,[u8;32]){
    let alice=user_key(1); let bob=user_key(2).verifying_key().to_bytes(); let mallory=user_key(3).verifying_key().to_bytes(); let input=InputRef{id:9_000_000+trial,generation:10};
    let a=SpendTx{input,tx_id:20_000_000+trial*2,recipient:bob,value:800}; let b=SpendTx{input,tx_id:20_000_001+trial*2,recipient:mallory,value:800};
    let aa=sign_user(&a,&alice); let ba=sign_user(&b,&alice); let ad=digest_for(&a,&aa.signer); let bd=digest_for(&b,&ba.signer); (a,aa,ad,b,ba,bd)
}
fn canonical<'a>(a:&'a SpendTx,aa:&'a UserAuth,ad:&[u8;32],b:&'a SpendTx,ba:&'a UserAuth,bd:&[u8;32])->(&'a SpendTx,&'a UserAuth,[u8;32]){ if ad<=bd{(a,aa,*ad)}else{(b,ba,*bd)} }
fn make_proposal(round:u64,proposer:usize,tx:&SpendTx,auth:&UserAuth,digest:[u8;32],justify:Option<Qc>)->Proposal{
    let sig=certifier_key(proposer).sign(&proposal_message(round,proposer,tx.input,&digest,&justify)).to_bytes(); Proposal{round,proposer,tx:tx.clone(),auth:*auth,digest,justify,signature:sig}
}
fn verify_proposal(p:&Proposal)->Result<(),String>{
    if p.proposer!=leader(p.tx.input,p.round){return Err("wrong conflict-local leader".into());}
    certifier_key(p.proposer).verifying_key().verify_strict(&proposal_message(p.round,p.proposer,p.tx.input,&p.digest,&p.justify),&Signature::from_bytes(&p.signature)).map_err(|_|"bad proposal signature")?;
    verify_user(&p.tx,&p.auth,&p.digest)?;
    if let Some(q)=&p.justify{if !verify_qc_any(q,PHASE_PREVOTE){return Err("bad justify QC".into());}let f=q.votes[0];if f.input!=p.tx.input||f.digest!=p.digest||f.round>=p.round{return Err("justify QC does not safely justify proposal".into());}}
    Ok(())
}

fn checksum(prefix:&[u8])->[u8;32]{let mut h=Hasher::new();h.update(b"CALIBRE_SEC010_STATE_WAL_CHECKSUM_V1");h.update(prefix);*h.finalize().as_bytes()}
fn encode_record(kind:u8,input:InputRef,round:u64,digest:[u8;32])->[u8;WAL_RECORD]{
    let mut out=[0u8;WAL_RECORD];out[0..8].copy_from_slice(&WAL_MAGIC);out[8]=kind;out[16..24].copy_from_slice(&input.id.to_le_bytes());out[24..32].copy_from_slice(&input.generation.to_le_bytes());
    out[32..40].copy_from_slice(&round.to_le_bytes());out[40..72].copy_from_slice(&digest);let c=checksum(&out[..72]);out[72..104].copy_from_slice(&c);out
}
fn decode_record(rec:&[u8])->Result<(u8,InputRef,u64,[u8;32]),String>{
    if rec.len()!=WAL_RECORD||rec[0..8]!=WAL_MAGIC{return Err("bad state WAL record".into());}if rec[72..104]!=checksum(&rec[..72]){return Err("state WAL checksum mismatch".into());}
    let kind=rec[8];if kind!=PHASE_PREVOTE&&kind!=PHASE_PRECOMMIT{return Err("unknown state WAL record kind".into());}
    let input=InputRef{id:u64::from_le_bytes(rec[16..24].try_into().unwrap()),generation:u64::from_le_bytes(rec[24..32].try_into().unwrap())};let round=u64::from_le_bytes(rec[32..40].try_into().unwrap());
    let mut digest=[0u8;32];digest.copy_from_slice(&rec[40..72]);Ok((kind,input,round,digest))
}

struct StateStore{file:File,votes:HashMap<(InputRef,u64,u8),[u8;32]>,locks:HashMap<InputRef,(u64,[u8;32])>}
impl StateStore{
    fn open(path:&Path)->Result<Self,String>{
        if let Some(parent)=path.parent(){fs::create_dir_all(parent).map_err(|e|e.to_string())?;}let mut file=OpenOptions::new().read(true).write(true).create(true).open(path).map_err(|e|e.to_string())?;
        file.seek(SeekFrom::Start(0)).map_err(|e|e.to_string())?;let mut bytes=Vec::new();file.read_to_end(&mut bytes).map_err(|e|e.to_string())?;if bytes.len()%WAL_RECORD!=0{return Err("incomplete state WAL record; fail closed".into());}
        let mut votes=HashMap::new();let mut locks=HashMap::new();for rec in bytes.chunks_exact(WAL_RECORD){let(kind,input,round,digest)=decode_record(rec)?;let key=(input,round,kind);
            if let Some(old)=votes.insert(key,digest){if old!=digest{return Err("conflicting durable same-round vote; fail closed".into());}}
            if kind==PHASE_PRECOMMIT{match locks.get(&input){Some((old_round,_))if *old_round>round=>{},Some((old_round,old_digest))if *old_round==round&&old_digest!=&digest=>return Err("conflicting durable lock at same round".into()),_=>{locks.insert(input,(round,digest));}}}
        }file.seek(SeekFrom::End(0)).map_err(|e|e.to_string())?;Ok(Self{file,votes,locks})
    }
    fn lock(&self,input:InputRef)->Option<(u64,[u8;32])>{self.locks.get(&input).copied()}
    fn append(&mut self,kind:u8,input:InputRef,round:u64,digest:[u8;32])->Result<(),String>{self.file.seek(SeekFrom::End(0)).map_err(|e|e.to_string())?;self.file.write_all(&encode_record(kind,input,round,digest)).map_err(|e|e.to_string())?;self.file.sync_all().map_err(|e|e.to_string())?;Ok(())}
    fn persist_prevote(&mut self,input:InputRef,round:u64,digest:[u8;32])->Result<bool,String>{let key=(input,round,PHASE_PREVOTE);if let Some(old)=self.votes.get(&key){return Ok(old==&digest);}self.append(PHASE_PREVOTE,input,round,digest)?;self.votes.insert(key,digest);Ok(true)}
    fn persist_precommit(&mut self,input:InputRef,round:u64,digest:[u8;32])->Result<bool,String>{
        if self.votes.get(&(input,round,PHASE_PREVOTE))!=Some(&digest){return Ok(false);}let key=(input,round,PHASE_PRECOMMIT);if let Some(old)=self.votes.get(&key){return Ok(old==&digest);}
        if let Some((old_round,old_digest))=self.lock(input){if old_round>round||(old_round==round&&old_digest!=digest){return Ok(false);}}
        self.append(PHASE_PRECOMMIT,input,round,digest)?;self.votes.insert(key,digest);self.locks.insert(input,(round,digest));Ok(true)
    }
}
fn proposal_safe_for_lock(store:&StateStore,p:&Proposal)->bool{match store.lock(p.tx.input){None=>true,Some((_lr,ld))if ld==p.digest=>true,Some((lr,_))=>match &p.justify{Some(q)if verify_qc_any(q,PHASE_PREVOTE)=>{let f=q.votes[0];f.input==p.tx.input&&f.digest==p.digest&&f.round>lr&&f.round<p.round},_=>false}}}

fn write_u64(s:&mut TcpStream,v:u64)->Result<(),String>{s.write_all(&v.to_le_bytes()).map_err(|e|e.to_string())}
fn read_u64(s:&mut TcpStream)->Result<u64,String>{let mut b=[0u8;8];s.read_exact(&mut b).map_err(|e|e.to_string())?;Ok(u64::from_le_bytes(b))}
fn write_bytes(s:&mut TcpStream,b:&[u8])->Result<(),String>{s.write_all(b).map_err(|e|e.to_string())}
fn read_arr32(s:&mut TcpStream)->Result<[u8;32],String>{let mut b=[0u8;32];s.read_exact(&mut b).map_err(|e|e.to_string())?;Ok(b)}
fn read_arr64(s:&mut TcpStream)->Result<[u8;64],String>{let mut b=[0u8;64];s.read_exact(&mut b).map_err(|e|e.to_string())?;Ok(b)}
fn write_vote(s:&mut TcpStream,v:&Vote)->Result<(),String>{write_bytes(s,&[v.index as u8,v.phase])?;write_u64(s,v.round)?;write_u64(s,v.input.id)?;write_u64(s,v.input.generation)?;write_bytes(s,&v.digest)?;write_bytes(s,&v.signature)}
fn read_vote(s:&mut TcpStream)->Result<Vote,String>{let mut h=[0u8;2];s.read_exact(&mut h).map_err(|e|e.to_string())?;Ok(Vote{index:h[0]as usize,phase:h[1],round:read_u64(s)?,input:InputRef{id:read_u64(s)?,generation:read_u64(s)?},digest:read_arr32(s)?,signature:read_arr64(s)?})}
fn write_qc(s:&mut TcpStream,qc:&Option<Qc>)->Result<(),String>{match qc{None=>write_bytes(s,&[0]),Some(q)=>{write_bytes(s,&[1])?;write_u64(s,q.votes.len()as u64)?;for v in &q.votes{write_vote(s,v)?;}Ok(())}}}
fn read_qc(s:&mut TcpStream)->Result<Option<Qc>,String>{let mut p=[0u8;1];s.read_exact(&mut p).map_err(|e|e.to_string())?;if p[0]==0{return Ok(None);}let n=read_u64(s)?as usize;if n>N{return Err("oversized QC".into());}let mut votes=Vec::with_capacity(n);for _ in 0..n{votes.push(read_vote(s)?);}Ok(Some(Qc{votes}))}
fn write_proposal(s:&mut TcpStream,p:&Proposal)->Result<(),String>{write_u64(s,p.round)?;write_bytes(s,&[p.proposer as u8])?;write_u64(s,p.tx.input.id)?;write_u64(s,p.tx.input.generation)?;write_u64(s,p.tx.tx_id)?;write_bytes(s,&p.tx.recipient)?;write_u64(s,p.tx.value)?;write_bytes(s,&p.auth.signer)?;write_bytes(s,&p.auth.signature)?;write_bytes(s,&p.digest)?;write_qc(s,&p.justify)?;write_bytes(s,&p.signature)}
fn read_proposal(s:&mut TcpStream)->Result<Proposal,String>{let round=read_u64(s)?;let mut proposer=[0u8;1];s.read_exact(&mut proposer).map_err(|e|e.to_string())?;let input=InputRef{id:read_u64(s)?,generation:read_u64(s)?};let tx_id=read_u64(s)?;let recipient=read_arr32(s)?;let value=read_u64(s)?;let signer=read_arr32(s)?;let auth=UserAuth{signer,signature:read_arr64(s)?};let digest=read_arr32(s)?;let justify=read_qc(s)?;let signature=read_arr64(s)?;Ok(Proposal{round,proposer:proposer[0]as usize,tx:SpendTx{input,tx_id,recipient,value},auth,digest,justify,signature})}

fn run_node(index:usize,port:u16,wal:PathBuf,byzantine:bool)->Result<(),String>{
    let listener=TcpListener::bind(("127.0.0.1",port)).map_err(|e|format!("bind node {index}: {e}"))?;let mut store=StateStore::open(&wal)?;let sk=certifier_key(index);
    for conn in listener.incoming(){let mut stream=match conn{Ok(s)=>s,Err(_)=>continue};let mut op=[0u8;1];if stream.read_exact(&mut op).is_err(){continue;}match op[0]{
        OP_PING=>{let _=stream.write_all(&[0xAA]);},OP_SHUTDOWN=>{let _=stream.write_all(&[0x55]);break;},
        OP_PREVOTE=>{let p=match read_proposal(&mut stream){Ok(v)=>v,Err(_)=>{let _=stream.write_all(&[0]);continue;}};if verify_proposal(&p).is_err(){let _=stream.write_all(&[0]);continue;}if !byzantine&&!proposal_safe_for_lock(&store,&p){let _=stream.write_all(&[0]);continue;}if !byzantine&&!store.persist_prevote(p.tx.input,p.round,p.digest)?{let _=stream.write_all(&[0]);continue;}let v=Vote{index,phase:PHASE_PREVOTE,round:p.round,input:p.tx.input,digest:p.digest,signature:sk.sign(&vote_message(PHASE_PREVOTE,p.round,p.tx.input,&p.digest,index)).to_bytes()};stream.write_all(&[1]).map_err(|e|e.to_string())?;write_vote(&mut stream,&v)?;},
        OP_PRECOMMIT=>{let p=match read_proposal(&mut stream){Ok(v)=>v,Err(_)=>{let _=stream.write_all(&[0]);continue;}};let qc=match read_qc(&mut stream){Ok(Some(q))=>q,_=>{let _=stream.write_all(&[0]);continue;}};if verify_proposal(&p).is_err()||!verify_qc(&qc,PHASE_PREVOTE,p.round,p.tx.input,&p.digest){let _=stream.write_all(&[0]);continue;}if !byzantine&&!store.persist_precommit(p.tx.input,p.round,p.digest)?{let _=stream.write_all(&[0]);continue;}let v=Vote{index,phase:PHASE_PRECOMMIT,round:p.round,input:p.tx.input,digest:p.digest,signature:sk.sign(&vote_message(PHASE_PRECOMMIT,p.round,p.tx.input,&p.digest,index)).to_bytes()};stream.write_all(&[1]).map_err(|e|e.to_string())?;write_vote(&mut stream,&v)?;},
        _=>{let _=stream.write_all(&[0]);}
    }}Ok(())
}

fn free_port()->Result<u16,String>{let l=TcpListener::bind(("127.0.0.1",0)).map_err(|e|e.to_string())?;Ok(l.local_addr().map_err(|e|e.to_string())?.port())}
struct NodeProc{index:usize,port:u16,wal:PathBuf,byzantine:bool,child:Child}
impl NodeProc{
    fn spawn(exe:&Path,index:usize,port:u16,wal:PathBuf,byzantine:bool)->Result<Self,String>{let child=Command::new(exe).arg("--node").arg(index.to_string()).arg(port.to_string()).arg(&wal).arg(if byzantine{"1"}else{"0"}).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e|e.to_string())?;let mut n=Self{index,port,wal,byzantine,child};n.wait_ready()?;Ok(n)}
    fn wait_ready(&mut self)->Result<(),String>{for _ in 0..400{if let Ok(mut s)=TcpStream::connect(("127.0.0.1",self.port)){let _=s.write_all(&[OP_PING]);let mut b=[0u8;1];if s.read_exact(&mut b).is_ok()&&b[0]==0xAA{return Ok(());}}thread::sleep(Duration::from_millis(5));}Err(format!("node {} not ready",self.index))}
    fn crash_restart(&mut self,exe:&Path)->Result<(),String>{let _=self.child.kill();let _=self.child.wait();self.port=free_port()?;self.child=Command::new(exe).arg("--node").arg(self.index.to_string()).arg(self.port.to_string()).arg(&self.wal).arg(if self.byzantine{"1"}else{"0"}).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map_err(|e|e.to_string())?;self.wait_ready()}
    fn stop(&mut self){if let Ok(mut s)=TcpStream::connect(("127.0.0.1",self.port)){let _=s.write_all(&[OP_SHUTDOWN]);}let _=self.child.wait();}
}

fn rpc_vote(port:u16,op:u8,p:&Proposal,qc:Option<&Qc>)->Option<Vote>{let addr:SocketAddr=format!("127.0.0.1:{port}").parse().ok()?;let mut s=TcpStream::connect_timeout(&addr,Duration::from_millis(1000)).ok()?;let _=s.set_read_timeout(Some(Duration::from_millis(1000)));let _=s.set_write_timeout(Some(Duration::from_millis(1000)));s.write_all(&[op]).ok()?;write_proposal(&mut s,p).ok()?;if op==OP_PRECOMMIT{write_qc(&mut s,&qc.cloned()).ok()?;}let mut st=[0u8;1];s.read_exact(&mut st).ok()?;if st[0]!=1{return None;}read_vote(&mut s).ok()}
fn collect_qc(nodes:&[NodeProc],op:u8,p:&Proposal,target_indices:&[usize],drop_mask:&HashSet<usize>,duplicate_mask:&HashSet<usize>,qc:Option<&Qc>,phase:u8)->(Option<Qc>,usize,usize){let mut votes=Vec::new();let mut sent=0usize;let mut dups=0usize;for &i in target_indices{if drop_mask.contains(&i){continue;}sent+=1;if let Some(v)=rpc_vote(nodes[i].port,op,p,qc){votes.push(v);}if duplicate_mask.contains(&i){dups+=1;if let Some(v)=rpc_vote(nodes[i].port,op,p,qc){votes.push(v);}}}(make_qc(votes,phase,p.round,p.tx.input,&p.digest),sent,dups)}

#[derive(Clone,Copy)]struct Prng(u64);
impl Prng{fn new(seed:u64)->Self{Self(seed.max(1))}fn next(&mut self)->u64{let mut x=self.0;x^=x<<13;x^=x>>7;x^=x<<17;self.0=x;x}fn range(&mut self,n:usize)->usize{(self.next()as usize)%n}fn chance(&mut self,a:usize,b:usize)->bool{self.range(b)<a}}

fn byzantine_round(_nodes:&[NodeProc],r:u64,a:&SpendTx,aa:&UserAuth,ad:[u8;32],b:&SpendTx,ba:&UserAuth,bd:[u8;32],rng:&mut Prng,highest:&Option<Qc>,stats:&mut Stats)->Vec<(Proposal,Option<Qc>)>{
    let l=leader(a.input,r);let action=rng.range(4);if action==0{stats.byz_withholds+=1;return vec![];}if action==1{let(tx,au,d)=if let Some(q)=highest{let d=q.votes[0].digest;if d==ad{(a,aa,ad)}else{(b,ba,bd)}}else if ad<=bd{(a,aa,ad)}else{(b,ba,bd)};return vec![(make_proposal(r,l,tx,au,d,highest.clone()),None)];}
    if action==2{let(tx,au,d)=if let Some(q)=highest{let d=q.votes[0].digest;if d==ad{(b,ba,bd)}else{(a,aa,ad)}}else if ad<=bd{(b,ba,bd)}else{(a,aa,ad)};stats.invalid_conflict_proposals+=1;return vec![(make_proposal(r,l,tx,au,d,None),None)];}
    stats.byz_equivocations+=1;vec![(make_proposal(r,l,a,aa,ad,None),None),(make_proposal(r,l,b,ba,bd,None),None)]
}

#[derive(Default)]struct Stats{trials:usize,finalized:usize,dual:usize,max_round:u64,actual_drops:usize,duplicate_attempts:usize,crash_restarts:usize,byz_equivocations:usize,byz_withholds:usize,invalid_conflict_proposals:usize,post_heal_rounds:u64,initial_3_2_reproductions:usize}
fn add_final(finalized:&mut Option<[u8;32]>,d:[u8;32])->Result<(),String>{match finalized{None=>{*finalized=Some(d);Ok(())},Some(old)if *old==d=>Ok(()),Some(_)=>Err("DUAL FINALITY: conflicting PRECOMMIT QCs".into())}}

fn controller()->Result<(),String>{
    let trials:usize=env::var("CALIBRE_SEC010_TRIALS").ok().and_then(|v|v.parse().ok()).unwrap_or(1000);let seed:u64=env::var("CALIBRE_SEC010_SEED").ok().and_then(|v|v.parse().ok()).unwrap_or(0xC411_B8E5_0100_0001);
    let exe=env::current_exe().map_err(|e|e.to_string())?;let root=env::temp_dir().join(format!("calibre-sec010-{}",std::process::id()));let _=fs::remove_dir_all(&root);fs::create_dir_all(&root).map_err(|e|e.to_string())?;
    let mut nodes=Vec::new();for i in 0..N{nodes.push(NodeProc::spawn(&exe,i,free_port()?,root.join(format!("node-{i}.wal")),BYZ.contains(&i))?);}
    println!("CALIBRE SECURITY SEC-010 v0.10.0");println!("RANDOMIZED CONFLICT-LOCAL ROUND-CHANGE / QC-LOCK SAFETY + LIVENESS CAMPAIGN");println!("N=7 Q=5 target f<=2; seven separate OS processes over real 127.0.0.1 TCP");println!("Trials={trials} Seed={seed}");
    println!("Protocol: durable same-round vote records + PREVOTE-QC lock + PRECOMMIT-QC finality + conflict-local leader rotation");println!("Faults: Byzantine proposer equivocation/withholding, invalid higher-round conflict proposals, scheduler drops, duplicates, bounded delays, partitions, and honest process crash/restart");println!("Global blockchain / universal transaction order: NOT USED");println!();
    let mut rng=Prng::new(seed);let mut stats=Stats::default();
    for t in 0..trials{
        let trial=50_000+t as u64;let(a,aa,ad,b,ba,bd)=make_pair(trial);let input=a.input;let mut start=0u64;while !BYZ.contains(&leader(input,start)){start+=1;}let l=leader(input,start);
        let pa=make_proposal(start,l,&a,&aa,ad,None);let pb=make_proposal(start,l,&b,&ba,bd,None);let left=[2usize,3,4];let right=[5usize,6];let empty=HashSet::new();
        let(qa,_,_)=collect_qc(&nodes,OP_PREVOTE,&pa,&left,&empty,&empty,None,PHASE_PREVOTE);let(qb,_,_)=collect_qc(&nodes,OP_PREVOTE,&pb,&right,&empty,&empty,None,PHASE_PREVOTE);if qa.is_some()||qb.is_some(){return Err(format!("trial {t}: reconstructed 3/2 split unexpectedly formed QC"));}stats.initial_3_2_reproductions+=1;
        let mut highest:Option<Qc>=None;let mut finalized:Option<[u8;32]>=None;let fault_rounds=1+rng.range(4)as u64;let mut r=start+1;
        for _ in 0..fault_rounds{
            let leader_id=leader(input,r);let proposals=if BYZ.contains(&leader_id){byzantine_round(&nodes,r,&a,&aa,ad,&b,&ba,bd,&mut rng,&highest,&mut stats)}else{let(tx,au,d)=if let Some(q)=&highest{let d=q.votes[0].digest;if d==ad{(&a,&aa,ad)}else{(&b,&ba,bd)}}else{canonical(&a,&aa,&ad,&b,&ba,&bd)};vec![(make_proposal(r,leader_id,tx,au,d,highest.clone()),None)]};
            for(pi,(p,_))in proposals.iter().enumerate(){let mut drops=HashSet::new();let mut dups=HashSet::new();for &i in &HONEST{if rng.chance(1,4){drops.insert(i);stats.actual_drops+=1;}if rng.chance(1,4){dups.insert(i);stats.duplicate_attempts+=1;}}let target:Vec<usize>=if proposals.len()==2{if pi==0{vec![2,3,4]}else{vec![5,6]}}else{HONEST.to_vec()};
                let(mut pqc,_,_)=collect_qc(&nodes,OP_PREVOTE,p,&target,&drops,&dups,None,PHASE_PREVOTE);let mut byz_votes=Vec::new();for &bi in &BYZ{if rng.chance(3,4){if let Some(v)=rpc_vote(nodes[bi].port,OP_PREVOTE,p,None){byz_votes.push(v);}}}if !byz_votes.is_empty(){let mut all=pqc.as_ref().map(|q|q.votes.clone()).unwrap_or_default();all.extend(byz_votes);pqc=make_qc(all,PHASE_PREVOTE,p.round,input,&p.digest);}
                if let Some(q)=pqc.clone(){if highest.as_ref().map(|h|h.votes[0].round).unwrap_or(0)<=q.votes[0].round{highest=Some(q.clone());}let mut pdrops=HashSet::new();let mut pdups=HashSet::new();for &i in &HONEST{if rng.chance(1,3){pdrops.insert(i);stats.actual_drops+=1;}if rng.chance(1,5){pdups.insert(i);stats.duplicate_attempts+=1;}}
                    let(mut cqc,_,_)=collect_qc(&nodes,OP_PRECOMMIT,p,&HONEST,&pdrops,&pdups,Some(&q),PHASE_PRECOMMIT);let mut bv=Vec::new();for &bi in &BYZ{if rng.chance(1,2){if let Some(v)=rpc_vote(nodes[bi].port,OP_PRECOMMIT,p,Some(&q)){bv.push(v);}}}if !bv.is_empty(){let mut all=cqc.as_ref().map(|x|x.votes.clone()).unwrap_or_default();all.extend(bv);cqc=make_qc(all,PHASE_PRECOMMIT,p.round,input,&p.digest);}if cqc.is_some(){add_final(&mut finalized,p.digest)?;}}
            }
            if rng.chance(1,8){let target=HONEST[rng.range(HONEST.len())];nodes[target].crash_restart(&exe)?;stats.crash_restarts+=1;}if rng.chance(1,3){thread::sleep(Duration::from_millis(1+rng.range(3)as u64));}r+=1;
        }
        let heal_start=r;let mut healed=false;for _ in 0..N{let leader_id=leader(input,r);if BYZ.contains(&leader_id){stats.byz_withholds+=1;r+=1;continue;}let(tx,au,d)=if let Some(q)=&highest{let d=q.votes[0].digest;if d==ad{(&a,&aa,ad)}else{(&b,&ba,bd)}}else{canonical(&a,&aa,&ad,&b,&ba,&bd)};let p=make_proposal(r,leader_id,tx,au,d,highest.clone());
            let(pqc,_,_)=collect_qc(&nodes,OP_PREVOTE,&p,&HONEST,&HashSet::new(),&HashSet::new(),None,PHASE_PREVOTE);if let Some(q)=pqc{highest=Some(q.clone());let(cqc,_,_)=collect_qc(&nodes,OP_PRECOMMIT,&p,&HONEST,&HashSet::new(),&HashSet::new(),Some(&q),PHASE_PRECOMMIT);if cqc.is_some(){add_final(&mut finalized,p.digest)?;healed=true;stats.post_heal_rounds+=r-heal_start+1;break;}}r+=1;}
        if !healed{return Err(format!("trial {t}: permanent deadlock after healed network and full honest-leader rotation"));}
        let winner=finalized.unwrap();let mut ar=r+1;while !BYZ.contains(&leader(input,ar)){ar+=1;}let(tx,au,d)=if winner==ad{(&b,&ba,bd)}else{(&a,&aa,ad)};let attack=make_proposal(ar,leader(input,ar),tx,au,d,None);let mut av=Vec::new();for &i in &HONEST{if let Some(v)=rpc_vote(nodes[i].port,OP_PREVOTE,&attack,None){av.push(v);}}for &i in &BYZ{if let Some(v)=rpc_vote(nodes[i].port,OP_PREVOTE,&attack,None){av.push(v);}}if make_qc(av,PHASE_PREVOTE,ar,input,&d).is_some(){return Err(format!("trial {t}: conflicting post-finality PREVOTE QC formed"));}
        stats.finalized+=1;stats.trials+=1;stats.max_round=stats.max_round.max(r);if(t+1)%250==0{println!("PROGRESS: {} / {} trials",t+1,trials);}
    }
    for n in &mut nodes{n.stop();}let _=fs::remove_dir_all(&root);
    println!();println!("=== SEC-010 RANDOMIZED CAMPAIGN SUMMARY ===");println!("TRIALS: {}",stats.trials);println!("RECONSTRUCTED BYZANTINE-LEADER 3/2 TENTATIVE SPLITS: {}",stats.initial_3_2_reproductions);println!("TRIALS FINALIZED AFTER HEAL: {}",stats.finalized);println!("DUAL-FINALITY VIOLATIONS WITH f<=2: {}",stats.dual);println!("PERMANENT DEADLOCKS AFTER FULL HONEST-LEADER ROTATION: 0");println!("ACTUAL SCHEDULER DROPS: {}",stats.actual_drops);println!("DUPLICATE DELIVERY ATTEMPTS: {}",stats.duplicate_attempts);println!("HONEST PROCESS CRASH/RESTARTS: {}",stats.crash_restarts);println!("BYZANTINE LEADER EQUIVOCATION ROUNDS: {}",stats.byz_equivocations);println!("BYZANTINE LEADER WITHHOLD ROUNDS: {}",stats.byz_withholds);println!("INVALID/UNJUSTIFIED CONFLICT PROPOSALS ATTEMPTED: {}",stats.invalid_conflict_proposals);println!("TOTAL POST-HEAL ROUNDS TO FINALITY: {}",stats.post_heal_rounds);
    println!();println!("=== SEC-010 DECISION ===");println!("CONFLICT-LOCAL ROUND-CHANGE SAFETY WITH f<=2: PASS IN TESTED RANDOMIZED SCHEDULES (0 DUAL FINALITY)");println!("POST-HEAL LIVENESS WITH ROTATING CONFLICT-LOCAL LEADERS: PASS IN TESTED SCHEDULES (ALL TRIALS FINALIZED)");println!("DURABLE SAME-ROUND PREVOTE/PRECOMMIT RECORDING ACROSS PROCESS RESTART: EXERCISED IN CAMPAIGN");println!("POST-FINALITY CONFLICTING BYZANTINE PROPOSAL WITHOUT JUSTIFY QC: REJECTED BELOW QUORUM IN ALL TRIALS");println!("GLOBAL BLOCKCHAIN / UNIVERSAL TRANSACTION ORDER USED: NO");println!("PHYSICAL MULTI-MACHINE / WAN: NOT YET");println!("ARBITRARY ASYNCHRONOUS LIVENESS / FORMAL BYZANTINE PROOF / PRODUCTION CONSENSUS: NOT PROVEN");Ok(())
}

fn main(){let args:Vec<String>=env::args().collect();let res=if args.get(1).map(String::as_str)==Some("--node"){if args.len()!=6{Err("node usage: --node <index> <port> <wal> <byzantine 0|1>".into())}else{let i=args[2].parse::<usize>().map_err(|e|e.to_string());let p=args[3].parse::<u16>().map_err(|e|e.to_string());match(i,p){(Ok(i),Ok(p))=>run_node(i,p,PathBuf::from(&args[4]),args[5]=="1"),(Err(e),_)|(_,Err(e))=>Err(e)}}}else{controller()};if let Err(e)=res{eprintln!("SEC-010 ERROR: {e}");std::process::exit(1);}}

#[cfg(test)]
mod tests{use super::*;#[test]fn quorum_intersection_is_three(){assert_eq!(Q+Q-N,3);assert!(Q+Q-N>2);}#[test]fn leaders_rotate_all_seven(){let input=InputRef{id:7,generation:1};let mut s=HashSet::new();for r in 0..7{s.insert(leader(input,r));}assert_eq!(s.len(),7);}#[test]fn conflicting_digests_differ(){let(a,aa,ad,b,ba,bd)=make_pair(1);assert_eq!(a.input,b.input);assert_eq!(aa.signer,ba.signer);assert_ne!(ad,bd);}#[test]fn wal_checksum_detects_mutation(){let input=InputRef{id:1,generation:2};let mut r=encode_record(PHASE_PREVOTE,input,3,[9u8;32]);assert!(decode_record(&r).is_ok());r[45]^=1;assert!(decode_record(&r).is_err());}#[test]fn five_unique_votes_make_qc(){let input=InputRef{id:3,generation:4};let d=[7u8;32];let mut v=Vec::new();for i in 0..5{v.push(Vote{index:i,phase:PHASE_PREVOTE,round:1,input,digest:d,signature:certifier_key(i).sign(&vote_message(PHASE_PREVOTE,1,input,&d,i)).to_bytes()});}assert!(make_qc(v,PHASE_PREVOTE,1,input,&d).is_some());}}
