//! Root-owned on-disk state: enrolled passkeys, the pending enrollment
//! token, and the execute-once ledger.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sudo_request_protocol::executor::{ExecResult, LedgerState, LookupResponse};

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_dir(path.parent().unwrap_or(Path::new("/")))
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredCredential {
    /// base64url, no padding.
    pub id: String,
    /// base64url SEC1 uncompressed P-256 point.
    pub public_key: String,
    pub label: String,
    pub created_at: i64,
    pub sign_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentToken {
    /// base64url of SHA-256("sudo-request-enroll:" + normalised token).
    pub challenge: String,
    pub expires_at: i64,
}

pub struct Store {
    dir: PathBuf,
    running: Mutex<HashSet<String>>,
}

/// An exclusive `flock` on `state.lock`, released on drop. The service and the
/// admin subcommands are separate processes, so credential and enrollment
/// read-modify-write cycles must be serialised through the filesystem.
struct StateLock(#[allow(dead_code)] File);

pub type EnrollError = (&'static str, String);

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir, running: Mutex::new(HashSet::new()) }
    }

    fn lock(&self) -> io::Result<StateLock> {
        let f = OpenOptions::new().create(true).write(true).mode(0o600).open(self.dir.join("state.lock"))?;
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(StateLock(f))
    }

    fn creds_path(&self) -> PathBuf {
        self.dir.join("credentials.json")
    }

    pub fn credentials(&self) -> io::Result<Vec<StoredCredential>> {
        match fs::read(self.creds_path()) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    fn write_credentials(&self, creds: &[StoredCredential]) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(creds).expect("serialisable");
        write_atomic(&self.creds_path(), &bytes).map_err(|e| format!("cannot write credentials: {e}"))
    }

    /// Read-modify-write of the credential list under the state lock.
    pub fn update_credentials<T>(
        &self,
        f: impl FnOnce(&mut Vec<StoredCredential>) -> Result<T, String>,
    ) -> Result<T, String> {
        let _lock = self.lock().map_err(|e| format!("cannot lock state: {e}"))?;
        let mut creds = self.credentials().map_err(|e| format!("cannot read credentials: {e}"))?;
        let out = f(&mut creds)?;
        self.write_credentials(&creds)?;
        Ok(out)
    }

    fn enroll_path(&self) -> PathBuf {
        self.dir.join("enroll.json")
    }

    pub fn put_enrollment(&self, token: &EnrollmentToken) -> io::Result<()> {
        let _lock = self.lock()?;
        write_atomic(&self.enroll_path(), &serde_json::to_vec(token).expect("serialisable"))
    }

    fn enrollment(&self) -> Option<EnrollmentToken> {
        let bytes = fs::read(self.enroll_path()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Validates against the open enrollment token, consumes it, and stores the
    /// credential `verify` returns, all under one lock. The token is removed
    /// (durably) before the credential is written, so a failure part-way
    /// leaves no usable token rather than a reusable one.
    pub fn enroll(
        &self,
        verify: impl FnOnce(&EnrollmentToken) -> Result<StoredCredential, EnrollError>,
    ) -> Result<StoredCredential, EnrollError> {
        let _lock = self.lock().map_err(|e| ("store_error", format!("cannot lock state: {e}")))?;
        let token = self.enrollment().filter(|t| t.expires_at > now_ms()).ok_or((
            "no_enrollment",
            "no enrollment is open; run `sudo sudo-request-executor enroll` first".to_string(),
        ))?;
        let cred = verify(&token)?;
        let mut creds = self.credentials().map_err(|e| ("store_error", format!("cannot read credentials: {e}")))?;
        if creds.iter().any(|c| c.id == cred.id) {
            return Err(("store_error", "this passkey is already enrolled".into()));
        }
        fs::remove_file(self.enroll_path())
            .and_then(|()| sync_dir(&self.dir))
            .map_err(|e| ("store_error", format!("cannot consume enrollment token: {e}")))?;
        creds.push(cred.clone());
        self.write_credentials(&creds).map_err(|e| ("store_error", e))?;
        Ok(cred)
    }

    // ---- ledger ----

    fn ledger_path(&self, nonce: &str, suffix: &str) -> PathBuf {
        self.dir.join("ledger").join(format!("{nonce}.{suffix}"))
    }

    /// Atomically claim an approval. Returns `false` if it was already claimed,
    /// which is how replays are rejected. The claim is durable before the
    /// process is spawned, so a crash can never lead to a second run.
    pub fn claim(&self, nonce: &str, record: &serde_json::Value) -> io::Result<bool> {
        debug_assert!(valid_nonce(nonce));
        let path = self.ledger_path(nonce, "claim");
        let mut f = match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
            Err(e) => return Err(e),
        };
        f.write_all(serde_json::to_string(record).expect("serialisable").as_bytes())?;
        f.sync_all()?;
        sync_dir(&self.dir.join("ledger"))?;
        self.running.lock().unwrap().insert(nonce.to_string());
        Ok(true)
    }

    pub fn finish(&self, nonce: &str, result: &ExecResult) -> io::Result<()> {
        let r = write_atomic(&self.ledger_path(nonce, "result"), &serde_json::to_vec(result).expect("serialisable"));
        self.running.lock().unwrap().remove(nonce);
        r
    }

    pub fn lookup(&self, nonce: &str) -> LookupResponse {
        if !valid_nonce(nonce) {
            return LookupResponse { state: LedgerState::Unknown, result: None };
        }
        if let Ok(bytes) = fs::read(self.ledger_path(nonce, "result")) {
            if let Ok(result) = serde_json::from_slice(&bytes) {
                return LookupResponse { state: LedgerState::Finished, result: Some(result) };
            }
        }
        if !self.ledger_path(nonce, "claim").exists() {
            return LookupResponse { state: LedgerState::Unknown, result: None };
        }
        let state = if self.running.lock().unwrap().contains(nonce) {
            LedgerState::Running
        } else {
            LedgerState::Interrupted
        };
        LookupResponse { state, result: None }
    }
}

pub fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 64 && nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> Store {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("sre-store-{}-{}-{n}", std::process::id(), now_ms()));
        fs::create_dir_all(dir.join("ledger")).unwrap();
        Store::new(dir)
    }

    #[test]
    fn claim_is_once_only() {
        let s = tmp_store();
        let n = "a".repeat(64);
        assert_eq!(s.lookup(&n).state, LedgerState::Unknown);
        assert!(s.claim(&n, &serde_json::json!({})).unwrap());
        assert!(!s.claim(&n, &serde_json::json!({})).unwrap());
        assert_eq!(s.lookup(&n).state, LedgerState::Running);
        s.finish(&n, &ExecResult { exit_code: Some(0), ..Default::default() }).unwrap();
        assert_eq!(s.lookup(&n).state, LedgerState::Finished);
    }

    #[test]
    fn claim_without_result_after_restart_is_interrupted() {
        let s = tmp_store();
        let n = "b".repeat(64);
        assert!(s.claim(&n, &serde_json::json!({})).unwrap());
        let restarted = Store::new(s.dir.clone());
        assert_eq!(restarted.lookup(&n).state, LedgerState::Interrupted);
        assert!(!restarted.claim(&n, &serde_json::json!({})).unwrap());
    }

    fn cred(id: &str) -> StoredCredential {
        StoredCredential { id: id.into(), public_key: "k".into(), label: "l".into(), created_at: 0, sign_count: 0 }
    }

    #[test]
    fn removal_is_not_undone_by_a_concurrent_update_from_another_instance() {
        use std::sync::{Arc, Barrier};
        let service = Arc::new(tmp_store());
        let admin = Store::new(service.dir.clone());
        service.update_credentials(|c| Ok(c.push(cred("revoked")))).unwrap();

        // The service is mid-way through a counter update when `passkeys remove` runs.
        let entered = Arc::new(Barrier::new(2));
        let (svc, e) = (service.clone(), entered.clone());
        let t = std::thread::spawn(move || {
            svc.update_credentials(|c| {
                e.wait();
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Some(x) = c.first_mut() {
                    x.sign_count = 1;
                }
                Ok(())
            })
            .unwrap()
        });
        entered.wait();
        admin.update_credentials(|c| Ok(c.clear())).unwrap();
        t.join().unwrap();
        assert!(admin.credentials().unwrap().is_empty());
    }

    #[test]
    fn enrollment_token_is_consumed_exactly_once_under_concurrency() {
        use std::sync::Arc;
        let s = Arc::new(tmp_store());
        s.put_enrollment(&EnrollmentToken { challenge: "c".into(), expires_at: now_ms() + 60_000 }).unwrap();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let s = Store::new(s.dir.clone());
                std::thread::spawn(move || s.enroll(|_| Ok(cred(&format!("key{i}")))).is_ok())
            })
            .collect();
        let successes = handles.into_iter().map(|h| h.join().unwrap()).filter(|ok| *ok).count();
        assert_eq!(successes, 1);
        assert_eq!(s.credentials().unwrap().len(), 1);
        assert!(s.enroll(|_| Ok(cred("late"))).is_err());
    }

    #[test]
    fn rejects_path_like_nonces() {
        assert!(!valid_nonce("../../etc/passwd"));
        assert!(!valid_nonce(&"A".repeat(64)));
    }
}
