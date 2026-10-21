use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use sudo_request_protocol::executor::{
    ApprovalPayload, Assertion, ExecResult, ExecuteEvent, ExecutorRequest, SimpleResponse, PAYLOAD_VERSION,
};
use sudo_request_protocol::limits;

use crate::config::Config;
use crate::run::{self, Limits};
use crate::store::{now_ms, valid_nonce, EnrollError, StoredCredential, Store};
use crate::webauthn::{self, b64decode, b64encode, RelyingParty};

const MAX_REQUEST_LIFETIME_MS: i64 = 24 * 60 * 60 * 1000;
const CLOCK_SKEW_MS: i64 = 60 * 1000;

pub struct Ctx {
    pub cfg: Config,
    pub rp: RelyingParty,
    pub store: Store,
    pub hostname: String,
}

pub fn serve(ctx: Arc<Ctx>) -> Result<(), String> {
    let path = &ctx.cfg.socket;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(format!("{} exists and is not a socket", path.display()));
        }
        std::fs::remove_file(path).map_err(|e| format!("cannot remove stale socket: {e}"))?;
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("cannot bind {}: {e}", path.display()))?;
    if crate::config::is_root() {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        if unsafe { libc::chown(c.as_ptr(), 0, ctx.cfg.allowed_peer_gid) } != 0 {
            return Err(format!("cannot chown socket: {}", std::io::Error::last_os_error()));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).map_err(|e| e.to_string())?;
    } else {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    eprintln!(
        "sudo-request-executor listening on {} (peer uid {}, origin {})",
        path.display(),
        ctx.cfg.allowed_peer_uid,
        ctx.cfg.origin
    );

    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        match peer_uid(&stream) {
            Some(uid) if uid == ctx.cfg.allowed_peer_uid => {}
            other => {
                eprintln!("rejected connection from uid {other:?}");
                continue;
            }
        }
        let ctx = ctx.clone();
        std::thread::spawn(move || handle(&ctx, stream));
    }
    Ok(())
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid for writes and sized for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

fn send<T: Serialize>(stream: &mut UnixStream, msg: &T) {
    let mut line = serde_json::to_string(msg).expect("serialisable");
    line.push('\n');
    // The backend may have gone away; the ledger still records the outcome.
    let _ = stream.write_all(line.as_bytes());
}

fn handle(ctx: &Ctx, mut stream: UnixStream) {
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut line = String::new();
    let read = BufReader::new(&stream).take(limits::MAX_LINE_BYTES as u64).read_line(&mut line);
    if read.is_err() || line.is_empty() {
        return;
    }
    let req: ExecutorRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => return send(&mut stream, &simple_err("malformed", &e.to_string())),
    };
    match req {
        ExecutorRequest::Execute { payload, assertion } => execute(ctx, &mut stream, &payload, &assertion),
        ExecutorRequest::Lookup { nonce } => send(&mut stream, &ctx.store.lookup(&nonce)),
        ExecutorRequest::Enroll { label, credential_id, client_data_json, attestation_object } => {
            let resp = match enroll(ctx, &label, &credential_id, &client_data_json, &attestation_object) {
                Ok(()) => SimpleResponse { ok: true, code: None, message: None, credentials: None },
                Err((code, msg)) => simple_err(code, &msg),
            };
            send(&mut stream, &resp)
        }
        ExecutorRequest::Info => {
            let n = ctx.store.credentials().map(|c| c.len()).unwrap_or(0);
            send(&mut stream, &SimpleResponse { ok: true, code: None, message: None, credentials: Some(n) })
        }
    }
}

fn simple_err(code: &str, message: &str) -> SimpleResponse {
    SimpleResponse { ok: false, code: Some(code.into()), message: Some(message.into()), credentials: None }
}

pub fn validate_payload(p: &ApprovalPayload, hostname: &str, now: i64) -> Result<(), String> {
    if p.v != PAYLOAD_VERSION {
        return Err(format!("unsupported payload version {}", p.v));
    }
    if !valid_nonce(&p.nonce) {
        return Err("invalid nonce".into());
    }
    if p.host != hostname {
        return Err(format!("request is for host {:?}, this is {hostname:?}", p.host));
    }
    if p.argv.is_empty() || p.argv[0].is_empty() || p.argv.len() > limits::MAX_ARGS {
        return Err("invalid argument vector".into());
    }
    let total: usize = p.argv.iter().map(String::len).sum();
    if total > limits::MAX_TOTAL_ARG_BYTES || p.argv.iter().any(|a| a.len() > limits::MAX_ARG_BYTES) {
        return Err("arguments too long".into());
    }
    if p.argv.iter().chain([&p.cwd, &p.executable]).any(|s| s.contains('\0')) {
        return Err("NUL byte in request".into());
    }
    if !p.cwd.starts_with('/') || p.cwd.len() > limits::MAX_PATH_BYTES {
        return Err("working directory must be an absolute path".into());
    }
    if !p.executable.starts_with('/') {
        return Err("executable must be an absolute path".into());
    }
    if p.created_at > now + CLOCK_SKEW_MS || p.expires_at - p.created_at > MAX_REQUEST_LIFETIME_MS {
        return Err("implausible request timestamps".into());
    }
    if now >= p.expires_at {
        return Err("request has expired".into());
    }
    Ok(())
}

fn execute(ctx: &Ctx, stream: &mut UnixStream, payload_str: &str, assertion: &Assertion) {
    let reject = |stream: &mut UnixStream, code: &str, message: String| {
        eprintln!("rejected execution: {code}: {message}");
        send(stream, &ExecuteEvent::Rejected { code: code.into(), message });
    };

    let payload: ApprovalPayload = match serde_json::from_str(payload_str) {
        Ok(p) => p,
        Err(e) => return reject(stream, "malformed_payload", e.to_string()),
    };
    if let Err(e) = validate_payload(&payload, &ctx.hostname, now_ms()) {
        return reject(stream, "invalid_payload", e);
    }

    let cred_id = match b64decode(&assertion.credential_id) {
        Ok(b) => b64encode(&b),
        Err(_) => return reject(stream, "unknown_credential", "malformed credential id".into()),
    };
    let challenge = Sha256::digest(payload_str.as_bytes());
    let verified = ctx.store.update_credentials(|creds| {
        let cred: &mut StoredCredential = creds
            .iter_mut()
            .find(|c| c.id == cred_id)
            .ok_or_else(|| "this passkey is not enrolled with the executor".to_string())?;
        let pk = b64decode(&cred.public_key).map_err(|e| e.to_string())?;
        let count = webauthn::verify_assertion(
            &ctx.rp,
            &pk,
            cred.sign_count,
            &assertion.client_data_json,
            &assertion.authenticator_data,
            &assertion.signature,
            &challenge,
        )
        .map_err(|e| e.to_string())?;
        cred.sign_count = count;
        Ok(cred.label.clone())
    });
    let label = match verified {
        Ok(l) => l,
        Err(e) => return reject(stream, "verification_failed", e),
    };

    let record = serde_json::json!({
        "id": payload.id,
        "user": payload.user,
        "argv": payload.argv,
        "cwd": payload.cwd,
        "credentialId": cred_id,
        "credentialLabel": label,
        "claimedAt": now_ms(),
    });
    match ctx.store.claim(&payload.nonce, &record) {
        Ok(true) => {}
        Ok(false) => return reject(stream, "replay", "this approval has already been used".into()),
        Err(e) => return reject(stream, "ledger_error", format!("cannot record approval: {e}")),
    }
    eprintln!(
        "approved by passkey {label:?}: request #{} from {} in {}: {:?}",
        payload.id, payload.user, payload.cwd, payload.argv
    );

    let result = match run::trusted_executable(&payload.executable) {
        Err(e) => ExecResult { started_at: now_ms(), finished_at: now_ms(), spawn_error: Some(e), ..Default::default() },
        Ok(exe) => {
            let limits = Limits {
                timeout: Duration::from_secs(ctx.cfg.timeout_seconds),
                kill_grace: Duration::from_secs(5),
                max_output_bytes: ctx.cfg.max_output_bytes,
            };
            run::run(&payload, &exe, &limits, |started_at| send(stream, &ExecuteEvent::Started { started_at }))
        }
    };
    if let Err(e) = ctx.store.finish(&payload.nonce, &result) {
        eprintln!("cannot record result for request #{}: {e}", payload.id);
    }
    eprintln!(
        "request #{} finished: exit={:?} signal={:?} timed_out={} spawn_error={:?}",
        payload.id, result.exit_code, result.signal, result.timed_out, result.spawn_error
    );
    send(stream, &ExecuteEvent::Finished { result });
}

fn enroll(
    ctx: &Ctx,
    label: &str,
    credential_id: &str,
    client_data_json: &str,
    attestation_object: &str,
) -> Result<(), EnrollError> {
    let label = label.chars().filter(|c| !c.is_control()).take(64).collect::<String>();
    let label = if label.is_empty() { "passkey".to_string() } else { label };
    ctx.store.enroll(|token| {
        let challenge = b64decode(&token.challenge).map_err(|e| ("internal", e.to_string()))?;
        let cred =
            webauthn::verify_registration(&ctx.rp, credential_id, client_data_json, attestation_object, &challenge)
                .map_err(|e| ("verification_failed", e.to_string()))?;
        Ok(StoredCredential {
            id: b64encode(&cred.id),
            public_key: b64encode(&cred.public_key),
            label: label.clone(),
            created_at: now_ms(),
            sign_count: cred.sign_count,
        })
    })?;
    eprintln!("enrolled passkey {label:?}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::EnrollmentToken;
    use crate::webauthn::testing::*;
    use sudo_request_protocol::executor::{LedgerState, LookupResponse};

    const RP_ID: &str = "pod042.example.ts.net";
    const ORIGIN: &str = "https://pod042.example.ts.net:10000";

    struct Harness {
        ctx: Arc<Ctx>,
        auth: SoftAuthenticator,
    }

    fn harness() -> Harness {
        let dir = std::env::temp_dir().join(format!("sre-srv-{}-{}", std::process::id(), rand_suffix()));
        crate::config::prepare_state_dir(&dir).unwrap();
        let uid = unsafe { libc::getuid() };
        let cfg = Config {
            rp_id: RP_ID.into(),
            origin: ORIGIN.into(),
            socket: dir.join("exec.sock"),
            state_dir: dir.clone(),
            allowed_peer_uid: uid,
            allowed_peer_gid: 0,
            timeout_seconds: 10,
            max_output_bytes: 4096,
        };
        let ctx = Arc::new(Ctx {
            rp: RelyingParty { rp_id: RP_ID.into(), origin: ORIGIN.into() },
            store: Store::new(dir),
            hostname: "testhost".into(),
            cfg,
        });
        let auth = SoftAuthenticator::new(RP_ID);
        let challenge = Sha256::digest(b"sudo-request-enroll:TESTTOKEN").to_vec();
        ctx.store.put_enrollment(&EnrollmentToken { challenge: b64encode(&challenge), expires_at: now_ms() + 60_000 }).unwrap();
        let (cd, att) = auth.register(ORIGIN, &challenge);
        enroll(&ctx, "test", &b64encode(&auth.id), &cd, &att).unwrap();
        Harness { ctx, auth }
    }

    fn rand_suffix() -> String {
        let mut b = [0u8; 8];
        std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut b).unwrap();
        b64encode(&b).replace(['-', '_'], "x")
    }

    fn nonce() -> String {
        let mut b = [0u8; 32];
        std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut b).unwrap();
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn payload(argv: &[&str]) -> String {
        let now = now_ms();
        serde_json::to_string(&ApprovalPayload {
            v: 1,
            id: 42,
            nonce: nonce(),
            host: "testhost".into(),
            user: "ctse".into(),
            uid: 1000,
            cwd: "/".into(),
            executable: "/bin/sh".into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            created_at: now,
            expires_at: now + 60_000,
        })
        .unwrap()
    }

    fn sign(h: &Harness, payload: &str) -> Assertion {
        let (cd, ad, sig) = h.auth.assert(ORIGIN, &Sha256::digest(payload.as_bytes()), UP_UV);
        Assertion { credential_id: b64encode(&h.auth.id), client_data_json: cd, authenticator_data: ad, signature: sig }
    }

    /// Drive `execute` over a real socket pair and collect the events.
    fn exec(h: &Harness, payload: &str, assertion: &Assertion) -> Vec<ExecuteEvent> {
        let (mut a, b) = UnixStream::pair().unwrap();
        execute(&h.ctx, &mut a, payload, assertion);
        drop(a);
        BufReader::new(b).lines().map(|l| serde_json::from_str(&l.unwrap()).unwrap()).collect()
    }

    fn rejected_code(events: &[ExecuteEvent]) -> Option<String> {
        match events {
            [ExecuteEvent::Rejected { code, .. }] => Some(code.clone()),
            _ => None,
        }
    }

    #[test]
    fn executes_exactly_once() {
        let h = harness();
        let p = payload(&["sh", "-c", "echo hi"]);
        let a = sign(&h, &p);
        let ev = exec(&h, &p, &a);
        assert!(matches!(ev[0], ExecuteEvent::Started { .. }));
        let ExecuteEvent::Finished { result } = &ev[1] else { panic!("{ev:?}") };
        assert_eq!(result.stdout, "hi\n");
        assert_eq!(result.exit_code, Some(0));

        // Replaying the identical approval is refused.
        assert_eq!(rejected_code(&exec(&h, &p, &a)).as_deref(), Some("replay"));

        let nonce = serde_json::from_str::<ApprovalPayload>(&p).unwrap().nonce;
        let LookupResponse { state, result } = h.ctx.store.lookup(&nonce);
        assert_eq!(state, LedgerState::Finished);
        assert_eq!(result.unwrap().stdout, "hi\n");
    }

    #[test]
    fn forged_or_missing_approval_is_rejected() {
        let h = harness();
        let p = payload(&["sh", "-c", "echo hi"]);
        let forged = Assertion {
            credential_id: b64encode(&h.auth.id),
            client_data_json: b64encode(br#"{"type":"webauthn.get","challenge":"x","origin":"https://pod042.example.ts.net:10000"}"#),
            authenticator_data: b64encode(&[0u8; 37]),
            signature: b64encode(b"approved: true"),
        };
        assert_eq!(rejected_code(&exec(&h, &p, &forged)).as_deref(), Some("verification_failed"));
    }

    #[test]
    fn modified_command_is_rejected() {
        let h = harness();
        let p = payload(&["sh", "-c", "echo harmless"]);
        let a = sign(&h, &p);
        let tampered = p.replace("echo harmless", "echo evil!!!");
        assert_eq!(rejected_code(&exec(&h, &tampered, &a)).as_deref(), Some("verification_failed"));
    }

    #[test]
    fn approval_is_bound_to_its_request() {
        let h = harness();
        let p1 = payload(&["sh", "-c", "echo one"]);
        let p2 = payload(&["sh", "-c", "echo one"]);
        let a1 = sign(&h, &p1);
        assert_eq!(rejected_code(&exec(&h, &p2, &a1)).as_deref(), Some("verification_failed"));
    }

    #[test]
    fn unenrolled_passkey_is_rejected() {
        let h = harness();
        let stranger = Harness { ctx: h.ctx.clone(), auth: SoftAuthenticator::new(RP_ID) };
        let p = payload(&["sh", "-c", "echo hi"]);
        let a = sign(&stranger, &p);
        assert_eq!(rejected_code(&exec(&h, &p, &a)).as_deref(), Some("verification_failed"));
    }

    #[test]
    fn expired_request_is_rejected() {
        let h = harness();
        let mut p: ApprovalPayload = serde_json::from_str(&payload(&["sh"])).unwrap();
        p.expires_at = now_ms() - 1;
        let s = serde_json::to_string(&p).unwrap();
        let a = sign(&h, &s);
        assert_eq!(rejected_code(&exec(&h, &s, &a)).as_deref(), Some("invalid_payload"));
    }

    #[test]
    fn untrusted_executable_is_claimed_but_not_run() {
        let h = harness();
        let mut p: ApprovalPayload = serde_json::from_str(&payload(&["x"])).unwrap();
        p.executable = "/tmp/definitely-not-trusted".into();
        let s = serde_json::to_string(&p).unwrap();
        let a = sign(&h, &s);
        let ev = exec(&h, &s, &a);
        let [ExecuteEvent::Finished { result }] = ev.as_slice() else { panic!("{ev:?}") };
        assert!(result.spawn_error.is_some());
    }

    #[test]
    fn enrollment_requires_token_and_is_single_use() {
        let h = harness();
        let auth = SoftAuthenticator::new(RP_ID);
        let (cd, att) = auth.register(ORIGIN, &[1u8; 32]);
        let e = enroll(&h.ctx, "agent", &b64encode(&auth.id), &cd, &att).unwrap_err();
        assert_eq!(e.0, "no_enrollment");

        let challenge = Sha256::digest(b"sudo-request-enroll:OTHER").to_vec();
        h.ctx.store.put_enrollment(&EnrollmentToken { challenge: b64encode(&challenge), expires_at: now_ms() + 60_000 }).unwrap();
        let (cd, att) = auth.register(ORIGIN, &[1u8; 32]);
        assert_eq!(enroll(&h.ctx, "agent", &b64encode(&auth.id), &cd, &att).unwrap_err().0, "verification_failed");
    }
}
