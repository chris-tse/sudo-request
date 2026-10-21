use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The executor reads the same TOML file as the backend but only the
/// `[webauthn]` and `[executor]` tables. Other tables are ignored.
#[derive(Debug, Deserialize)]
struct File {
    webauthn: WebauthnSection,
    #[serde(default)]
    executor: ExecutorSection,
}

#[derive(Debug, Deserialize)]
struct WebauthnSection {
    rp_id: String,
    origin: String,
}

#[derive(Debug, Default, Deserialize)]
struct ExecutorSection {
    socket: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    allowed_peer_user: Option<String>,
    timeout_seconds: Option<u64>,
    max_output_bytes: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub rp_id: String,
    pub origin: String,
    pub socket: PathBuf,
    pub state_dir: PathBuf,
    /// Only this uid may connect to the socket. Defaults to the executor's own
    /// uid when it is not running as root (development).
    pub allowed_peer_uid: u32,
    pub allowed_peer_gid: u32,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn load(path: &Path) -> Result<Config, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
    if is_root() && (meta.uid() != 0 || meta.mode() & 0o022 != 0) {
        return Err(format!(
            "refusing config {}: when running as root it must be owned by root and not group/world-writable",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
    let file: File = toml::from_str(&text).map_err(|e| format!("invalid config {}: {e}", path.display()))?;

    if !file.webauthn.origin.starts_with("https://") && !file.webauthn.origin.starts_with("http://localhost") {
        return Err("webauthn.origin must be https:// (or http://localhost for development)".into());
    }

    let (allowed_peer_uid, allowed_peer_gid) = match &file.executor.allowed_peer_user {
        Some(name) => lookup_user(name).ok_or_else(|| format!("executor.allowed_peer_user {name:?} does not exist"))?,
        None if is_root() => return Err("executor.allowed_peer_user is required when running as root".into()),
        None => unsafe { (libc::getuid(), libc::getgid()) },
    };
    if is_root() && allowed_peer_uid == 0 {
        return Err("executor.allowed_peer_user must not be root".into());
    }

    Ok(Config {
        rp_id: file.webauthn.rp_id,
        origin: file.webauthn.origin,
        socket: file.executor.socket.unwrap_or_else(|| "/run/sudo-request-executor/executor.sock".into()),
        state_dir: file.executor.state_dir.unwrap_or_else(|| "/var/lib/sudo-request-executor".into()),
        allowed_peer_uid,
        allowed_peer_gid,
        timeout_seconds: file.executor.timeout_seconds.unwrap_or(15 * 60),
        max_output_bytes: file.executor.max_output_bytes.unwrap_or(1024 * 1024),
    })
}

fn lookup_user(name: &str) -> Option<(u32, u32)> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam returns null or a pointer to static storage that we read immediately.
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some(((*pw).pw_uid, (*pw).pw_gid))
        }
    }
}

/// Create the state directory if needed and make sure nobody but its owner
/// can tamper with credentials or the ledger.
pub fn prepare_state_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    for sub in [dir.to_path_buf(), dir.join("ledger")] {
        if !sub.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&sub)
                .map_err(|e| format!("cannot create {}: {e}", sub.display()))?;
        }
        let meta = std::fs::metadata(&sub).map_err(|e| format!("cannot stat {}: {e}", sub.display()))?;
        let me = unsafe { libc::geteuid() };
        if meta.uid() != me {
            return Err(format!("{} must be owned by uid {me}", sub.display()));
        }
        if meta.mode() & 0o077 != 0 {
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("cannot chmod {}: {e}", sub.display()))?;
        }
    }
    Ok(())
}
