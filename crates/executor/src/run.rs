use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sudo_request_protocol::executor::{ApprovalPayload, ExecResult};

use crate::store::now_ms;

pub const SECURE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The executable, after resolving symlinks, and every directory above it
/// must be owned by root and not writable by group or others. Otherwise a
/// non-root user could swap the binary between approval and execution.
pub fn trusted_executable(path: &str) -> Result<PathBuf, String> {
    if !path.starts_with('/') {
        return Err(format!("{path:?} is not an absolute path"));
    }
    let canonical = std::fs::canonicalize(path).map_err(|e| format!("{path}: {e}"))?;
    let meta = std::fs::metadata(&canonical).map_err(|e| format!("{}: {e}", canonical.display()))?;
    if !meta.is_file() || meta.mode() & 0o111 == 0 {
        return Err(format!("{} is not an executable file", canonical.display()));
    }
    let mut cur: Option<&Path> = Some(&canonical);
    while let Some(p) = cur {
        let m = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(format!(
                "{} is writable by a non-root user ({}); refusing to run {} as root",
                p.display(),
                if m.uid() != 0 { "not owned by root" } else { "group/world-writable" },
                canonical.display()
            ));
        }
        cur = p.parent();
    }
    Ok(canonical)
}

pub struct Limits {
    pub timeout: Duration,
    /// Time between SIGTERM and SIGKILL once the timeout fires.
    pub kill_grace: Duration,
    pub max_output_bytes: usize,
}

/// Runs the approved command. `on_started` fires once the process exists.
pub fn run(payload: &ApprovalPayload, executable: &Path, limits: &Limits, on_started: impl FnOnce(i64)) -> ExecResult {
    let started_at = now_ms();
    let mut cmd = Command::new(executable);
    cmd.arg0(&payload.argv[0])
        .args(&payload.argv[1..])
        .current_dir(&payload.cwd)
        .env_clear()
        .env("PATH", SECURE_PATH)
        .env("LANG", "C.UTF-8")
        .env("TERM", "dumb")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("SUDO_USER", &payload.user)
        .env("SUDO_UID", payload.uid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if crate::config::is_root() {
        cmd.env("HOME", "/root").env("USER", "root").env("LOGNAME", "root");
    } else if let Ok(home) = std::env::var("HOME") {
        cmd.env("HOME", home);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ExecResult {
                started_at,
                finished_at: now_ms(),
                spawn_error: Some(format!("could not start {}: {e}", executable.display())),
                ..Default::default()
            }
        }
    };
    on_started(started_at);

    let pgid = child.id() as i32;
    let stdout = capture(child.stdout.take().unwrap(), limits.max_output_bytes);
    let stderr = capture(child.stderr.take().unwrap(), limits.max_output_bytes);

    let deadline = Instant::now() + limits.timeout;
    let mut timed_out = false;
    let mut kill_at: Option<Instant> = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => break None,
        }
        let now = Instant::now();
        if !timed_out && now >= deadline {
            timed_out = true;
            unsafe { libc::killpg(pgid, libc::SIGTERM) };
            kill_at = Some(now + limits.kill_grace);
        }
        if kill_at.is_some_and(|k| now >= k) {
            unsafe { libc::killpg(pgid, libc::SIGKILL) };
            kill_at = None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    // The direct child may exit on SIGTERM while descendants in its group
    // ignore it, so keep escalating against the group, not just the child.
    // (A descendant that moved to its own session or group is out of reach.)
    if timed_out {
        let kill_at = kill_at.unwrap_or_else(Instant::now);
        while unsafe { libc::killpg(pgid, 0) } == 0 {
            if Instant::now() >= kill_at {
                unsafe { libc::killpg(pgid, libc::SIGKILL) };
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // A daemonised grandchild may keep the pipes open; don't hang on it.
    let collect = |rx: mpsc::Receiver<(Vec<u8>, bool)>| {
        rx.recv_timeout(Duration::from_secs(3)).unwrap_or((Vec::new(), true))
    };
    let (out, out_trunc) = collect(stdout);
    let (err, err_trunc) = collect(stderr);

    ExecResult {
        started_at,
        finished_at: now_ms(),
        exit_code: status.and_then(|s| s.code()),
        signal: status.and_then(|s| s.signal()),
        timed_out,
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
        stdout_truncated: out_trunc,
        stderr_truncated: err_trunc,
        spawn_error: None,
    }
}

fn capture<R: Read + Send + 'static>(mut reader: R, cap: usize) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut truncated = false;
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = cap.saturating_sub(buf.len());
                    if n > room {
                        truncated = true;
                    }
                    buf.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
        }
        let _ = tx.send((buf, truncated));
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(exe: &str, argv: &[&str]) -> ApprovalPayload {
        ApprovalPayload {
            v: 1,
            id: 1,
            nonce: "0".repeat(64),
            host: "h".into(),
            user: "ctse".into(),
            uid: 1000,
            cwd: "/".into(),
            executable: exe.into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            created_at: 0,
            expires_at: 0,
        }
    }

    fn limits() -> Limits {
        Limits { timeout: Duration::from_secs(10), kill_grace: Duration::from_secs(5), max_output_bytes: 64 }
    }

    #[test]
    fn captures_output_and_exit_code() {
        let exe = trusted_executable("/bin/sh").unwrap();
        let p = payload("/bin/sh", &["sh", "-c", "echo out; echo err >&2; exit 3"]);
        let r = run(&p, &exe, &limits(), |_| {});
        assert_eq!(r.exit_code, Some(3));
        assert_eq!(r.stdout, "out\n");
        assert_eq!(r.stderr, "err\n");
    }

    #[test]
    fn truncates_large_output() {
        let exe = trusted_executable("/bin/sh").unwrap();
        let p = payload("/bin/sh", &["sh", "-c", "head -c 100000 /dev/zero | tr '\\0' x"]);
        let r = run(&p, &exe, &limits(), |_| {});
        assert_eq!(r.stdout.len(), 64);
        assert!(r.stdout_truncated);
    }

    #[test]
    fn times_out() {
        let exe = trusted_executable("/bin/sh").unwrap();
        let p = payload("/bin/sh", &["sh", "-c", "sleep 30"]);
        let r = run(&p, &exe, &Limits { timeout: Duration::from_millis(200), kill_grace: Duration::from_secs(5), max_output_bytes: 64 }, |_| {});
        assert!(r.timed_out);
        assert_eq!(r.signal, Some(libc::SIGTERM));
    }

    #[test]
    fn timeout_kills_descendants_that_ignore_sigterm() {
        let dir = std::env::temp_dir().join(format!("sre-orphan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("pid");
        let script = format!("(trap '' TERM; exec sleep 30) & echo $! > {}; sleep 30", pidfile.display());
        let exe = trusted_executable("/bin/sh").unwrap();
        let limits = Limits { timeout: Duration::from_millis(200), kill_grace: Duration::from_millis(300), max_output_bytes: 64 };
        let r = run(&payload("/bin/sh", &["sh", "-c", &script]), &exe, &limits, |_| {});
        assert!(r.timed_out);
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let gone = (0..60).any(|_| {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            let zombie_or_gone = stat.is_empty() || stat.split(") ").nth(1).is_some_and(|s| s.starts_with('Z'));
            if !zombie_or_gone {
                std::thread::sleep(Duration::from_millis(50));
            }
            zombie_or_gone
        });
        if !gone {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        assert!(gone, "descendant {pid} survived the timeout");
    }

    #[test]
    fn clean_environment() {
        let exe = trusted_executable("/usr/bin/env").unwrap();
        let r = run(&payload("/usr/bin/env", &["env"]), &exe, &Limits { timeout: Duration::from_secs(5), kill_grace: Duration::from_secs(5), max_output_bytes: 4096 }, |_| {});
        assert!(r.stdout.contains(&format!("PATH={SECURE_PATH}")));
        assert!(!r.stdout.contains("LD_PRELOAD"));
    }

    #[test]
    fn untrusted_executables_are_refused() {
        assert!(trusted_executable("sh").is_err());
        let dir = std::env::temp_dir().join(format!("sre-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("evil");
        std::fs::write(&f, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        assert!(trusted_executable(f.to_str().unwrap()).is_err());
    }
}
