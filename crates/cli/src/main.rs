use std::ffi::CStr;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use sudo_request_protocol::broker::{ClientMessage, RequestView, ServerMessage, Status};
use sudo_request_protocol::{limits, DEFAULT_CLI_SOCKET};

/// Exit codes. `wait` and `status` on a completed request exit with the
/// command's own exit code instead.
mod exit {
    pub const ERROR: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const NOT_RUN: u8 = 3; // denied, cancelled, expired
    pub const FAILED: u8 = 4; // failed to start, or outcome uncertain
    pub const STILL_PENDING: u8 = 5; // `wait --timeout` elapsed
    pub const UNAVAILABLE: u8 = 6; // backend unreachable
}

#[derive(Parser)]
#[command(
    name = "sudo-request",
    version,
    about = "Queue a privileged command for human approval on the sudo-request dashboard",
    after_help = "Shorthand: `sudo-request -- <command> [args...]` is the same as `submit`."
)]
struct Cli {
    /// Print machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    /// Backend socket path (default: $SUDO_REQUEST_SOCKET or /run/sudo-request/cli.sock).
    #[arg(long, global = true, value_name = "PATH")]
    socket: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Queue a command and exit immediately. Nothing runs until a human approves it.
    Submit {
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
        argv: Vec<String>,
    },
    /// Show a request's status (and its output once finished).
    Status { id: i64 },
    /// Block until a request finishes, then print its output.
    Wait {
        id: i64,
        /// Give up after this many seconds (exit code 5). Default: wait until it finishes or expires.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },
    /// Cancel a request that has not started executing.
    Cancel { id: i64 },
    /// List pending requests (or recent ones with --all).
    List {
        #[arg(long)]
        all: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(expand_shorthand(std::env::args().collect()));
    let socket = cli
        .socket
        .clone()
        .or_else(|| std::env::var("SUDO_REQUEST_SOCKET").ok())
        .unwrap_or_else(|| DEFAULT_CLI_SOCKET.to_string());
    let out = Output { json: cli.json };

    match run(&cli.command, &socket, &out) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            out.error(&err);
            ExitCode::from(err.exit_code)
        }
    }
}

/// Rewrites `sudo-request [global options] -- cmd...` to `... submit -- cmd...`.
fn expand_shorthand(mut args: Vec<String>) -> Vec<String> {
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                args.insert(i, "submit".into());
                break;
            }
            "--json" => i += 1,
            "--socket" => i += 2,
            a if a.starts_with("--socket=") => i += 1,
            _ => break,
        }
    }
    args
}

struct CliError {
    exit_code: u8,
    code: String,
    message: String,
}

impl CliError {
    fn new(exit_code: u8, code: &str, message: impl Into<String>) -> Self {
        Self { exit_code, code: code.into(), message: message.into() }
    }
}

fn run(command: &Command, socket: &str, out: &Output) -> Result<u8, CliError> {
    match command {
        Command::Submit { argv } => {
            validate_argv(argv)?;
            let cwd = std::env::current_dir()
                .map_err(|e| CliError::new(exit::ERROR, "cwd", format!("cannot read working directory: {e}")))?;
            let (user, uid) = current_user();
            let resp = call(
                socket,
                &ClientMessage::Submit { argv: argv.clone(), cwd: cwd.to_string_lossy().into_owned(), user, uid },
            )?;
            let req = resp.request.clone().ok_or_else(missing_request)?;
            out.submitted(&req, resp.dashboard_url.as_deref());
            Ok(0)
        }
        Command::Status { id } => {
            let req = call(socket, &ClientMessage::Status { id: *id })?.request.ok_or_else(missing_request)?;
            out.request(&req);
            Ok(exit_code_for(&req))
        }
        Command::Wait { id, timeout } => {
            let deadline = timeout.map(|s| Instant::now() + Duration::from_secs(s));
            let mut announced = false;
            loop {
                let req = call(socket, &ClientMessage::Status { id: *id })?.request.ok_or_else(missing_request)?;
                if req.status.is_terminal() {
                    out.request(&req);
                    return Ok(exit_code_for(&req));
                }
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    out.request(&req);
                    return Ok(exit::STILL_PENDING);
                }
                if !announced && !out.json {
                    eprintln!("Waiting for request #{} ({})...", req.id, req.status.as_str());
                    announced = true;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        Command::Cancel { id } => {
            let req = call(socket, &ClientMessage::Cancel { id: *id })?.request.ok_or_else(missing_request)?;
            out.request(&req);
            Ok(0)
        }
        Command::List { all } => {
            let resp = call(socket, &ClientMessage::List { all: *all })?;
            out.list(&resp.requests.unwrap_or_default(), resp.dashboard_url.as_deref());
            Ok(0)
        }
    }
}

fn missing_request() -> CliError {
    CliError::new(exit::ERROR, "protocol", "backend response did not include a request")
}

fn exit_code_for(req: &RequestView) -> u8 {
    match req.status {
        Status::Completed => match req.result.as_ref().and_then(|r| r.exit_code) {
            Some(code) => code.clamp(0, 255) as u8,
            None => exit::FAILED, // killed by a signal
        },
        Status::Failed | Status::Uncertain => exit::FAILED,
        Status::Denied | Status::Cancelled | Status::Expired => exit::NOT_RUN,
        Status::Pending | Status::Approved | Status::Executing => 0,
    }
}

fn validate_argv(argv: &[String]) -> Result<(), CliError> {
    let usage = |m: &str| CliError::new(exit::USAGE, "invalid_command", m);
    if argv.is_empty() || argv[0].is_empty() {
        return Err(usage("no command given"));
    }
    if argv.len() > limits::MAX_ARGS {
        return Err(usage("too many arguments"));
    }
    if argv.iter().any(|a| a.len() > limits::MAX_ARG_BYTES) || argv.iter().map(String::len).sum::<usize>() > limits::MAX_TOTAL_ARG_BYTES {
        return Err(usage("command line too long"));
    }
    if argv[0] == "sudo" {
        return Err(usage("submit the command without the leading `sudo`"));
    }
    Ok(())
}

fn current_user() -> (String, u32) {
    let uid = unsafe { libc::getuid() };
    // SAFETY: getpwuid returns a pointer into static storage or null; we copy
    // the name out immediately and never hold the pointer.
    let name = unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() || (*pw).pw_name.is_null() {
            None
        } else {
            Some(CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned())
        }
    };
    (name.unwrap_or_else(|| uid.to_string()), uid)
}

fn call(socket: &str, msg: &ClientMessage) -> Result<ServerMessage, CliError> {
    let stream = UnixStream::connect(socket).map_err(|e| {
        CliError::new(
            exit::UNAVAILABLE,
            "unavailable",
            format!("cannot reach the sudo-request backend at {socket}: {e}"),
        )
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let io_err = |e: std::io::Error| CliError::new(exit::UNAVAILABLE, "io", format!("backend connection failed: {e}"));

    let mut line = serde_json::to_string(msg).expect("serialisable");
    line.push('\n');
    (&stream).write_all(line.as_bytes()).map_err(io_err)?;

    let mut reader = BufReader::new(&stream).take(limits::MAX_LINE_BYTES as u64 * 8);
    let mut buf = String::new();
    reader.read_line(&mut buf).map_err(io_err)?;
    if buf.is_empty() {
        return Err(CliError::new(exit::UNAVAILABLE, "io", "backend closed the connection without replying"));
    }
    let resp: ServerMessage = serde_json::from_str(&buf)
        .map_err(|e| CliError::new(exit::ERROR, "protocol", format!("invalid backend response: {e}")))?;
    if !resp.ok {
        let e = resp.error.unwrap_or(sudo_request_protocol::broker::ErrorBody {
            code: "unknown".into(),
            message: "backend reported an error".into(),
        });
        let exit_code = if e.code == "invalid_command" { exit::USAGE } else { exit::ERROR };
        return Err(CliError { exit_code, code: e.code, message: e.message });
    }
    Ok(resp)
}

struct Output {
    json: bool,
}

impl Output {
    fn emit_json(&self, value: serde_json::Value) {
        println!("{}", serde_json::to_string(&value).expect("serialisable"));
    }

    fn error(&self, err: &CliError) {
        if self.json {
            self.emit_json(serde_json::json!({ "ok": false, "error": { "code": err.code, "message": err.message } }));
        } else {
            eprintln!("sudo-request: {}", err.message);
        }
    }

    fn submitted(&self, req: &RequestView, dashboard: Option<&str>) {
        if self.json {
            self.emit_json(serde_json::json!({ "ok": true, "request": req, "dashboardUrl": dashboard }));
            return;
        }
        println!("Request #{} queued.", req.id);
        println!("Command: {}", shell_join(&req.argv));
        if req.executable != req.argv[0] {
            println!("Executable: {}", req.executable);
        }
        println!("Status: {}", req.status.as_str());
        if let Some(url) = dashboard {
            println!("Approval dashboard: {url}");
        }
        for w in &req.warnings {
            println!("Warning: {w}");
        }
        println!("Nothing runs until a human approves it. Check with: sudo-request wait {}", req.id);
    }

    fn request(&self, req: &RequestView) {
        if self.json {
            self.emit_json(serde_json::json!({ "ok": true, "request": req }));
            return;
        }
        // Status lines go to stderr so stdout carries only the command's output.
        eprintln!("Request #{}: {}", req.id, describe_status(req));
        if let Some(reason) = &req.status_reason {
            eprintln!("Reason: {reason}");
        }
        if let Some(err) = &req.last_error {
            if !req.status.is_terminal() {
                eprintln!("Last approval attempt failed: {err}");
            }
        }
        if let Some(r) = &req.result {
            if let Some(e) = &r.spawn_error {
                eprintln!("Could not start: {e}");
            }
            print!("{}", r.stdout);
            std::io::stdout().flush().ok();
            eprint!("{}", r.stderr);
            if r.stdout_truncated {
                eprintln!("[stdout truncated]");
            }
            if r.stderr_truncated {
                eprintln!("[stderr truncated]");
            }
        }
    }

    fn list(&self, reqs: &[RequestView], dashboard: Option<&str>) {
        if self.json {
            self.emit_json(serde_json::json!({ "ok": true, "requests": reqs, "dashboardUrl": dashboard }));
            return;
        }
        if reqs.is_empty() {
            println!("No requests.");
        }
        for r in reqs {
            println!("#{:<5} {:<10} {}", r.id, r.status.as_str(), shell_join(&r.argv));
        }
        if let Some(url) = dashboard {
            println!("Dashboard: {url}");
        }
    }
}

fn describe_status(req: &RequestView) -> String {
    match (req.status, &req.result) {
        (Status::Completed, Some(r)) => match (r.exit_code, r.signal) {
            (Some(c), _) if r.timed_out => format!("completed (timed out, exit code {c})"),
            (Some(c), _) => format!("completed (exit code {c})"),
            (None, Some(s)) => format!("completed (killed by signal {s}{})", if r.timed_out { ", timed out" } else { "" }),
            _ => "completed".into(),
        },
        (Status::Uncertain, _) => "uncertain (the executor stopped mid-run; it will not be retried)".into(),
        (s, _) => s.as_str().into(),
    }
}

fn shell_join(argv: &[String]) -> String {
    argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ")
}

fn shell_quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./=:,+@%".contains(&b));
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(shell_join(&["ufw".into(), "allow".into(), "22/tcp".into()]), "ufw allow 22/tcp");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn rejects_leading_sudo() {
        assert!(validate_argv(&["sudo".into(), "ls".into()]).is_err());
        assert!(validate_argv(&["ls".into()]).is_ok());
    }

    #[test]
    fn shorthand_parses_as_submit() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for input in [
            &["sudo-request", "--", "ufw", "allow", "22/tcp"][..],
            &["sudo-request", "--json", "--socket", "/x", "--", "ufw", "allow", "22/tcp"][..],
            &["sudo-request", "submit", "--", "ufw", "allow", "22/tcp"][..],
        ] {
            let cli = Cli::parse_from(expand_shorthand(args(input)));
            assert!(matches!(cli.command, Command::Submit { argv } if argv == ["ufw", "allow", "22/tcp"]));
        }
        // A command named like a subcommand is still just an argument after `--`.
        let cli = Cli::parse_from(expand_shorthand(args(&["sudo-request", "--", "status", "1"])));
        assert!(matches!(cli.command, Command::Submit { argv } if argv == ["status", "1"]));
    }
}
