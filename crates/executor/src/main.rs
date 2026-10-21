//! `sudo-request-executor`: the only component that runs as root.
//!
//! It accepts connections solely from the backend's uid, and runs a command
//! only when presented with a WebAuthn assertion, from an enrolled passkey,
//! whose challenge is the SHA-256 of the exact request being executed.

mod config;
mod run;
mod server;
mod store;
mod webauthn;

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use sudo_request_protocol::DEFAULT_CONFIG_PATH;

use store::{now_ms, EnrollmentToken, Store};

#[derive(Parser)]
#[command(name = "sudo-request-executor", version, about = "Privileged executor for sudo-request")]
struct Cli {
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the executor service.
    Serve,
    /// Open a one-time enrollment window and print the code to enter on the dashboard.
    Enroll {
        #[arg(long, default_value_t = 15)]
        minutes: i64,
    },
    /// Manage enrolled passkeys.
    Passkeys {
        #[command(subcommand)]
        action: PasskeyAction,
    },
}

#[derive(Subcommand)]
enum PasskeyAction {
    List,
    Remove { id: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sudo-request-executor: {e}");
            ExitCode::FAILURE
        }
    }
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn run(cli: Cli) -> Result<(), String> {
    let cfg = config::load(&cli.config)?;
    config::prepare_state_dir(&cfg.state_dir)?;
    let store = Store::new(cfg.state_dir.clone());

    match cli.command {
        Command::Serve => {
            if !config::is_root() {
                eprintln!("warning: not running as root; commands will run as the current user (development mode)");
            }
            let ctx = Arc::new(server::Ctx {
                rp: webauthn::RelyingParty { rp_id: cfg.rp_id.clone(), origin: cfg.origin.clone() },
                store,
                hostname: hostname(),
                cfg,
            });
            server::serve(ctx)
        }
        Command::Enroll { minutes } => {
            let token = new_token();
            let challenge = Sha256::digest(format!("sudo-request-enroll:{}", normalise_token(&token)).as_bytes());
            store
                .put_enrollment(&EnrollmentToken {
                    challenge: webauthn::b64encode(&challenge),
                    expires_at: now_ms() + minutes.clamp(1, 60) * 60_000,
                })
                .map_err(|e| format!("cannot write enrollment token: {e}"))?;
            println!("Enrollment code (valid {minutes} minutes, single use):\n");
            println!("    {token}\n");
            println!("On your phone, open {}/#/enroll, enter the code, and create the passkey.", cfg.origin);
            println!("Do not paste this code into an agent session.");
            Ok(())
        }
        Command::Passkeys { action: PasskeyAction::List } => {
            let creds = store.credentials().map_err(|e| e.to_string())?;
            if creds.is_empty() {
                println!("No passkeys enrolled.");
            }
            for c in creds {
                println!("{}  {:<24} enrolled {}", c.id, c.label, c.created_at);
            }
            Ok(())
        }
        Command::Passkeys { action: PasskeyAction::Remove { id } } => {
            let removed = store.update_credentials(|creds| {
                let before = creds.len();
                creds.retain(|c| c.id != id);
                Ok(before - creds.len())
            })?;
            if removed == 0 {
                return Err(format!("no passkey with id {id}"));
            }
            println!("Removed.");
            Ok(())
        }
    }
}

const TOKEN_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// 16 characters from a 31-symbol alphabet (~79 bits), shown in groups of four.
fn new_token() -> String {
    let mut bytes = [0u8; 64];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).expect("urandom");
    let chars: Vec<char> = bytes
        .iter()
        .filter(|&&b| (b as usize) < TOKEN_ALPHABET.len() * 8) // rejection sampling, 248 = 31*8
        .map(|&b| TOKEN_ALPHABET[b as usize % TOKEN_ALPHABET.len()] as char)
        .take(16)
        .collect();
    assert_eq!(chars.len(), 16, "not enough random bytes");
    chars.chunks(4).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join("-")
}

/// Must match `normaliseToken` in the web client.
fn normalise_token(token: &str) -> String {
    token.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_uppercase()).collect()
}
