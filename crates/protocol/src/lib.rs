//! Wire types shared by the `sudo-request` CLI and the root executor.
//!
//! Both sockets speak newline-delimited JSON: the client writes one request
//! line and reads one (CLI) or more (executor `execute`) response lines.
//! The TypeScript backend implements the other side of both protocols; keep
//! `server/src/protocol.ts` in sync with this file.

use serde::{Deserialize, Serialize};

pub const DEFAULT_CLI_SOCKET: &str = "/run/sudo-request/cli.sock";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/sudo-request/config.toml";

/// Upper bounds enforced by both the backend and the executor.
pub mod limits {
    pub const MAX_ARGS: usize = 256;
    pub const MAX_ARG_BYTES: usize = 4096;
    pub const MAX_TOTAL_ARG_BYTES: usize = 32 * 1024;
    pub const MAX_PATH_BYTES: usize = 4096;
    pub const MAX_LINE_BYTES: usize = 1024 * 1024;
}

pub mod broker {
    //! CLI <-> backend (`cli.sock`).
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "op", rename_all = "camelCase")]
    pub enum ClientMessage {
        Submit {
            argv: Vec<String>,
            cwd: String,
            user: String,
            uid: u32,
        },
        Status {
            id: i64,
        },
        List {
            #[serde(default)]
            all: bool,
        },
        Cancel {
            id: i64,
        },
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ServerMessage {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub request: Option<RequestView>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub requests: Option<Vec<RequestView>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dashboard_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<ErrorBody>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ErrorBody {
        pub code: String,
        pub message: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub enum Status {
        Pending,
        Approved,
        Executing,
        Completed,
        Failed,
        Uncertain,
        Denied,
        Cancelled,
        Expired,
    }

    impl Status {
        pub fn is_terminal(self) -> bool {
            matches!(
                self,
                Status::Completed
                    | Status::Failed
                    | Status::Uncertain
                    | Status::Denied
                    | Status::Cancelled
                    | Status::Expired
            )
        }

        pub fn as_str(self) -> &'static str {
            match self {
                Status::Pending => "pending",
                Status::Approved => "approved",
                Status::Executing => "executing",
                Status::Completed => "completed",
                Status::Failed => "failed",
                Status::Uncertain => "uncertain",
                Status::Denied => "denied",
                Status::Cancelled => "cancelled",
                Status::Expired => "expired",
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct RequestView {
        pub id: i64,
        pub status: Status,
        pub user: String,
        pub host: String,
        pub cwd: String,
        pub executable: String,
        pub argv: Vec<String>,
        pub created_at: i64,
        pub expires_at: i64,
        #[serde(default)]
        pub status_reason: Option<String>,
        #[serde(default)]
        pub last_error: Option<String>,
        #[serde(default)]
        pub warnings: Vec<String>,
        #[serde(default)]
        pub result: Option<super::executor::ExecResult>,
    }
}

pub mod executor {
    //! Backend <-> root executor (`executor.sock`).
    use super::*;

    /// The exact bytes the human approves. The backend serialises this once at
    /// submission time and stores the string; the WebAuthn challenge is
    /// `SHA-256(payload string)`, and the executor runs what it parses from
    /// that same string. No re-canonicalisation happens anywhere.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct ApprovalPayload {
        pub v: u32,
        pub id: i64,
        pub nonce: String,
        pub host: String,
        pub user: String,
        pub uid: u32,
        pub cwd: String,
        pub executable: String,
        pub argv: Vec<String>,
        pub created_at: i64,
        pub expires_at: i64,
    }

    pub const PAYLOAD_VERSION: u32 = 1;

    /// Fields are base64url (padding optional), as produced by
    /// `@simplewebauthn/browser`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Assertion {
        pub credential_id: String,
        pub client_data_json: String,
        pub authenticator_data: String,
        pub signature: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "op", rename_all = "camelCase")]
    pub enum ExecutorRequest {
        Execute {
            payload: String,
            assertion: Assertion,
        },
        Lookup {
            nonce: String,
        },
        Enroll {
            label: String,
            #[serde(rename = "credentialId")]
            credential_id: String,
            #[serde(rename = "clientDataJson")]
            client_data_json: String,
            #[serde(rename = "attestationObject")]
            attestation_object: String,
        },
        Info,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "event", rename_all = "camelCase")]
    pub enum ExecuteEvent {
        /// Verification failed or the executor refused; nothing was started.
        Rejected { code: String, message: String },
        /// The approval was claimed and the process was spawned.
        #[serde(rename_all = "camelCase")]
        Started { started_at: i64 },
        /// Terminal event. `result.spawn_error` is set if the process never ran.
        Finished { result: ExecResult },
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ExecResult {
        pub started_at: i64,
        pub finished_at: i64,
        pub exit_code: Option<i32>,
        pub signal: Option<i32>,
        pub timed_out: bool,
        pub stdout: String,
        pub stderr: String,
        pub stdout_truncated: bool,
        pub stderr_truncated: bool,
        pub spawn_error: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub enum LedgerState {
        /// No claim exists: this approval was never accepted.
        Unknown,
        Running,
        Finished,
        /// Claimed, but the executor stopped before recording a result.
        Interrupted,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct LookupResponse {
        pub state: LedgerState,
        #[serde(default)]
        pub result: Option<ExecResult>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SimpleResponse {
        pub ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credentials: Option<usize>,
    }
}

#[cfg(test)]
mod tests {
    use super::executor::*;

    #[test]
    fn payload_rejects_unknown_fields() {
        let raw = r#"{"v":1,"id":1,"nonce":"aa","host":"h","user":"u","uid":1,"cwd":"/","executable":"/bin/true","argv":["true"],"createdAt":1,"expiresAt":2,"approved":true}"#;
        assert!(serde_json::from_str::<ApprovalPayload>(raw).is_err());
    }

    #[test]
    fn execute_request_round_trips() {
        let raw = r#"{"op":"execute","payload":"{}","assertion":{"credentialId":"a","clientDataJson":"b","authenticatorData":"c","signature":"d"}}"#;
        let req: ExecutorRequest = serde_json::from_str(raw).unwrap();
        assert!(matches!(req, ExecutorRequest::Execute { .. }));
    }
}
