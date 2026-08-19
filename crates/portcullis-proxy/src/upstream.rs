//! Talking to one upstream MCP server.
//!
//! # Why this is generic over the streams
//!
//! In production an upstream is a child process and the streams are its stdin
//! and stdout. [`Upstream::connect`] does not know that: it takes any reader
//! and writer, and [`Upstream::spawn`] is the thin layer that produces them
//! from a [`Child`]. That split is what lets the entire request and response
//! path be tested over an in-memory duplex, with no process, no binary to
//! build, and no platform-specific shell script in the test suite.
//!
//! # Concurrency shape
//!
//! One task owns the read half and one owns the write half, and the rest of the
//! program talks to them through channels. Requests get an id from an atomic
//! counter and register a oneshot sender in a pending table; the reader task
//! matches responses back by id.
//!
//! The alternative, locking a mutex over the stream for the duration of a call,
//! serialises every request behind the slowest one. A gateway fronting several
//! servers cannot afford that: one upstream running a thirty-second query would
//! stall calls to the others.
//!
//! # Failure is always delivered
//!
//! Every path that ends the reader task drains the pending table and wakes each
//! waiter. Without that, an upstream crashing mid-request leaves the caller
//! awaiting a oneshot whose sender was dropped silently, and the symptom is a
//! hung agent rather than an error. `request` therefore always terminates:
//! with a response, with a timeout, or with [`UpstreamError::Closed`].

use portcullis_core::mcp::{
    ClientCapabilities, Implementation, InitializeParams, InitializeResult,
};
use portcullis_core::{
    ErrorObject, Message, MessageReader, MessageWriter, Notification, Request, RequestId, Response,
    ResponsePayload, TransportError, method,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc, oneshot};

/// How long to wait for a response before giving up on it.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for the handshake specifically.
///
/// Shorter than a normal request, because a server that has not answered
/// `initialize` in ten seconds is misconfigured rather than busy, and failing
/// fast at startup is much easier to diagnose than a stall later.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How to start an upstream server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Name used to namespace this server's tools and to scope policy rules.
    pub name: String,
    /// Executable to run.
    pub command: String,
    /// Arguments to pass.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables to set.
    ///
    /// The child inherits the gateway's environment and these are layered on
    /// top. Trimming the inherited environment is left to the operator, since
    /// most MCP servers need `PATH` and `HOME` to function at all and silently
    /// clearing them produces failures that look like bugs in the server.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Working directory for the child.
    #[serde(default)]
    pub cwd: Option<PathBuf>,
}

/// Something that went wrong talking to an upstream.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// The child process could not be started.
    #[error("cannot start upstream {name:?} ({command}): {source}")]
    Spawn {
        /// The upstream's configured name.
        name: String,
        /// The command that failed to start.
        command: String,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// The transport failed.
    #[error("upstream {name:?} transport failure: {source}")]
    Transport {
        /// The upstream's configured name.
        name: String,
        /// The underlying failure.
        #[source]
        source: Box<TransportError>,
    },

    /// The server answered with a JSON-RPC error.
    #[error("upstream {name:?} rejected {method}: {source}")]
    Rejected {
        /// The upstream's configured name.
        name: String,
        /// The method that was rejected.
        method: String,
        /// The error the server returned.
        #[source]
        source: Box<ErrorObject>,
    },

    /// The response did not match the expected shape.
    #[error("upstream {name:?} returned an unusable {method} result: {detail}")]
    Malformed {
        /// The upstream's configured name.
        name: String,
        /// The method whose result was unusable.
        method: String,
        /// What was wrong with it.
        detail: String,
    },

    /// The server did not answer in time.
    #[error("upstream {name:?} did not answer {method} within {timeout:?}")]
    Timeout {
        /// The upstream's configured name.
        name: String,
        /// The method that timed out.
        method: String,
        /// How long was allowed.
        timeout: Duration,
    },

    /// The connection ended.
    #[error("upstream {name:?} connection closed")]
    Closed {
        /// The upstream's configured name.
        name: String,
    },
}

impl UpstreamError {
    /// The upstream this failure concerns.
    pub fn upstream(&self) -> &str {
        match self {
            Self::Spawn { name, .. }
            | Self::Transport { name, .. }
            | Self::Rejected { name, .. }
            | Self::Malformed { name, .. }
            | Self::Timeout { name, .. }
            | Self::Closed { name } => name,
        }
    }
}

type Pending = Arc<Mutex<HashMap<RequestId, oneshot::Sender<Response>>>>;

/// A live connection to one upstream MCP server.
#[derive(Debug)]
pub struct Upstream {
    name: String,
    outbound: mpsc::Sender<Message>,
    pending: Pending,
    next_id: AtomicI64,
    /// Set once the reader task has ended.
    ///
    /// Without this, a request issued *after* the upstream died would register
    /// in a pending table nobody is draining any more and block until its own
    /// timeout. The flag turns that into an immediate Closed. Ordering with the
    /// pending table is what makes it race-free: the reader sets the flag
    /// before clearing, and `request` checks it after inserting, so whichever
    /// happens first, the caller is woken exactly once.
    closed: Arc<AtomicBool>,
    handshake: InitializeResult,
    request_timeout: Duration,
    child: Mutex<Option<Child>>,
}

impl Upstream {
    /// Starts a server as a child process and completes the handshake.
    pub async fn spawn(
        config: &UpstreamConfig,
        client_info: Implementation,
    ) -> Result<Self, UpstreamError> {
        let mut command = Command::new(&config.command);
        command
            .args(&config.args)
            .envs(&config.env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            // Without this the child outlives a crashed gateway and keeps
            // holding whatever it had open.
            .kill_on_drop(true);

        if let Some(cwd) = &config.cwd {
            command.current_dir(cwd);
        }

        let mut child = command.spawn().map_err(|source| UpstreamError::Spawn {
            name: config.name.clone(),
            command: config.command.clone(),
            source,
        })?;

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");

        // Servers log to stderr, sometimes chattily. An undrained pipe fills
        // its buffer and blocks the child on its next write, which presents as
        // a mysteriously hung server, so this is drained even when discarded.
        if let Some(stderr) = child.stderr.take() {
            let name = config.name.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, BufReader};
                let mut lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(upstream = %name, "{line}");
                }
            });
        }

        let mut upstream = Self::connect(&config.name, stdout, stdin, client_info).await?;
        *upstream.child.get_mut() = Some(child);
        Ok(upstream)
    }

    /// Completes the handshake over an already-established pair of streams.
    ///
    /// Exists separately from [`Upstream::spawn`] so the protocol path can be
    /// tested without a process.
    pub async fn connect<R, W>(
        name: &str,
        reader: R,
        writer: W,
        client_info: Implementation,
    ) -> Result<Self, UpstreamError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let (outbound, mut outbox) = mpsc::channel::<Message>(64);

        let writer_name = name.to_owned();
        tokio::spawn(async move {
            let mut writer = MessageWriter::new(writer);
            while let Some(message) = outbox.recv().await {
                if let Err(error) = writer.send(&message).await {
                    tracing::warn!(upstream = %writer_name, %error, "upstream write failed");
                    break;
                }
            }
        });

        let closed = Arc::new(AtomicBool::new(false));
        let reader_pending = Arc::clone(&pending);
        let reader_closed = Arc::clone(&closed);
        let reader_name = name.to_owned();
        tokio::spawn(async move {
            let mut reader = MessageReader::new(reader);
            loop {
                match reader.next_message().await {
                    Ok(Some(Message::Response(response))) => {
                        let waiter = reader_pending.lock().await.remove(&response.id);
                        if let Some(waiter) = waiter {
                            // The receiver is gone if the caller timed out
                            // first, which is normal and not worth logging.
                            let _ = waiter.send(response);
                        } else {
                            tracing::debug!(
                                upstream = %reader_name,
                                id = %response.id,
                                "response for an unknown request id"
                            );
                        }
                    }
                    // Server-initiated traffic is not answered here. Routing it
                    // back to the client is the session layer's job.
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(error) => {
                        tracing::warn!(upstream = %reader_name, %error, "upstream read failed");
                        if matches!(error, TransportError::Io(_)) {
                            break;
                        }
                    }
                }
            }

            // Whatever ended the loop, everyone still waiting has to be woken,
            // and everyone arriving later has to be turned away. The flag is
            // set first so a request that registers after this point still sees
            // it. Dropping the senders resolves each pending receiver with an
            // error rather than leaving the caller parked forever.
            reader_closed.store(true, Ordering::SeqCst);
            reader_pending.lock().await.clear();
        });

        let upstream = Self {
            name: name.to_owned(),
            outbound,
            pending,
            next_id: AtomicI64::new(1),
            closed,
            handshake: InitializeResult {
                protocol_version: portcullis_core::PREFERRED_PROTOCOL_VERSION.to_owned(),
                capabilities: portcullis_core::mcp::ServerCapabilities::default(),
                server_info: Implementation::new(name, "unknown"),
                instructions: None,
                extra: serde_json::Map::new(),
            },
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            child: Mutex::new(None),
        };

        let handshake = upstream.handshake(client_info).await?;
        Ok(Self {
            handshake,
            ..upstream
        })
    }

    async fn handshake(
        &self,
        client_info: Implementation,
    ) -> Result<InitializeResult, UpstreamError> {
        let params = InitializeParams {
            protocol_version: portcullis_core::PREFERRED_PROTOCOL_VERSION.to_owned(),
            capabilities: ClientCapabilities::default(),
            client_info,
            extra: serde_json::Map::new(),
        };

        let result = self
            .request_with_timeout(
                method::INITIALIZE,
                Some(serde_json::to_value(params).expect("initialize params serialise")),
                HANDSHAKE_TIMEOUT,
            )
            .await?;

        let handshake: InitializeResult =
            serde_json::from_value(result).map_err(|error| UpstreamError::Malformed {
                name: self.name.clone(),
                method: method::INITIALIZE.to_owned(),
                detail: error.to_string(),
            })?;

        self.notify(method::INITIALIZED, None).await?;
        Ok(handshake)
    }

    /// The upstream's configured name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What the server reported during the handshake.
    pub fn handshake_result(&self) -> &InitializeResult {
        &self.handshake
    }

    /// Whether the server advertised any tools.
    pub fn advertises_tools(&self) -> bool {
        self.handshake.capabilities.tools.is_some()
    }

    /// Sends a request and waits for its response.
    pub async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, UpstreamError> {
        self.request_with_timeout(method, params, self.request_timeout)
            .await
    }

    async fn request_with_timeout(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, UpstreamError> {
        let id = RequestId::Number(self.next_id.fetch_add(1, Ordering::Relaxed));
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(id.clone(), sender);

        let sent = self
            .outbound
            .send(Message::Request(Request::new(id.clone(), method, params)))
            .await;

        // The closed check has to come after the insert above, not before it.
        // Checking first leaves a window where the reader task ends between the
        // check and the insert, so the entry lands in a table nobody will drain
        // again and the caller waits out its whole timeout. Inserting first and
        // then checking means one of the two always fires: either we observe
        // the flag, or the reader's clear() drops our sender and wakes us.
        if sent.is_err() || self.closed.load(Ordering::SeqCst) {
            self.pending.lock().await.remove(&id);
            return Err(UpstreamError::Closed {
                name: self.name.clone(),
            });
        }

        let response = match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(response)) => response,
            // The sender was dropped, which means the reader task ended.
            Ok(Err(_)) => {
                return Err(UpstreamError::Closed {
                    name: self.name.clone(),
                });
            }
            Err(_) => {
                // Stop tracking a request nobody is waiting for, or the pending
                // table grows without bound on a slow upstream.
                self.pending.lock().await.remove(&id);
                return Err(UpstreamError::Timeout {
                    name: self.name.clone(),
                    method: method.to_owned(),
                    timeout,
                });
            }
        };

        match response.payload {
            ResponsePayload::Result(value) => Ok(value),
            ResponsePayload::Error(error) => Err(UpstreamError::Rejected {
                name: self.name.clone(),
                method: method.to_owned(),
                source: Box::new(error),
            }),
        }
    }

    /// Sends a notification, which expects no response.
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), UpstreamError> {
        self.outbound
            .send(Message::Notification(Notification::new(method, params)))
            .await
            .map_err(|_| UpstreamError::Closed {
                name: self.name.clone(),
            })
    }

    /// Whether the connection has ended.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Closes the connection and reaps the child process if there is one.
    pub async fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.pending.lock().await.clear();

        if let Some(mut child) = self.child.lock().await.take() {
            // MCP has no in-band shutdown handshake over stdio: closing stdin
            // is the signal. Give the server a moment to exit on its own before
            // killing it, so it can flush whatever it was writing.
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            let _ = child.start_kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::Response as RpcResponse;
    use serde_json::json;
    use tokio::io::duplex;

    /// A scripted server: answers `initialize`, then whatever the handler says.
    fn serve<F>(handler: F) -> (tokio::io::DuplexStream, tokio::io::DuplexStream)
    where
        F: Fn(&Request) -> Option<RpcResponse> + Send + 'static,
    {
        let (client_side, server_side) = duplex(8192);
        let (server_read, server_write) = tokio::io::split(server_side);

        tokio::spawn(async move {
            let mut reader = MessageReader::new(server_read);
            let mut writer = MessageWriter::new(server_write);

            while let Ok(Some(message)) = reader.next_message().await {
                let Message::Request(request) = message else {
                    continue;
                };

                let response = if request.method == method::INITIALIZE {
                    Some(RpcResponse::success(
                        request.id.clone(),
                        json!({
                            "protocolVersion": "2025-06-18",
                            "capabilities": { "tools": { "listChanged": false } },
                            "serverInfo": { "name": "scripted", "version": "1.0" }
                        }),
                    ))
                } else {
                    handler(&request)
                };

                if let Some(response) = response {
                    let _ = writer.send(&Message::Response(response)).await;
                }
            }
        });

        let (client_read, client_write) = tokio::io::split(client_side);
        // Re-join the halves for the caller's convenience.
        (client_read.unsplit(client_write), duplex(1).0)
    }

    async fn connect<F>(handler: F) -> Result<Upstream, UpstreamError>
    where
        F: Fn(&Request) -> Option<RpcResponse> + Send + 'static,
    {
        let (stream, _) = serve(handler);
        let (reader, writer) = tokio::io::split(stream);
        Upstream::connect(
            "test",
            reader,
            writer,
            Implementation::new("portcullis", "0.1.0"),
        )
        .await
    }

    #[tokio::test]
    async fn completes_the_handshake_and_records_what_the_server_said() {
        let upstream = connect(|_| None).await.expect("handshake succeeds");

        assert_eq!(upstream.name(), "test");
        assert_eq!(upstream.handshake_result().server_info.name, "scripted");
        assert_eq!(upstream.handshake_result().protocol_version, "2025-06-18");
        assert!(upstream.advertises_tools());
    }

    #[tokio::test]
    async fn round_trips_a_request() {
        let upstream = connect(|request| {
            Some(RpcResponse::success(
                request.id.clone(),
                json!({ "tools": [] }),
            ))
        })
        .await
        .expect("connects");

        let result = upstream
            .request(method::TOOLS_LIST, None)
            .await
            .expect("succeeds");
        assert_eq!(result, json!({ "tools": [] }));
    }

    #[tokio::test]
    async fn surfaces_a_server_error_as_rejected() {
        let upstream = connect(|request| {
            Some(RpcResponse::error(
                request.id.clone(),
                ErrorObject::new(portcullis_core::error_code::METHOD_NOT_FOUND, "nope"),
            ))
        })
        .await
        .expect("connects");

        let error = upstream.request("tools/call", None).await.unwrap_err();
        let UpstreamError::Rejected { source, .. } = &error else {
            panic!("{error}")
        };
        assert_eq!(source.code, portcullis_core::error_code::METHOD_NOT_FOUND);
        assert_eq!(error.upstream(), "test");
    }

    #[tokio::test]
    async fn concurrent_requests_are_matched_back_by_id() {
        // The property that justifies the pending table over a stream mutex:
        // a slow call must not hold up a fast one.
        let upstream = Arc::new(
            connect(|request| {
                let echo = request.params.clone().unwrap_or(Value::Null);
                Some(RpcResponse::success(request.id.clone(), echo))
            })
            .await
            .expect("connects"),
        );

        let mut handles = Vec::new();
        for n in 0..16 {
            let upstream = Arc::clone(&upstream);
            handles.push(tokio::spawn(async move {
                let result = upstream
                    .request("echo", Some(json!({ "n": n })))
                    .await
                    .unwrap();
                assert_eq!(
                    result,
                    json!({ "n": n }),
                    "a response was matched to the wrong request"
                );
            }));
        }
        for handle in handles {
            handle.await.expect("no task panicked");
        }
    }

    #[tokio::test]
    async fn a_request_the_server_never_answers_times_out() {
        let mut upstream = connect(|_| None).await.expect("connects");
        upstream.request_timeout = Duration::from_millis(150);

        let error = upstream.request("tools/list", None).await.unwrap_err();
        assert!(matches!(error, UpstreamError::Timeout { .. }), "{error}");

        // The abandoned request must not stay in the pending table.
        assert!(
            upstream.pending.lock().await.is_empty(),
            "timed-out request leaked"
        );
    }

    #[tokio::test]
    async fn a_closed_connection_wakes_waiters_instead_of_hanging() {
        // The failure this module exists to avoid: an upstream dying mid-call
        // presenting as a hung agent rather than an error.
        let (client, server) = duplex(8192);

        tokio::spawn(async move {
            let (read, write) = tokio::io::split(server);
            let mut reader = MessageReader::new(read);
            let mut writer = MessageWriter::new(write);

            if let Ok(Some(Message::Request(request))) = reader.next_message().await {
                let _ = writer
                    .send(&Message::Response(RpcResponse::success(
                        request.id,
                        json!({
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "serverInfo": { "name": "dying", "version": "1.0" }
                        }),
                    )))
                    .await;
            }
            // Drop everything: the upstream has crashed.
        });

        let (reader, writer) = tokio::io::split(client);
        let upstream = Upstream::connect(
            "dying",
            reader,
            writer,
            Implementation::new("portcullis", "0.1.0"),
        )
        .await
        .expect("handshake completes before the server dies");

        let error = tokio::time::timeout(
            Duration::from_secs(5),
            upstream.request(method::TOOLS_LIST, None),
        )
        .await
        .expect("must not hang")
        .unwrap_err();

        assert!(matches!(error, UpstreamError::Closed { .. }), "{error}");
    }

    #[tokio::test]
    async fn a_missing_executable_names_the_command() {
        let config = UpstreamConfig {
            name: "ghost".to_owned(),
            command: "portcullis-no-such-binary".to_owned(),
            args: Vec::new(),
            env: HashMap::new(),
            cwd: None,
        };

        let error = Upstream::spawn(&config, Implementation::new("portcullis", "0.1.0"))
            .await
            .unwrap_err();

        assert!(matches!(error, UpstreamError::Spawn { .. }), "{error}");
        assert!(
            error.to_string().contains("portcullis-no-such-binary"),
            "{error}"
        );
        assert_eq!(error.upstream(), "ghost");
    }
}
