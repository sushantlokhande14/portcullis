//! Newline-delimited JSON transport.
//!
//! MCP's stdio transport frames messages by newline: one JSON object per line,
//! with embedded newlines forbidden inside a message. That is simple enough to
//! implement with [`tokio::io::AsyncBufReadExt::read_line`] in about five lines,
//! and this module deliberately does not.
//!
//! # Why the framing is hand-rolled
//!
//! `read_line` grows its buffer until it finds a newline. A gateway reads from
//! processes it did not write, on behalf of a model that can be talked into
//! calling them, so "grows until the peer stops sending" is a memory exhaustion
//! bug with extra steps. One upstream server returning a gigabyte on a single
//! line should be a failed request, not a dead gateway.
//!
//! [`MessageReader`] therefore enforces [`DEFAULT_MAX_LINE_BYTES`] while it
//! reads, and, crucially, *resynchronises* afterwards by discarding the rest of
//! the oversized line. Without that the next read would start mid-message and
//! every subsequent message on the connection would fail to parse, turning one
//! bad response into a permanently broken session.
//!
//! # Errors are per-message, not per-connection
//!
//! A line that is not valid JSON yields an `Err` from [`MessageReader::next_message`]
//! and leaves the reader positioned at the start of the next line. The caller
//! decides whether one malformed message is worth tearing the session down.
//! That matters for a proxy, which would otherwise let a single misbehaving
//! upstream take out a session that other upstreams are still serving.

use crate::Message;
use std::fmt;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Maximum bytes accepted on a single line before the message is rejected.
///
/// Sized to comfortably hold a large tool result (a file listing, a page of
/// query rows, a base64 screenshot) while staying far below the point where a
/// hostile or broken upstream can exhaust memory.
pub const DEFAULT_MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// A transport-level failure.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The underlying stream failed.
    #[error("transport io failure: {0}")]
    Io(#[from] std::io::Error),

    /// A line was received but was not a valid JSON-RPC message.
    ///
    /// Carries a bounded excerpt of the offending line. The excerpt is capped
    /// because this string reaches logs, and an unbounded one would let an
    /// upstream write arbitrary volume into the operator's log pipeline.
    #[error("malformed message: {source} (near: {excerpt})")]
    Decode {
        /// Bounded excerpt of the line that failed to parse.
        excerpt: String,
        /// The underlying parse failure.
        #[source]
        source: serde_json::Error,
    },

    /// A line exceeded the configured limit and was discarded.
    #[error("message exceeded the {limit} byte line limit and was discarded")]
    LineTooLong {
        /// The limit that was exceeded.
        limit: usize,
    },
}

/// How much of a bad line to quote back in an error.
const EXCERPT_BYTES: usize = 200;

fn excerpt(line: &[u8]) -> String {
    let head = &line[..line.len().min(EXCERPT_BYTES)];
    let mut text = String::from_utf8_lossy(head).replace(['\n', '\r'], " ");
    if line.len() > EXCERPT_BYTES {
        text.push_str("...");
    }
    text
}

/// Reads newline-delimited JSON-RPC messages from an async stream.
#[derive(Debug)]
pub struct MessageReader<R> {
    inner: BufReader<R>,
    max_line_bytes: usize,
}

impl<R: AsyncRead + Unpin> MessageReader<R> {
    /// Wraps a stream with the default line limit.
    pub fn new(inner: R) -> Self {
        Self {
            inner: BufReader::new(inner),
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        }
    }

    /// Overrides the maximum accepted line length.
    #[must_use]
    pub fn with_max_line_bytes(mut self, max_line_bytes: usize) -> Self {
        self.max_line_bytes = max_line_bytes;
        self
    }

    /// Returns the configured line limit.
    pub fn max_line_bytes(&self) -> usize {
        self.max_line_bytes
    }

    /// Reads the next message.
    ///
    /// Returns `Ok(None)` at end of stream. A decode failure is reported as an
    /// error while leaving the reader positioned at the following line, so the
    /// caller may continue reading.
    pub async fn next_message(&mut self) -> Result<Option<Message>, TransportError> {
        loop {
            let Some(line) = self.fill_next_line().await? else {
                return Ok(None);
            };

            // Servers occasionally emit blank lines around messages. They carry
            // no content, so they are skipped rather than reported as garbage.
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }

            return match serde_json::from_slice::<Message>(&line) {
                Ok(message) => Ok(Some(message)),
                Err(source) => Err(TransportError::Decode {
                    excerpt: excerpt(&line),
                    source,
                }),
            };
        }
    }

    /// Reads bytes up to and including the next newline, enforcing the limit.
    ///
    /// On overflow the remainder of the line is drained before the error is
    /// returned, so the reader stays aligned to message boundaries.
    async fn fill_next_line(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        let mut line = Vec::new();

        loop {
            let available = self.inner.fill_buf().await?;

            if available.is_empty() {
                // End of stream. A trailing fragment with no newline is still a
                // complete message as far as the peer is concerned.
                return Ok(if line.is_empty() { None } else { Some(line) });
            }

            if let Some(index) = memchr::memchr(b'\n', available) {
                if line.len() + index > self.max_line_bytes {
                    self.inner.consume(index + 1);
                    return Err(TransportError::LineTooLong {
                        limit: self.max_line_bytes,
                    });
                }
                line.extend_from_slice(&available[..index]);
                self.inner.consume(index + 1);
                // Tolerate CRLF from servers that were written for Windows
                // pipes without normalising their output.
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }

            let consumed = available.len();
            if line.len() + consumed > self.max_line_bytes {
                self.inner.consume(consumed);
                self.discard_to_newline().await?;
                return Err(TransportError::LineTooLong {
                    limit: self.max_line_bytes,
                });
            }
            line.extend_from_slice(available);
            self.inner.consume(consumed);
        }
    }

    /// Drops bytes until the current line ends, so the next read starts at a
    /// message boundary rather than in the middle of one.
    async fn discard_to_newline(&mut self) -> Result<(), TransportError> {
        loop {
            let available = self.inner.fill_buf().await?;
            if available.is_empty() {
                return Ok(());
            }
            if let Some(index) = memchr::memchr(b'\n', available) {
                self.inner.consume(index + 1);
                return Ok(());
            }
            let consumed = available.len();
            self.inner.consume(consumed);
        }
    }

    /// Unwraps the reader, discarding any buffered bytes.
    pub fn into_inner(self) -> R {
        self.inner.into_inner()
    }
}

/// Writes newline-delimited JSON-RPC messages to an async stream.
pub struct MessageWriter<W> {
    inner: W,
    scratch: Vec<u8>,
}

impl<W> fmt::Debug for MessageWriter<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageWriter").finish_non_exhaustive()
    }
}

impl<W: AsyncWrite + Unpin> MessageWriter<W> {
    /// Wraps a stream.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            scratch: Vec::with_capacity(1024),
        }
    }

    /// Serialises and writes one message, then flushes.
    ///
    /// The message is encoded into a scratch buffer and written in a single
    /// call so that a message never reaches the peer half-written. Two tasks
    /// writing interleaved halves of two messages would produce a stream that
    /// is not recoverable by any framing.
    pub async fn send(&mut self, message: &Message) -> Result<(), TransportError> {
        self.scratch.clear();
        serde_json::to_writer(&mut self.scratch, message).map_err(|source| {
            TransportError::Decode {
                excerpt: String::new(),
                source,
            }
        })?;

        debug_assert!(
            !self.scratch.contains(&b'\n'),
            "serde_json must not emit raw newlines; framing would break"
        );

        self.scratch.push(b'\n');
        self.inner.write_all(&self.scratch).await?;
        self.inner.flush().await?;
        Ok(())
    }

    /// Unwraps the writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Notification, Request, Response};
    use serde_json::json;
    use tokio::io::duplex;

    /// Drains a stream, keeping per-message errors instead of stopping at the
    /// first one, so tests can assert on recovery behaviour.
    async fn read_all(input: &str) -> Vec<Result<Message, TransportError>> {
        let mut reader = MessageReader::new(input.as_bytes());
        let mut out = Vec::new();
        loop {
            match reader.next_message().await {
                Ok(Some(message)) => out.push(Ok(message)),
                Ok(None) => return out,
                Err(error) => out.push(Err(error)),
            }
        }
    }

    #[tokio::test]
    async fn reads_a_sequence_of_messages() {
        let input = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
        );

        let messages = read_all(input).await;
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].as_ref().unwrap().method(), Some("tools/list"));
        assert_eq!(
            messages[1].as_ref().unwrap().method(),
            Some("notifications/initialized")
        );
    }

    #[tokio::test]
    async fn accepts_a_final_message_with_no_trailing_newline() {
        let messages = read_all(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#).await;
        assert_eq!(messages.len(), 1);
        assert!(messages[0].is_ok());
    }

    #[tokio::test]
    async fn skips_blank_lines() {
        let input = "\n\n   \n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\n";
        let messages = read_all(input).await;
        assert_eq!(
            messages.len(),
            1,
            "blank lines should not surface as messages or errors"
        );
    }

    #[tokio::test]
    async fn tolerates_crlf_line_endings() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n";
        let messages = read_all(input).await;
        assert_eq!(messages.len(), 1);
        assert!(messages[0].is_ok(), "{:?}", messages[0]);
    }

    #[tokio::test]
    async fn a_malformed_line_does_not_poison_the_rest_of_the_stream() {
        // This is the property that keeps one broken upstream from taking down
        // a session that other upstreams are still serving.
        let input = concat!(
            "{not json at all}\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
            "\n",
        );

        let messages = read_all(input).await;
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Err(TransportError::Decode { .. })));
        assert_eq!(messages[1].as_ref().unwrap().method(), Some("ping"));
    }

    #[tokio::test]
    async fn decode_errors_quote_a_bounded_excerpt() {
        let long = "x".repeat(5_000);
        let input = format!("{{\"garbage\":\"{long}\"}}\n");
        let messages = read_all(&input).await;

        let Err(TransportError::Decode { excerpt, .. }) = &messages[0] else {
            panic!("expected a decode error, got {:?}", messages[0]);
        };
        assert!(
            excerpt.len() <= EXCERPT_BYTES + 3,
            "excerpt must stay bounded: {}",
            excerpt.len()
        );
        assert!(excerpt.ends_with("..."));
    }

    #[tokio::test]
    async fn rejects_an_oversized_line_and_resynchronises() {
        // The resynchronisation half is the point: after rejecting the huge
        // line, the reader must land exactly on the start of the next one.
        let huge = "y".repeat(4096);
        let input = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{huge}\"}}\n{}\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#
        );

        let mut reader = MessageReader::new(input.as_bytes()).with_max_line_bytes(1024);

        let first = reader.next_message().await;
        assert!(
            matches!(first, Err(TransportError::LineTooLong { limit: 1024 })),
            "{first:?}"
        );

        let second = reader
            .next_message()
            .await
            .expect("reader survived")
            .expect("a second message");
        assert_eq!(
            second.method(),
            Some("ping"),
            "reader failed to resynchronise"
        );
    }

    #[tokio::test]
    async fn writes_one_line_per_message() {
        let (client, server) = duplex(4096);
        let mut writer = MessageWriter::new(client);

        writer
            .send(&Message::from(Request::new(1, "tools/list", None)))
            .await
            .unwrap();
        writer
            .send(&Message::from(Notification::new("ping", None)))
            .await
            .unwrap();
        drop(writer);

        let mut reader = MessageReader::new(server);
        let first = reader.next_message().await.unwrap().unwrap();
        let second = reader.next_message().await.unwrap().unwrap();

        assert_eq!(first.method(), Some("tools/list"));
        assert_eq!(second.method(), Some("ping"));
        assert!(reader.next_message().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn round_trips_a_payload_containing_escaped_newlines() {
        // A tool result full of newlines is the common case, and it must not
        // break framing: JSON escapes them, so the wire form stays one line.
        let (client, server) = duplex(4096);
        let mut writer = MessageWriter::new(client);

        let original = Message::from(Response::success(
            1,
            json!({ "content": [{ "type": "text", "text": "line one\nline two\r\nline three" }] }),
        ));
        writer.send(&original).await.unwrap();
        drop(writer);

        let decoded = MessageReader::new(server)
            .next_message()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decoded, original);
    }

    #[tokio::test]
    async fn reads_a_message_larger_than_the_buffer_chunk() {
        // Exercises the multi-chunk path in fill_next_line.
        let payload = "z".repeat(200_000);
        let original = Message::from(Response::success(
            1,
            json!({ "content": [{ "text": payload }] }),
        ));

        let (client, server) = duplex(4096);
        let writer = tokio::spawn(async move {
            MessageWriter::new(client)
                .send(&original.clone())
                .await
                .unwrap();
            original
        });

        let decoded = MessageReader::new(server)
            .next_message()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decoded, writer.await.unwrap());
    }
}
