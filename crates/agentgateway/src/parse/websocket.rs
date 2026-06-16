use std::io::{Error, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use async_openai::types::realtime::{
	RealtimeClientEvent, RealtimeResponseUsage, RealtimeServerEvent, UserMessageContent,
};
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use websocket_sans_io::{FrameInfo, Opcode, WebsocketFrameEncoder, WebsocketFrameEvent};

use crate::llm::policy::PromptGuard;
use crate::llm::{LLMInfo, LLMResponse};
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::log::AsyncLog;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseDoneEvent {
	/// The response resource.
	pub response: ResponseResource,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResponseResource {
	/// Usage statistics for the response.
	pub usage: Option<RealtimeResponseUsage>,
}

struct Parser<IO> {
	inner: IO,
	decoder: websocket_sans_io::WebsocketFrameDecoder,
	buf: BytesMut,
	buffer_limit: usize,
	disabled: bool,
	log: AsyncLog<LLMInfo>,
}

impl<IO> Parser<IO> {
	fn record_text_payload(&mut self, data: &[u8]) -> bool {
		if self.buf.len() + data.len() > self.buffer_limit {
			self.buf = Default::default();
			self.disabled = true;
			return false;
		}
		self.buf.extend_from_slice(data);
		true
	}

	fn emit(&self, data: Bytes) {
		let Ok(data) = str::from_utf8(&data) else {
			return;
		};
		if data.contains("response.done") {
			let Ok(typed) = serde_json::from_str::<ResponseDoneEvent>(data) else {
				return;
			};
			if let Some(usage) = typed.response.usage {
				// TODO: do we need to parse the request side to get the request model?
				// it seems like we get an event from the server with the same thing.
				// also, the model can change... so what do we report??
				self.log.non_atomic_mutate(|r| {
					r.response = LLMResponse {
						input_tokens: Some(usage.input_tokens as u64),
						input_image_tokens: None,
						input_text_tokens: None,
						input_audio_tokens: None,
						output_tokens: Some(usage.output_tokens as u64),
						output_image_tokens: None,
						output_text_tokens: None,
						output_audio_tokens: None,
						total_tokens: Some(usage.total_tokens as u64),
						service_tier: None,
						provider_model: None,
						completion: None,
						first_token: None,
						count_tokens: None,
						reasoning_tokens: None,
						cache_creation_input_tokens: None,
						cached_input_tokens: usage
							.input_token_details
							.as_ref()
							.and_then(|d| d.cached_tokens)
							.map(|x| x as u64),
					}
				});
			}
		}
	}
}

impl<IO: AsyncWrite + Unpin + 'static> AsyncWrite for Parser<IO> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<Result<usize, Error>> {
		Pin::new(&mut self.inner).poll_write(cx, buf)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
		Pin::new(&mut self.inner).poll_flush(cx)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
		Pin::new(&mut self.inner).poll_shutdown(cx)
	}

	fn poll_write_vectored(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &[IoSlice<'_>],
	) -> Poll<Result<usize, Error>> {
		Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
	}

	fn is_write_vectored(&self) -> bool {
		self.inner.is_write_vectored()
	}
}
impl<IO: AsyncRead + Unpin + 'static> AsyncRead for Parser<IO> {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<std::io::Result<()>> {
		let orig = buf.filled().len();
		ready!(Pin::new(&mut self.inner).poll_read(cx, buf)?);
		if buf.filled().len() - orig == 0 {
			// EOF
			return Poll::Ready(Ok(()));
		}
		if self.disabled {
			return Poll::Ready(Ok(()));
		}
		let mut processed_offset = 0;
		loop {
			let unprocessed_part_of_buf = &buf.filled()[processed_offset..buf.filled().len()];
			// Websocket logic needs owned copy to apply the mask. However, we need to keep the untouched stuff
			// so we are not modifying the response.
			let Ok(ret) = self.decoder.add_data(&mut unprocessed_part_of_buf.to_vec());
			processed_offset += ret.consumed_bytes;

			if ret.event.is_none() && ret.consumed_bytes == 0 {
				return Poll::Ready(Ok(()));
			}

			match ret.event {
				Some(WebsocketFrameEvent::PayloadChunk {
					original_opcode: Opcode::Text,
				}) if !self.record_text_payload(&unprocessed_part_of_buf[0..ret.consumed_bytes]) => {
					return Poll::Ready(Ok(()));
				},
				Some(WebsocketFrameEvent::End {
					frame_info: FrameInfo { fin: true, .. },
					original_opcode: Opcode::Text,
				}) => {
					let got = self.buf.split();
					self.emit(got.freeze());
				},
				_ => (),
			}
		}
	}
}

pub async fn parser<IO>(
	body: IO,
	log: AsyncLog<LLMInfo>,
) -> impl AsyncRead + AsyncWrite + Unpin + 'static
where
	IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
	parser_with_limit(body, log, crate::defaults::max_buffer_size())
}

fn parser_with_limit<IO>(
	body: IO,
	log: AsyncLog<LLMInfo>,
	buffer_limit: usize,
) -> impl AsyncRead + AsyncWrite + Unpin + 'static
where
	IO: AsyncRead + AsyncWrite + Unpin + 'static,
{
	Parser {
		inner: body,
		decoder: websocket_sans_io::WebsocketFrameDecoder::new(),
		buf: Default::default(),
		buffer_limit,
		disabled: false,
		log,
	}
}

// ---------------------------------------------------------------------------
// Guarded WebSocket realtime proxy
// ---------------------------------------------------------------------------

/// Encode a WebSocket text frame (server-side, unmasked) containing `payload`.
fn encode_ws_text_frame(payload: &[u8]) -> Bytes {
	let mut encoder = WebsocketFrameEncoder::new();
	let frame_info = FrameInfo {
		opcode: Opcode::Text,
		payload_length: payload.len() as u64,
		mask: None,
		fin: true,
		reserved: 0,
	};
	let header = encoder.start_frame(&frame_info);
	let mut out = BytesMut::with_capacity(header.len() + payload.len());
	out.extend_from_slice(&header);
	out.extend_from_slice(payload);
	out.freeze()
}

/// Encode a WebSocket text frame with `mask` (client-side, masked).
fn encode_ws_text_frame_masked(payload: &[u8], mask: [u8; 4]) -> Bytes {
	let mut encoder = WebsocketFrameEncoder::new();
	let frame_info = FrameInfo {
		opcode: Opcode::Text,
		payload_length: payload.len() as u64,
		mask: Some(mask),
		fin: true,
		reserved: 0,
	};
	let header = encoder.start_frame(&frame_info);
	let mut out = BytesMut::with_capacity(header.len() + payload.len());
	out.extend_from_slice(&header);
	let mut payload_copy = payload.to_vec();
	encoder.transform_frame_payload(&mut payload_copy);
	out.extend_from_slice(&payload_copy);
	out.freeze()
}

/// Synthetic WebSocket error event sent when a guardrail blocks content.
fn guardrail_blocked_ws_event_bytes() -> Bytes {
	let json = br#"{"type":"error","error":{"type":"guardrail_blocked","code":"guardrail_intervention","message":"Content blocked by guardrail policy"}}"#;
	encode_ws_text_frame(json)
}

/// Synthetic `response.cancel` event sent to the server when a response guard blocks.
///
/// The WebSocket spec requires client→server frames to be masked. We use a zero mask
/// so the XOR is identity (payload bytes are unchanged) while the frame is formally masked.
fn response_cancel_event_bytes(response_id: &str, mask: [u8; 4]) -> Bytes {
	let json = format!(r#"{{"type":"response.cancel","response_id":"{response_id}"}}"#);
	encode_ws_text_frame_masked(json.as_bytes(), mask)
}

// ---------------------------------------------------------------------------
// WebSocket frame accumulator
// ---------------------------------------------------------------------------

struct WsFrameAccumulator {
	decoder: websocket_sans_io::WebsocketFrameDecoder,
	pending: BytesMut,
	frame_raw: BytesMut,
	frame_payload: BytesMut,
}

enum WsCompletedFrame {
	Text { raw: Bytes, payload: Bytes },
	Other { raw: Bytes },
}

impl WsFrameAccumulator {
	fn new() -> Self {
		Self {
			decoder: websocket_sans_io::WebsocketFrameDecoder::new(),
			pending: BytesMut::new(),
			frame_raw: BytesMut::new(),
			frame_payload: BytesMut::new(),
		}
	}

	fn push(&mut self, data: &[u8]) {
		self.pending.extend_from_slice(data);
	}

	fn drain_frames(&mut self) -> Vec<WsCompletedFrame> {
		let mut result = Vec::new();
		loop {
			let mut copy = self.pending.to_vec();
			let ret = match self.decoder.add_data(&mut copy) {
				Ok(r) => r,
				Err(_) => {
					// Protocol error: forward all pending raw bytes as an opaque frame and
					// clear accumulator state so the proxy makes progress rather than
					// retrying the same bytes and stalling indefinitely.
					if !self.pending.is_empty() {
						let raw = self.pending.split().freeze();
						self.frame_raw.clear();
						self.frame_payload.clear();
						result.push(WsCompletedFrame::Other { raw });
					}
					break;
				},
			};
			if ret.consumed_bytes == 0 && ret.event.is_none() {
				break;
			}

			let raw_chunk = self.pending.split_to(ret.consumed_bytes).freeze();
			self.frame_raw.extend_from_slice(&raw_chunk);

			match ret.event {
				Some(WebsocketFrameEvent::PayloadChunk {
					original_opcode: Opcode::Text,
				}) => {
					self
						.frame_payload
						.extend_from_slice(&copy[..ret.consumed_bytes]);
				},
				Some(WebsocketFrameEvent::End {
					original_opcode: Opcode::Text,
					frame_info: FrameInfo { fin: true, .. },
				}) => {
					self
						.frame_payload
						.extend_from_slice(&copy[..ret.consumed_bytes]);
					let raw = self.frame_raw.split().freeze();
					let payload = self.frame_payload.split().freeze();
					result.push(WsCompletedFrame::Text { raw, payload });
				},
				Some(WebsocketFrameEvent::End { .. }) => {
					let raw = self.frame_raw.split().freeze();
					self.frame_payload.clear();
					result.push(WsCompletedFrame::Other { raw });
				},
				Some(WebsocketFrameEvent::PayloadChunk { .. })
				| Some(WebsocketFrameEvent::Start { .. })
				| None => {},
			}
		}
		result
	}
}

// ---------------------------------------------------------------------------
// Guarded realtime proxy
// ---------------------------------------------------------------------------

/// A bidirectional guarded WebSocket proxy for the OpenAI Realtime API.
///
/// - **Client→Server:** applies request guards to `conversation.item.create` events.
/// - **Server→Client:** windowed evaluation of `response.output_text.delta` events —
///   deltas are held until ~`DEFAULT_EVAL_THRESHOLD` bytes of text accumulate, then
///   evaluated (with an overlap tail from previously evaluated text) and flushed on
///   pass. On block, the held (never-forwarded) deltas are discarded, a synthetic
///   error event is sent to the client, and `response.cancel` is sent to the server;
///   subsequent deltas for that response are dropped.
/// - Preserves existing telemetry on `response.done`.
/// - All non-text frames (audio, control, etc.) are forwarded immediately.
pub async fn guarded_realtime_proxy<C, S>(
	client: C,
	server: S,
	guard: PromptGuard,
	policy_client: PolicyClient,
	log: AsyncLog<LLMInfo>,
	// Original HTTP upgrade request headers — forwarded to webhook response guards via
	// begin_streaming_response_guard so that forward_header_matches works on this path.
	req_headers: ::http::HeaderMap,
) where
	C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	use std::collections::HashSet;

	use crate::llm::policy::streaming_guardrails::{
		DEFAULT_EVAL_THRESHOLD, OVERLAP_BYTES, evaluate_window, tail_chars,
	};

	let (mut client_reader, mut client_writer_io) = tokio::io::split(client);
	let (mut server_reader, mut server_writer_io) = tokio::io::split(server);

	let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<Bytes>(256);
	let (server_tx, mut server_rx) = tokio::sync::mpsc::channel::<Bytes>(256);

	let guard_clone = guard.clone();
	let policy_client_clone = policy_client.clone();
	let log_clone = log.clone();

	let client_to_server = {
		let server_tx = server_tx.clone();
		let client_tx_err = client_tx.clone();
		async move {
			let mut accum = WsFrameAccumulator::new();
			let mut read_buf = [0u8; 4096];

			loop {
				let n = match client_reader.read(&mut read_buf).await {
					Ok(0) | Err(_) => break,
					Ok(n) => n,
				};
				accum.push(&read_buf[..n]);

				for frame in accum.drain_frames() {
					match frame {
						WsCompletedFrame::Text { raw, payload } => {
							if let Ok(text) = std::str::from_utf8(&payload)
								&& let Ok(RealtimeClientEvent::ConversationItemCreate(create)) =
									serde_json::from_str::<RealtimeClientEvent>(text)
							{
								let mut input_text = String::new();
								if let async_openai::types::realtime::RealtimeConversationItem::Message(
									async_openai::types::realtime::RealtimeConversationItemMessage::User(user_msg),
								) = &create.item
								{
									for content in &user_msg.content {
										if let UserMessageContent::InputText(t) = content {
											input_text.push_str(&t.text);
											input_text.push(' ');
										}
									}
								}

								if !input_text.is_empty()
									&& guard
										.apply_realtime_request_guards(input_text.trim(), &policy_client)
										.await
								{
									let _ = client_tx_err.send(guardrail_blocked_ws_event_bytes()).await;
									continue;
								}
							}
							let _ = server_tx.send(raw).await;
						},
						WsCompletedFrame::Other { raw } => {
							let _ = server_tx.send(raw).await;
						},
					}
				}
			}
			drop(server_tx);
		}
	};

	let server_to_client = {
		async move {
			let mut accum = WsFrameAccumulator::new();
			let mut read_buf = [0u8; 4096];
			let mut evaluators =
				guard_clone.begin_streaming_response_guard(&policy_client_clone, &req_headers);
			let mut delta_hold: Vec<Bytes> = Vec::new();
			let mut pending_text = String::new();
			let mut overlap_tail = String::new();
			// Keyed by response_id so that blocking one concurrent response does not
			// suppress deltas from unrelated concurrent responses.
			let mut blocked_responses: HashSet<String> = HashSet::new();

			loop {
				let n = match server_reader.read(&mut read_buf).await {
					Ok(0) | Err(_) => break,
					Ok(n) => n,
				};
				accum.push(&read_buf[..n]);

				for frame in accum.drain_frames() {
					match frame {
						WsCompletedFrame::Text { raw, payload } => {
							let event = std::str::from_utf8(&payload)
								.ok()
								.and_then(|s| serde_json::from_str::<RealtimeServerEvent>(s).ok());

							match event {
								Some(RealtimeServerEvent::ResponseOutputTextDelta(ref delta_event)) => {
									if blocked_responses.contains(&delta_event.response_id) {
										continue;
									}
									pending_text.push_str(&delta_event.delta);
									delta_hold.push(raw);

									if pending_text.len() >= DEFAULT_EVAL_THRESHOLD {
										let batch = std::mem::take(&mut pending_text);
										let window = format!("{overlap_tail}{batch}");
										overlap_tail = tail_chars(&window, OVERLAP_BYTES).to_string();

										if evaluate_window(&mut evaluators, &window).await {
											delta_hold.clear();
											// Clear shared text-state so a blocked response's content
											// does not bleed into subsequent concurrent responses.
											overlap_tail.clear();
											pending_text.clear();
											blocked_responses.insert(delta_event.response_id.clone());
											let _ = client_tx.send(guardrail_blocked_ws_event_bytes()).await;
											let _ = server_tx
												.send(response_cancel_event_bytes(
													&delta_event.response_id,
													[0, 0, 0, 0],
												))
												.await;
										} else {
											for f in delta_hold.drain(..) {
												let _ = client_tx.send(f).await;
											}
										}
									}
								},
								Some(RealtimeServerEvent::ResponseOutputTextDone(ref done_event)) => {
									if blocked_responses.contains(&done_event.response_id) {
										blocked_responses.remove(&done_event.response_id);
										overlap_tail.clear();
										pending_text.clear();
										delta_hold.clear();
										continue;
									}

									let mut blocked = false;
									if !pending_text.is_empty() {
										let batch = std::mem::take(&mut pending_text);
										let window = format!("{overlap_tail}{batch}");
										blocked = evaluate_window(&mut evaluators, &window).await;
									}
									overlap_tail.clear();

									if blocked {
										delta_hold.clear();
										// Prevent stale deltas from a race between the cancel
										// reaching the server and buffered frames arriving here.
										blocked_responses.insert(done_event.response_id.clone());
										let _ = client_tx.send(guardrail_blocked_ws_event_bytes()).await;
										let _ = server_tx
											.send(response_cancel_event_bytes(
												&done_event.response_id,
												[0, 0, 0, 0],
											))
											.await;
									} else {
										for f in delta_hold.drain(..) {
											let _ = client_tx.send(f).await;
										}
										let _ = client_tx.send(raw).await;
									}
								},
								Some(RealtimeServerEvent::ResponseDone(ref done_event)) => {
									if let Some(usage) = done_event.response.usage.as_ref() {
										let usage_clone = usage.clone();
										log_clone.non_atomic_mutate(|r| {
											r.response = LLMResponse {
												input_tokens: Some(usage_clone.input_tokens as u64),
												input_image_tokens: None,
												input_text_tokens: None,
												input_audio_tokens: None,
												output_tokens: Some(usage_clone.output_tokens as u64),
												output_image_tokens: None,
												output_text_tokens: None,
												output_audio_tokens: None,
												total_tokens: Some(usage_clone.total_tokens as u64),
												service_tier: None,
												provider_model: None,
												completion: None,
												first_token: None,
												count_tokens: None,
												reasoning_tokens: None,
												cache_creation_input_tokens: None,
												cached_input_tokens: usage_clone
													.input_token_details
													.as_ref()
													.and_then(|d| d.cached_tokens)
													.map(|x| x as u64),
											}
										});
									}
									let _ = client_tx.send(raw).await;
								},
								_ => {
									let _ = client_tx.send(raw).await;
								},
							}
						},
						WsCompletedFrame::Other { raw } => {
							let _ = client_tx.send(raw).await;
						},
					}
				}
			}
			drop(client_tx);
		}
	};

	let client_writer_task = async move {
		while let Some(bytes) = client_rx.recv().await {
			if client_writer_io.write_all(&bytes).await.is_err() {
				break;
			}
		}
	};

	let server_writer_task = async move {
		while let Some(bytes) = server_rx.recv().await {
			if server_writer_io.write_all(&bytes).await.is_err() {
				break;
			}
		}
	};

	// Wait for one read direction to close (server EOF or client disconnect).
	// When either reader task exits or is cancelled, it drops its channel senders,
	// allowing the writer tasks to drain naturally.
	tokio::select! {
		_ = client_to_server => {},
		_ = server_to_client => {},
	}
	// Join the writer tasks so queued frames are flushed before this function returns.
	// They exit quickly because all senders are dropped by this point.
	tokio::join!(client_writer_task, server_writer_task);
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	use super::*;

	#[test]
	fn record_text_payload_disables_after_limit() {
		let (io, _) = tokio::io::duplex(1);
		let mut parser = Parser {
			inner: io,
			decoder: websocket_sans_io::WebsocketFrameDecoder::new(),
			buf: Default::default(),
			buffer_limit: 4,
			disabled: false,
			log: AsyncLog::default(),
		};

		assert!(parser.record_text_payload(b"abc"));
		assert_eq!(&parser.buf[..], b"abc");
		parser.buf.reserve(1024);
		assert!(!parser.record_text_payload(b"de"));
		assert!(parser.disabled);
		assert!(parser.buf.is_empty());
		assert_eq!(parser.buf.capacity(), 0);
	}

	// -------------------------------------------------------------------------
	// Bug regression tests
	// -------------------------------------------------------------------------

	/// Bug: response_cancel_event_bytes produced {"type":"response.cancel"} with no
	/// response_id, so the server cancelled whatever it treated as the current response
	/// rather than the specific blocked one.
	///
	/// Fix: include the response_id of the blocked response in the cancel payload.
	#[test]
	fn response_cancel_includes_response_id() {
		let bytes = response_cancel_event_bytes("resp_X", [0, 0, 0, 0]);
		let mut accum = WsFrameAccumulator::new();
		accum.push(&bytes);
		let frames = accum.drain_frames();
		let WsCompletedFrame::Text { payload, .. } = &frames[0] else {
			panic!("expected text frame");
		};
		let json: serde_json::Value = serde_json::from_slice(payload).unwrap();
		assert_eq!(
			json.get("response_id").and_then(|v| v.as_str()),
			Some("resp_X"),
			"response.cancel must carry response_id to target the correct response; got: {json}"
		);
	}

	/// Bug: response_blocked was a single bool shared across all concurrent Realtime API
	/// responses. Blocking response A set response_blocked=true, which then silently
	/// dropped all ResponseOutputTextDelta events for unrelated concurrent response B.
	///
	/// Fix: key blocked state on response_id (HashSet<String>).
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn blocked_response_does_not_suppress_concurrent_response() {
		use crate::llm::LLMInfo;
		use crate::llm::policy::{
			Action, PromptGuard, RegexRule, RegexRules, ResponseGuard, ResponseGuardKind,
		};
		use crate::telemetry::log::AsyncLog;

		let guard = PromptGuard {
			request: vec![],
			response: vec![ResponseGuard {
				rejection: Default::default(),
				kind: ResponseGuardKind::Regex(RegexRules {
					action: Action::Reject,
					rules: vec![RegexRule::Regex {
						pattern: regex::Regex::new("BLOCK_THIS").unwrap(),
					}],
				}),
			}],
		};

		let (client_io, mut test_client) = tokio::io::duplex(1 << 20);
		let (mut test_server, server_io) = tokio::io::duplex(1 << 20);

		let policy = crate::test_helpers::policy_client();
		let log = AsyncLog::<LLMInfo>::default();

		tokio::spawn(guarded_realtime_proxy(
			client_io,
			server_io,
			guard,
			policy,
			log,
			::http::HeaderMap::new(),
		));

		// Frame 1 – resp_A delta: 1025 chars including trigger word.
		// Crosses DEFAULT_EVAL_THRESHOLD (1024) → guard fires → blocks resp_A.
		let padding = "x".repeat(1020);
		let delta_a = serde_json::json!({
			"type": "response.output_text.delta",
			"event_id": "e1",
			"response_id": "resp_A",
			"item_id": "i1",
			"output_index": 0,
			"content_index": 0,
			"delta": format!("{padding}BLOCK_THIS")
		});
		test_server
			.write_all(&encode_ws_text_frame(delta_a.to_string().as_bytes()))
			.await
			.unwrap();

		// Frame 2 – resp_B delta: clean content from a different concurrent response.
		// With the fix this accumulates in delta_hold for resp_B.
		let delta_b = serde_json::json!({
			"type": "response.output_text.delta",
			"event_id": "e2",
			"response_id": "resp_B",
			"item_id": "i2",
			"output_index": 0,
			"content_index": 0,
			"delta": "clean content from B"
		});
		test_server
			.write_all(&encode_ws_text_frame(delta_b.to_string().as_bytes()))
			.await
			.unwrap();

		// Frame 3 – resp_B TextDone: triggers final evaluation of accumulated resp_B text
		// ("clean content from B" has no match → flush delta_hold to client).
		let done_b = serde_json::json!({
			"type": "response.output_text.done",
			"event_id": "e3",
			"response_id": "resp_B",
			"item_id": "i2",
			"output_index": 0,
			"content_index": 0,
			"text": "clean content from B"
		});
		test_server
			.write_all(&encode_ws_text_frame(done_b.to_string().as_bytes()))
			.await
			.unwrap();

		// Close the server write half so the proxy can exit cleanly.
		drop(test_server);

		// Give the proxy and channel-writer tasks time to drain.
		tokio::time::sleep(Duration::from_millis(300)).await;

		let mut buf = vec![0u8; 1 << 20];
		let n = tokio::time::timeout(Duration::from_millis(500), test_client.read(&mut buf))
			.await
			.unwrap_or(Ok(0))
			.unwrap_or(0);

		let mut accum = WsFrameAccumulator::new();
		accum.push(&buf[..n]);
		let frames = accum.drain_frames();
		let events: Vec<serde_json::Value> = frames
			.into_iter()
			.filter_map(|f| {
				if let WsCompletedFrame::Text { payload, .. } = f {
					serde_json::from_slice(&payload).ok()
				} else {
					None
				}
			})
			.collect();

		// resp_B's delta must reach the client.
		// Fails without the fix: response_blocked=true drops all deltas regardless of response_id.
		assert!(
			events.iter().any(|e| {
				e.get("type").and_then(|t| t.as_str())
					== Some("response.output_text.delta")
					&& e.get("response_id").and_then(|r| r.as_str()) == Some("resp_B")
			}),
			"resp_B delta must reach the client; received events: {events:?}"
		);
	}
}
