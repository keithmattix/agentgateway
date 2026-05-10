use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::anyhow;
use bytes::{Buf, Bytes};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use itertools::Itertools;
use pin_project_lite::pin_project;
use prost_wkt_types::Struct;
use proto::body_mutation::Mutation;
use proto::processing_request::Request;
use proto::processing_response::Response;
use protos::envoy::service::ext_proc::v3::{
	BodySendMode as EnvoyBodySendMode, ProtocolConfiguration,
};
use serde_json::Value as JsonValue;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;

use crate::cel::{Executor, Expression, RequestSnapshot};
use crate::client::ResolvedDestination;
use crate::http::buflist::BufList;
use crate::http::ext_proc::proto::{
	BodyMutation, BodyResponse, HeaderMutation, HeadersResponse, HttpBody, HttpHeaders, HttpTrailers,
	ImmediateResponse, Metadata, ProcessingRequest, ProcessingResponse, processing_response,
};
use crate::http::{HeaderName, PolicyResponse, bufferbody, envoy_proto_common};
use crate::proxy::ProxyError;
use crate::proxy::dtrace::{self, pol_result};
use crate::proxy::httpproxy::PolicyClient;
use crate::types::agent::{BackendTrafficPolicy, SimpleBackendReference};
use crate::{http, *};

/// The namespace key used for ext_proc attributes in ProcessingRequest.attributes
const EXTPROC_ATTRIBUTES_NAMESPACE: &str = "envoy.filters.http.ext_proc";

#[cfg(test)]
#[path = "ext_proc_tests.rs"]
mod tests;

const TRACE_POLICY_KIND: &str = "ext_proc";

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("failed to send request")]
	RequestSend,
	#[error("no more response messages")]
	NoMoreResponses,
	#[error("no more responses")]
	ResponseDropped,
	#[error("failed to buffer body: {0}")]
	BodyBuffer(String),
	#[error("failed to convert metadata value: {0}")]
	MetadataConversion(String),
	#[error(transparent)]
	InvalidHeaderName(#[from] http::header::InvalidHeaderName),
	#[error(transparent)]
	InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),
}

#[apply(schema!)]
#[derive(Default, ::cel::DynamicType)]
pub struct ExtProcDynamicMetadata(serde_json::Map<String, JsonValue>);

#[allow(warnings)]
#[allow(clippy::derive_partial_eq_without_eq)]
pub mod proto {
	pub use protos::envoy::service::common::v3::{
		HeaderValue, HeaderValueOption, HttpStatus, Metadata, StatusCode, header_value_option,
	};
	pub use protos::envoy::service::ext_proc::v3::*;
}

#[apply(schema!)]
#[derive(Default, Copy, PartialEq, Eq)]
pub enum FailureMode {
	#[default]
	FailClosed,
	FailOpen,
}

#[apply(schema!)]
#[derive(Default, Copy, PartialEq, Eq)]
pub enum BodySendMode {
	None,
	Buffered,
	BufferedPartial,
	#[default]
	FullDuplexStreamed,
}

impl From<BodySendMode> for EnvoyBodySendMode {
	fn from(val: BodySendMode) -> Self {
		match val {
			BodySendMode::None => EnvoyBodySendMode::None,
			BodySendMode::Buffered => EnvoyBodySendMode::Buffered,
			BodySendMode::BufferedPartial => EnvoyBodySendMode::BufferedPartial,
			BodySendMode::FullDuplexStreamed => EnvoyBodySendMode::FullDuplexStreamed,
		}
	}
}

impl From<BodySendMode> for i32 {
	fn from(val: BodySendMode) -> Self {
		match val {
			BodySendMode::None => EnvoyBodySendMode::None as i32,
			BodySendMode::Buffered => EnvoyBodySendMode::Buffered as i32,
			BodySendMode::BufferedPartial => EnvoyBodySendMode::BufferedPartial as i32,
			BodySendMode::FullDuplexStreamed => EnvoyBodySendMode::FullDuplexStreamed as i32,
		}
	}
}

impl From<EnvoyBodySendMode> for BodySendMode {
	fn from(val: EnvoyBodySendMode) -> Self {
		match val {
			EnvoyBodySendMode::None => BodySendMode::None,
			EnvoyBodySendMode::Buffered => BodySendMode::Buffered,
			EnvoyBodySendMode::BufferedPartial => BodySendMode::BufferedPartial,
			EnvoyBodySendMode::FullDuplexStreamed => BodySendMode::FullDuplexStreamed,
			EnvoyBodySendMode::Streamed => {
				// This mode is not currently supported, so we map it to the closest available mode and log a warning.
				warn!(
					"received unsupported Envoy body send mode STREAMED; treating as FULL_DUPLEX_STREAMED"
				);
				BodySendMode::FullDuplexStreamed
			},
		}
	}
}

#[apply(schema!)]
#[derive(Default, Copy, PartialEq, Eq)]
pub enum HeaderSendMode {
	#[default]
	Send,
	Skip,
}

#[apply(schema!)]
#[derive(Default, Copy, PartialEq, Eq)]
pub enum TrailerSendMode {
	Send,
	#[default]
	Skip,
}

#[apply(schema!)]
#[derive(Default, Copy, PartialEq, Eq)]
/// Controls how an endpoint-picker-selected destination is used.
pub enum InferenceRoutingDestinationMode {
	/// Require the selected destination to match agentgateway's local service endpoints.
	#[default]
	Validated,
	/// Trust the selected destination directly without local endpoint validation.
	Passthrough,
}

#[apply(schema_ser_schema!)]
pub struct InferenceRouting {
	#[serde(rename = "endpointPicker")]
	pub target: Arc<SimpleBackendReference>,
	#[serde(
		default,
		rename = "destinationMode",
		skip_serializing_if = "crate::serdes::is_default"
	)]
	pub destination_mode: InferenceRoutingDestinationMode,
	#[serde(default, skip_serializing_if = "crate::serdes::is_default")]
	#[cfg_attr(feature = "schema", schemars(skip))]
	pub failure_mode: FailureMode,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InferenceRoutingConfig {
	endpoint_picker: Arc<SimpleBackendReference>,
	#[serde(default)]
	destination_mode: InferenceRoutingDestinationMode,
}

impl<'de> serde::Deserialize<'de> for InferenceRouting {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let InferenceRoutingConfig {
			endpoint_picker,
			destination_mode,
		} = InferenceRoutingConfig::deserialize(deserializer)?;
		Ok(Self {
			target: endpoint_picker,
			destination_mode,
			// TODO: expose fail-open configuration for standalone EPP once the fallback behavior is
			// explicitly supported and documented end-to-end.
			failure_mode: FailureMode::FailClosed,
		})
	}
}

#[derive(Debug, Default)]
pub struct InferencePoolRouter {
	ext_proc: Option<ExtProcInstance>,
	destination_mode: InferenceRoutingDestinationMode,
}

#[derive(Debug, Default)]
pub struct InferenceRequestResult {
	pub destination: Option<SocketAddr>,
	pub destination_mode: InferenceRoutingDestinationMode,
	pub policy_response: PolicyResponse,
	pub failed_open: bool,
}

impl InferenceRouting {
	pub fn build(&self, client: PolicyClient) -> InferencePoolRouter {
		InferencePoolRouter {
			destination_mode: self.destination_mode,
			ext_proc: Some(ExtProcInstance::new(
				client,
				Vec::new(),
				self.target.clone(),
				self.failure_mode,
				None,
				None,
				None,
				ProcessingOptions {
					request_body_mode: BodySendMode::FullDuplexStreamed,
					response_body_mode: BodySendMode::FullDuplexStreamed,
					..Default::default()
				},
			)),
		}
	}
}

impl InferencePoolRouter {
	pub async fn mutate_request(
		&mut self,
		req: &mut http::Request,
	) -> Result<InferenceRequestResult, ProxyError> {
		let Some(ext_proc) = &mut self.ext_proc else {
			return Ok(Default::default());
		};
		let r = std::mem::take(req);
		let (new_req, pr) = ext_proc.mutate_request(r).await?;
		let failed_open = ext_proc.skipped;
		*req = new_req;
		let dest = req
			.headers()
			.get(HeaderName::from_static("x-gateway-destination-endpoint"))
			.and_then(|v| v.to_str().ok())
			.map(|v| v.parse::<SocketAddr>())
			.transpose()
			.map_err(|e| ProxyError::Processing(anyhow!("EPP returned invalid address: {e}")))?;
		Ok(InferenceRequestResult {
			destination: dest,
			destination_mode: self.destination_mode,
			policy_response: pr.unwrap_or_default(),
			failed_open,
		})
	}

	pub async fn mutate_response(
		&mut self,
		resp: &mut http::Response,
	) -> Result<PolicyResponse, ProxyError> {
		let rd = resp.extensions().get::<ResolvedDestination>().map(|d| d.0);
		let Some(ext_proc) = &mut self.ext_proc else {
			return Ok(Default::default());
		};
		let r = std::mem::take(resp);
		let (new_resp, pr) = ext_proc.mutate_response(r, None, rd).await?;
		*resp = new_resp;
		Ok(pr.unwrap_or_default())
	}
}

#[apply(schema!)]
#[derive(Copy)]
pub struct ProcessingOptions {
	#[serde(default = "default_body_send_mode")]
	pub request_body_mode: BodySendMode,
	#[serde(default = "default_body_send_mode")]
	pub response_body_mode: BodySendMode,
	#[serde(default)]
	pub request_header_mode: HeaderSendMode,
	#[serde(default)]
	pub response_header_mode: HeaderSendMode,
	#[serde(default)]
	pub request_trailer_mode: TrailerSendMode,
	#[serde(default)]
	pub response_trailer_mode: TrailerSendMode,
	/// Allow ext_proc `mode_override` values from matching headers responses to update
	/// subsequent request/response processing phases for this exchange.
	#[serde(default)]
	pub allow_mode_override: bool,
}

fn default_body_send_mode() -> BodySendMode {
	BodySendMode::FullDuplexStreamed
}

impl Default for ProcessingOptions {
	fn default() -> Self {
		Self {
			request_body_mode: BodySendMode::FullDuplexStreamed,
			response_body_mode: BodySendMode::FullDuplexStreamed,
			request_header_mode: HeaderSendMode::Send,
			response_header_mode: HeaderSendMode::Send,
			request_trailer_mode: TrailerSendMode::Skip,
			response_trailer_mode: TrailerSendMode::Skip,
			allow_mode_override: false,
		}
	}
}

#[derive(Debug, Copy, Clone)]
enum HeaderPhase {
	Request,
	Response,
}

#[derive(Debug, Copy, Clone)]
enum BodyModeOverrideDirection {
	Request,
	Response,
}

// Tracks the negotiated ext_proc processing modes for the lifetime of a single
// gRPC bidirectional stream. This is the protocol-facing state: it stores what we believe
// Envoy ext_proc wants us to send next, and applies mode_override updates with
// protocol validity checks.
#[derive(Debug, Copy, Clone)]
struct ModeStateMachine {
	request_body_mode: BodySendMode,
	response_body_mode: BodySendMode,
	request_header_mode: HeaderSendMode,
	response_header_mode: HeaderSendMode,
	request_trailer_mode: TrailerSendMode,
	response_trailer_mode: TrailerSendMode,
	allow_mode_override: bool,
	request_headers_processed: bool,
	response_headers_processed: bool,
}

impl From<ProcessingOptions> for ModeStateMachine {
	fn from(opts: ProcessingOptions) -> Self {
		Self {
			request_body_mode: opts.request_body_mode,
			response_body_mode: opts.response_body_mode,
			request_header_mode: opts.request_header_mode,
			response_header_mode: opts.response_header_mode,
			request_trailer_mode: opts.request_trailer_mode,
			response_trailer_mode: opts.response_trailer_mode,
			allow_mode_override: opts.allow_mode_override,
			request_headers_processed: false,
			response_headers_processed: false,
		}
	}
}

impl ModeStateMachine {
	fn current_mode_allows_body_override(
		current_mode: BodySendMode,
		phase: HeaderPhase,
		direction: BodyModeOverrideDirection,
	) -> bool {
		if current_mode == BodySendMode::FullDuplexStreamed {
			warn!(
				phase = ?phase,
				direction = ?direction,
				"ignoring body mode_override because current body mode is FULL_DUPLEX_STREAMED"
			);
			return false;
		}
		true
	}

	fn apply_body_mode_override(
		current_mode: &mut BodySendMode,
		next_mode: EnvoyBodySendMode,
		phase: HeaderPhase,
		direction: BodyModeOverrideDirection,
		phase_name: &'static str,
		field_name: &'static str,
	) {
		match next_mode {
			// TODO: Should we abort the stream?
			EnvoyBodySendMode::Streamed => {
				warn!(
					phase = phase_name,
					field = field_name,
					"mode_override body_mode=STREAMED is not implemented; keeping current body mode"
				)
			},
			_ if Self::current_mode_allows_body_override(*current_mode, phase, direction) => {
				*current_mode = BodySendMode::from(next_mode);
			},
			_ => {},
		}
	}

	fn mark_headers_processed(&mut self, phase: HeaderPhase) {
		match phase {
			HeaderPhase::Request => self.request_headers_processed = true,
			HeaderPhase::Response => self.response_headers_processed = true,
		}
	}

	fn apply_envoy_mode_override(&mut self, phase: HeaderPhase, mode: &proto::ProcessingMode) {
		use proto::processing_mode::HeaderSendMode as EnvoyHeaderSendMode;
		let phase_name = match phase {
			HeaderPhase::Request => "request_headers",
			HeaderPhase::Response => "response_headers",
		};

		if mode.request_header_mode != EnvoyHeaderSendMode::Default as i32 {
			warn!(
				phase = phase_name,
				"mode_override.request_header_mode is ignored by protocol"
			);
		}

		if let Ok(hm) = EnvoyHeaderSendMode::try_from(mode.response_header_mode) {
			match hm {
				EnvoyHeaderSendMode::Default => {},
				EnvoyHeaderSendMode::Send if !self.response_headers_processed => {
					self.response_header_mode = HeaderSendMode::Send;
				},
				EnvoyHeaderSendMode::Skip if !self.response_headers_processed => {
					self.response_header_mode = HeaderSendMode::Skip;
				},
				_ => {},
			}
		}

		if let Ok(bm) = EnvoyBodySendMode::try_from(mode.request_body_mode) {
			Self::apply_body_mode_override(
				&mut self.request_body_mode,
				bm,
				phase,
				BodyModeOverrideDirection::Request,
				phase_name,
				"request_body_mode",
			);
		}

		if let Ok(bm) = EnvoyBodySendMode::try_from(mode.response_body_mode) {
			Self::apply_body_mode_override(
				&mut self.response_body_mode,
				bm,
				phase,
				BodyModeOverrideDirection::Response,
				phase_name,
				"response_body_mode",
			);
		}

		if let Ok(hm) = EnvoyHeaderSendMode::try_from(mode.request_trailer_mode) {
			match hm {
				EnvoyHeaderSendMode::Default => {},
				EnvoyHeaderSendMode::Send => self.request_trailer_mode = TrailerSendMode::Send,
				EnvoyHeaderSendMode::Skip => self.request_trailer_mode = TrailerSendMode::Skip,
			}
		}
		if let Ok(hm) = EnvoyHeaderSendMode::try_from(mode.response_trailer_mode) {
			match hm {
				EnvoyHeaderSendMode::Default => {},
				EnvoyHeaderSendMode::Send => self.response_trailer_mode = TrailerSendMode::Send,
				EnvoyHeaderSendMode::Skip => self.response_trailer_mode = TrailerSendMode::Skip,
			}
		}
	}
}

// Request-side execution FSM. Unlike ModeStateMachine (which stores ext_proc
// protocol configuration), this FSM captures local control-flow transitions in
// mutate_request: whether we are waiting on headers, body, or can return.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum RequestPhase {
	AwaitingHeaders,
	AwaitingBody,
	StreamingContinuation,
	Complete,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum BodyPath {
	None,
	Buffered,
	BufferedPartial,
	FullDuplex,
}

#[derive(Debug, Copy, Clone)]
struct RequestFlowFsm {
	phase: RequestPhase,
	body_path: BodyPath,
	had_body: bool,
	expect_body_response: bool,
}

impl RequestFlowFsm {
	fn new(send_headers: bool, had_body: bool, body_mode: BodySendMode) -> Self {
		let body_path = BodyPath::from(body_mode);
		let expect_body_response = body_path != BodyPath::None && had_body;
		let phase = if send_headers {
			RequestPhase::AwaitingHeaders
		} else if expect_body_response {
			RequestPhase::AwaitingBody
		} else {
			RequestPhase::Complete
		};
		Self {
			phase,
			body_path,
			had_body,
			expect_body_response,
		}
	}

	fn reconcile_potential_mode_override(&mut self, mode: BodySendMode) {
		self.body_path = BodyPath::from(mode);
		self.expect_body_response = self.body_path != BodyPath::None && self.had_body;
		if self.phase == RequestPhase::AwaitingBody && !self.expect_body_response {
			self.phase = RequestPhase::Complete;
		}
	}

	fn finish_headers_phase(&mut self) {
		self.phase = if self.expect_body_response {
			RequestPhase::AwaitingBody
		} else {
			RequestPhase::Complete
		};
	}

	fn enter_streaming_continuation(&mut self) {
		self.phase = RequestPhase::StreamingContinuation;
	}

	fn advance_after_response(&mut self, headers_done: bool) -> bool {
		if headers_done {
			self.finish_headers_phase();
		}
		self.phase != RequestPhase::AwaitingHeaders
	}

	fn should_restore_original_buffered_body(&self, body_no_mutation: bool) -> bool {
		body_no_mutation && self.expect_body_response && self.body_path != BodyPath::FullDuplex
	}

	fn should_fail_open_on_disconnect(&self, failure_mode: FailureMode) -> bool {
		failure_mode == FailureMode::FailOpen
			&& (!self.had_body || self.body_path != BodyPath::FullDuplex)
	}
}

impl From<BodySendMode> for BodyPath {
	fn from(mode: BodySendMode) -> Self {
		match mode {
			BodySendMode::None => BodyPath::None,
			BodySendMode::Buffered => BodyPath::Buffered,
			BodySendMode::BufferedPartial => BodyPath::BufferedPartial,
			BodySendMode::FullDuplexStreamed => BodyPath::FullDuplex,
		}
	}
}

// Response-side execution FSM mirroring RequestFlowFsm. This controls local
// phase progression in mutate_response independently of protocol mode storage.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ResponsePhase {
	AwaitingHeaders,
	AwaitingBody,
	StreamingContinuation,
	Complete,
}

#[derive(Debug, Copy, Clone)]
struct ResponseFlowFsm {
	phase: ResponsePhase,
	body_path: BodyPath,
	had_body: bool,
	send_body: bool,
}

enum ResponseLoopMessage {
	Immediate(PolicyResponse),
	Processing(ProcessingResponse),
}

struct RequestLoopStep {
	transitioned: bool,
	eos: bool,
	body_no_mutation: bool,
}

#[derive(Copy, Clone)]
struct BodyMessageFns {
	body: fn(HttpBody) -> Request,
	trailers: fn(HttpTrailers) -> Request,
}

impl BodyMessageFns {
	const REQUEST: Self = Self {
		body: Request::RequestBody,
		trailers: Request::RequestTrailers,
	};
	const RESPONSE: Self = Self {
		body: Request::ResponseBody,
		trailers: Request::ResponseTrailers,
	};
}

impl ResponseFlowFsm {
	fn new(send_headers: bool, body_mode: BodySendMode, had_body: bool) -> Self {
		let body_path = BodyPath::from(body_mode);
		let send_body = body_path != BodyPath::None && had_body;
		let phase = if send_headers {
			ResponsePhase::AwaitingHeaders
		} else if send_body {
			ResponsePhase::AwaitingBody
		} else {
			ResponsePhase::Complete
		};
		Self {
			phase,
			body_path,
			had_body,
			send_body,
		}
	}

	fn reconcile_potential_mode_override(&mut self, mode: BodySendMode) {
		self.body_path = BodyPath::from(mode);
		self.send_body = self.body_path != BodyPath::None && self.had_body;
		if self.phase == ResponsePhase::AwaitingBody && !self.send_body {
			self.phase = ResponsePhase::Complete;
		}
	}

	fn finish_headers_phase(&mut self) {
		self.phase = if self.send_body {
			ResponsePhase::AwaitingBody
		} else {
			ResponsePhase::Complete
		};
	}

	fn enter_streaming_continuation(&mut self) {
		self.phase = ResponsePhase::StreamingContinuation;
	}

	fn advance_after_response(&mut self, headers_done: bool) -> bool {
		if headers_done {
			self.finish_headers_phase();
		}
		self.phase != ResponsePhase::AwaitingHeaders
	}

	fn should_restore_original_buffered_body(&self, body_no_mutation: bool) -> bool {
		body_no_mutation && self.send_body && self.body_path != BodyPath::FullDuplex
	}
}

#[derive(Debug, Default)]
struct FirstExtProcMessage {
	attributes: Option<HashMap<String, Struct>>,
	protocol_config: Option<ProtocolConfiguration>,
}

impl FirstExtProcMessage {
	fn for_body_phase(
		send_headers: bool,
		send_body: bool,
		attributes: HashMap<String, Struct>,
		protocol_config: ProtocolConfiguration,
		protocol_config_sent: bool,
	) -> Self {
		Self {
			attributes: (!send_headers && send_body).then_some(attributes),
			protocol_config: (!send_headers && send_body && !protocol_config_sent)
				.then_some(protocol_config),
		}
	}

	fn take_attributes_or_default(&mut self) -> HashMap<String, Struct> {
		self.attributes.take().unwrap_or_default()
	}

	fn take_protocol_config(&mut self) -> Option<ProtocolConfiguration> {
		self.protocol_config.take()
	}

	fn has_protocol_config(&self) -> bool {
		self.protocol_config.is_some()
	}

	fn take_for_send(message: &mut Self) -> (Self, bool) {
		let message = std::mem::take(message);
		let sends_protocol_config = message.has_protocol_config();
		(message, sends_protocol_config)
	}
}

enum BufferedBodyPhase {
	Deferred {
		body: http::Body,
		mode: BodySendMode,
		limit: usize,
		error_message: &'static str,
	},
	Replaying {
		original: bytes::Bytes,
	},
	PartialReplaying {
		original: Option<bytes::Bytes>,
		remainder: Option<http::Body>,
	},
}

enum PendingBufferedBody {
	Body {
		body: http::Body,
		handle: bufferbody::BufferedBodyHandle,
		error_message: &'static str,
	},
	Partial {
		body: bytes::Bytes,
		end_stream: bool,
		trailers: Option<::http::HeaderMap>,
	},
}

impl BufferedBodyPhase {
	fn new(body: http::Body, mode: BodySendMode, limit: usize, error_message: &'static str) -> Self {
		Self::Deferred {
			body,
			mode,
			limit,
			error_message,
		}
	}

	async fn take_pending_send(
		phase: &mut Option<Self>,
	) -> Result<Option<PendingBufferedBody>, Error> {
		let Some(buffered_body) = phase.take() else {
			return Ok(None);
		};
		match buffered_body {
			Self::Deferred {
				body,
				mode,
				limit,
				error_message,
			} => match mode {
				BodySendMode::Buffered => {
					let (buffered_body, handle) = bufferbody::BufferedBody::new_with_limit(body, limit);
					Ok(Some(PendingBufferedBody::Body {
						body: http::Body::new(buffered_body),
						handle,
						error_message,
					}))
				},
				BodySendMode::BufferedPartial => {
					let buffered = buffer_body_partial(body, limit, error_message).await?;
					*phase = Some(Self::PartialReplaying {
						original: Some(buffered.body.clone()),
						remainder: buffered.remainder,
					});
					Ok(Some(PendingBufferedBody::Partial {
						body: buffered.body,
						end_stream: buffered.end_stream,
						trailers: buffered.trailers,
					}))
				},
				_ => Ok(None),
			},
			replaying @ Self::Replaying { .. } => {
				*phase = Some(replaying);
				Ok(None)
			},
			partial @ Self::PartialReplaying { .. } => {
				*phase = Some(partial);
				Ok(None)
			},
		}
	}

	fn take_deferred_body(phase: &mut Option<Self>) -> Option<http::Body> {
		let deferred = phase.take()?;
		match deferred {
			Self::Deferred { body, .. } => Some(body),
			other => {
				*phase = Some(other);
				None
			},
		}
	}

	fn update_deferred_mode(phase: &mut Option<Self>, next_mode: BodySendMode) {
		if let Some(Self::Deferred { mode, .. }) = phase.as_mut() {
			*mode = next_mode;
		}
	}

	fn take_partial_remainder(phase: &mut Option<Self>) -> Option<http::Body> {
		let buffered = phase.take()?;
		match buffered {
			Self::PartialReplaying { remainder, .. } => remainder,
			other => {
				*phase = Some(other);
				None
			},
		}
	}

	fn replay_from_handle(
		phase: &mut Option<Self>,
		handle: bufferbody::BufferedBodyHandle,
	) -> Result<(), Error> {
		let Some(original) = handle.bytes() else {
			return Err(Error::BodyBuffer(
				"buffered body completed without captured bytes".into(),
			));
		};
		*phase = Some(Self::Replaying { original });
		Ok(())
	}

	async fn restore_original_if(
		phase: &mut Option<Self>,
		restore: bool,
		body_tx: &mut Sender<Result<Frame<Bytes>, Infallible>>,
	) {
		if !restore {
			return;
		}
		let Some(buffered_body) = phase.take() else {
			return;
		};
		match buffered_body {
			Self::Replaying { original } => {
				let _ = body_tx.send(Ok(Frame::data(original))).await;
			},
			Self::PartialReplaying {
				mut original,
				remainder,
			} => {
				if let Some(original) = original.take()
					&& !original.is_empty()
				{
					let _ = body_tx.send(Ok(Frame::data(original))).await;
				}
				*phase = Some(Self::PartialReplaying {
					original,
					remainder,
				});
			},
			other => {
				*phase = Some(other);
			},
		}
	}
}

struct BufferedPartialBody {
	body: bytes::Bytes,
	end_stream: bool,
	trailers: Option<::http::HeaderMap>,
	remainder: Option<http::Body>,
}

pin_project! {
	// Body wrapper used when the configured partial-buffer limit falls in the middle of a data
	// frame. The bytes after the limit have already been read, so replay them before polling the
	// original body for the rest of the stream.
	struct RemainderBody {
		prefix: Option<bytes::Bytes>,
		#[pin]
		inner: http::Body,
	}
}

impl RemainderBody {
	fn new(prefix: Option<bytes::Bytes>, inner: http::Body) -> Self {
		Self { prefix, inner }
	}
}

impl Body for RemainderBody {
	type Data = Bytes;
	type Error = axum_core::Error;

	fn poll_frame(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let this = self.project();
		if let Some(prefix) = this.prefix.take()
			&& !prefix.is_empty()
		{
			return Poll::Ready(Some(Ok(Frame::data(prefix))));
		}
		this.inner.poll_frame(cx)
	}

	fn is_end_stream(&self) -> bool {
		self.prefix.as_ref().map(Bytes::is_empty).unwrap_or(true) && self.inner.is_end_stream()
	}

	fn size_hint(&self) -> SizeHint {
		let prefix_len = self.prefix.as_ref().map(Bytes::len).unwrap_or_default() as u64;
		let mut hint = self.inner.size_hint();
		hint.set_lower(hint.lower().saturating_add(prefix_len));
		if let Some(upper) = hint.upper() {
			hint.set_upper(upper.saturating_add(prefix_len));
		}
		hint
	}
}

async fn buffer_body_partial(
	mut body: http::Body,
	limit: usize,
	error_message: &'static str,
) -> Result<BufferedPartialBody, Error> {
	// A zero-byte limit still means BufferedPartial should send a body message to ext_proc; it
	// just contains no data and the original body remains entirely local pass-through.
	if limit == 0 {
		return Ok(BufferedPartialBody {
			body: bytes::Bytes::new(),
			end_stream: false,
			trailers: None,
			remainder: Some(body),
		});
	}

	let mut buffer = BufList::default();
	let mut buffered = 0usize;
	let mut trailers = None;
	loop {
		let Some(frame) = body
			.frame()
			.await
			.transpose()
			.map_err(|e| Error::BodyBuffer(format!("{error_message}: {e}")))?
		else {
			let body = buffered_bytes(buffer);
			return Ok(BufferedPartialBody {
				body,
				end_stream: trailers.is_none(),
				trailers,
				remainder: None,
			});
		};

		match frame.into_data().map_err(Frame::into_trailers) {
			Ok(mut data) => {
				let len = data.remaining();
				let remaining_limit = limit.saturating_sub(buffered);
				if len <= remaining_limit {
					// The whole frame fits in the partial buffer. If this reaches the limit and
					// the body is not at EOF, stop reading and leave the rest for normal upstream
					// or downstream forwarding.
					let bytes = data.copy_to_bytes(len);
					if bytes.has_remaining() {
						buffer.push(bytes);
						buffered += len;
					}
					if buffered == limit && !body.is_end_stream() {
						return Ok(BufferedPartialBody {
							body: buffered_bytes(buffer),
							end_stream: false,
							trailers: None,
							remainder: Some(body),
						});
					}
				} else {
					// The frame crosses the partial-buffer boundary. Split it so ext_proc sees
					// only the prefix, then replay the remaining bytes before polling the body
					// again.
					let prefix = data.copy_to_bytes(remaining_limit);
					if prefix.has_remaining() {
						buffer.push(prefix);
					}
					let rest = data.copy_to_bytes(data.remaining());
					let remainder = http::Body::new(RemainderBody::new(Some(rest), body));
					return Ok(BufferedPartialBody {
						body: buffered_bytes(buffer),
						end_stream: false,
						trailers: None,
						remainder: Some(remainder),
					});
				}
			},
			Err(Ok(frame_trailers)) => {
				trailers = Some(frame_trailers);
			},
			Err(Err(_unknown)) => {
				tracing::warn!("An unknown body frame has been buffered");
				return Ok(BufferedPartialBody {
					body: buffered_bytes(buffer),
					end_stream: true,
					trailers,
					remainder: None,
				});
			},
		}
	}
}

fn buffered_bytes(mut buffer: BufList) -> bytes::Bytes {
	let len = buffer.remaining();
	buffer.copy_to_bytes(len)
}

fn attach_request_body_channel(
	req: http::Request,
	rx_chunk: &mut Option<Receiver<Result<Frame<Bytes>, Infallible>>>,
) -> (http::Request, http::Body) {
	let (parts, body) = req.into_parts();
	let rx_chunk = rx_chunk
		.take()
		.expect("request body channel should only be attached once");
	let upstream_body = http_body_util::StreamBody::new(ReceiverStream::new(rx_chunk));
	(
		http::Request::from_parts(parts, http::Body::new(upstream_body)),
		body,
	)
}

#[cfg(debug_assertions)]
fn debug_assert_preserved_request_body(req: &http::Request, had_body: bool, context: &'static str) {
	if had_body {
		debug_assert!(
			!req.body().is_end_stream(),
			"{context}: returning request should preserve the original non-empty body"
		);
	}
}

#[cfg(not(debug_assertions))]
fn debug_assert_preserved_request_body(
	_req: &http::Request,
	_had_body: bool,
	_context: &'static str,
) {
}

fn should_buffer_body(body_mode: BodySendMode, had_body: bool) -> bool {
	had_body
		&& matches!(
			body_mode,
			BodySendMode::Buffered | BodySendMode::BufferedPartial
		)
}

fn start_buffered_request_body(
	req: http::Request,
	body_mode: BodySendMode,
	had_body: bool,
	rx_chunk: &mut Option<Receiver<Result<Frame<Bytes>, Infallible>>>,
) -> (http::Request, Option<BufferedBodyPhase>) {
	if !should_buffer_body(body_mode, had_body) {
		return (req, None);
	}
	let max_request_bytes = http::buffer_limit(&req);
	let (req, req_body) = attach_request_body_channel(req, rx_chunk);
	let phase = BufferedBodyPhase::new(
		req_body,
		body_mode,
		max_request_bytes,
		"failed to read request body for buffering",
	);
	(req, Some(phase))
}

fn start_buffered_response_body(
	body: &mut Option<http::Body>,
	body_mode: BodySendMode,
	had_body: bool,
	max_response_bytes: usize,
) -> Option<BufferedBodyPhase> {
	if !should_buffer_body(body_mode, had_body) {
		return None;
	}
	let body = body
		.take()
		.expect("response body should be available before buffering starts");
	Some(BufferedBodyPhase::new(
		body,
		body_mode,
		max_response_bytes,
		"failed to read response body for buffering",
	))
}

#[apply(schema!)]
pub struct ExtProc {
	/// Reference to the external processing service backend
	#[serde(flatten)]
	pub target: Arc<SimpleBackendReference>,
	/// Policies to connect to the backend
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	#[serde(deserialize_with = "crate::types::local::de_from_local_backend_policy")]
	#[cfg_attr(
		feature = "schema",
		schemars(with = "Option<crate::types::local::SimpleLocalBackendPolicies>")
	)]
	pub policies: Vec<BackendTrafficPolicy>,
	/// Behavior when the ext_proc service is unavailable or returns an error
	#[serde(default)]
	pub failure_mode: FailureMode,

	/// Additional metadata to send to the external processing service.
	/// Maps to the `metadata_context.filter_metadata` field in ProcessingRequest, and allows dynamic CEL expressions.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub metadata_context: Option<HashMap<String, HashMap<String, Arc<cel::Expression>>>>,

	/// Maps to the request `attributes` field in ProcessingRequest, and allows dynamic CEL expressions.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub request_attributes: Option<HashMap<String, Arc<cel::Expression>>>,
	/// Maps to the response `attributes` field in ProcessingRequest, and allows dynamic CEL expressions.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub response_attributes: Option<HashMap<String, Arc<cel::Expression>>>,
	#[serde(default)]
	pub processing_options: ProcessingOptions,
}

impl ExtProc {
	pub fn build(&self, client: PolicyClient) -> ExtProcRequest {
		ExtProcRequest {
			ext_proc: Some(ExtProcInstance::new(
				client,
				self.policies.clone(),
				self.target.clone(),
				self.failure_mode,
				self.metadata_context.clone(),
				self.request_attributes.clone(),
				self.response_attributes.clone(),
				self.processing_options,
			)),
		}
	}

	pub fn expressions(&self) -> Box<dyn Iterator<Item = &Expression> + '_> {
		Box::new(
			self
				.metadata_context
				.iter()
				.flat_map(|m| {
					m.values()
						.flat_map(|inner| inner.values().map(AsRef::as_ref))
				})
				.chain(
					self
						.request_attributes
						.iter()
						.chain(self.response_attributes.iter())
						.flat_map(|m| m.values().map(AsRef::as_ref)),
				),
		)
	}
}

impl crate::store::HasExpressions for ExtProc {
	fn expressions(&self) -> impl Iterator<Item = &Expression> {
		ExtProc::expressions(self)
	}
}

#[derive(Debug)]
pub struct ExtProcRequest {
	ext_proc: Option<ExtProcInstance>,
}

impl ExtProcRequest {
	pub async fn mutate_request(
		&mut self,
		req: &mut http::Request,
	) -> Result<PolicyResponse, ProxyError> {
		let Some(ext_proc) = &mut self.ext_proc else {
			return Ok(PolicyResponse::default());
		};
		let r = std::mem::take(req);
		let (new_req, pr) = ext_proc.mutate_request(r).await?;
		*req = new_req;
		let pr = pr.unwrap_or_default();
		pol_result!(
			dtrace::Info,
			Apply,
			"ext_proc request ({})",
			dtrace::policy_response_details(&pr)
		);
		Ok(pr)
	}

	pub async fn mutate_response(
		&mut self,
		resp: &mut http::Response,
		request: Option<&RequestSnapshot>,
	) -> Result<PolicyResponse, ProxyError> {
		let Some(ext_proc) = &mut self.ext_proc else {
			return Ok(PolicyResponse::default());
		};
		let r = std::mem::take(resp);
		let (new_resp, pr) = ext_proc.mutate_response(r, request, None).await?;
		*resp = new_resp;
		let pr = pr.unwrap_or_default();
		pol_result!(
			dtrace::Info,
			Apply,
			"ext_proc response ({})",
			dtrace::policy_response_details(&pr)
		);
		Ok(pr)
	}
}

// Very experimental support for ext_proc
#[derive(Debug)]
struct ExtProcInstance {
	failure_mode: FailureMode,
	skipped: bool,
	protocol_config_sent: bool,
	mode_state: ModeStateMachine,
	tx_req: Sender<ProcessingRequest>,
	rx_resp_for_request: Option<Receiver<ProcessingResponse>>,
	rx_resp_for_response: Option<Receiver<ProcessingResponse>>,
	metadata_context: Option<HashMap<String, HashMap<String, Arc<cel::Expression>>>>,
	req_attributes: Option<HashMap<String, Arc<cel::Expression>>>,
	resp_attributes: Option<HashMap<String, Arc<cel::Expression>>>,
}

impl ExtProcInstance {
	#[allow(clippy::too_many_arguments)]
	fn new(
		client: PolicyClient,
		policies: Vec<BackendTrafficPolicy>,
		target: Arc<SimpleBackendReference>,
		failure_mode: FailureMode,
		metadata_context: Option<HashMap<String, HashMap<String, Arc<cel::Expression>>>>,
		req_attributes: Option<HashMap<String, Arc<cel::Expression>>>,
		resp_attributes: Option<HashMap<String, Arc<cel::Expression>>>,
		processing_options: ProcessingOptions,
	) -> ExtProcInstance {
		trace!("connecting to {:?}", target);
		let chan = GrpcReferenceChannel {
			target,
			client,
			policies: Arc::new(policies),
		};
		let mut c = proto::external_processor_client::ExternalProcessorClient::new(chan);
		let (tx_req, rx_req) = tokio::sync::mpsc::channel(10);
		let (tx_resp, mut rx_resp) = tokio::sync::mpsc::channel(10);
		let req_stream = tokio_stream::wrappers::ReceiverStream::new(rx_req);
		tokio::task::spawn(async move {
			// Spawn a task to handle processing requests.
			// Incoming requests get send to tx_req and will be piped through here.
			let responses = match c.process(req_stream).await {
				Ok(r) => r,
				Err(e) => {
					warn!(?failure_mode, "failed to initialize extproc client: {e:?}");
					return;
				},
			};
			trace!("initial stream established");
			let mut responses = responses.into_inner();
			while let Ok(Some(item)) = responses.message().await {
				trace!("received response item {item:?}");
				let _ = tx_resp.send(item).await;
			}
		});
		let (tx_resp_for_request, rx_resp_for_request) = tokio::sync::mpsc::channel(1);
		let (tx_resp_for_response, rx_resp_for_response) = tokio::sync::mpsc::channel(1);
		tokio::task::spawn(async move {
			while let Some(item) = rx_resp.recv().await {
				match &item.response {
					Some(processing_response::Response::ResponseBody(_))
					| Some(processing_response::Response::ResponseHeaders(_))
					| Some(processing_response::Response::ResponseTrailers(_)) => {
						let _ = tx_resp_for_response.send(item).await;
					},
					Some(processing_response::Response::RequestBody(_))
					| Some(processing_response::Response::RequestHeaders(_))
					| Some(processing_response::Response::RequestTrailers(_)) => {
						let _ = tx_resp_for_request.send(item).await;
					},
					Some(processing_response::Response::ImmediateResponse(_)) => {
						// In this case we aren't sure which is going to handle things...
						// Send to both
						let _ = tx_resp_for_request.send(item.clone()).await;
						let _ = tx_resp_for_response.send(item).await;
					},
					None => {},
				}
			}
		});
		Self {
			skipped: Default::default(),
			failure_mode,
			protocol_config_sent: false,
			mode_state: processing_options.into(),
			tx_req,
			rx_resp_for_request: Some(rx_resp_for_request),
			rx_resp_for_response: Some(rx_resp_for_response),
			metadata_context,
			req_attributes,
			resp_attributes,
		}
	}

	async fn send_request(&mut self, req: ProcessingRequest) -> Result<(), Error> {
		self.tx_req.send(req).await.map_err(|_| Error::RequestSend)
	}

	fn protocol_config_for_headers(
		&self,
		protocol_config: ProtocolConfiguration,
	) -> (Option<ProtocolConfiguration>, bool) {
		let sends_protocol_config = !self.protocol_config_sent;
		(
			sends_protocol_config.then_some(protocol_config),
			sends_protocol_config,
		)
	}

	fn mark_protocol_config_sent_if(&mut self, sent: bool) {
		if sent {
			self.protocol_config_sent = true;
		}
	}

	async fn send_pending_buffered_body(
		&mut self,
		buffered_body: &mut Option<BufferedBodyPhase>,
		metadata_context: &Option<Arc<Metadata>>,
		first_message: &mut FirstExtProcMessage,
		message_fns: BodyMessageFns,
		send_trailers: bool,
	) -> Result<bool, Error> {
		let Some(pending) = BufferedBodyPhase::take_pending_send(buffered_body).await? else {
			return Ok(false);
		};
		match pending {
			PendingBufferedBody::Body {
				body,
				handle,
				error_message,
			} => {
				let (first_message, sends_protocol_config) =
					FirstExtProcMessage::take_for_send(first_message);
				Self::send_body_stream(
					metadata_context.clone(),
					body,
					self.tx_req.clone(),
					message_fns.body,
					message_fns.trailers,
					send_trailers,
					first_message,
					error_message,
				)
				.await?;
				self.mark_protocol_config_sent_if(sends_protocol_config);
				BufferedBodyPhase::replay_from_handle(buffered_body, handle)?;
			},
			PendingBufferedBody::Partial {
				body,
				end_stream,
				trailers,
			} => {
				let (first_message, sends_protocol_config) =
					FirstExtProcMessage::take_for_send(first_message);
				Self::send_partial_body(
					metadata_context.clone(),
					self.tx_req.clone(),
					message_fns.body,
					message_fns.trailers,
					body,
					end_stream,
					trailers,
					send_trailers,
					first_message,
				)
				.await?;
				self.mark_protocol_config_sent_if(sends_protocol_config);
			},
		}
		Ok(true)
	}

	#[allow(clippy::too_many_arguments)]
	async fn send_partial_body(
		metadata_context: Option<Arc<Metadata>>,
		tx: Sender<ProcessingRequest>,
		body_fn: fn(HttpBody) -> Request,
		trail_fn: fn(HttpTrailers) -> Request,
		body: bytes::Bytes,
		end_stream: bool,
		trailers: Option<::http::HeaderMap>,
		send_trailers: bool,
		first_message: FirstExtProcMessage,
	) -> Result<(), Error> {
		let mut first_message = first_message;
		tx.send(ProcessingRequest {
			request: Some(body_fn(HttpBody {
				body: body.into(),
				end_of_stream: end_stream,
			})),
			metadata_context: metadata_context.as_deref().cloned(),
			attributes: first_message.take_attributes_or_default(),
			protocol_config: first_message.take_protocol_config(),
			observability_mode: false,
		})
		.await
		.map_err(|_| Error::RequestSend)?;

		let Some(trailers) = trailers else {
			return Ok(());
		};
		if send_trailers {
			tx.send(ProcessingRequest {
				request: Some(trail_fn(HttpTrailers {
					trailers: to_header_map(&trailers),
				})),
				metadata_context: metadata_context.as_deref().cloned(),
				attributes: first_message.take_attributes_or_default(),
				protocol_config: first_message.take_protocol_config(),
				observability_mode: false,
			})
			.await
			.map_err(|_| Error::RequestSend)?;
		}
		tx.send(ProcessingRequest {
			request: Some(body_fn(HttpBody {
				body: Default::default(),
				end_of_stream: true,
			})),
			metadata_context: metadata_context.and_then(Arc::into_inner),
			attributes: first_message.take_attributes_or_default(),
			protocol_config: first_message.take_protocol_config(),
			observability_mode: false,
		})
		.await
		.map_err(|_| Error::RequestSend)?;
		Ok(())
	}

	fn spawn_body_stream(
		&self,
		metadata_context: &Option<Arc<Metadata>>,
		pending_body: &mut Option<http::Body>,
		tx: Sender<ProcessingRequest>,
		message_fns: BodyMessageFns,
		send_trailers: bool,
		first_message: FirstExtProcMessage,
		missing_body_message: &'static str,
	) {
		tokio::task::spawn(Self::handle_body_stream(
			metadata_context.clone(),
			pending_body.take().expect(missing_body_message),
			tx,
			message_fns.body,
			message_fns.trailers,
			send_trailers,
			first_message,
		));
	}

	async fn recv_response_loop_message(
		rx: &mut Receiver<ProcessingResponse>,
	) -> Result<ResponseLoopMessage, Error> {
		let Some(presp) = rx.recv().await else {
			trace!("done receiving response");
			return Err(Error::NoMoreResponses);
		};
		if let Some(dr) = to_immediate_response(&presp) {
			trace!("got immediate response in request handler");
			return Ok(ResponseLoopMessage::Immediate(dr));
		}
		Ok(ResponseLoopMessage::Processing(presp))
	}

	async fn process_response_loop_message(
		&mut self,
		presp: ProcessingResponse,
		resp: Option<&mut http::Response>,
		tx_chunk: &mut Sender<Result<Frame<Bytes>, Infallible>>,
		response_fsm: &mut ResponseFlowFsm,
		send_response_headers: bool,
		ignore_mode_override: bool,
	) -> (bool, bool) {
		if matches!(presp.response, Some(Response::ResponseHeaders(_))) {
			self
				.mode_state
				.mark_headers_processed(HeaderPhase::Response);
			if ignore_mode_override && presp.mode_override.is_some() {
				warn!("received mode_override after full-duplex response body streaming started; ignoring");
			} else {
				self.maybe_apply_mode_override(HeaderPhase::Response, &presp);
			}
			response_fsm.reconcile_potential_mode_override(self.mode_state.response_body_mode);
		}
		let (headers_done, eos) = handle_response_for_response_mutation(
			response_fsm.send_body,
			send_response_headers,
			resp,
			tx_chunk,
			presp,
		)
		.await;
		(response_fsm.advance_after_response(headers_done), eos)
	}

	async fn process_request_loop_message(
		&mut self,
		presp: ProcessingResponse,
		req: Option<&mut http::Request>,
		tx_chunk: &mut Sender<Result<Frame<Bytes>, Infallible>>,
		request_fsm: &mut RequestFlowFsm,
		send_request_headers: bool,
		ignore_mode_override: bool,
	) -> RequestLoopStep {
		let body_no_mutation = request_body_response_has_no_mutation(&presp);
		if matches!(presp.response, Some(Response::RequestHeaders(_))) {
			self.mode_state.mark_headers_processed(HeaderPhase::Request);
			if ignore_mode_override && presp.mode_override.is_some() {
				warn!("received mode_override after full-duplex request body streaming started; ignoring");
			} else {
				self.maybe_apply_mode_override(HeaderPhase::Request, &presp);
			}
			request_fsm.reconcile_potential_mode_override(self.mode_state.request_body_mode);
		}
		let (headers_done, eos) = handle_response_for_request_mutation(
			request_fsm.expect_body_response,
			send_request_headers,
			req,
			tx_chunk,
			presp,
		)
		.await;
		RequestLoopStep {
			transitioned: request_fsm.advance_after_response(headers_done),
			eos,
			body_no_mutation,
		}
	}

	async fn forward_response_stream_continuation(
		mut rx: Receiver<ProcessingResponse>,
		mut tx_chunk: Sender<Result<Frame<Bytes>, Infallible>>,
		send_response_body: bool,
		send_response_headers: bool,
	) {
		loop {
			let Some(presp) = rx.recv().await else {
				trace!("done receiving response");
				return;
			};
			let (_, eos) = handle_response_for_response_mutation(
				send_response_body,
				send_response_headers,
				None,
				&mut tx_chunk,
				presp,
			)
			.await;
			if eos || !send_response_body {
				trace!("response EOS!");
				drop(tx_chunk);
				return;
			}
		}
	}

	fn protocol_config(&self) -> ProtocolConfiguration {
		ProtocolConfiguration {
			request_body_mode: self.mode_state.request_body_mode.into(),
			response_body_mode: self.mode_state.response_body_mode.into(),
			..Default::default()
		}
	}

	fn maybe_apply_mode_override(&mut self, phase: HeaderPhase, presp: &ProcessingResponse) {
		let Some(mode_override) = presp.mode_override.as_ref() else {
			return;
		};
		// This updates mode_state (protocol configuration). RequestFlowFsm/
		// ResponseFlowFsm are synced from mode_state when we consume header-phase
		// responses in the mutate_* loops.
		let valid_phase_response = matches!(
			(phase, &presp.response),
			(
				HeaderPhase::Request,
				Some(processing_response::Response::RequestHeaders(_))
			) | (
				HeaderPhase::Response,
				Some(processing_response::Response::ResponseHeaders(_))
			)
		);
		if !valid_phase_response {
			warn!(phase = ?phase, "received mode_override outside matching headers response phase; ignoring");
			return;
		}
		if !self.mode_state.allow_mode_override {
			warn!("received mode_override but allow_mode_override is disabled; ignoring");
			return;
		}
		self
			.mode_state
			.apply_envoy_mode_override(phase, mode_override);
	}

	pub async fn mutate_request(
		&mut self,
		mut req: http::Request,
	) -> Result<(http::Request, Option<PolicyResponse>), Error> {
		let headers = req_to_header_map(&req);

		let exec = cel::Executor::new_request(&req);
		// request_attributes should only be sent on first ProcessingRequest
		// this will need to be modified if we configure which Requests to send
		// Wrap metadata_context in Arc for cheap cloning across body chunks
		let metadata_context = self.metadata_context.as_ref().map(|meta| {
			Arc::new(Metadata {
				filter_metadata: meta
					.iter()
					.filter_map(|(n, e)| {
						eval_to_struct(&exec, e).map(|v| (n.clone(), v)).ok() // TODO(mk): where best to log convertion issues
					})
					.collect(),
			})
		});
		let attributes = self
			.req_attributes
			.as_ref()
			.and_then(|attrs| {
				eval_to_struct(&exec, attrs)
					.map(|v| HashMap::from([(EXTPROC_ATTRIBUTES_NAMESPACE.to_string(), v)]))
					.ok()
			})
			.unwrap_or_default();

		let failure_mode = self.failure_mode;
		let end_of_stream = req.body().is_end_stream();
		let had_body = !end_of_stream;
		let send_request_headers = self.mode_state.request_header_mode == HeaderSendMode::Send;
		let send_request_trailers = self.mode_state.request_trailer_mode == TrailerSendMode::Send;
		let req_body_mode = self.mode_state.request_body_mode;
		// request_fsm is method-local execution state (what phase mutate_request is
		// waiting on). mode_state is protocol state that can be updated by
		// mode_override responses.
		let mut request_fsm = RequestFlowFsm::new(send_request_headers, had_body, req_body_mode);
		let protocol_config = self.protocol_config();
		// If request headers are skipped, the first body-phase ProcessingRequest must carry
		// attributes/protocol_config, and subsequent ProcessingRequests must not.
		let mut first_message_when_headers_skipped = FirstExtProcMessage::for_body_phase(
			send_request_headers,
			request_fsm.expect_body_response,
			attributes.clone(),
			protocol_config,
			self.protocol_config_sent,
		);

		// Send request headers unless processing options explicitly skip this phase.
		if send_request_headers {
			let (header_protocol_config, sends_protocol_config) =
				self.protocol_config_for_headers(protocol_config);
			if let Err(e) = self
				.send_request(ProcessingRequest {
					request: Some(Request::RequestHeaders(HttpHeaders {
						headers,
						end_of_stream,
					})),
					metadata_context: metadata_context.as_deref().cloned(),
					attributes: attributes.clone(),
					protocol_config: header_protocol_config,
					observability_mode: false,
				})
				.await
			{
				if failure_mode == FailureMode::FailOpen {
					trace!("fail open triggered");
					self.skipped = true;
					debug_assert_preserved_request_body(
						&req,
						had_body,
						"fail_open_after_request_header_send_failure_preserves_original_body",
					);
					return Ok((req, None));
				}
				return Err(e);
			}
			self.mark_protocol_config_sent_if(sends_protocol_config);
		}

		if request_fsm.phase == RequestPhase::Complete {
			// Nothing to send for request-side processing. Keep the original request intact; this
			// includes initial requestBodyMode=None when request headers are skipped.
			debug_assert_preserved_request_body(
				&req,
				had_body,
				"complete_request_phase_preserves_original_body",
			);
			return Ok((req, None));
		}

		let tx = self.tx_req.clone();
		let (mut tx_chunk, rx_chunk) = tokio::sync::mpsc::channel(1);
		let mut rx_chunk = Some(rx_chunk);
		let mut pending_full_duplex_body = None;

		// FULL_DUPLEX_STREAMED sends body chunks as they arrive. The ext_proc server may buffer
		// the headers and complete body before sending any response, so waiting for the headers
		// response here would deadlock that valid server behavior.
		let request_body_streamed_before_header_response =
			req_body_mode == BodySendMode::FullDuplexStreamed && had_body;
		if request_body_streamed_before_header_response {
			let (req_with_channel, body) = attach_request_body_channel(req, &mut rx_chunk);
			req = req_with_channel;
			pending_full_duplex_body = Some(body);
			let (first_message, sends_protocol_config) =
				FirstExtProcMessage::take_for_send(&mut first_message_when_headers_skipped);
			self.spawn_body_stream(
				&metadata_context,
				&mut pending_full_duplex_body,
				tx.clone(),
				BodyMessageFns::REQUEST,
				send_request_trailers,
				first_message,
				"request body should be available before streaming starts",
			);
			self.mark_protocol_config_sent_if(sends_protocol_config);
		}

		// Common response-processing loop shared across all body modes.
		let mut rx = self
			.rx_resp_for_request
			.take()
			.expect("mutate_request called twice");
		// For buffered modes: send the held body after headers_done. Buffered drains to EOF;
		// BufferedPartial sends one prefix and keeps the remainder for local pass-through.
		let mut pending_buffered_body = None;
		if request_fsm.phase != RequestPhase::AwaitingHeaders
			&& matches!(
				request_fsm.body_path,
				BodyPath::Buffered | BodyPath::BufferedPartial
			) && pending_buffered_body.is_none()
			&& rx_chunk.is_some()
		{
			let (req_with_channel, buffered_body) = start_buffered_request_body(
				req,
				self.mode_state.request_body_mode,
				had_body,
				&mut rx_chunk,
			);
			req = req_with_channel;
			pending_buffered_body = buffered_body;
		}
		if request_fsm.phase != RequestPhase::AwaitingHeaders
			&& let Err(e) = self
				.send_pending_buffered_body(
					&mut pending_buffered_body,
					&metadata_context,
					&mut first_message_when_headers_skipped,
					BodyMessageFns::REQUEST,
					send_request_trailers,
				)
				.await
		{
			if failure_mode == FailureMode::FailOpen {
				trace!("fail open triggered");
				self.skipped = true;
				debug_assert_preserved_request_body(
					&req,
					had_body && rx_chunk.is_some(),
					"fail_open_before_request_body_phase_preserves_original_body",
				);
				return Ok((req, None));
			}
			return Err(e);
		}
		loop {
			let Some(presp) = rx.recv().await else {
				// Fail-open unless we're mid-stream (FullDuplexStreamed with body in flight),
				// where failing open could silently corrupt data.
				if request_fsm.should_fail_open_on_disconnect(failure_mode) {
					trace!("fail open triggered");
					self.skipped = true;
					debug_assert_preserved_request_body(
						&req,
						had_body && rx_chunk.is_some(),
						"fail_open_on_disconnect_preserves_original_body_before_body_phase",
					);
					return Ok((req, None));
				}
				trace!("done receiving request");
				return Err(Error::NoMoreResponses);
			};
			if let Some(resp) = to_immediate_response(&presp) {
				trace!("got immediate response in request handler");
				return Ok((req, Some(resp)));
			}
			let step = self
				.process_request_loop_message(
					presp,
					Some(&mut req),
					&mut tx_chunk,
					&mut request_fsm,
					send_request_headers,
					request_body_streamed_before_header_response,
				)
				.await;
			BufferedBodyPhase::update_deferred_mode(
				&mut pending_buffered_body,
				self.mode_state.request_body_mode,
			);
			BufferedBodyPhase::restore_original_if(
				&mut pending_buffered_body,
				request_fsm.should_restore_original_buffered_body(step.body_no_mutation),
				&mut tx_chunk,
			)
			.await;
			if step.transitioned {
				match request_fsm.body_path {
					BodyPath::Buffered | BodyPath::BufferedPartial => {
						// For buffered modes: ext_proc has finished with the headers. Buffer and
						// send the body now, after any headers mode_override has settled the
						// effective body mode.
						if pending_buffered_body.is_none() && rx_chunk.is_some() {
							let (req_with_channel, buffered_body) = start_buffered_request_body(
								req,
								self.mode_state.request_body_mode,
								had_body,
								&mut rx_chunk,
							);
							req = req_with_channel;
							pending_buffered_body = buffered_body;
						}
						match self
							.send_pending_buffered_body(
								&mut pending_buffered_body,
								&metadata_context,
								&mut first_message_when_headers_skipped,
								BodyMessageFns::REQUEST,
								send_request_trailers,
							)
							.await
						{
							Ok(true) => {
								// Loop again to receive the RequestBody response from ext_proc.
								continue;
							},
							Ok(false) => {},
							Err(e) => {
								if failure_mode == FailureMode::FailOpen {
									trace!("fail open triggered");
									self.skipped = true;
									return Ok((req, None));
								}
								return Err(e);
							},
						}
					},
					BodyPath::FullDuplex => {
						if pending_full_duplex_body.is_none() {
							pending_full_duplex_body =
								BufferedBodyPhase::take_deferred_body(&mut pending_buffered_body);
							if pending_full_duplex_body.is_none() && rx_chunk.is_some() {
								let (req_with_channel, body) = attach_request_body_channel(req, &mut rx_chunk);
								req = req_with_channel;
								pending_full_duplex_body = Some(body);
							}
						}
					},
					BodyPath::None => {
						if let Some(original_body) =
							BufferedBodyPhase::take_deferred_body(&mut pending_buffered_body)
						{
							let (parts, _) = req.into_parts();
							let req = http::Request::from_parts(parts, original_body);
							debug_assert_preserved_request_body(
								&req,
								had_body,
								"body_mode_override_none_restores_original_body",
							);
							return Ok((req, None));
						}
						debug_assert_preserved_request_body(
							&req,
							had_body && rx_chunk.is_some(),
							"body_mode_override_none_preserves_original_body",
						);
						return Ok((req, None));
					},
				}

				if let Some(remainder) =
					BufferedBodyPhase::take_partial_remainder(&mut pending_buffered_body)
				{
					Self::spawn_forward_body_to_channel(
						remainder,
						tx_chunk.clone(),
						"failed to forward unprocessed request body remainder",
					);
				}

				if pending_full_duplex_body.is_some() && request_fsm.expect_body_response {
					let (first_message, sends_protocol_config) =
						FirstExtProcMessage::take_for_send(&mut first_message_when_headers_skipped);
					self.spawn_body_stream(
						&metadata_context,
						&mut pending_full_duplex_body,
						tx.clone(),
						BodyMessageFns::REQUEST,
						send_request_trailers,
						first_message,
						"request body should be available before streaming continuation starts",
					);
					self.mark_protocol_config_sent_if(sends_protocol_config);
				}

				if !step.eos && request_fsm.body_path != BodyPath::BufferedPartial {
					request_fsm.enter_streaming_continuation();
					trace!("spawn body!");
					// Move remaining body response handling to an async task so we can return
					// the request to the caller while body chunks continue to flow.
					tokio::task::spawn(async move {
						loop {
							let Some(presp) = rx.recv().await else {
								trace!("done receiving request");
								return;
							};
							let (_, eos) = handle_response_for_request_mutation(
								request_fsm.expect_body_response,
								send_request_headers,
								None,
								&mut tx_chunk,
								presp,
							)
							.await;
							if eos || !request_fsm.expect_body_response {
								trace!("request EOS!");
								drop(tx_chunk);
								return;
							}
						}
					});
				}
				if request_fsm.expect_body_response {
					// Skip content-length when the request body passed through ext_proc, since the
					// body may have been rewritten and we do not recompute the final byte length.
					req.headers_mut().remove(http::header::CONTENT_LENGTH);
				}
				return Ok((req, None));
			}
		}
	}

	#[allow(clippy::too_many_arguments)]
	async fn handle_body_stream(
		metadata_context: Option<Arc<Metadata>>,
		body: http::Body,
		tx: Sender<ProcessingRequest>,
		body_fn: fn(HttpBody) -> Request,
		trail_fn: fn(HttpTrailers) -> Request,
		send_trailers: bool,
		first_message: FirstExtProcMessage,
	) {
		if let Err(error) = Self::send_body_stream(
			metadata_context,
			body,
			tx,
			body_fn,
			trail_fn,
			send_trailers,
			first_message,
			"failed to read body stream",
		)
		.await
		{
			match error {
				Error::RequestSend => trace!("body stream stopped after ext_proc request channel closed"),
				error => warn!("body stream stopped: {error}"),
			}
		}
	}

	#[allow(clippy::too_many_arguments)]
	async fn send_body_stream(
		metadata_context: Option<Arc<Metadata>>,
		mut body: http::Body,
		tx: Sender<ProcessingRequest>,
		body_fn: fn(HttpBody) -> Request,
		trail_fn: fn(HttpTrailers) -> Request,
		send_trailers: bool,
		first_message: FirstExtProcMessage,
		body_error_message: &'static str,
	) -> Result<(), Error> {
		let mut first_message = first_message;
		let mut sent_end_stream = false;
		while let Some(frame) = body
			.frame()
			.await
			.transpose()
			.map_err(|e| Error::BodyBuffer(format!("{body_error_message}: {e}")))?
		{
			let request = Some(if frame.is_data() {
				let frame = frame.into_data().expect("already checked");
				let end_of_stream = body.is_end_stream();
				sent_end_stream |= end_of_stream;
				trace!("sending body chunk...",);
				body_fn(HttpBody {
					body: frame,
					end_of_stream,
				})
			} else if frame.is_trailers() {
				if !send_trailers {
					continue;
				}
				let frame = frame.into_trailers().expect("already checked");
				trail_fn(HttpTrailers {
					trailers: to_header_map(&frame),
				})
			} else {
				// http_body::Frame only has data and trailers variants
				unreachable!("Frame is neither data nor trailers")
			});
			tx.send(ProcessingRequest {
				request,
				metadata_context: metadata_context.as_deref().cloned(),
				attributes: first_message.take_attributes_or_default(),
				protocol_config: first_message.take_protocol_config(),
				observability_mode: false,
			})
			.await
			.map_err(|_| Error::RequestSend)?;
		}

		if sent_end_stream {
			trace!("body request done");
			return Ok(());
		}

		// Send end of stream marker - try to unwrap Arc to avoid final clone
		let final_metadata = metadata_context.and_then(Arc::into_inner);
		tx.send(ProcessingRequest {
			request: Some(body_fn(HttpBody {
				body: Default::default(),
				end_of_stream: true,
			})),
			metadata_context: final_metadata,
			attributes: first_message.take_attributes_or_default(),
			protocol_config: first_message.take_protocol_config(),
			observability_mode: false,
		})
		.await
		.map_err(|_| Error::RequestSend)?;
		trace!("body request done");
		Ok(())
	}

	async fn forward_body_to_channel(
		mut body: http::Body,
		tx_chunk: Sender<Result<Frame<Bytes>, Infallible>>,
		body_error_message: &'static str,
	) -> Result<(), Error> {
		while let Some(frame) = body
			.frame()
			.await
			.transpose()
			.map_err(|e| Error::BodyBuffer(format!("{body_error_message}: {e}")))?
		{
			tx_chunk
				.send(Ok(frame))
				.await
				.map_err(|_| Error::RequestSend)?;
		}
		Ok(())
	}

	fn spawn_forward_body_to_channel(
		body: http::Body,
		tx_chunk: Sender<Result<Frame<Bytes>, Infallible>>,
		body_error_message: &'static str,
	) {
		tokio::task::spawn(async move {
			if let Err(error) = Self::forward_body_to_channel(body, tx_chunk, body_error_message).await {
				match error {
					Error::RequestSend => trace!("body remainder stopped after body channel closed"),
					error => warn!("body remainder stopped: {error}"),
				}
			}
		});
	}

	pub async fn mutate_response(
		&mut self,
		response: http::Response,
		request: Option<&RequestSnapshot>,
		resolved_destination_metadata: Option<SocketAddr>,
	) -> Result<(http::Response, Option<PolicyResponse>), Error> {
		if self.skipped {
			return Ok((response, None));
		}
		let headers = resp_to_header_map(&response);
		let send_response_headers = self.mode_state.response_header_mode == HeaderSendMode::Send;
		let send_response_trailers = self.mode_state.response_trailer_mode == TrailerSendMode::Send;

		let exec = cel::Executor::new_response(request, &response);
		// Wrap metadata_context in Arc for cheap cloning across body chunks
		let metadata_context = if self.metadata_context.is_none()
			&& let Some(rd) = resolved_destination_metadata
		{
			Some(Arc::new(Metadata {
				filter_metadata: HashMap::from([(
					// This is gross, but the GIE project unfairly favors Envoy, so we have to adapt to its limitations.
					"envoy.lb".to_string(),
					serde_json::from_value(serde_json::json!({"x-gateway-destination-endpoint-served": rd}))
						.unwrap(),
				)]),
			}))
		} else {
			self.metadata_context.as_ref().map(|meta| {
				Arc::new(Metadata {
					filter_metadata: meta
						.iter()
						.filter_map(|(n, e)| eval_to_struct(&exec, e).map(|v| (n.clone(), v)).ok())
						.collect(),
				})
			})
		};
		// response_attributes should only be sent on first ProcessingRequest
		// this will need to be modified if we configure which Requests to send
		let attributes = self
			.resp_attributes
			.as_ref()
			.and_then(|attrs| {
				eval_to_struct(&exec, attrs)
					.map(|v| HashMap::from([(EXTPROC_ATTRIBUTES_NAMESPACE.to_string(), v)]))
					.ok()
			})
			.unwrap_or_default();
		let max_response_bytes = http::response_buffer_limit(&response);
		let (parts, body) = response.into_parts();
		let end_of_stream = body.is_end_stream();
		let had_body = !end_of_stream;
		let response_body_mode = self.mode_state.response_body_mode;
		// response_fsm drives local flow in mutate_response, while mode_state tracks
		// the currently effective ext_proc processing modes.
		let mut response_fsm =
			ResponseFlowFsm::new(send_response_headers, response_body_mode, had_body);
		let protocol_config = self.protocol_config();
		let mut first_message = FirstExtProcMessage::for_body_phase(
			send_response_headers,
			response_fsm.send_body,
			attributes.clone(),
			protocol_config,
			self.protocol_config_sent,
		);

		// Send the response headers to ext_proc.
		// No response side fail_open handling.
		if send_response_headers {
			let (header_protocol_config, sends_protocol_config) =
				self.protocol_config_for_headers(protocol_config);
			self
				.send_request(ProcessingRequest {
					request: Some(Request::ResponseHeaders(HttpHeaders {
						headers,
						end_of_stream,
					})),
					metadata_context: metadata_context.as_deref().cloned(),
					attributes: attributes.clone(),
					protocol_config: header_protocol_config,
					observability_mode: false,
				})
				.await?;
			self.mark_protocol_config_sent_if(sends_protocol_config);
		}

		if response_fsm.phase == ResponsePhase::Complete {
			return Ok((http::Response::from_parts(parts, body), None));
		}

		let tx = self.tx_req.clone();
		let mut pending_response_body = Some(body);
		let mut pending_response_buffer = None;
		// Now we need to build the new body. This is going to be streamed in from the ext_proc server.
		let (mut tx_chunk, rx_chunk) = tokio::sync::mpsc::channel(1);
		let body = http_body_util::StreamBody::new(ReceiverStream::new(rx_chunk));
		let mut resp = http::Response::from_parts(parts, http::Body::new(body));

		// FULL_DUPLEX_STREAMED sends response body chunks as they arrive. The ext_proc server may
		// buffer the response headers and complete body before sending any response, so do not wait
		// for the response-headers ProcessingResponse before forwarding body frames to ext_proc.
		let response_body_streamed_before_header_response =
			response_body_mode == BodySendMode::FullDuplexStreamed && had_body;
		if response_body_streamed_before_header_response {
			let (first_message, sends_protocol_config) =
				FirstExtProcMessage::take_for_send(&mut first_message);
			self.spawn_body_stream(
				&metadata_context,
				&mut pending_response_body,
				tx.clone(),
				BodyMessageFns::RESPONSE,
				send_response_trailers,
				first_message,
				"response body should be available before streaming starts",
			);
			self.mark_protocol_config_sent_if(sends_protocol_config);
		} else if !send_response_headers && had_body {
			pending_response_buffer = start_buffered_response_body(
				&mut pending_response_body,
				response_body_mode,
				had_body,
				max_response_bytes,
			);
			let sent_buffered = self
				.send_pending_buffered_body(
					&mut pending_response_buffer,
					&metadata_context,
					&mut first_message,
					BodyMessageFns::RESPONSE,
					send_response_trailers,
				)
				.await?;
			if !sent_buffered {
				let (first_message, sends_protocol_config) =
					FirstExtProcMessage::take_for_send(&mut first_message);
				self.spawn_body_stream(
					&metadata_context,
					&mut pending_response_body,
					tx.clone(),
					BodyMessageFns::RESPONSE,
					send_response_trailers,
					first_message,
					"response body should be available before streaming starts",
				);
				self.mark_protocol_config_sent_if(sends_protocol_config);
			}
		}

		let mut rx = self
			.rx_resp_for_response
			.take()
			.expect("mutate_response called twice");
		loop {
			let msg = Self::recv_response_loop_message(&mut rx).await?;
			let (transitioned, eos) = match msg {
				ResponseLoopMessage::Immediate(dr) => return Ok((resp, Some(dr))),
				ResponseLoopMessage::Processing(presp) => {
					let response_body_no_mutation = response_body_response_has_no_mutation(&presp);
					let result = self
						.process_response_loop_message(
							presp,
							Some(&mut resp),
							&mut tx_chunk,
							&mut response_fsm,
							send_response_headers,
							response_body_streamed_before_header_response,
						)
						.await;
					BufferedBodyPhase::update_deferred_mode(
						&mut pending_response_buffer,
						self.mode_state.response_body_mode,
					);
					// For buffered modes: if ext_proc returned no body mutation, forward the
					// original buffered bytes to the client instead of an empty body.
					BufferedBodyPhase::restore_original_if(
						&mut pending_response_buffer,
						response_fsm.should_restore_original_buffered_body(response_body_no_mutation),
						&mut tx_chunk,
					)
					.await;
					result
				},
			};
			if transitioned {
				match response_fsm.body_path {
					BodyPath::Buffered | BodyPath::BufferedPartial if !eos && response_fsm.send_body => {
						if pending_response_buffer.is_none() {
							pending_response_buffer = start_buffered_response_body(
								&mut pending_response_body,
								self.mode_state.response_body_mode,
								had_body,
								max_response_bytes,
							);
						}
						if self
							.send_pending_buffered_body(
								&mut pending_response_buffer,
								&metadata_context,
								&mut first_message,
								BodyMessageFns::RESPONSE,
								send_response_trailers,
							)
							.await?
						{
							continue;
						}
					},
					BodyPath::FullDuplex if !eos && response_fsm.send_body => {
						if pending_response_body.is_none() {
							pending_response_body =
								BufferedBodyPhase::take_deferred_body(&mut pending_response_buffer);
						}
					},
					BodyPath::None => {
						if let Some(original_body) =
							BufferedBodyPhase::take_deferred_body(&mut pending_response_buffer)
						{
							let (parts, _) = resp.into_parts();
							return Ok((http::Response::from_parts(parts, original_body), None));
						}
						if let Some(original_body) = pending_response_body.take() {
							let (parts, _) = resp.into_parts();
							return Ok((http::Response::from_parts(parts, original_body), None));
						}
					},
					_ => {},
				}
				if let Some(remainder) =
					BufferedBodyPhase::take_partial_remainder(&mut pending_response_buffer)
				{
					Self::spawn_forward_body_to_channel(
						remainder,
						tx_chunk.clone(),
						"failed to forward unprocessed response body remainder",
					);
				}
				if !eos && response_fsm.send_body && response_fsm.body_path == BodyPath::FullDuplex {
					if pending_response_body.is_some() {
						let (first_message, sends_protocol_config) =
							FirstExtProcMessage::take_for_send(&mut first_message);
						trace!("spawn body!");
						self.spawn_body_stream(
							&metadata_context,
							&mut pending_response_body,
							tx.clone(),
							BodyMessageFns::RESPONSE,
							send_response_trailers,
							first_message,
							"response body should be available before streaming continuation starts",
						);
						self.mark_protocol_config_sent_if(sends_protocol_config);
					}
					response_fsm.enter_streaming_continuation();
					tokio::task::spawn(Self::forward_response_stream_continuation(
						rx,
						tx_chunk,
						true,
						send_response_headers,
					));
				}
				if response_fsm.send_body {
					// Skip content-length when the response body passed through ext_proc, since the
					// body may have been rewritten and we do not recompute the final byte length.
					resp.headers_mut().remove(http::header::CONTENT_LENGTH);
				}
				return Ok((resp, None));
			}
		}
	}
}

fn to_immediate_response(rp: &ProcessingResponse) -> Option<PolicyResponse> {
	match &rp.response {
		Some(Response::ImmediateResponse(ir)) => {
			let ImmediateResponse {
				status,
				headers,
				body,
				grpc_status: _,
				details: _,
			} = ir;
			let rb =
				::http::response::Builder::new().status(status.map(|s| s.code).unwrap_or(200) as u16);

			let mut resp = rb
				.body(http::Body::from(body.to_string()))
				.map_err(|e| ProxyError::Processing(e.into()))
				.unwrap();
			apply_header_mutations_response(&mut resp, headers.as_ref());
			Some(crate::http::PolicyResponse {
				direct_response: Some(resp),
				response_headers: None,
			})
		},
		_ => None,
	}
}

fn request_body_response_has_no_mutation(presp: &ProcessingResponse) -> bool {
	matches!(
		&presp.response,
		Some(Response::RequestBody(BodyResponse { response: None }))
	) || matches!(
		&presp.response,
		Some(Response::RequestBody(BodyResponse { response: Some(cr) })) if cr.body_mutation.is_none()
	)
}

fn response_body_response_has_no_mutation(presp: &ProcessingResponse) -> bool {
	matches!(
		&presp.response,
		Some(Response::ResponseBody(BodyResponse { response: None }))
	) || matches!(
		&presp.response,
		Some(Response::ResponseBody(BodyResponse { response: Some(cr) })) if cr.body_mutation.is_none()
	)
}

// handle_response_for_request_mutation handles a single ext_proc response. If it returns 'true' we are done processing.
async fn handle_response_for_request_mutation(
	had_body: bool,
	allow_header_mutations: bool,
	mut req: Option<&mut http::Request>,
	body_tx: &mut Sender<Result<Frame<Bytes>, Infallible>>,
	presp: ProcessingResponse,
) -> (bool, bool) {
	if let Some(dm) = &presp.dynamic_metadata {
		if let Some(req) = req.as_mut() {
			if let Err(e) = extract_dynamic_metadata(req, dm) {
				warn!("Failed to extract ext_proc dynamic metadata: {}", e);
			}
		} else if !dm.fields.is_empty() {
			warn!(
				"ext_proc server sent dynamic_metadata after headers were processed; \
					 metadata cannot be attached and will be ignored. Consider sending \
					 metadata in the RequestHeaders response instead."
			);
		}
	}

	let res = matches!(&presp.response, Some(Response::RequestHeaders(_)));
	let is_body_response = matches!(&presp.response, Some(Response::RequestBody(_)));
	let cr = match presp.response {
		Some(Response::RequestHeaders(HeadersResponse { response: None })) => {
			trace!("no headers");
			return (true, !had_body);
		},
		Some(Response::RequestHeaders(HeadersResponse { response: Some(cr) })) => {
			trace!("got request headers back");
			cr
		},
		Some(Response::RequestBody(BodyResponse { response: None })) => {
			trace!("got empty request body back");
			return (false, true);
		},
		Some(Response::RequestBody(BodyResponse { response: Some(cr) })) => {
			trace!("got request body back");
			cr
		},
		Some(Response::ImmediateResponse(_)) => {
			if req.is_none() {
				trace!("immediate response received after request sent; will apply only on the response");
			}
			// Handled out of this function.
			return (true, true);
		},
		msg => {
			// In theory, there can trailers too. EPP never sends them
			warn!("ignoring response during request {msg:?}");
			return (false, false);
		},
	};
	if allow_header_mutations && let Some(req) = req {
		apply_header_mutations_request(req, cr.header_mutation.as_ref());
	}
	if let Some(BodyMutation { mutation: Some(b) }) = cr.body_mutation {
		if !had_body {
			trace!("ignoring request body mutation when no body is expected");
			return (res, true);
		}
		match b {
			Mutation::StreamedResponse(bb) => {
				let eos = bb.end_of_stream;
				let _ = body_tx.send(Ok(Frame::data(bb.body))).await;

				trace!(eos, "got stream request body");
				return (res, eos);
			},
			Mutation::Body(b) => {
				// Used in Buffered mode: ext_proc replaces the entire body at once.
				let _ = body_tx.send(Ok(Frame::data(bytes::Bytes::from(b)))).await;
				return (true, true);
			},
			Mutation::ClearBody(_) => {
				// Body cleared: signal end-of-stream with no data.
				return (true, true);
			},
		}
	} else if !had_body {
		trace!("got headers back and do not expect body; we are done");
		return (res, true);
	} else if is_body_response {
		trace!("got request body back without body mutation; forwarding original body");
		return (true, true);
	}
	trace!("still waiting for response...");
	(res, false)
}

fn apply_header_mutations_request(req: &mut http::Request, h: Option<&HeaderMutation>) {
	if let Some(hm) = h {
		for rm in &hm.remove_headers {
			req.headers_mut().remove(rm);
		}
		for set in &hm.set_headers {
			envoy_proto_common::apply_header_option(&mut req.into(), set);
		}
	}
}

fn apply_header_mutations_response(resp: &mut http::Response, h: Option<&HeaderMutation>) {
	if let Some(hm) = h {
		for rm in &hm.remove_headers {
			resp.headers_mut().remove(rm);
		}
		for set in &hm.set_headers {
			envoy_proto_common::apply_header_option(&mut resp.into(), set);
		}
	}
}

fn merge_dynamic_metadata(
	extensions: &mut ::http::Extensions,
	metadata: &prost_wkt_types::Struct,
) -> Result<(), Error> {
	let mut dynamic_metadata = extensions
		.remove::<ExtProcDynamicMetadata>()
		.unwrap_or_default();

	for (key, value) in &metadata.fields {
		let json_val = envoy_proto_common::prost_value_to_json(value)
			.map_err(|e| Error::MetadataConversion(format!("failed to convert key '{}': {}", key, e)))?;
		dynamic_metadata.0.insert(key.clone(), json_val);
	}

	if !dynamic_metadata.0.is_empty() {
		extensions.insert(dynamic_metadata);
	}

	Ok(())
}

// handle_response_for_response_mutation handles a single ext_proc response. If it returns 'true' we are done processing.
async fn handle_response_for_response_mutation(
	had_body: bool,
	allow_header_mutations: bool,
	mut resp: Option<&mut http::Response>,
	body_tx: &mut Sender<Result<Frame<Bytes>, Infallible>>,
	presp: ProcessingResponse,
) -> (bool, bool) {
	if let Some(dm) = &presp.dynamic_metadata {
		if let Some(resp) = resp.as_mut() {
			if let Err(e) = extract_dynamic_metadata_response(resp, dm) {
				warn!("Failed to extract ext_proc dynamic metadata: {}", e);
			}
		} else if !dm.fields.is_empty() {
			warn!(
				"ext_proc server sent dynamic_metadata after response headers were processed; \
				 metadata cannot be attached and will be ignored. Consider sending \
				 metadata in the ResponseHeaders response instead."
			);
		}
	}

	let res = matches!(&presp.response, Some(Response::ResponseHeaders(_)));
	let is_body_response = matches!(&presp.response, Some(Response::ResponseBody(_)));
	let cr = match presp.response {
		Some(Response::ResponseHeaders(HeadersResponse { response: None })) => {
			trace!("no headers");
			return (res, false);
		},
		Some(Response::ResponseHeaders(HeadersResponse { response: Some(cr) })) => cr,
		Some(Response::ResponseBody(BodyResponse { response: Some(cr) })) => cr,
		Some(Response::ResponseBody(BodyResponse { response: None })) => {
			trace!("got empty response body back");
			return (res, true);
		},
		msg => {
			// In theory, there can trailers too. EPP never sends them
			warn!("ignoring {msg:?}");
			return (res, false);
		},
	};
	if allow_header_mutations && let Some(resp) = resp {
		apply_header_mutations_response(resp, cr.header_mutation.as_ref());
	}
	if let Some(BodyMutation { mutation: Some(b) }) = cr.body_mutation {
		if !had_body {
			trace!("ignoring response body mutation when no body is expected");
			return (res, true);
		}
		match b {
			Mutation::StreamedResponse(bb) => {
				let eos = bb.end_of_stream;
				let _ = body_tx.send(Ok(Frame::data(bb.body))).await;
				trace!(%eos, "got body chunk");
				return (res, eos);
			},
			Mutation::Body(b) => {
				let _ = body_tx.send(Ok(Frame::data(bytes::Bytes::from(b)))).await;
				return (true, true);
			},
			Mutation::ClearBody(_) => {
				return (true, true);
			},
		}
	} else if !had_body {
		trace!("got headers back and do not expect body; we are done");
		return (res, true);
	} else if is_body_response {
		trace!("got response body back without body mutation; forwarding original body");
		return (true, true);
	}
	trace!("still waiting for response for response...");
	(res, false)
}

fn req_to_header_map(req: &http::Request) -> Option<proto::HeaderMap> {
	let mut pseudo = crate::http::get_request_pseudo_headers(req);
	let has_scheme = pseudo
		.iter()
		.any(|(p, _)| matches!(p, crate::http::HeaderOrPseudo::Scheme));
	if !has_scheme {
		// Default to http when scheme is not explicitly present on the request URI
		pseudo.push((crate::http::HeaderOrPseudo::Scheme, "http".to_string()));
	}
	let pseudo_header_pairs: Vec<(String, String)> = pseudo
		.into_iter()
		.map(|(p, v)| (p.to_string(), v))
		.collect();
	to_header_map_extra(
		req.headers(),
		&pseudo_header_pairs
			.iter()
			.map(|(k, v)| (k.as_str(), v.as_str()))
			.collect::<Vec<_>>(),
	)
}

fn resp_to_header_map(res: &http::Response) -> Option<proto::HeaderMap> {
	to_header_map_extra(res.headers(), &[(":status", res.status().as_str())])
}

fn to_header_map(headers: &http::HeaderMap) -> Option<proto::HeaderMap> {
	to_header_map_extra(headers, &[])
}

fn to_header_map_extra(
	headers: &http::HeaderMap,
	additional_headers: &[(&str, &str)],
) -> Option<proto::HeaderMap> {
	let h = headers
		.iter()
		.map(|(k, v)| proto::HeaderValue {
			key: k.to_string(),
			value: String::new(),
			raw_value: v.as_bytes().to_vec(),
		})
		.chain(additional_headers.iter().map(|(k, v)| proto::HeaderValue {
			key: k.to_string(),
			value: v.to_string(),
			raw_value: vec![],
		}))
		.collect_vec();
	Some(proto::HeaderMap { headers: h })
}

fn eval_expression(exec: &Executor, v: &Expression) -> Result<prost_wkt_types::Value, ProxyError> {
	let res = exec.eval(v).map_err(|e| ProxyError::Processing(e.into()))?;
	let js = res
		.json()
		.map_err(|_| ProxyError::Processing(cel::Error::JsonConvert.into()))?;
	envoy_proto_common::json_to_prost_value(js)
}

fn eval_to_struct(
	exec: &Executor<'_>,
	expressions: &HashMap<String, Arc<cel::Expression>>,
) -> Result<prost_wkt_types::Struct, ProxyError> {
	Ok(Struct {
		fields: expressions
			.iter()
			.filter_map(|(key, expr)| match eval_expression(exec, expr) {
				Ok(result) => Some((key.clone(), result)),
				Err(error) => {
					warn!(%key, %error, "failed to evaluate metadata_context CEL expression");
					None
				},
			})
			.collect(),
	})
}

pub(crate) fn extract_dynamic_metadata(
	req: &mut http::Request,
	metadata: &prost_wkt_types::Struct,
) -> Result<(), Error> {
	merge_dynamic_metadata(req.extensions_mut(), metadata)
}

fn extract_dynamic_metadata_response(
	resp: &mut http::Response,
	metadata: &prost_wkt_types::Struct,
) -> Result<(), Error> {
	merge_dynamic_metadata(resp.extensions_mut(), metadata)
}

#[derive(Clone, Debug)]
pub struct GrpcReferenceChannel {
	pub target: Arc<SimpleBackendReference>,
	pub client: PolicyClient,
	pub policies: Arc<Vec<BackendTrafficPolicy>>,
}

impl tower::Service<::http::Request<tonic::body::Body>> for GrpcReferenceChannel {
	type Response = http::Response;
	type Error = ProxyError;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		Ok(()).into()
	}

	fn call(&mut self, req: ::http::Request<tonic::body::Body>) -> Self::Future {
		let client = self.client.clone();
		let target = self.target.clone();
		let policies = self.policies.clone();
		let req = req.map(http::Body::new);
		Box::pin(async move {
			client
				.call_reference_with_policies(req, &target, policies.as_slice())
				.await
		})
	}
}
