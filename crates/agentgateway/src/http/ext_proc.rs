use std::convert::Infallible;

use anyhow::anyhow;
use bytes::Bytes;
use http_body::{Body, Frame};
use http_body_util::BodyStream;
use itertools::Itertools;
use prost_wkt_types::Struct;
use proto::body_mutation::Mutation;
use proto::processing_request::Request;
use proto::processing_response::Response;
use protos::envoy::service::ext_proc::v3::{
	BodySendMode as EnvoyBodySendMode, ProtocolConfiguration,
};
use serde_json::Value as JsonValue;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;

use crate::cel::{Executor, Expression, RequestSnapshot};
use crate::client::ResolvedDestination;
use crate::http::bufferbody::BufferRequestBodyError;
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
	#[default]
	None,
	Buffered,
	BufferedPartial,
	FullDuplexStreamed,
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
		let failed_open = ext_proc.did_fail_open();
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
	pub request_body_mode: BodySendMode,
	pub response_body_mode: BodySendMode,
	pub request_header_mode: HeaderSendMode,
	pub response_header_mode: HeaderSendMode,
	pub request_trailer_mode: TrailerSendMode,
	pub response_trailer_mode: TrailerSendMode,
	#[serde(default)]
	pub allow_mode_override: bool,
	#[serde(default)]
	pub send_body_without_waiting_for_header_response: bool,
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
			send_body_without_waiting_for_header_response: false,
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
// HTTP exchange. This is the protocol-facing state: it stores what we believe
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
	send_body_without_waiting_for_header_response: bool,
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
			send_body_without_waiting_for_header_response: opts
				.send_body_without_waiting_for_header_response,
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

	fn allow_mode_override(&self) -> bool {
		self.allow_mode_override
	}

	fn send_body_without_waiting_for_header_response(&self) -> bool {
		self.send_body_without_waiting_for_header_response
	}

	fn mark_headers_processed(&mut self, phase: HeaderPhase) {
		match phase {
			HeaderPhase::Request => self.request_headers_processed = true,
			HeaderPhase::Response => self.response_headers_processed = true,
		}
	}

	fn apply_envoy_mode_override(&mut self, phase: HeaderPhase, mode: &proto::ProcessingMode) {
		use proto::processing_mode::{
			BodySendMode as ProtoBodySendMode, HeaderSendMode as ProtoHeaderSendMode,
		};
		let phase_name = match phase {
			HeaderPhase::Request => "request_headers",
			HeaderPhase::Response => "response_headers",
		};

		if mode.request_header_mode != ProtoHeaderSendMode::Default as i32 {
			warn!(
				phase = phase_name,
				"mode_override.request_header_mode is ignored by protocol"
			);
		}

		if let Ok(hm) = ProtoHeaderSendMode::try_from(mode.response_header_mode) {
			match hm {
				ProtoHeaderSendMode::Default => {},
				ProtoHeaderSendMode::Send if !self.response_headers_processed => {
					self.response_header_mode = HeaderSendMode::Send;
				},
				ProtoHeaderSendMode::Skip if !self.response_headers_processed => {
					self.response_header_mode = HeaderSendMode::Skip;
				},
				_ => {},
			}
		}

		if let Ok(bm) = ProtoBodySendMode::try_from(mode.request_body_mode) {
			match bm {
				// TODO: Should we abort the stream?
				ProtoBodySendMode::Streamed => {
					warn!(
						phase = phase_name,
						"mode_override request_body_mode=STREAMED is not implemented; keeping current request body mode"
					)
				},
				_ if !Self::current_mode_allows_body_override(
					self.request_body_mode,
					phase,
					BodyModeOverrideDirection::Request,
				) => {},
				ProtoBodySendMode::None => {
					self.request_body_mode = BodySendMode::None;
				},
				ProtoBodySendMode::Buffered => {
					self.request_body_mode = BodySendMode::Buffered;
				},
				ProtoBodySendMode::BufferedPartial => {
					self.request_body_mode = BodySendMode::BufferedPartial;
				},
				ProtoBodySendMode::FullDuplexStreamed => {
					self.request_body_mode = BodySendMode::FullDuplexStreamed;
				},
			}
		}

		if let Ok(bm) = ProtoBodySendMode::try_from(mode.response_body_mode) {
			match bm {
				ProtoBodySendMode::Streamed => {
					warn!(
						phase = phase_name,
						"mode_override response_body_mode=STREAMED is not implemented; keeping current response body mode"
					)
				},
				_ if !Self::current_mode_allows_body_override(
					self.response_body_mode,
					phase,
					BodyModeOverrideDirection::Response,
				) => {},
				ProtoBodySendMode::None => {
					self.response_body_mode = BodySendMode::None;
				},
				ProtoBodySendMode::Buffered => {
					self.response_body_mode = BodySendMode::Buffered;
				},
				ProtoBodySendMode::BufferedPartial => {
					self.response_body_mode = BodySendMode::BufferedPartial;
				},
				ProtoBodySendMode::FullDuplexStreamed => {
					self.response_body_mode = BodySendMode::FullDuplexStreamed;
				},
			}
		}

		if let Ok(hm) = ProtoHeaderSendMode::try_from(mode.request_trailer_mode) {
			match hm {
				ProtoHeaderSendMode::Default => {},
				ProtoHeaderSendMode::Send => self.request_trailer_mode = TrailerSendMode::Send,
				ProtoHeaderSendMode::Skip => self.request_trailer_mode = TrailerSendMode::Skip,
			}
		}
		if let Ok(hm) = ProtoHeaderSendMode::try_from(mode.response_trailer_mode) {
			match hm {
				ProtoHeaderSendMode::Default => {},
				ProtoHeaderSendMode::Send => self.response_trailer_mode = TrailerSendMode::Send,
				ProtoHeaderSendMode::Skip => self.response_trailer_mode = TrailerSendMode::Skip,
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
	fn new(send_headers: bool, had_body: bool, body_mode: EnvoyBodySendMode) -> Self {
		let body_path = match body_mode {
			EnvoyBodySendMode::None => BodyPath::None,
			EnvoyBodySendMode::Buffered | EnvoyBodySendMode::BufferedPartial => BodyPath::Buffered,
			EnvoyBodySendMode::FullDuplexStreamed => BodyPath::FullDuplex,
			EnvoyBodySendMode::Streamed => {
				warn!("request body mode STREAMED is not implemented; disabling request body phase");
				BodyPath::None
			},
		};
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

	fn sync_body_path_from_mode(&mut self, mode: BodySendMode) {
		self.body_path = match mode {
			BodySendMode::None => BodyPath::None,
			BodySendMode::Buffered | BodySendMode::BufferedPartial => BodyPath::Buffered,
			BodySendMode::FullDuplexStreamed => BodyPath::FullDuplex,
		};
		self.expect_body_response = self.body_path != BodyPath::None && self.had_body;
		if self.phase == RequestPhase::AwaitingBody && !self.expect_body_response {
			self.phase = RequestPhase::Complete;
		}
	}

	fn reconcile_headers_response(&mut self, mode: BodySendMode) {
		self.sync_body_path_from_mode(mode);
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

	fn is_awaiting_headers(&self) -> bool {
		self.phase == RequestPhase::AwaitingHeaders
	}

	fn advance_after_response(&mut self, headers_done: bool) -> bool {
		if headers_done {
			self.finish_headers_phase();
		}
		!self.is_awaiting_headers()
	}

	fn should_restore_original_buffered_body(&self, body_no_mutation: bool) -> bool {
		body_no_mutation && self.expect_body_response && self.body_path != BodyPath::FullDuplex
	}

	fn should_fail_open_on_disconnect(&self, failure_mode: FailureMode) -> bool {
		failure_mode == FailureMode::FailOpen
			&& (!self.had_body || self.body_path != BodyPath::FullDuplex)
	}

	fn strip_content_length(&self) -> bool {
		self.expect_body_response
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
	had_body: bool,
	send_body: bool,
}

enum ResponseLoopMessage {
	Immediate(PolicyResponse),
	Processing(ProcessingResponse),
}

impl ResponseFlowFsm {
	fn new(send_headers: bool, send_body: bool, had_body: bool) -> Self {
		let phase = if send_headers {
			ResponsePhase::AwaitingHeaders
		} else if send_body {
			ResponsePhase::AwaitingBody
		} else {
			ResponsePhase::Complete
		};
		Self {
			phase,
			had_body,
			send_body,
		}
	}

	fn sync_send_body_from_mode(&mut self, mode: BodySendMode) {
		self.send_body = mode != BodySendMode::None && self.had_body;
		if self.phase == ResponsePhase::AwaitingBody && !self.send_body {
			self.phase = ResponsePhase::Complete;
		}
	}

	fn reconcile_headers_response(&mut self, mode: BodySendMode) {
		self.sync_send_body_from_mode(mode);
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

	fn is_awaiting_headers(&self) -> bool {
		self.phase == ResponsePhase::AwaitingHeaders
	}

	fn advance_after_response(&mut self, headers_done: bool) -> bool {
		if headers_done {
			self.finish_headers_phase();
		}
		!self.is_awaiting_headers()
	}

	fn strip_content_length(&self) -> bool {
		self.send_body
	}
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
	fn did_fail_open(&self) -> bool {
		self.skipped
	}

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

	async fn send_buffered_request_body(
		&mut self,
		buf: bytes::Bytes,
		metadata_context: &Option<Arc<Metadata>>,
		first_request_attributes: &mut Option<HashMap<String, Struct>>,
		first_request_protocol_config: &mut Option<ProtocolConfiguration>,
	) -> Result<(), Error> {
		let include_protocol = first_request_protocol_config.is_some();
		self
			.send_request(ProcessingRequest {
				request: Some(Request::RequestBody(HttpBody {
					body: buf.to_vec(),
					end_of_stream: true,
				})),
				metadata_context: metadata_context.as_deref().cloned(),
				attributes: first_request_attributes.take().unwrap_or_default(),
				protocol_config: first_request_protocol_config.take(),
				observability_mode: false,
			})
			.await?;
		if include_protocol {
			self.protocol_config_sent = true;
		}
		Ok(())
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
	) -> (bool, bool) {
		if matches!(presp.response, Some(Response::ResponseHeaders(_))) {
			self
				.mode_state
				.mark_headers_processed(HeaderPhase::Response);
			self.maybe_apply_mode_override(HeaderPhase::Response, &presp);
			response_fsm.reconcile_headers_response(self.mode_state.response_body_mode);
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
		let req_body_mode = match self.mode_state.request_body_mode {
			BodySendMode::None => EnvoyBodySendMode::None,
			BodySendMode::Buffered => EnvoyBodySendMode::Buffered,
			BodySendMode::BufferedPartial => EnvoyBodySendMode::BufferedPartial,
			BodySendMode::FullDuplexStreamed => EnvoyBodySendMode::FullDuplexStreamed,
		};
		let resp_body_mode = match self.mode_state.response_body_mode {
			BodySendMode::None => EnvoyBodySendMode::None,
			BodySendMode::Buffered => EnvoyBodySendMode::Buffered,
			BodySendMode::BufferedPartial => EnvoyBodySendMode::BufferedPartial,
			BodySendMode::FullDuplexStreamed => EnvoyBodySendMode::FullDuplexStreamed,
		};
		ProtocolConfiguration {
			request_body_mode: req_body_mode.into(),
			response_body_mode: resp_body_mode.into(),
			send_body_without_waiting_for_header_response: self
				.mode_state
				.send_body_without_waiting_for_header_response(),
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
		if !self.mode_state.allow_mode_override() {
			warn!("received mode_override but allow_mode_override is disabled; ignoring");
			return;
		}
		if self
			.mode_state
			.send_body_without_waiting_for_header_response()
		{
			warn!(
				"received mode_override while send_body_without_waiting_for_header_response=true; ignoring"
			);
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
		let req_body_mode = match self.mode_state.request_body_mode {
			BodySendMode::None => EnvoyBodySendMode::None,
			BodySendMode::Buffered => EnvoyBodySendMode::Buffered,
			BodySendMode::BufferedPartial => EnvoyBodySendMode::BufferedPartial,
			BodySendMode::FullDuplexStreamed => EnvoyBodySendMode::FullDuplexStreamed,
		};
		// request_fsm is method-local execution state (what phase mutate_request is
		// waiting on). mode_state is protocol state that can be updated by
		// mode_override responses.
		let mut request_fsm = RequestFlowFsm::new(send_request_headers, had_body, req_body_mode);
		let protocol_config = self.protocol_config();
		// If request headers are skipped, the first body-phase ProcessingRequest must carry
		// attributes/protocol_config, and subsequent ProcessingRequests must not.
		let mut first_request_attributes = (!send_request_headers).then(|| attributes.clone());
		let mut first_request_protocol_config =
			(!send_request_headers && !self.protocol_config_sent).then_some(protocol_config);

		// For buffered modes, kick off body buffering concurrently with sending headers so the
		// network round-trip for header processing overlaps with reading the request body.
		// We will await the result only after the headers response has been received.
		type BufferResult = Result<bytes::Bytes, Error>;
		let body_buffer_task: Option<tokio::task::JoinHandle<BufferResult>> = match req_body_mode {
			EnvoyBodySendMode::Buffered | EnvoyBodySendMode::BufferedPartial if had_body => {
				let body_opts = bufferbody::BodyOptions {
					allow_partial_message: req_body_mode == EnvoyBodySendMode::BufferedPartial,
					pack_as_bytes: true, // Envoy ext_proc always packs buffered bodies as bytes
					..Default::default()
				};
				// Detach the body from `req` so the buffer task can drain it independently,
				// while we continue with the (now body-less) `req` for header sending.
				let (req_parts, req_body) = req.into_parts();
				// Wrap in a minimal request since buffer_request_body takes &mut Request.
				let mut body_req = http::Request::new(req_body);
				let handle = tokio::task::spawn(async move {
					match bufferbody::buffer_request_body(&mut body_req, &body_opts).await {
						Ok(buffered) => Ok(buffered.body),
						Err(BufferRequestBodyError::TooLarge) => Err(Error::BodyBuffer(format!(
							"body exceeded max buffer size of {} bytes",
							body_opts.max_request_bytes
						))),
						Err(BufferRequestBodyError::Read(e)) => Err(Error::BodyBuffer(format!(
							"failed to read body for buffering: {e}"
						))),
					}
				});
				// Rebuild req with an empty body; the real body is being drained by the task.
				req = http::Request::from_parts(req_parts, http::Body::empty());
				Some(handle)
			},
			_ => None,
		};

		// Send request headers unless processing options explicitly skip this phase.
		if send_request_headers
			&& let Err(e) = self
				.send_request(ProcessingRequest {
					request: Some(Request::RequestHeaders(HttpHeaders {
						headers,
						end_of_stream,
					})),
					metadata_context: metadata_context.as_deref().cloned(),
					attributes: attributes.clone(),
					protocol_config: (!self.protocol_config_sent).then_some(protocol_config),
					observability_mode: false,
				})
				.await
		{
			if failure_mode == FailureMode::FailOpen {
				trace!("fail open triggered");
				self.skipped = true;
				return Ok((req, None));
			}
			return Err(e);
		}
		if send_request_headers {
			self.protocol_config_sent = true;
		}

		// BodySendMode::None means request bodies are never sent to ext_proc and must
		// continue upstream unchanged.
		if req_body_mode == EnvoyBodySendMode::None {
			if !send_request_headers {
				return Ok((req, None));
			}

			let mut rx = self
				.rx_resp_for_request
				.take()
				.expect("mutate_request called twice");
			let (mut tx_chunk, _rx_chunk) = tokio::sync::mpsc::channel(1);
			loop {
				let Some(presp) = rx.recv().await else {
					if failure_mode == FailureMode::FailOpen {
						trace!("fail open triggered");
						self.skipped = true;
						return Ok((req, None));
					}
					trace!("done receiving request");
					return Err(Error::NoMoreResponses);
				};
				if let Some(resp) = to_immediate_response(&presp) {
					trace!("got immediate response in request handler");
					return Ok((req, Some(resp)));
				}
				if matches!(presp.response, Some(Response::RequestHeaders(_))) {
					self.mode_state.mark_headers_processed(HeaderPhase::Request);
					self.maybe_apply_mode_override(HeaderPhase::Request, &presp);
				}
				let (headers_done, _) = handle_response_for_request_mutation(
					false,
					send_request_headers,
					Some(&mut req),
					&mut tx_chunk,
					presp,
				)
				.await;
				if headers_done {
					return Ok((req, None));
				}
			}
		}

		if !send_request_headers && !had_body {
			// Nothing to send for request-side processing when both headers and body are skipped/empty.
			return Ok((req, None));
		}

		// Decompose the request and reconstruct it with an upstream body channel that the
		// response loop will populate with (potentially mutated) bytes from ext_proc.
		let (parts, body) = req.into_parts();
		let tx = self.tx_req.clone();
		let (mut tx_chunk, rx_chunk) = tokio::sync::mpsc::channel(1);
		let upstream_body = http_body_util::StreamBody::new(ReceiverStream::new(rx_chunk));
		let mut req = http::Request::from_parts(parts, http::Body::new(upstream_body));

		// Set up body forwarding to ext_proc based on the negotiated mode.
		//
		// Returns `true` when body data is being piped asynchronously (FullDuplexStreamed
		// with a body), which suppresses fail-open after the headers have been acknowledged.
		match req_body_mode {
			EnvoyBodySendMode::None => {
				// Semantics: ext_proc client doesn't send the body at all.
			},
			EnvoyBodySendMode::Streamed => {
				// Semantics: extproc client sends a chunk, the server processes it and sends a chunk back 1:1.
				unimplemented!("streamed body mode is not yet implemented")
			},
			EnvoyBodySendMode::Buffered | EnvoyBodySendMode::BufferedPartial => {
				// Semantics(Buffered): extproc client sends the entire body buffered in memory.
				// Semantics(BufferedPartial): extproc client buffers up to max_request_bytes, then sends it.
				// The buffer task runs concurrently with the headers round-trip; we will
				// await it and send the body inside the response loop once ext_proc
				// acknowledges the headers, maximising overlap.
			},
			EnvoyBodySendMode::FullDuplexStreamed => {
				// In this mode, the extproc server can modify body and streams it back to us as it comes in.
				// We behave approximately like Envoy here (https://github.com/envoyproxy/envoy/pull/41276); after
				// the headers are sent we drop fail_open for requests with a body in flight.
				if had_body {
					let include_protocol = first_request_protocol_config.is_some();
					tokio::task::spawn(Self::handle_body_stream(
						metadata_context.clone(),
						body,
						tx,
						Request::RequestBody,
						Request::RequestTrailers,
						send_request_trailers,
						first_request_attributes.take(),
						first_request_protocol_config.take(),
					));
					if include_protocol {
						self.protocol_config_sent = true;
					}
				}
			},
		}

		// Whether ext_proc will send RequestBody phase responses (i.e. we sent body data).
		// Used to decide whether the response loop should wait for body-phase messages after
		// the headers response, and whether to spawn a body continuation task.
		let strip_request_content_length = request_fsm.strip_content_length();

		// Common response-processing loop shared across all body modes.
		let mut rx = self
			.rx_resp_for_request
			.take()
			.expect("mutate_request called twice");
		// For Buffered mode: the buffer task has been running in parallel with the headers
		// round-trip. We consume it here so we can send the body after headers_done.
		let mut pending_body_task = body_buffer_task;
		let mut buffered_original_body: Option<bytes::Bytes> = None;
		if !request_fsm.is_awaiting_headers()
			&& let Some(task) = pending_body_task.take()
		{
			let buf = task
				.await
				.map_err(|_| Error::BodyBuffer("body buffer task panicked".into()))??;
			buffered_original_body = Some(buf.clone());
			if let Err(e) = self
				.send_buffered_request_body(
					buf,
					&metadata_context,
					&mut first_request_attributes,
					&mut first_request_protocol_config,
				)
				.await
			{
				if failure_mode == FailureMode::FailOpen {
					trace!("fail open triggered");
					self.skipped = true;
					return Ok((req, None));
				}
				return Err(e);
			}
		}
		loop {
			let Some(presp) = rx.recv().await else {
				// Fail-open unless we're mid-stream (FullDuplexStreamed with body in flight),
				// where failing open could silently corrupt data.
				if request_fsm.should_fail_open_on_disconnect(failure_mode) {
					trace!("fail open triggered");
					self.skipped = true;
					return Ok((req, None));
				}
				trace!("done receiving request");
				return Err(Error::NoMoreResponses);
			};
			if let Some(resp) = to_immediate_response(&presp) {
				trace!("got immediate response in request handler");
				return Ok((req, Some(resp)));
			}
			if matches!(presp.response, Some(Response::RequestHeaders(_))) {
				self.mode_state.mark_headers_processed(HeaderPhase::Request);
				self.maybe_apply_mode_override(HeaderPhase::Request, &presp);
				request_fsm.reconcile_headers_response(self.mode_state.request_body_mode);
			}
			let request_body_no_mutation = matches!(
				presp.response,
				Some(Response::RequestBody(BodyResponse { response: None }))
			);
			let (headers_done, eos) = handle_response_for_request_mutation(
				request_fsm.expect_body_response,
				send_request_headers,
				Some(&mut req),
				&mut tx_chunk,
				presp,
			)
			.await;
			if request_fsm.should_restore_original_buffered_body(request_body_no_mutation)
				&& let Some(original) = buffered_original_body.take()
			{
				let _ = tx_chunk.send(Ok(Frame::data(original))).await;
			}
			if request_fsm.advance_after_response(headers_done) {
				// For Buffered/BufferedPartial: ext_proc has finished with the headers.
				// Await the body buffer task (which has been running concurrently) and send
				// the body now. Then continue the loop to receive the body-phase response.
				if let Some(task) = pending_body_task.take() {
					let buf = task
						.await
						.map_err(|_| Error::BodyBuffer("body buffer task panicked".into()))??;
					buffered_original_body = Some(buf.clone());
					if let Err(e) = self
						.send_buffered_request_body(
							buf,
							&metadata_context,
							&mut first_request_attributes,
							&mut first_request_protocol_config,
						)
						.await
					{
						if failure_mode == FailureMode::FailOpen {
							trace!("fail open triggered");
							self.skipped = true;
							return Ok((req, None));
						}
						return Err(e);
					}
					// Loop again to receive the RequestBody response from ext_proc.
					continue;
				}

				if !eos {
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
				if strip_request_content_length {
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
		first_attributes: Option<HashMap<String, Struct>>,
		first_protocol_config: Option<ProtocolConfiguration>,
	) {
		let mut first_attributes = first_attributes;
		let mut first_protocol_config = first_protocol_config;
		let mut stream = BodyStream::new(body);
		while let Some(Ok(frame)) = stream.next().await {
			let request = Some(if frame.is_data() {
				let frame = frame.into_data().expect("already checked");
				trace!("sending body chunk...",);
				body_fn(HttpBody {
					body: frame.into(),
					end_of_stream: false,
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
			let Ok(()) = tx
				.send(ProcessingRequest {
					request,
					metadata_context: metadata_context.as_deref().cloned(),
					attributes: first_attributes.take().unwrap_or_default(),
					protocol_config: first_protocol_config.take(),
					observability_mode: false,
				})
				.await
			else {
				return;
			};
		}

		// Send end of stream marker - try to unwrap Arc to avoid final clone
		let final_metadata = metadata_context.and_then(Arc::into_inner);
		let _ = tx
			.send(ProcessingRequest {
				request: Some(body_fn(HttpBody {
					body: Default::default(),
					end_of_stream: true,
				})),
				metadata_context: final_metadata,
				attributes: first_attributes.take().unwrap_or_default(),
				protocol_config: first_protocol_config.take(),
				observability_mode: false,
			})
			.await;
		trace!("body request done");
	}

	pub async fn mutate_response(
		&mut self,
		req: http::Response,
		request: Option<&RequestSnapshot>,
		resolved_destination_metadata: Option<SocketAddr>,
	) -> Result<(http::Response, Option<PolicyResponse>), Error> {
		if self.skipped {
			return Ok((req, None));
		}
		let headers = resp_to_header_map(&req);
		let send_response_headers = self.mode_state.response_header_mode == HeaderSendMode::Send;
		let send_response_trailers = self.mode_state.response_trailer_mode == TrailerSendMode::Send;

		let exec = cel::Executor::new_response(request, &req);
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
		let (parts, body) = req.into_parts();
		let end_of_stream = body.is_end_stream();
		let had_body = !end_of_stream;
		let send_response_body = self.mode_state.response_body_mode != BodySendMode::None && had_body;
		// response_fsm drives local flow in mutate_response, while mode_state tracks
		// the currently effective ext_proc processing modes.
		let mut response_fsm =
			ResponseFlowFsm::new(send_response_headers, send_response_body, had_body);
		let mut first_response_attributes =
			(!send_response_headers && send_response_body).then(|| attributes.clone());
		let protocol_config = self.protocol_config();
		let mut first_response_protocol_config =
			(!send_response_headers && send_response_body && !self.protocol_config_sent)
				.then_some(protocol_config);

		// Send the response headers to ext_proc.
		// No response side fail_open handling.
		if send_response_headers {
			let include_protocol = !self.protocol_config_sent;
			self
				.send_request(ProcessingRequest {
					request: Some(Request::ResponseHeaders(HttpHeaders {
						headers,
						end_of_stream,
					})),
					metadata_context: metadata_context.as_deref().cloned(),
					attributes: attributes.clone(),
					protocol_config: include_protocol.then_some(protocol_config),
					observability_mode: false,
				})
				.await?;
			if include_protocol {
				self.protocol_config_sent = true;
			}
		}

		if !send_response_body {
			let mut resp = http::Response::from_parts(parts, body);
			if !send_response_headers {
				return Ok((resp, None));
			}

			let mut rx = self
				.rx_resp_for_response
				.take()
				.expect("mutate_response called twice");
			let (mut tx_chunk, _rx_chunk) = tokio::sync::mpsc::channel(1);
			loop {
				let msg = Self::recv_response_loop_message(&mut rx).await?;
				match msg {
					ResponseLoopMessage::Immediate(dr) => return Ok((resp, Some(dr))),
					ResponseLoopMessage::Processing(presp) => {
						let (headers_done, _) = handle_response_for_response_mutation(
							false,
							send_response_headers,
							Some(&mut resp),
							&mut tx_chunk,
							presp,
						)
						.await;
						if headers_done {
							return Ok((resp, None));
						}
					},
				}
			}
		}
		if !send_response_headers && !had_body {
			let resp = http::Response::from_parts(parts, body);
			return Ok((resp, None));
		}

		// Response headers are allowed to change the effective body mode. Keep the upstream body
		// local until the headers response has been applied, then start forwarding only if the
		// response FSM still expects a body phase.
		let tx = self.tx_req.clone();
		let mut pending_response_body = Some(body);
		if !send_response_headers && had_body {
			let include_protocol = first_response_protocol_config.is_some();
			tokio::task::spawn(Self::handle_body_stream(
				metadata_context.clone(),
				pending_response_body
					.take()
					.expect("response body should be available before streaming starts"),
				tx.clone(),
				Request::ResponseBody,
				Request::ResponseTrailers,
				send_response_trailers,
				first_response_attributes.take(),
				first_response_protocol_config.take(),
			));
			if include_protocol {
				self.protocol_config_sent = true;
			}
		}

		// Now we need to build the new body. This is going to be streamed in from the ext_proc server.
		let (mut tx_chunk, rx_chunk) = tokio::sync::mpsc::channel(1);

		let body = http_body_util::StreamBody::new(ReceiverStream::new(rx_chunk));
		let mut resp = http::Response::from_parts(parts, http::Body::new(body));
		let strip_response_content_length = response_fsm.strip_content_length();
		let mut rx = self
			.rx_resp_for_response
			.take()
			.expect("mutate_response called twice");
		loop {
			let msg = Self::recv_response_loop_message(&mut rx).await?;
			let (transitioned, eos) = match msg {
				ResponseLoopMessage::Immediate(dr) => return Ok((resp, Some(dr))),
				ResponseLoopMessage::Processing(presp) => {
					self
						.process_response_loop_message(
							presp,
							Some(&mut resp),
							&mut tx_chunk,
							&mut response_fsm,
							send_response_headers,
						)
						.await
				},
			};
			if transitioned {
				if !eos && response_fsm.send_body {
					if pending_response_body.is_some() {
						let include_protocol = first_response_protocol_config.is_some();
						trace!("spawn body!");
						tokio::task::spawn(Self::handle_body_stream(
							metadata_context.clone(),
							pending_response_body
								.take()
								.expect("response body should be available before streaming continuation starts"),
							tx.clone(),
							Request::ResponseBody,
							Request::ResponseTrailers,
							send_response_trailers,
							first_response_attributes.take(),
							first_response_protocol_config.take(),
						));
						if include_protocol {
							self.protocol_config_sent = true;
						}
					}
					response_fsm.enter_streaming_continuation();
					tokio::task::spawn(Self::forward_response_stream_continuation(
						rx,
						tx_chunk,
						true,
						send_response_headers,
					));
				}
				if strip_response_content_length {
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

	let res = matches!(presp.response, Some(Response::RequestHeaders(_)));
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
				let by = bytes::Bytes::from(bb.body);
				let _ = body_tx.send(Ok(Frame::data(by.clone()))).await;

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

	let res = matches!(presp.response, Some(Response::ResponseHeaders(_)));
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
				let by = bytes::Bytes::from(bb.body);
				let _ = body_tx.send(Ok(Frame::data(by.clone()))).await;
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
