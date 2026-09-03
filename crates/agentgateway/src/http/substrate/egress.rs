use tonic::Code;

use super::{ActorIdentity, ActorRef, TRACE_POLICY_KIND};
use crate::http::{PolicyResponse, Request};
use crate::proxy::httpproxy::PolicyClient;
use crate::proxy::{ProxyError, ProxyResponse};
use crate::store::RequestPolicyTrait;
use crate::telemetry::log::RequestLog;
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
use crate::types::agent::SimpleBackendReferenceWithPolicies;
use crate::*;

/// Retrieves and enforces the current Substrate egress policy for each request.
#[apply(schema!)]
pub struct SubstrateEgress {
	/// Backend that receives GetActorEgressPolicy calls and policies used when connecting to it.
	#[serde(flatten)]
	pub target: SimpleBackendReferenceWithPolicies,
}

impl RequestPolicyTrait for SubstrateEgress {
	async fn apply(
		&self,
		client: &PolicyClient,
		log: &mut RequestLog,
		req: &mut Request,
	) -> Result<PolicyResponse, ProxyResponse> {
		let identity = req.extensions().get::<ActorIdentity>().ok_or_else(|| {
			ProxyError::SubstrateEgressDenied("missing CONNECT-authorized actor identity".to_owned())
		})?;
		let actor = ActorRef {
			atespace: identity.atespace.clone(),
			name: identity.actor_name.clone(),
		};
		log.ate_actor_name = Some(actor.name.clone());
		log.ate_actor_uid = Some(identity.actor_uid.clone());
		log.ate_atespace = Some(actor.atespace.clone());
		let channel = self
			.target
			.grpc_channel(client.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Substrate));
		let mut control = protos::ateapi::control_client::ControlClient::new(channel);
		let policy = crate::proxy::dtrace::scope_future(
			Some(TRACE_POLICY_KIND),
			control.get_actor_egress_policy(protos::ateapi::GetActorEgressPolicyRequest {
				actor: Some(protos::ateapi::ObjectRef {
					atespace: actor.atespace,
					name: actor.name,
				}),
			}),
		)
		.await
		.map_err(|status| match status.code() {
			Code::Unavailable | Code::DeadlineExceeded => {
				ProxyError::SubstrateEgressUnavailable(format!("actor egress policy unavailable: {status}"))
			},
			_ => ProxyError::SubstrateEgressDenied(format!("actor egress policy denied: {status}")),
		})?
		.into_inner();
		// TODO: Translate this EgressPolicy into equivalent native policies.
		let _ = policy;
		Ok(PolicyResponse::default())
	}
}
