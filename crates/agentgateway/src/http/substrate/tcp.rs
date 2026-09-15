use super::{ActorIdentity, SubstrateIngress, egress};
use crate::cel::{DestinationContext, SourceContext};
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::log::RequestLog;
use crate::types::agent::{SimpleBackendReferenceWithPolicies, Target};
use crate::*;

/// Enforces the actor's egress policy once before forwarding a TCP connection.
#[apply(schema!)]
pub struct SubstrateTcpEgress {
	/// Backend that receives GetActorEgressPolicy calls.
	#[serde(flatten)]
	pub target: SimpleBackendReferenceWithPolicies,
}

impl SubstrateTcpEgress {
	pub(crate) async fn apply(
		&self,
		client: &PolicyClient,
		log: &mut RequestLog,
		identity: Option<&ActorIdentity>,
		destination: &DestinationContext,
	) -> Result<(), ProxyError> {
		let identity = identity.ok_or_else(|| {
			ProxyError::SubstrateEgressDenied("missing CONNECT-authorized actor identity".to_owned())
		})?;
		let policy = egress::fetch_policy(&self.target, client, log, identity).await?;
		let destination = DestinationContext {
			hostname: destination
				.hostname
				.as_deref()
				.map(|hostname| hostname.trim_end_matches('.').to_ascii_lowercase())
				.filter(|hostname| !hostname.is_empty())
				.map(strng::new),
			..destination.clone()
		};
		let rule = egress::matching_destination_rule(&policy, &destination)?;
		validate_tcp_effects(rule)
	}
}

fn validate_tcp_effects(rule: &protos::ateapi::EgressRule) -> Result<(), ProxyError> {
	if rule
		.hostnames
		.as_ref()
		.and_then(|h| h.effects.as_ref())
		.is_some_and(|effects| !effects.inject_static_headers.is_empty())
	{
		return Err(ProxyError::SubstrateEgressDenied(
			"TCP passthrough cannot apply HTTP header injection effects".to_owned(),
		));
	}
	Ok(())
}

/// Resolves an actor selected by CONNECT metadata and forwards TCP through its atunnel.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SubstrateTcpIngress {
	pub ingress: SubstrateIngress,
}

pub(crate) struct TcpIngressTarget {
	pub worker: Target,
	pub authority: Target,
	pub actor_header: ::http::HeaderValue,
}

impl SubstrateTcpIngress {
	pub(crate) async fn apply(
		&self,
		client: &PolicyClient,
		log: &mut RequestLog,
		source: &SourceContext,
		destination: &DestinationContext,
	) -> Result<TcpIngressTarget, ProxyError> {
		self
			.ingress
			.resolve_tcp(client, log, source, destination)
			.await
	}
}
