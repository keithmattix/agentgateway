use std::sync::Arc;

use tonic::Code;

use super::{ActorIdentity, ActorRef, TRACE_POLICY_KIND};
use crate::http::authorization::{HTTPAuthorizationSet, PolicySet, RuleSet};
use crate::http::{PolicyResponse, Request};
use crate::proxy::httpproxy::PolicyClient;
use crate::proxy::{ProxyError, ProxyResponse};
use crate::store::RequestPolicyTrait;
use crate::telemetry::log::RequestLog;
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
use crate::transport::stream::TLSConnectionInfo;
use crate::types::agent::SimpleBackendReferenceWithPolicies;
use crate::{cel, *};

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
		set_egress_destination_hostname(req);
		http_authorization(&policy)?.apply(req).map_err(|_| {
			ProxyError::SubstrateEgressDenied("actor egress policy denied destination".to_owned())
		})?;
		// TODO: After Substrate defines a credential-provider data-plane contract, apply the
		// first matching hostname rule's `inject_static_headers` effects here.
		Ok(PolicyResponse::default())
	}
}

fn set_egress_destination_hostname(req: &mut Request) {
	let hostname = request_hostname(req);
	if let Some(destination) = req.extensions_mut().get_mut::<cel::DestinationContext>() {
		destination.hostname = hostname.map(Into::into);
	}
}

fn request_hostname(req: &Request) -> Option<String> {
	// TODO: Add a network-level Substrate egress policy for opaque TLS so it can
	// authorize its sniffed SNI before TCP routing.
	//
	// An outer CONNECT is also TLS, but its SNI names the egress gateway. An
	// inner MITM TLS connection has no actor identity, so its SNI is a fallback
	// when the decrypted HTTP request has no authority.
	let inner_tls_sni = req
		.extensions()
		.get::<TLSConnectionInfo>()
		.filter(|tls| tls.src_identity.is_none())
		.and_then(|tls| tls.server_name.as_deref());
	let hostname = req
		.uri()
		.authority()
		.map(|authority| authority.host().to_owned())
		.or_else(|| {
			req
				.headers()
				.get(::http::header::HOST)
				.and_then(|host| host.to_str().ok())
				.and_then(|host| host.parse::<::http::uri::Authority>().ok())
				.map(|authority| authority.host().to_owned())
		})
		.or_else(|| inner_tls_sni.map(str::to_owned))?;
	normalize_hostname(&hostname)
}

fn normalize_hostname(hostname: &str) -> Option<String> {
	let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
	(!hostname.is_empty()).then(|| hostname.to_ascii_lowercase())
}

fn http_authorization(
	policy: &protos::ateapi::EgressPolicy,
) -> Result<HTTPAuthorizationSet, ProxyResponse> {
	let mut allow = Vec::new();
	for rule in &policy.rules {
		if let Some(ip_blocks) = &rule.ip_blocks {
			for cidr in &ip_blocks.cidrs {
				let expression = cel::Expression::new_strict(format!(
					r#"cidr({}).containsIP(destination.address)"#,
					serde_json::to_string(cidr).expect("CIDR string serializes")
				))
				.map_err(|error| {
					ProxyError::SubstrateEgressDenied(format!("invalid actor egress CIDR: {error}"))
				})?;
				allow.push(Arc::new(expression));
			}
		}
		if rule.all.is_some() {
			let expression = cel::Expression::new_strict("true").expect("literal true is valid CEL");
			allow.push(Arc::new(expression));
		}
		if let Some(hostnames) = &rule.hostnames {
			for pattern in &hostnames.patterns {
				let expression = cel::Expression::new_strict(format!(
					r#"destination.hostname.matches({})"#,
					serde_json::to_string(&hostname_pattern(pattern)).expect("regex serializes")
				))
				.map_err(|error| {
					ProxyError::SubstrateEgressDenied(format!("invalid actor egress hostname: {error}"))
				})?;
				allow.push(Arc::new(expression));
			}
		}
	}
	if allow.is_empty() {
		// A Substrate policy with no matching rule denies the request, whereas an
		// empty HTTPAuthorizationSet permits it by default.
		allow.push(Arc::new(
			cel::Expression::new_strict("false").expect("literal false is valid CEL"),
		));
	}
	Ok(HTTPAuthorizationSet::new(
		vec![RuleSet {
			rules: PolicySet::new(allow, vec![], vec![]),
		}]
		.into(),
	))
}

fn hostname_pattern(pattern: &str) -> String {
	let pattern = regex::escape(&normalize_hostname(pattern).unwrap_or_default());
	if let Some(suffix) = pattern.strip_prefix(r"\*\.") {
		format!(r"^[^.]+\.{suffix}$")
	} else {
		format!(r"^{pattern}$")
	}
}

#[cfg(test)]
mod tests {
	use std::net::IpAddr;

	use super::*;

	fn request(address: &str, hostname: Option<&str>) -> Request {
		let address = address.parse::<IpAddr>().unwrap();
		let mut request = Request::new(crate::http::Body::empty());
		request.extensions_mut().insert(cel::DestinationContext {
			address,
			port: 443,
			hostname: hostname.map(Into::into),
		});
		request
	}

	#[test]
	fn cidr_rules_authorize_only_matching_destinations() {
		let authorization = http_authorization(&protos::ateapi::EgressPolicy {
			rules: vec![protos::ateapi::EgressRule {
				ip_blocks: Some(protos::ateapi::IpBlockRule {
					cidrs: vec!["192.0.2.0/24".to_owned()],
				}),
				..Default::default()
			}],
			..Default::default()
		})
		.unwrap();
		assert!(authorization.apply(&request("192.0.2.10", None)).is_ok());
		assert!(
			authorization
				.apply(&request("198.51.100.10", None))
				.is_err()
		);
	}

	#[test]
	fn hostname_rules_match_exact_and_single_label_wildcards() {
		let authorization = http_authorization(&protos::ateapi::EgressPolicy {
			rules: vec![protos::ateapi::EgressRule {
				hostnames: Some(protos::ateapi::HostnameRule {
					patterns: vec!["api.example.com".to_owned(), "*.example.net".to_owned()],
					..Default::default()
				}),
				..Default::default()
			}],
			..Default::default()
		})
		.unwrap();
		assert!(
			authorization
				.apply(&request("192.0.2.1", Some("api.example.com")))
				.is_ok()
		);
		assert!(
			authorization
				.apply(&request("192.0.2.1", Some("one.example.net")))
				.is_ok()
		);
		assert!(
			authorization
				.apply(&request("192.0.2.1", Some("nested.one.example.net")))
				.is_err()
		);
	}

	#[test]
	fn request_hostname_prefers_http_host_and_falls_back_to_inner_tls_sni() {
		let mut request = ::http::Request::builder()
			.header(::http::header::HOST, "api.example.com:443")
			.body(crate::http::Body::empty())
			.unwrap();
		assert_eq!(
			request_hostname(&request).as_deref(),
			Some("api.example.com")
		);
		request.extensions_mut().insert(TLSConnectionInfo {
			server_name: Some("tls.example.com".to_owned()),
			..Default::default()
		});
		assert_eq!(
			request_hostname(&request).as_deref(),
			Some("api.example.com")
		);
		request.headers_mut().remove(::http::header::HOST);
		assert_eq!(
			request_hostname(&request).as_deref(),
			Some("tls.example.com")
		);
	}
}
