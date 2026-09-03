use ipnet::IpNet;
use tonic::Code;

use super::{ActorIdentity, ActorRef, TRACE_POLICY_KIND};
use crate::http::{PolicyResponse, Request};
use crate::proxy::httpproxy::PolicyClient;
use crate::proxy::{ProxyError, ProxyResponse};
use crate::store::RequestPolicyTrait;
use crate::telemetry::log::RequestLog;
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
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
		let matched_rule = matching_rule(&policy, req)?;
		// TODO: After Substrate defines a credential-provider data-plane contract, apply the
		// matched hostname rule's `inject_static_headers` effects here.
		let _ = matched_rule;
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
		})?;
	normalize_hostname(&hostname)
}

fn normalize_hostname(hostname: &str) -> Option<String> {
	let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
	(!hostname.is_empty()).then(|| hostname.to_ascii_lowercase())
}

fn matching_rule<'a>(
	policy: &'a protos::ateapi::EgressPolicy,
	req: &Request,
) -> Result<&'a protos::ateapi::EgressRule, ProxyResponse> {
	let destination = req
		.extensions()
		.get::<cel::DestinationContext>()
		.ok_or_else(|| {
			ProxyError::SubstrateEgressDenied("missing egress destination context".to_owned())
		})?;
	for rule in &policy.rules {
		if rule_matches(rule, destination)? {
			return Ok(rule);
		}
	}
	Err(ProxyError::SubstrateEgressDenied("actor egress policy denied destination".to_owned()).into())
}

fn rule_matches(
	rule: &protos::ateapi::EgressRule,
	destination: &cel::DestinationContext,
) -> Result<bool, ProxyResponse> {
	if let Some(hostnames) = &rule.hostnames {
		return Ok(destination.hostname.as_deref().is_some_and(|hostname| {
			hostnames
				.patterns
				.iter()
				.any(|pattern| hostname_matches(pattern, hostname))
		}));
	}
	if let Some(ip_blocks) = &rule.ip_blocks {
		return ip_blocks.cidrs.iter().try_fold(false, |matches, cidr| {
			if matches {
				return Ok(true);
			}
			let network = cidr.parse::<IpNet>().map_err(|error| {
				ProxyError::SubstrateEgressDenied(format!("invalid actor egress CIDR: {error}"))
			})?;
			Ok(network.contains(&destination.address))
		});
	}
	Ok(rule.all.is_some())
}

fn hostname_matches(pattern: &str, hostname: &str) -> bool {
	if let Some(suffix) = pattern.strip_prefix("*.") {
		let Some(prefix) = hostname.strip_suffix(suffix) else {
			return false;
		};
		let Some(label) = prefix.strip_suffix('.') else {
			return false;
		};
		!label.is_empty() && !label.contains('.')
	} else {
		pattern == hostname
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
		let policy = protos::ateapi::EgressPolicy {
			rules: vec![protos::ateapi::EgressRule {
				ip_blocks: Some(protos::ateapi::IpBlockRule {
					cidrs: vec!["192.0.2.0/24".to_owned()],
				}),
				..Default::default()
			}],
			..Default::default()
		};
		assert!(matching_rule(&policy, &request("192.0.2.10", None)).is_ok());
		assert!(matching_rule(&policy, &request("198.51.100.10", None)).is_err());
	}

	#[test]
	fn hostname_rules_match_exact_and_single_label_wildcards() {
		let policy = protos::ateapi::EgressPolicy {
			rules: vec![protos::ateapi::EgressRule {
				hostnames: Some(protos::ateapi::HostnameRule {
					patterns: vec!["api.example.com".to_owned(), "*.example.net".to_owned()],
					..Default::default()
				}),
				..Default::default()
			}],
			..Default::default()
		};
		assert!(matching_rule(&policy, &request("192.0.2.1", Some("api.example.com"))).is_ok());
		assert!(matching_rule(&policy, &request("192.0.2.1", Some("one.example.net"))).is_ok());
		assert!(
			matching_rule(
				&policy,
				&request("192.0.2.1", Some("nested.one.example.net"))
			)
			.is_err()
		);
	}

	#[test]
	fn request_hostname_uses_inner_http_authority_or_host() {
		let mut request = ::http::Request::builder()
			.header(::http::header::HOST, "api.example.com:443")
			.body(crate::http::Body::empty())
			.unwrap();
		assert_eq!(
			request_hostname(&request).as_deref(),
			Some("api.example.com")
		);
		request.headers_mut().remove(::http::header::HOST);
		assert_eq!(request_hostname(&request), None);

		let request = ::http::Request::builder()
			.uri("http://authority.example.com:8443/path")
			.body(crate::http::Body::empty())
			.unwrap();
		assert_eq!(
			request_hostname(&request).as_deref(),
			Some("authority.example.com")
		);
	}

	#[test]
	fn first_matching_rule_wins_over_later_all() {
		let policy = protos::ateapi::EgressPolicy {
			rules: vec![
				protos::ateapi::EgressRule {
					hostnames: Some(protos::ateapi::HostnameRule {
						patterns: vec!["api.example.com".to_owned()],
						..Default::default()
					}),
					..Default::default()
				},
				protos::ateapi::EgressRule {
					all: Some(()),
					..Default::default()
				},
			],
			..Default::default()
		};
		let matched =
			matching_rule(&policy, &request("198.51.100.10", Some("api.example.com"))).unwrap();
		assert!(matched.hostnames.is_some());

		let matched = matching_rule(
			&policy,
			&request("198.51.100.10", Some("other.example.com")),
		)
		.unwrap();
		assert!(matched.all.is_some());
	}
}
