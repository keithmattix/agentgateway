use std::sync::Arc;

use http::HeaderValue;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::transport::stream::{Socket, TLSConnectionInfo};
use crate::transport::{hbone, stream};

#[derive(Debug, thiserror::Error)]
#[error("atunnel rejected a stale worker assignment")]
struct StaleAssignment;

pub fn is_stale_assignment_error(error: &anyhow::Error) -> bool {
	if error.downcast_ref::<StaleAssignment>().is_some() {
		return true;
	}
	error
		.downcast_ref::<agent_hbone::client::UnexpectedConnectResponse>()
		.is_some_and(|response| {
			response.status == http::StatusCode::MISDIRECTED_REQUEST
				&& response
					.headers
					.get("x-ate-assignment-stale")
					.is_some_and(|value| value == "true")
		})
}

/// Establish an HTTP/1.1 CONNECT tunnel.
///
/// This is retained for configured, conventional HTTP proxy tunnels. Native
/// atunnel CONNECT uses [`handshake`], which selects the framing from ALPN.
pub async fn handshake_h1(
	conn: Socket,
	dest: &str,
	auth: Option<HeaderValue>,
) -> Result<Socket, anyhow::Error> {
	let (ext, metrics, inner) = conn.into_parts();
	let mut conn = Socket::new_rewind(inner);
	// While the raw HTTP/1 usage here looks pretty sketchy, hyper itself is doing this so its probably sufficient
	// for our simple needs here.
	// If we need to add TLS (which implies ALPN negotiation, etc) then we will want to make this more robust.
	let mut buf = format!(
		"\
         CONNECT {dest} HTTP/1.1\r\n\
         Host: {dest}\r\n\
         "
	)
	.into_bytes();

	if let Some(auth) = auth {
		buf.extend_from_slice(b"Proxy-Authorization: ");
		buf.extend_from_slice(auth.as_bytes());
		buf.extend_from_slice(b"\r\n");
	}
	// headers end
	buf.extend_from_slice(b"\r\n");
	conn.write_all(&buf).await?;

	let mut buf = [0; 8192];
	let mut pos = 0;
	loop {
		let n = conn
			.read(&mut buf[pos..])
			.await
			.map_err(crate::http::Error::new)?;
		if n == 0 {
			return Err(anyhow::anyhow!("tunnel unexpected eof"));
		}
		pos += n;

		if let Some(end) = header_end(&buf[..pos]) {
			let recvd = &buf[..pos];
			if recvd.starts_with(b"HTTP/1.1 200") || recvd.starts_with(b"HTTP/1.0 200") {
				let conn = conn.keep_after(end);
				return Ok(Socket::from_rewind(ext, metrics, conn));
			} else if recvd.starts_with(b"HTTP/1.1 407") || recvd.starts_with(b"HTTP/1.0 407") {
				return Err(anyhow::anyhow!("tunnel required auth"));
			} else if h1_stale_assignment(recvd) {
				return Err(StaleAssignment.into());
			} else {
				return Err(anyhow::anyhow!("tunnel failed"));
			}
		}
		if pos == buf.len() {
			return Err(anyhow::anyhow!("headers too long"));
		}
	}
}

fn h1_stale_assignment(response: &[u8]) -> bool {
	if !(response.starts_with(b"HTTP/1.1 421") || response.starts_with(b"HTTP/1.0 421")) {
		return false;
	}
	std::str::from_utf8(response).is_ok_and(|response| {
		response.lines().skip(1).any(|line| {
			let Some((name, value)) = line.split_once(':') else {
				return false;
			};
			name.eq_ignore_ascii_case("x-ate-assignment-stale") && value.trim() == "true"
		})
	})
}

/// Establish a CONNECT tunnel using the protocol selected by TLS ALPN.
///
/// atunnel advertises both HTTP/2 and HTTP/1.1. HTTP/2 CONNECT is represented
/// by a bidirectional request/response stream, whereas HTTP/1.1 CONNECT can
/// continue using the raw socket after its response headers.
pub async fn handshake(
	conn: Socket,
	dest: &str,
	hbone_config: Arc<agent_hbone::Config>,
) -> Result<Socket, anyhow::Error> {
	match conn
		.ext::<TLSConnectionInfo>()
		.and_then(|info| info.negotiated_alpn)
	{
		Some(stream::Alpn::H2) => handshake_h2(conn, dest, hbone_config).await,
		Some(stream::Alpn::Http11) => handshake_h1(conn, dest, None).await,
		alpn => Err(anyhow::anyhow!(
			"atunnel CONNECT negotiated unsupported ALPN: {alpn:?}"
		)),
	}
}

async fn handshake_h2(
	conn: Socket,
	dest: &str,
	hbone_config: Arc<agent_hbone::Config>,
) -> Result<Socket, anyhow::Error> {
	let target = conn.target_address();
	let (ext, _metrics, inner) = conn.into_parts();
	let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
	let key = hbone::WorkloadKey {
		dst_id: vec![],
		dst: target,
	};
	let mut sender =
		agent_hbone::client::spawn_connection(hbone_config, inner, drain_rx, key).await?;
	let uri = http::Uri::builder()
		.scheme(http::uri::Scheme::HTTPS)
		.authority(dest)
		.path_and_query("/")
		.build()?;
	let request = http::Request::builder()
		.method(http::Method::CONNECT)
		.uri(uri)
		.version(http::Version::HTTP_2)
		.body(())?;
	let stream = sender.send_request(request).await?;
	Ok(Socket::from_hbone(
		Arc::new(ext),
		target,
		agent_hbone::RWStream {
			stream,
			buf: Default::default(),
			drain_tx: Some(drain_tx),
		},
	))
}

fn header_end(buf: &[u8]) -> Option<usize> {
	buf
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.map(|pos| pos + 4)
}

#[cfg(test)]
mod tests {
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};
	use std::time::Instant;

	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	use super::*;
	use crate::transport::stream::TCPConnectionInfo;

	fn memory_socket(stream: tokio::io::DuplexStream) -> Socket {
		Socket::from_memory(
			stream,
			TCPConnectionInfo {
				peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
				local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4321),
				start: Instant::now(),
				raw_peer_addr: None,
			},
		)
	}

	#[tokio::test]
	async fn handshake_replays_bytes_after_connect_headers() {
		let (client, mut server) = tokio::io::duplex(1024);
		let server_task = tokio::spawn(async move {
			let mut request = vec![0; 256];
			let n = server.read(&mut request).await.expect("read request");
			assert!(
				std::str::from_utf8(&request[..n])
					.unwrap()
					.starts_with("CONNECT dest:443 ")
			);
			server
				.write_all(b"HTTP/1.1 200 OK\r\n\r\nhello")
				.await
				.expect("write response");
		});

		let mut tunneled = handshake_h1(memory_socket(client), "dest:443", None)
			.await
			.expect("handshake should succeed");
		let mut first_bytes = [0; 5];
		tunneled
			.read_exact(&mut first_bytes)
			.await
			.expect("read replayed bytes");

		assert_eq!(&first_bytes, b"hello");
		server_task.await.expect("server task");
	}

	#[tokio::test]
	async fn handshake_h1_marks_stale_assignment() {
		let (client, mut server) = tokio::io::duplex(1024);
		let server_task = tokio::spawn(async move {
			let mut request = [0; 256];
			server.read(&mut request).await.expect("read request");
			server
				.write_all(b"HTTP/1.1 421 Misdirected Request\r\nx-ate-assignment-stale: true\r\n\r\n")
				.await
				.expect("write response");
		});

		let error = match handshake_h1(memory_socket(client), "dest:443", None).await {
			Ok(_) => panic!("stale assignment must fail the tunnel handshake"),
			Err(error) => error,
		};
		assert!(is_stale_assignment_error(&error));
		server_task.await.expect("server task");
	}

	#[test]
	fn handshake_h2_marks_stale_assignment() {
		let mut headers = http::HeaderMap::new();
		headers.insert(
			"x-ate-assignment-stale",
			http::HeaderValue::from_static("true"),
		);
		let error = anyhow::Error::from(agent_hbone::client::UnexpectedConnectResponse {
			status: http::StatusCode::MISDIRECTED_REQUEST,
			headers,
		});

		assert!(is_stale_assignment_error(&error));
	}
}
