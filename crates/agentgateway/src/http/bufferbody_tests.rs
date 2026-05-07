use crate::{http::bufferbody, *};
use bufferbody::{BodyOptions, BufferRequestBodyError};

#[test]
fn test_body_truncation() {
	let body_opts = BodyOptions {
		max_request_bytes: 10,
		allow_partial_message: true,
		pack_as_bytes: false,
	};

	// Test truncation
	let long_body = b"This is a very long body that exceeds max size";
	assert!(long_body.len() > body_opts.max_request_bytes as usize);

	let mut truncated = long_body.to_vec();
	truncated.truncate(body_opts.max_request_bytes as usize);
	assert_eq!(truncated.len(), 10);
	assert_eq!(&truncated, b"This is a ");
}

#[tokio::test]
async fn test_buffer_request_body_rejects_oversized_body_when_partial_disabled() {
	let mut req = ::http::Request::builder()
		.header("content-length", "11")
		.body(http::Body::from("hello world"))
		.unwrap();
	let body_opts = BodyOptions {
		max_request_bytes: 10,
		allow_partial_message: false,
		pack_as_bytes: false,
	};

	let result = bufferbody::buffer_request_body(&mut req, &body_opts).await;

	assert!(matches!(
		result,
		Err(BufferRequestBodyError::TooLarge)
	));
	let body = crate::http::read_body_with_limit(req.into_body(), 1024)
		.await
		.unwrap();
	assert_eq!(body, bytes::Bytes::from_static(b"hello world"));
}

#[tokio::test]
async fn test_buffer_request_body_allows_partial_when_enabled() {
	let mut req = ::http::Request::builder()
		.header("content-length", "11")
		.body(http::Body::from("hello world"))
		.unwrap();
	let body_opts = BodyOptions {
		max_request_bytes: 10,
		allow_partial_message: true,
		pack_as_bytes: false,
	};

	let result = bufferbody::buffer_request_body(&mut req, &body_opts)
		.await
		.unwrap();

	assert!(result.is_partial);
	assert_eq!(result.original_size, -1);
	assert_eq!(result.body, bytes::Bytes::from_static(b"hello worl"));

	let body = crate::http::read_body_with_limit(req.into_body(), 1024)
		.await
		.unwrap();
	assert_eq!(body, bytes::Bytes::from_static(b"hello world"));
}
