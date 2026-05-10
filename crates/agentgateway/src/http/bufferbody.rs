use crate::http::Request;
use crate::*;

#[cfg(test)]
#[path = "bufferbody_tests.rs"]
mod tests;

#[apply(schema!)]
pub struct BodyOptions {
	/// Maximum size of request body to buffer (default: 8192)
	#[serde(default)]
	pub max_request_bytes: u32,
	/// If true, send partial body when max_request_bytes is reached
	#[serde(default)]
	pub allow_partial_message: bool,
	/// If true, pack body as raw bytes in gRPC
	#[serde(default)]
	pub pack_as_bytes: bool,
}

impl Default for BodyOptions {
	fn default() -> Self {
		Self {
			max_request_bytes: 8192,
			allow_partial_message: false,
			pack_as_bytes: false,
		}
	}
}

// TODO(keithmattix): Should this be a trait instead?
pub struct BufferedRequestBody {
	pub body: Bytes,
	pub is_partial: bool,
	pub original_size: i64,
}

#[derive(Debug)]
pub enum BufferRequestBodyError {
	TooLarge,
	Read(anyhow::Error),
}

pub async fn buffer_request_body(
	req: &mut Request,
	body_opts: &BodyOptions,
) -> Result<BufferedRequestBody, BufferRequestBodyError> {
	let max_size = body_opts.max_request_bytes as usize;

	let peek_limit = max_size.saturating_add(1);
	let body = crate::http::inspect_body_with_limit(req.body_mut(), peek_limit)
		.await
		.map_err(BufferRequestBodyError::Read)?;
	let is_partial = body.len() > max_size;

	if is_partial && !body_opts.allow_partial_message {
		return Err(BufferRequestBodyError::TooLarge);
	}

	let body = if is_partial {
		body.slice(0..max_size)
	} else {
		body
	};
	let original_size = match is_partial {
		false => i64::try_from(body.len()).unwrap_or(i64::MAX),
		true => -1,
	};

	Ok(BufferedRequestBody {
		body,
		is_partial,
		original_size,
	})
}
