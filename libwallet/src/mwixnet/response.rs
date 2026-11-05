// Copyright 2026 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Mwixnet response parsing.

use serde::Deserialize;
use serde_json::{self, Value};

/// Result returned by a mwixnet server after submitting a request.
#[derive(Debug, Eq, PartialEq)]
pub enum MwixnetResponse {
	/// The request was accepted.
	Accepted,
	/// The request was rejected with a message.
	//TODO: extend it with actual errors from mwixnet
	Rejected(String),
}

/// Error parsing or validating a mwixnet response.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum MwixnetError {
	/// General error
	#[error("{0}")]
	GenericError(String),
	/// Tor request error
	#[error("{0}")]
	TorError(grin_p2p::tor::Error),
}

#[derive(Deserialize)]
struct JsonRpcResponse {
	result: Option<Value>,
	error: Option<JsonRpcError>,
	id: Value,
	jsonrpc: Option<String>,
}

#[derive(Deserialize)]
struct JsonRpcError {
	#[serde(rename = "code")]
	_code: i32,
	message: String,
}

/// Parse and validate the JSON-RPC response returned by a mwixnet server.
pub fn parse_mwixnet_response(response: &str) -> Result<MwixnetResponse, MwixnetError> {
	let response: JsonRpcResponse = serde_json::from_str(response)
		.map_err(|e| MwixnetError::GenericError(format!("Invalid mwixnet response: {}", e)))?;

	if response.jsonrpc.as_deref() != Some("2.0") {
		return Err(MwixnetError::GenericError(
			"Invalid mwixnet response version".to_string(),
		));
	}
	if response.id != serde_json::json!(1) {
		return Err(MwixnetError::GenericError(
			"Invalid mwixnet response ID".to_string(),
		));
	}
	if response.result.is_some() && response.error.is_some() {
		return Err(MwixnetError::GenericError(
			"Mwixnet response contains both result and error".to_string(),
		));
	}
	if let Some(error) = response.error {
		return Ok(MwixnetResponse::Rejected(error.message));
	}
	if response.result == Some(serde_json::json!("success"))
		|| response.result == Some(serde_json::json!("ok"))
	{
		return Ok(MwixnetResponse::Accepted);
	}

	Err(MwixnetError::GenericError(format!(
		"Unexpected mwixnet response result: {:?}",
		response.result
	)))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_mwixnet_response() {
		assert_eq!(
			parse_mwixnet_response(r#"{"jsonrpc":"2.0","result":"success","id":1}"#).unwrap(),
			MwixnetResponse::Accepted
		);

		assert_eq!(
			parse_mwixnet_response(r#"{"jsonrpc":"2.0","result":"ok","id":1}"#).unwrap(),
			MwixnetResponse::Accepted
		);

		assert_eq!(
			parse_mwixnet_response(
				r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"invalid swap"},"id":1}"#,
			)
			.unwrap(),
			MwixnetResponse::Rejected("invalid swap".to_string())
		);

		assert!(parse_mwixnet_response(r#"{"jsonrpc":"2.0","result":"success","id":2}"#).is_err());
		assert!(parse_mwixnet_response(r#"{"jsonrpc":"1.0","result":"success","id":1}"#).is_err());
	}
}
