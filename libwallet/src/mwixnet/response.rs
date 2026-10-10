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

//! MWixnet response parsing.

use serde::Deserialize;
use serde_json::{self, Value};

/// Result returned by an mwixnet server after submitting a swap request.
#[derive(Debug, Eq, PartialEq)]
pub enum MwixnetResponse {
	/// The swap request was accepted.
	Accepted,
	/// The swap request was rejected with a message.
	Rejected(String),
}

/// Error parsing or validating an mwixnet response.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct MwixnetResponseError(String);

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

/// Parse and validate the JSON-RPC response returned by an mwixnet server.
pub fn parse_mwixnet_response(response: &str) -> Result<MwixnetResponse, MwixnetResponseError> {
	let response: JsonRpcResponse = serde_json::from_str(response)
		.map_err(|e| MwixnetResponseError(format!("Invalid mwixnet response: {}", e)))?;

	if response.jsonrpc.as_deref() != Some("2.0") {
		return Err(MwixnetResponseError(
			"Invalid mwixnet response version".to_string(),
		));
	}
	if response.id != serde_json::json!(1) {
		return Err(MwixnetResponseError(
			"Invalid mwixnet response ID".to_string(),
		));
	}
	if response.result.is_some() && response.error.is_some() {
		return Err(MwixnetResponseError(
			"MWixnet response contains both result and error".to_string(),
		));
	}
	if let Some(error) = response.error {
		return Ok(MwixnetResponse::Rejected(error.message));
	}
	if response.result == Some(serde_json::json!("success")) {
		return Ok(MwixnetResponse::Accepted);
	}

	Err(MwixnetResponseError(format!(
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
