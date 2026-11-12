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

use crate::mwixnet::{parse_mwixnet_response, MwixnetError, MwixnetResponse, SwapReq};

use grin_api::json_rpc;
use grin_p2p::tor::config::TorConfig;
use grin_p2p::tor::ov3::OnionV3Address;
use grin_p2p::tor::TorHttpClient;
use grin_wallet_config::TorWalletConfig;

use async_trait::async_trait;
use std::collections::HashMap;

/// Client to send requests to mwixnet service.
#[async_trait]
pub trait MwixnetClient<T>: TorHttpClient<T> + Send + Sync
where
	T: TorConfig + Sync,
{
	/// Get service URL.
	fn server_url(&self) -> &OnionV3Address;

	/// Send request to service.
	async fn send_request(
		&self,
		method: &str,
		req: &serde_json::Value,
	) -> Result<MwixnetResponse, MwixnetError> {
		let url = format!("{}/v1", self.server_url().to_http_str());
		let rpc_request = json_rpc::build_request(method, req);
		let body = serde_json::json!(rpc_request).to_string();

		let mut headers = HashMap::new();
		headers.insert("accept", "application/json");
		headers.insert("content-type", "application/json");

		let response = match self
			.post_tor(&url, Some(headers), body, TorWalletConfig::RESPONSE_LIMIT)
			.await
		{
			Ok(response) => response,
			Err(e) => {
				return Err(MwixnetError::TorError(e));
			}
		};
		parse_mwixnet_response(response.body())
	}

	/// Swap outputs request.
	async fn swap(&self, req: &SwapReq) -> Result<MwixnetResponse, MwixnetError> {
		let req = serde_json::json!([req]);
		self.send_request("swap", &req).await
	}

	/// Health request.
	async fn health(&self) -> Result<MwixnetResponse, MwixnetError> {
		let req = serde_json::json!([]);
		self.send_request("health", &req).await
	}
}

/// Mwixnet requests client.
pub struct MwixnetClientImpl<T> {
	tor_config: T,
	server_url: OnionV3Address,
}

impl<T: TorConfig + Send + Sync> MwixnetClient<T> for MwixnetClientImpl<T> {
	fn server_url(&self) -> &OnionV3Address {
		&self.server_url
	}
}

impl<T: TorConfig + Send + Sync> TorHttpClient<T> for MwixnetClientImpl<T> {
	fn tor_config(&self) -> &T {
		&self.tor_config
	}
}

impl<T> MwixnetClientImpl<T> {
	/// Create new client instance.
	pub fn new(tor_config: T, server_url: OnionV3Address) -> Self {
		MwixnetClientImpl {
			tor_config,
			server_url,
		}
	}
}
