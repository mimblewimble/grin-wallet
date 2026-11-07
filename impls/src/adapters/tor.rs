// Copyright 2021 The Grin Developers
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

use crate::adapters::types::HttpSlateSender;
use crate::config::TorWalletConfig;
use crate::libwallet::Error;
use crate::libwallet::SlatepackAddress;

use grin_p2p::tor::ov3::OnionV3Address;
use grin_p2p::tor::{start_tor, TorHttpClient};

use async_trait::async_trait;
use std::collections::HashMap;

#[derive(Clone)]
pub struct TorSlateSender {
	host_url: String,
	tor_config: TorWalletConfig,
}

impl TorSlateSender {
	/// Create instance from receiver address and Tor config, return Error if Tor can not be started.
	pub fn new(
		dest: &SlatepackAddress,
		tor_config: TorWalletConfig,
	) -> Result<TorSlateSender, Error> {
		let tor_addr = OnionV3Address::from(dest);
		let host_url = tor_addr.to_http_str();
		start_tor(&tor_config)?;
		Ok(TorSlateSender {
			host_url,
			tor_config,
		})
	}
}

impl TorHttpClient<TorWalletConfig> for TorSlateSender {
	fn tor_config(&self) -> &TorWalletConfig {
		&self.tor_config
	}
}

#[async_trait]
impl HttpSlateSender for TorSlateSender {
	fn host_url(&self) -> String {
		self.host_url.clone()
	}

	async fn post(&self, url: &str, body: String) -> Result<String, Error> {
		let mut headers = HashMap::new();
		headers.insert("accept", "application/json");
		headers.insert("content-type", "application/json");
		self.post_tor(url, Some(headers), body, TorWalletConfig::RESPONSE_LIMIT)
			.await
			.map(|response| response.into_body())
			.map_err(|e| e.into())
	}
}
