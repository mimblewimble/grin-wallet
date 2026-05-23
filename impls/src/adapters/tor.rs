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

use grin_wallet_config::TorConfig;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::client_utils::{Client, ClientError};
use crate::libwallet::slate_versions::{SlateVersion, VersionedSlate};
use crate::libwallet::{Error, Slate};
use crate::tor::arti::{start_tor_client, tor_post};
use crate::tor::bridge::TorBridge;
use crate::tor::process::TorProcess;
use crate::tor::proxy::TorProxy;
use crate::tor::{config as tor_config, Tor};
use crate::SlateSender;

#[derive(Clone)]
pub struct TorSlateSender {
	base_url: String,
	config: TorConfig,
	tor: Arc<Tor>,
}

impl TorSlateSender {
	/// Create, return Err if scheme is not "http"
	pub fn new(base_url: &str, config: TorConfig) -> Result<TorSlateSender, Error> {
		if !base_url.starts_with("http") && !base_url.starts_with("https") {
			Err(Error::GenericError("Scheme must be http".to_string()))
		} else {
			let tor_dir = {
				let mut path = PathBuf::from(&config.send_config_dir);
				path.push("tor");
				path.push("sender");
				path
			};
			let tor = if config.use_integrated.unwrap_or(true) {
				start_tor_client(tor_dir.to_str().unwrap(), config.clone())?
			} else {
				Self::launch_tor_process(&config, &tor_dir)?
			};
			Ok(TorSlateSender {
				base_url: base_url.to_owned(),
				config,
				tor: Arc::new(tor),
			})
		}
	}

	/// Launch external Tor process.
	fn launch_tor_process(config: &TorConfig, tor_dir: &PathBuf) -> Result<Tor, Error> {
		let mut tor = TorProcess::new();
		let socks_proxy_addr = SocketAddr::V4(
			config
				.socks_proxy_addr
				.parse()
				.map_err(|e| Error::TorConfig(format!("{:?}", e)))?,
		);
		info!("Starting TOR Process for send at {:?}", socks_proxy_addr);

		let mut hm_tor_bridge: HashMap<String, String> = HashMap::new();
		if config.bridge.bridge_line.is_some() {
			let bridge_struct = TorBridge::try_from(config.bridge.clone())
				.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
			hm_tor_bridge = bridge_struct
				.to_hashmap()
				.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
		}

		let mut hm_tor_proxy: HashMap<String, String> = HashMap::new();
		if config.proxy.transport.is_some() || config.proxy.allowed_port.is_some() {
			let proxy = TorProxy::try_from(config.proxy.clone())
				.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
			hm_tor_proxy = proxy
				.to_hashmap()
				.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
		}

		tor_config::output_tor_sender_config(
			tor_dir.to_str().unwrap(),
			socks_proxy_addr.to_string().as_str(),
			hm_tor_bridge,
			hm_tor_proxy,
		)
		.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
		// Start TOR process
		let mut path = tor_dir.clone();
		path.push("torrc");
		tor.torrc_path(path.to_str().unwrap())
			.working_dir(tor_dir.to_str().unwrap())
			.timeout(20)
			.completion_percent(100)
			.launch()
			.map_err(|e| Error::TorProcess(format!("{:?}", e)))?;
		Ok(Tor {
			process: Some(tor),
			service: None,
			client: None,
		})
	}

	/// Check version of the listening wallet
	pub fn check_other_version(&mut self, url: &str) -> Result<SlateVersion, Error> {
		let req = json!({
			"jsonrpc": "2.0",
			"method": "check_version",
			"id": 1,
			"params": []
		});

		let res: String = self.post(url, req).map_err(|e| {
			let mut report = format!("Performing version check (is recipient listening?): {}", e);
			let err_string = format!("{}", e);
			if err_string.contains("404") {
				// Report that the other version of the wallet is out of date
				report = "Other wallet is incompatible and requires an upgrade. \
				          Please urge the other wallet owner to upgrade and try the transaction again."
					.to_string();
				error!("{}", report);
			}
			Error::ClientCallback(report)
		})?;

		let res: Value = serde_json::from_str(&res).unwrap();
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Posting transaction slate: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}

		let resp_value = res["result"]["Ok"].clone();
		trace!("resp_value: {}", resp_value.clone());
		let foreign_api_version: u16 =
			serde_json::from_value(resp_value["foreign_api_version"].clone()).unwrap();
		let supported_slate_versions: Vec<String> =
			serde_json::from_value(resp_value["supported_slate_versions"].clone()).unwrap();

		// trivial tests for now, but will be expanded later
		if foreign_api_version < 2 {
			let report = "Other wallet reports unrecognized API format.".to_string();
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}

		if supported_slate_versions.contains(&"V4".to_owned()) {
			return Ok(SlateVersion::V4);
		}

		let report = "Unable to negotiate slate format with other wallet.".to_string();
		error!("{}", report);
		Err(Error::ClientCallback(report))
	}

	fn post<IN>(&self, url: &str, input: IN) -> Result<String, ClientError>
	where
		IN: Serialize,
	{
		let res = if self.tor.process.is_some() {
			let socks_proxy_addr =
				SocketAddr::V4(self.config.socks_proxy_addr.parse().map_err(|_| {
					ClientError::Internal("Socks proxy address is not set".to_string())
				})?);
			let client = Client::with_proxy(socks_proxy_addr, "socks5h://")
				.map_err(|_| ClientError::Internal("Unable to create http client".into()))?;
			let req = client.create_post_request(url, None, &input)?;
			let res = client.send_request(req)?;
			res
		} else {
			if let Some(client) = &self.tor.client {
				tor_post(client.clone(), &input, url)
					.map_err(|e| ClientError::RequestError(format!("{:?}", e)))?
			} else {
				return Err(ClientError::Internal("Tor is not configured".to_string()));
			}
		};
		Ok(res)
	}
}

impl SlateSender for TorSlateSender {
	fn send_tx(&mut self, slate: &Slate, finalize: bool) -> Result<Slate, Error> {
		let trailing = match self.base_url.ends_with('/') {
			true => "",
			false => "/",
		};
		let url_str = format!("{}{}v2/foreign", self.base_url, trailing);

		let slate_send = match self.check_other_version(&url_str)? {
			SlateVersion::V4 => VersionedSlate::into_version(slate.clone(), SlateVersion::V4)?,
		};
		// Note: not using easy-jsonrpc as don't want the dependencies in this crate
		let req = match finalize {
			false => json!({
				"jsonrpc": "2.0",
				"method": "receive_tx",
				"id": 1,
				"params": [
							slate_send,
							null,
							null
						]
			}),
			true => json!({
				"jsonrpc": "2.0",
				"method": "finalize_tx",
				"id": 1,
				"params": [
							slate_send
						]
			}),
		};

		trace!("Sending receive_tx request: {}", req);

		let res: String = self.post(&url_str, req).map_err(|e| {
			let report = format!(
				"Sending transaction slate to other wallet (is recipient listening?): {}",
				e
			);
			Error::ClientCallback(report)
		})?;

		let res: Value = serde_json::from_str(&res).unwrap();
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Posting transaction slate: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(Error::ClientCallback(report));
		}

		let slate_value = res["result"]["Ok"].clone();

		trace!("slate_value: {}", slate_value);
		let slate = Slate::deserialize_upgrade(&serde_json::to_string(&slate_value).unwrap())
			.map_err(|e| {
				error!("Error deserializing response slate: {}", e);
				Error::SlateDeser
			})?;

		Ok(slate)
	}
}
