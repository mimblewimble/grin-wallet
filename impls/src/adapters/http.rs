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

/// HTTP Wallet 'plugin' implementation
use crate::client_utils::{Client, ClientError, ClientErrorKind};
use crate::libwallet::slate_versions::{SlateVersion, VersionedSlate};
use crate::libwallet::{Error, ErrorKind, Slate, SlateState};
use crate::SlateSender;
use serde::Serialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::MAIN_SEPARATOR;
use std::sync::Arc;

use crate::tor::config as tor_config;
use crate::tor::process as tor_process;

const TOR_CONFIG_PATH: &str = "tor/sender";

#[derive(Clone)]
pub struct HttpSlateSender {
	base_url: String,
	use_socks: bool,
	socks_proxy_addr: Option<SocketAddr>,
	tor_config_dir: String,
	process: Option<Arc<tor_process::TorProcess>>,
}

impl HttpSlateSender {
	/// Create, return Err if scheme is not "http"
	fn new(base_url: &str) -> Result<HttpSlateSender, SchemeNotHttp> {
		if !base_url.starts_with("http") && !base_url.starts_with("https") {
			Err(SchemeNotHttp)
		} else {
			Ok(HttpSlateSender {
				base_url: base_url.to_owned(),
				use_socks: false,
				socks_proxy_addr: None,
				tor_config_dir: String::from(""),
				process: None,
			})
		}
	}

	/// Switch to using socks proxy
	pub fn with_socks_proxy(
		base_url: &str,
		proxy_addr: &str,
		tor_config_dir: &str,
	) -> Result<HttpSlateSender, SchemeNotHttp> {
		let mut ret = Self::new(base_url)?;
		ret.use_socks = true;
		//TODO: Unwrap
		ret.socks_proxy_addr = Some(SocketAddr::V4(proxy_addr.parse().unwrap()));
		ret.tor_config_dir = tor_config_dir.into();
		Ok(ret)
	}

	/// launch TOR process
	pub fn launch_tor(&mut self) -> Result<(), Error> {
		// set up tor send process if needed
		let mut tor = tor_process::TorProcess::new();
		if self.use_socks && self.process.is_none() {
			let tor_dir = format!(
				"{}{}{}",
				&self.tor_config_dir, MAIN_SEPARATOR, TOR_CONFIG_PATH
			);
			info!(
				"Starting TOR Process for send at {:?}",
				self.socks_proxy_addr
			);
			tor_config::output_tor_sender_config(
				&tor_dir,
				&self.socks_proxy_addr.unwrap().to_string(),
			)
			.map_err(|e| ErrorKind::TorConfig(format!("{:?}", e)))?;
			// Start TOR process
			tor.torrc_path(&format!("{}/torrc", &tor_dir))
				.working_dir(&tor_dir)
				.timeout(20)
				.completion_percent(100)
				.launch()
				.map_err(|e| ErrorKind::TorProcess(format!("{:?}", e)))?;
			self.process = Some(Arc::new(tor));
		}
		Ok(())
	}

	/// Check version of the listening wallet
	pub fn check_other_version(&mut self, url: &str) -> Result<SlateVersion, Error> {
		self.launch_tor()?;
		let req = json!({
			"jsonrpc": "2.0",
			"method": "check_version",
			"id": 1,
			"params": []
		});

		let res: String = self.post(url, None, req).map_err(|e| {
			let mut report = format!("Performing version check (is recipient listening?): {}", e);
			let err_string = format!("{}", e);
			if err_string.contains("404") {
				// Report that the other version of the wallet is out of date
				report = "Other wallet is incompatible and requires an upgrade. \
				          Please urge the other wallet owner to upgrade and try the transaction again."
					.to_string();
				error!("{}", report);
			}
			ErrorKind::ClientCallback(report)
		})?;

		let res: Value = serde_json::from_str(&res).unwrap();
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Posting transaction slate: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
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
			return Err(ErrorKind::ClientCallback(report).into());
		}

		if supported_slate_versions.contains(&"V5".to_owned()) {
			return Ok(SlateVersion::V5);
		}

		if supported_slate_versions.contains(&"V4".to_owned()) {
			return Ok(SlateVersion::V4);
		}

		let report = "Unable to negotiate slate format with other wallet.".to_string();
		error!("{}", report);
		Err(ErrorKind::ClientCallback(report).into())
	}

	fn post<IN>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: IN,
	) -> Result<String, ClientError>
	where
		IN: Serialize,
	{
		let client =
			if self.use_socks {
				Client::new()
			} else {
				Client::with_socks_proxy(self.socks_proxy_addr.ok_or_else(|| {
					ClientErrorKind::Internal("No socks proxy address set".into())
				})?)
			}
			.map_err(|_| ClientErrorKind::Internal("Unable to create http client".into()))?;
		let req = client.create_post_request(url, api_secret, &input)?;
		let res = client.send_request(req)?;
		Ok(res)
	}
}

impl SlateSender for HttpSlateSender {
	fn send_tx(&mut self, slate: &Slate, finalize: bool) -> Result<Slate, Error> {
		let trailing = match self.base_url.ends_with('/') {
			true => "",
			false => "/",
		};
		let url_str = format!("{}{}v2/foreign", self.base_url, trailing);

		self.launch_tor()?;

		let slate_send = match self.check_other_version(&url_str)? {
			SlateVersion::V4 => VersionedSlate::into_version(slate.clone(), SlateVersion::V4)?,
			SlateVersion::V5 => VersionedSlate::into_version(slate.clone(), SlateVersion::V5)?,
		};
		// Note: not using easy-jsonrpc as don't want the dependencies in this crate
		let req = match finalize {
			false => match slate.state {
				SlateState::Standard1 | SlateState::Invoice1 => json!({
					"jsonrpc": "2.0",
					"method": "receive_tx",
					"id": 1,
					"params": [
								slate_send,
								null,
								null
							]
				}),
				SlateState::Atomic1 => json!({
					"jsonrpc": "2.0",
					"method": "receive_atomic_tx",
					"id": 1,
					"params": [
								slate_send,
								null,
								null
							]
				}),
				SlateState::Atomic2 => json!({
					"jsonrpc": "2.0",
					"method": "countersign_atomic_swap",
					"id": 1,
					"params": [
								slate_send,
								null,
								null
							]
				}),
				_ => return Err(ErrorKind::ClientCallback("invalid slate state".into()).into()),
			},
			true => match slate.state {
				SlateState::Standard2 | SlateState::Invoice2 => json!({
					"jsonrpc": "2.0",
					"method": "finalize_tx",
					"id": 1,
					"params": [
								slate_send
							]
				}),
				SlateState::Atomic3 => json!({
					"jsonrpc": "2.0",
					"method": "finalize_atomic_swap",
					"id": 1,
					"params": [
								slate_send
							]
				}),
				_ => return Err(ErrorKind::ClientCallback("invalid slate state".into()).into()),
			},
		};

		trace!("Sending receive_tx request: {}", req);

		let res: String = self.post(&url_str, None, req).map_err(|e| {
			let report = format!(
				"Sending transaction slate to other wallet (is recipient listening?): {}",
				e
			);
			ErrorKind::ClientCallback(report)
		})?;

		let res: Value = serde_json::from_str(&res).unwrap();
		trace!("Response: {}", res);
		if res["error"] != json!(null) {
			let report = format!(
				"Posting transaction slate: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			);
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		let slate_value = res["result"]["Ok"].clone();

		trace!("slate_value: {}", slate_value);
		let slate = Slate::deserialize_upgrade(&serde_json::to_string(&slate_value).unwrap())
			.map_err(|e| {
				error!("Error deserializing response slate: {}", e);
				ErrorKind::SlateDeser
			})?;

		Ok(slate)
	}
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct SchemeNotHttp;

impl Into<Error> for SchemeNotHttp {
	fn into(self) -> Error {
		let err_str = "url scheme must be http".to_string();
		ErrorKind::GenericError(err_str).into()
	}
}
