// Copyright 2018 The Grin Developers
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

//TODO: Update to V2 API when after Hard fork

/// HTTP Wallet 'plugin' implementation
use crate::api;
use crate::libwallet::slate_versions::{v0, v1};
use crate::libwallet::{Error, ErrorKind, Slate};
use crate::WalletCommAdapter;
use config::WalletConfig;
use failure::ResultExt;
use std::collections::HashMap;

#[derive(Clone)]
pub struct HTTPWalletCommAdapter {}

impl HTTPWalletCommAdapter {
	/// Create
	pub fn new() -> Box<dyn WalletCommAdapter> {
		Box::new(HTTPWalletCommAdapter {})
	}
}

impl WalletCommAdapter for HTTPWalletCommAdapter {
	fn supports_sync(&self) -> bool {
		true
	}

	fn send_tx_sync(&self, dest: &str, slate: &Slate) -> Result<Slate, Error> {
		if &dest[..4] != "http" {
			let err_str = format!(
				"dest formatted as {} but send -d expected stdout or http://IP:port",
				dest
			);
			error!("{}", err_str,);
			Err(ErrorKind::Uri)?
		}
		let url = format!("{}/v1/wallet/foreign/receive_tx", dest);
		debug!("Posting transaction slate to {}", url);
		//TODO: Use VersionedSlate when converting to V2 API
		let slate = slate.serialize_to_version(Some(slate.version_info.orig_version))?;
		// For compatibility with older clients
		let res: Slate = {
			if let None = slate.find("version_info") {
				let version = Slate::parse_slate_version(&slate)?;
				match version {
					1 => {
						let ver1: v1::SlateV1 =
							serde_json::from_str(&slate).context(ErrorKind::SlateDeser)?;
						let r: Result<v1::SlateV1, _> =
							api::client::post(url.as_str(), None, &ver1);
						match r {
							Err(e) => {
								let report = format!(
									"Posting transaction slate (is recipient listening?): {}",
									e
								);
								error!("{}", report);
								return Err(ErrorKind::ClientCallback(report).into());
							}
							Ok(s) => Slate::deserialize_upgrade(
								&serde_json::to_string(&s).context(ErrorKind::SlateDeser)?,
							)?,
						}
					}
					_ => {
						let ver0: v0::SlateV0 =
							serde_json::from_str(&slate).context(ErrorKind::SlateDeser)?;
						let r: Result<v0::SlateV0, _> =
							api::client::post(url.as_str(), None, &ver0);
						match r {
							Err(e) => {
								let report = format!(
									"Posting transaction slate (is recipient listening?): {}",
									e
								);
								error!("{}", report);
								return Err(ErrorKind::ClientCallback(report).into());
							}
							Ok(s) => Slate::deserialize_upgrade(
								&serde_json::to_string(&s).context(ErrorKind::SlateDeser)?,
							)?,
						}
					}
				}
			} else {
				let res: Result<String, _> = api::client::post(url.as_str(), None, &slate);
				match res {
					Err(e) => {
						let report =
							format!("Posting transaction slate (is recipient listening?): {}", e);
						error!("{}", report);
						return Err(ErrorKind::ClientCallback(report).into());
					}
					Ok(r) => Slate::deserialize_upgrade(&r)?,
				}
			}
		};
		Ok(res)
	}

	fn send_tx_async(&self, _dest: &str, _slate: &Slate) -> Result<(), Error> {
		unimplemented!();
	}

	fn receive_tx_async(&self, _params: &str) -> Result<Slate, Error> {
		unimplemented!();
	}

	fn listen(
		&self,
		_params: HashMap<String, String>,
		_config: WalletConfig,
		_passphrase: &str,
		_account: &str,
		_node_api_secret: Option<String>,
	) -> Result<(), Error> {
		unimplemented!();
	}
}
