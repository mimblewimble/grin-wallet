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

/// HTTP Wallet 'plugin' implementation
use crate::api;
use crate::libwallet::slate::Slate;
use crate::libwallet::{Error, ErrorKind};
use crate::WalletCommAdapter;
use config::WalletConfig;
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
		let slate = slate.serialize_to_version(Some(slate.version_info.orig_version))?;
		let res: Result<String, _> = api::client::post(url.as_str(), None, &slate);
		match res {
			Err(e) => {
				let report = format!("Posting transaction slate (is recipient listening?): {}", e);
				error!("{}", report);
				Err(ErrorKind::ClientCallback(report).into())
			}
			Ok(r) => Ok(Slate::deserialize_upgrade(&r)?),
		}
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
