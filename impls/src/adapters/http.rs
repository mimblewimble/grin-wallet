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
use crate::libwallet::{Error, ErrorKind, Slate};
use crate::WalletCommAdapter;
use config::WalletConfig;
use serde::Serialize;
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
		let res: String = post(url.as_str(), None, &slate).map_err(|e| {
			let report = format!("Posting transaction slate (is recipient listening?): {}", e);
			error!("{}", report);
			ErrorKind::ClientCallback(report)
		})?;
		let slate = Slate::deserialize_upgrade(&res).map_err(|_| ErrorKind::SlateDeser)?;

		Ok(slate)
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

pub fn post<IN>(url: &str, api_secret: Option<String>, input: &IN) -> Result<String, api::Error>
where
	IN: Serialize,
{
	let req = api::client::create_post_request(url, api_secret, input)?;
	let res = api::client::send_request(req)?;
	Ok(res)
}
