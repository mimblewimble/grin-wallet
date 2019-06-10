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
use crate::libwallet::{Error, ErrorKind, Slate};
use crate::WalletCommAdapter;
use config::WalletConfig;
use serde::Serialize;
use serde_json::{json, Value};
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
		let url = format!("{}/v2/foreign", dest);
		debug!("Posting transaction slate to {}", url);

		// Note: not using easy-jsonrpc as don't want the dependencies in this crate
		let req = json!({
			"jsonrpc": "2.0",
			"method": "receive_tx",
			"id": 1,
			"params": [
						slate,
						null,
						null
					]
		});
		trace!("Sending receive_tx request: {}", req);

		let res: String = post(url.as_str(), None, &req).map_err(|e| {
			let report = format!("Posting transaction slate (is recipient listening?): {}", e);
			error!("{}", report);
			ErrorKind::ClientCallback(report)
		})?;

		let res: Value = serde_json::from_str(&res).unwrap();
		trace!("Response: {}", res);
		if res["result"]["error"] != json!(null) {
			let report = format!("Posting transaction slate: Error: {}, Message: {}",
				res["result"]["error"]["code"],
				res["result"]["error"]["message"]
			);
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		let slate_value = res["result"]["Ok"].clone();
		trace!("slate_value: {}", slate_value);
		let slate = Slate::deserialize_upgrade(&serde_json::to_string(&slate_value).unwrap()).map_err(|_| ErrorKind::SlateDeser)?;

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
