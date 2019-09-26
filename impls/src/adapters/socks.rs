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

/// SOCKS Wallet 'plugin' implementation
use crate::libwallet::{Error, ErrorKind, Slate};
use crate::client_utils::{Client, ClientError};
use crate::SlateSender;
use std::net::SocketAddr;
use serde_json::{json, Value};

#[derive(Clone)]
pub struct SocksSlateSender {
	onion_service_addr: String,
}

impl SocksSlateSender {
	/// Create, return Err if scheme is not "http"
	pub fn new(onion_service_addr: &str) -> SocksSlateSender {
		SocksSlateSender {
			onion_service_addr: onion_service_addr.to_owned(),
		}
	}

	/// Check version of the listening wallet
	fn check_other_version(&self, dest: &str) -> Result<(), Error> {
		let req = json!({
			"jsonrpc": "2.0",
			"method": "check_version",
			"id": 1,
			"params": []
		});

		let res: String = post(dest, None, req.to_string()).map_err(|e| {
			let mut report = format!("Performing version check (is recipient listening?): {}", e);
			let err_string = format!("{}", e);
			if err_string.contains("404") {
				// Report that the other version of the wallet is out of date
				report = format!(
					"Other wallet is incompatible and requires an upgrade. \
					 Please urge the other wallet owner to upgrade and try the transaction again."
				);
			}
			error!("{}", report);
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
			let report = format!("Other wallet reports unrecognized API format.");
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		if !supported_slate_versions.contains(&"V2".to_owned()) {
			let report = format!("Unable to negotiate slate format with other wallet.");
			error!("{}", report);
			return Err(ErrorKind::ClientCallback(report).into());
		}

		Ok(())
	}
}

impl SlateSender for SocksSlateSender {
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		let dest = format!("http://{}/v2/foreign", self.onion_service_addr);
		//let dest = format!("http://{}/v2/foreign", self.onion_service_addr);
		debug!("Posting transaction slate to {}", dest);

		self.check_other_version(&dest)?;

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

		let res: String = post(&dest, None, req.to_string()).map_err(|e| {
			let report = format!("Posting transaction slate (is recipient listening?): {}", e);
			error!("{}", report);
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
			.map_err(|_| ErrorKind::SlateDeser)?;

		Ok(slate)
	}
}

pub fn post(dest: &str, api_secret: Option<String>, input: String) -> Result<String, ClientError>
{
	let mut client = Client::new();
	client.use_socks = true;
	//Todo: Unwrap

	client.socks_proxy_addr = Some(SocketAddr::V4("127.0.0.1:9050".parse().unwrap()));
  debug!("Onion hidden service request details:");
  debug!("Socks proxy addr: {:?}", client.socks_proxy_addr);
  debug!("Destination Onion Service URL: {}", dest);
	let req = client.create_post_request(dest, api_secret, &input)?;
	let res = client.send_request(req)?;
	Ok(res)
}
