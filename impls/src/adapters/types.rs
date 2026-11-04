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

use crate::libwallet::{Error, Slate, SlateVersion, VersionedSlate};

use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
pub trait HttpSlateSender: Send + Sync {
	fn host_url(&self) -> String;

	async fn post(&self, url: &str, body: String) -> Result<String, Error>;

	/// Check version of the listening wallet
	async fn check_other_version(&self, url: &str) -> Result<SlateVersion, Error> {
		let req = json!({
			"jsonrpc": "2.0",
			"method": "check_version",
			"id": 1,
			"params": []
		});

		let res: String = self.post(url, req.to_string()).await.map_err(|e| {
			let report = format!("Performing version check (is recipient listening?): {}", e);
			Error::ClientCallback(report)
		})?;

		let res: Value = serde_json::from_str(&res)
			.map_err(|_| Error::ClientCallback(format!("Can not parse response {:?}", res)))?;
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
			serde_json::from_value(resp_value["foreign_api_version"].clone())
				.map_err(|_| Error::ClientCallback(format!("Can not parse response {:?}", res)))?;
		let supported_slate_versions: Vec<String> =
			serde_json::from_value(resp_value["supported_slate_versions"].clone())
				.map_err(|_| Error::ClientCallback(format!("Can not parse response {:?}", res)))?;

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

	async fn send(&self, slate: &Slate, finalize: bool) -> Result<Slate, Error> {
		let trailing = match self.host_url().ends_with('/') {
			true => "",
			false => "/",
		};
		let url_str = format!("{}{}v2/foreign", self.host_url(), trailing);

		let slate_send = match self.check_other_version(&url_str).await? {
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

		let res: String = self.post(&url_str, req.to_string()).await.map_err(|e| {
			let report = format!(
				"Sending transaction slate to other wallet (is recipient listening?): {}",
				e
			);
			Error::ClientCallback(report)
		})?;

		let res: Value = serde_json::from_str(&res)
			.map_err(|_| Error::ClientCallback(format!("Can not parse response {:?}", res)))?;
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
		if let Ok(slate_value) = serde_json::to_string(&slate_value) {
			let slate = Slate::deserialize_upgrade(&slate_value).map_err(|e| {
				error!("Error deserializing response slate: {}", e);
				Error::SlateDeser
			})?;
			Ok(slate)
		} else {
			error!("Error deserializing response slate: {}", slate_value);
			Err(Error::SlateDeser)
		}
	}
}

/// Posts slates to be read later by a corresponding getter
pub trait SlatePutter {
	/// Send a transaction asynchronously
	fn put_tx(&self, slate: &Slate, as_bin: bool) -> Result<(), Error>;
}

/// Checks for a transaction from a corresponding SlatePutter, returns the transaction if it exists
pub trait SlateGetter {
	/// Receive a transaction async. (Actually just read it from wherever and return the slate).
	/// Returns (Slate, whether it was in binary form)
	fn get_tx(&self) -> Result<(Slate, bool), Error>;
}
