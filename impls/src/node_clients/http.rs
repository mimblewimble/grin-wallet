// Copyright 2019 The Grin Developers
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

//! Client functions, implementations of the NodeClient trait

use crate::api::{self, LocatedTxKernel, OutputPrintable};
use crate::core::core::{Transaction, TxKernel};
use crate::libwallet::{NodeClient, NodeVersionInfo};
use futures::{stream, Stream};
use semver::Version;
use std::collections::HashMap;
use std::env;
use tokio::runtime::Runtime;

use crate::client_utils::Client;
use crate::libwallet;
use crate::util::secp::pedersen;
use crate::util::{self, to_hex};

use super::resp_types::*;
use crate::client_utils::json_rpc::*;

#[derive(Clone)]
pub struct HTTPNodeClient {
	node_url: String,
	node_api_secret: Option<String>,
	node_version_info: Option<NodeVersionInfo>,
}

impl HTTPNodeClient {
	/// Create a new client that will communicate with the given grin node
	pub fn new(node_url: &str, node_api_secret: Option<String>) -> HTTPNodeClient {
		HTTPNodeClient {
			node_url: node_url.to_owned(),
			node_api_secret: node_api_secret,
			node_version_info: None,
		}
	}

	/// Allow returning the chain height without needing a wallet instantiated
	pub fn chain_height(&self) -> Result<(u64, String), libwallet::Error> {
		self.get_chain_tip()
	}

	fn send_json_request<D: serde::de::DeserializeOwned>(
		&self,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, libwallet::Error> {
		let url = format!("{}/v2/foreign", self.node_url());
		let client = Client::new();
		let req = build_request(method, params);
		let res = client.post::<Request, Response>(url.as_str(), self.node_api_secret(), &req);

		match res {
			Err(e) => {
				let report = format!("Error calling {}: {}", method, e);
				error!("{}", report);
				Err(libwallet::ErrorKind::ClientCallback(report).into())
			}
			Ok(inner) => match inner.into_result() {
				Ok(r) => Ok(r),
				Err(e) => {
					let report = format!("Unable to parse response for {}: {}", method, e);
					error!("{}", report);
					Err(libwallet::ErrorKind::ClientCallback(report).into())
				}
			},
		}
	}
}

impl NodeClient for HTTPNodeClient {
	fn node_url(&self) -> &str {
		&self.node_url
	}
	fn node_api_secret(&self) -> Option<String> {
		self.node_api_secret.clone()
	}

	fn set_node_url(&mut self, node_url: &str) {
		self.node_url = node_url.to_owned();
	}

	fn set_node_api_secret(&mut self, node_api_secret: Option<String>) {
		self.node_api_secret = node_api_secret;
	}

	fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
		if let Some(v) = self.node_version_info.as_ref() {
			return Some(v.clone());
		}
		let retval = match self
			.send_json_request::<GetVersionResp>("get_version", &serde_json::Value::Null)
		{
			Ok(n) => NodeVersionInfo {
				node_version: n.node_version,
				block_header_version: n.block_header_version,
				verified: Some(true),
			},
			Err(e) => {
				// If node isn't available, allow offline functions
				// unfortunately have to parse string due to error structure
				let err_string = format!("{}", e);
				if err_string.contains("404") {
					return Some(NodeVersionInfo {
						node_version: "1.0.0".into(),
						block_header_version: 1,
						verified: Some(false),
					});
				} else {
					error!("Unable to contact Node to get version info: {}", e);
					return None;
				}
			}
		};
		self.node_version_info = Some(retval.clone());
		Some(retval)
	}

	/// Posts a transaction to a grin node
	fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), libwallet::Error> {
		let params = json!([tx, fluff]);
		self.send_json_request::<serde_json::Value>("push_transaction", &params)?;
		Ok(())
	}

	/// Return the chain tip from a given node
	fn get_chain_tip(&self) -> Result<(u64, String), libwallet::Error> {
		let result = self.send_json_request::<GetTipResp>("get_tip", &serde_json::Value::Null)?;
		Ok((result.height, result.last_block_pushed))
	}

	/// Get kernel implementation
	fn get_kernel(
		&mut self,
		excess: &pedersen::Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, libwallet::Error> {
		let version = self
			.get_version_info()
			.ok_or_else(|| libwallet::ErrorKind::ClientCallback("Unable to get version".into()))?;
		let version = Version::parse(&version.node_version)
			.map_err(|_| libwallet::ErrorKind::ClientCallback("Unable to parse version".into()))?;
		if version <= Version::new(2, 0, 0) {
			return Err(libwallet::ErrorKind::ClientCallback(
				"Kernel lookup not supported by node, please upgrade it".into(),
			)
			.into());
		}

		let mut query = String::new();
		if let Some(h) = min_height {
			query += &format!("min_height={}", h);
		}
		if let Some(h) = max_height {
			if !query.is_empty() {
				query += "&";
			}
			query += &format!("max_height={}", h);
		}
		if !query.is_empty() {
			query.insert_str(0, "?");
		}

		let url = format!(
			"{}/v1/chain/kernels/{}{}",
			self.node_url(),
			to_hex(excess.0.to_vec()),
			query
		);
		let client = Client::new();
		let res: Option<LocatedTxKernel> = client
			.get(url.as_str(), self.node_api_secret())
			.map_err(|e| libwallet::ErrorKind::ClientCallback(format!("Kernel lookup: {}", e)))?;

		Ok(res.map(|k| (k.tx_kernel, k.height, k.mmr_index)))
	}

	/// Retrieve outputs from node
	fn get_outputs_from_node(
		&self,
		wallet_outputs: Vec<pedersen::Commitment>,
	) -> Result<HashMap<pedersen::Commitment, (String, u64, u64)>, libwallet::Error> {
		// build a map of api outputs by commit so we can look them up efficiently
		let mut api_outputs: HashMap<pedersen::Commitment, (String, u64, u64)> = HashMap::new();

		if wallet_outputs.is_empty() {
			return Ok(api_outputs);
		}

		// build vec of commits for inclusion in query
		let query_params: Vec<String> = wallet_outputs
			.iter()
			.map(|commit| format!("{}", util::to_hex(commit.as_ref().to_vec())))
			.collect();

		let mut tasks = Vec::new();
		// going to leave this here even though we're moving
		// to the json RPC api to keep the functionality of
		// parallelizing larger requests. Will raise default
		// from 200 to 500, however
		let chunk_default = 500;
		let chunk_size = match env::var("GRIN_OUTPUT_QUERY_SIZE") {
			Ok(s) => match s.parse::<usize>() {
				Ok(c) => c,
				Err(e) => {
					error!(
						"Unable to parse GRIN_OUTPUT_QUERY_SIZE, defaulting to {}",
						chunk_default
					);
					error!("Reason: {}", e);
					chunk_default
				}
			},
			Err(_) => chunk_default,
		};

		trace!("Output query chunk size is: {}", chunk_size);

		let url = format!("{}/v2/foreign", self.node_url());
		let client = Client::new();
		/*let res = client.post::<Request, Response>(url.as_str(), self.node_api_secret(), &req);*/

		for query_chunk in query_params.chunks(chunk_size) {
			let params = json!([query_chunk, null, null, false, false]);
			let req = build_request("get_outputs", &params);
			tasks.push(client.post_async::<Request, Response>(
				url.as_str(),
				&req,
				self.node_api_secret(),
			));
		}

		let task = stream::futures_unordered(tasks).collect();
		let mut rt = Runtime::new().unwrap();
		let results: Vec<OutputPrintable> = match rt.block_on(task) {
			Ok(resps) => {
				let mut results = vec![];
				for r in resps {
					match r.into_result::<Vec<OutputPrintable>>() {
						Ok(mut r) => results.append(&mut r),
						Err(e) => {
							let report = format!("Unable to parse response for get_outputs: {}", e);
							error!("{}", report);
							return Err(libwallet::ErrorKind::ClientCallback(report).into());
						}
					};
				}
				results
			}
			Err(e) => {
				let report = format!("Getting outputs by id: {}", e);
				error!("Outputs by id failed: {}", e);
				return Err(libwallet::ErrorKind::ClientCallback(report).into());
			}
		};

		for out in results.iter() {
			let height = match out.block_height {
				Some(h) => h,
				None => {
					let msg = format!("Missing block height for output {:?}", out.commit);
					return Err(libwallet::ErrorKind::ClientCallback(msg).into());
				}
			};
			api_outputs.insert(
				out.commit,
				(util::to_hex(out.commit.0.to_vec()), height, out.mmr_index),
			);
		}
		Ok(api_outputs)
	}

	fn get_outputs_by_pmmr_index(
		&self,
		start_index: u64,
		end_index: Option<u64>,
		max_outputs: u64,
	) -> Result<
		(
			u64,
			u64,
			Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)>,
		),
		libwallet::Error,
	> {
		let addr = self.node_url();
		let mut query_param = format!("start_index={}&max={}", start_index, max_outputs);

		if let Some(e) = end_index {
			query_param = format!("{}&end_index={}", query_param, e);
		};

		let url = format!("{}/v1/txhashset/outputs?{}", addr, query_param,);

		let mut api_outputs: Vec<(pedersen::Commitment, pedersen::RangeProof, bool, u64, u64)> =
			Vec::new();

		let client = Client::new();

		match client.get::<api::OutputListing>(url.as_str(), self.node_api_secret()) {
			Ok(o) => {
				for out in o.outputs {
					let is_coinbase = match out.output_type {
						api::OutputType::Coinbase => true,
						api::OutputType::Transaction => false,
					};
					let range_proof = match out.range_proof() {
						Ok(r) => r,
						Err(e) => {
							let msg = format!("Unexpected error in returned output (missing range proof): {:?}. {:?}, {}",
									out.commit,
									out,
									e);
							error!("{}", msg);
							return Err(libwallet::ErrorKind::ClientCallback(msg).into());
						}
					};
					let block_height = match out.block_height {
						Some(h) => h,
						None => {
							let msg = format!("Unexpected error in returned output (missing block height): {:?}. {:?}",
									out.commit,
									out);
							error!("{}", msg);
							return Err(libwallet::ErrorKind::ClientCallback(msg).into());
						}
					};
					api_outputs.push((
						out.commit,
						range_proof,
						is_coinbase,
						block_height,
						out.mmr_index,
					));
				}
				Ok((o.highest_index, o.last_retrieved_index, api_outputs))
			}
			Err(e) => {
				// if we got anything other than 200 back from server, bye
				error!(
					"get_outputs_by_pmmr_index: error contacting {}. Error: {}",
					addr, e
				);
				let report = format!("outputs by pmmr index: {}", e);
				Err(libwallet::ErrorKind::ClientCallback(report).into())
			}
		}
	}

	fn height_range_to_pmmr_indices(
		&self,
		start_height: u64,
		end_height: Option<u64>,
	) -> Result<(u64, u64), libwallet::Error> {
		debug!("Indices start");
		let addr = self.node_url();
		let mut query_param = format!("start_height={}", start_height);
		if let Some(e) = end_height {
			query_param = format!("{}&end_height={}", query_param, e);
		};

		let url = format!("{}/v1/txhashset/heightstopmmr?{}", addr, query_param,);

		let client = Client::new();

		match client.get::<api::OutputListing>(url.as_str(), self.node_api_secret()) {
			Ok(o) => Ok((o.last_retrieved_index, o.highest_index)),
			Err(e) => {
				// if we got anything other than 200 back from server, bye
				error!("heightstopmmr: error contacting {}. Error: {}", addr, e);
				let report = format!(": {}", e);
				Err(libwallet::ErrorKind::ClientCallback(report).into())
			}
		}
	}
}

/*
/// Call the wallet API to create a coinbase output for the given block_fees.
/// Will retry based on default "retry forever with backoff" behavior.
pub fn create_coinbase(dest: &str, block_fees: &BlockFees) -> Result<CbData, Error> {
	let url = format!("{}/v1/wallet/foreign/build_coinbase", dest);
	match single_create_coinbase(&url, &block_fees) {
		Err(e) => {
			error!(
				"Failed to get coinbase from {}. Run grin-wallet listen?",
				url
			);
			error!("Underlying Error: {}", e.cause().unwrap());
			error!("Backtrace: {}", e.backtrace().unwrap());
			Err(e)?
		}
		Ok(res) => Ok(res),
	}
}

/// Makes a single request to the wallet API to create a new coinbase output.
fn single_create_coinbase(url: &str, block_fees: &BlockFees) -> Result<CbData, Error> {
	let res = Client::post(url, None, block_fees).context(ErrorKind::GenericError(
		"Posting create coinbase".to_string(),
	))?;
	Ok(res)
}*/
