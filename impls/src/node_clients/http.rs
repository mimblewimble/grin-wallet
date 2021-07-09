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

//! Client functions, implementations of the NodeClient trait

use crate::api::{self, LocatedTxKernel, OutputListing, OutputPrintable};
use crate::core::core::{Transaction, TxKernel};
use crate::libwallet::{NodeClient, NodeVersionInfo};
use futures::stream::FuturesUnordered;
use futures::TryStreamExt;
use std::collections::HashMap;
use std::env;

use crate::client_utils::{Client, RUNTIME};
use crate::libwallet;
use crate::util::secp::pedersen;
use crate::util::ToHex;

use super::resp_types::*;
use crate::client_utils::json_rpc::*;

const ENDPOINT: &str = "/v2/foreign";

#[derive(Clone)]
pub struct HTTPNodeClient {
	client: Client,
	node_url: String,
	node_api_secret: Option<String>,
	node_version_info: Option<NodeVersionInfo>,
}

impl HTTPNodeClient {
	/// Create a new client that will communicate with the given grin node
	pub fn new(
		node_url: &str,
		node_api_secret: Option<String>,
	) -> Result<HTTPNodeClient, libwallet::Error> {
		Ok(HTTPNodeClient {
			client: Client::new().map_err(|_| libwallet::ErrorKind::Node)?,
			node_url: node_url.to_owned(),
			node_api_secret: node_api_secret,
			node_version_info: None,
		})
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
		let url = format!("{}{}", self.node_url(), ENDPOINT);
		let req = build_request(method, params);
		let res = self
			.client
			.post::<Request, Response>(url.as_str(), self.node_api_secret(), &req);

		match res {
			Err(e) => {
				let report = format!("Error calling {}: {}", method, e);
				error!("{}", report);
				Err(libwallet::ErrorKind::ClientCallback(report).into())
			}
			Ok(inner) => match inner.clone().into_result() {
				Ok(r) => Ok(r),
				Err(e) => {
					error!("{:?}", inner);
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
		let method = "get_kernel";
		let params = json!([excess.0.as_ref().to_hex(), min_height, max_height]);
		// have to handle this manually since the error needs to be parsed
		let url = format!("{}{}", self.node_url(), ENDPOINT);
		let req = build_request(method, &params);
		let res = self
			.client
			.post::<Request, Response>(url.as_str(), self.node_api_secret(), &req);

		match res {
			Err(e) => {
				let report = format!("Error calling {}: {}", method, e);
				error!("{}", report);
				Err(libwallet::ErrorKind::ClientCallback(report).into())
			}
			Ok(inner) => match inner.clone().into_result::<LocatedTxKernel>() {
				Ok(r) => Ok(Some((r.tx_kernel, r.height, r.mmr_index))),
				Err(e) => {
					let contents = format!("{:?}", inner);
					if contents.contains("NotFound") {
						Ok(None)
					} else {
						let report = format!("Unable to parse response for {}: {}", method, e);
						error!("{}", report);
						Err(libwallet::ErrorKind::ClientCallback(report).into())
					}
				}
			},
		}
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
			.map(|commit| format!("{}", commit.as_ref().to_hex()))
			.collect();

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

		let url = format!("{}{}", self.node_url(), ENDPOINT);
		let api_secret = self.node_api_secret();
		let task = async move {
			let params: Vec<_> = query_params
				.chunks(chunk_size)
				.map(|c| json!([c, null, null, false, false]))
				.collect();

			let mut reqs = Vec::with_capacity(params.len());
			for p in &params {
				reqs.push(build_request("get_outputs", p));
			}

			let mut tasks = Vec::with_capacity(params.len());
			for req in &reqs {
				tasks.push(self.client.post_async::<Request, Response>(
					url.as_str(),
					req,
					api_secret.clone(),
				));
			}

			let task: FuturesUnordered<_> = tasks.into_iter().collect();
			task.try_collect().await
		};

		let res: Result<Vec<_>, _> = RUNTIME.lock().unwrap().block_on(task);

		let results: Vec<OutputPrintable> = match res {
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
				(out.commit.as_ref().to_hex(), height, out.mmr_index),
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
			Vec<(
				pedersen::Commitment,
				pedersen::RangeProof,
				bool,
				bool,
				u64,
				u64,
			)>,
		),
		libwallet::Error,
	> {
		let mut api_outputs: Vec<(
			pedersen::Commitment,
			pedersen::RangeProof,
			bool,
			bool,
			u64,
			u64,
		)> = Vec::new();

		let params = json!([start_index, end_index, max_outputs, Some(true)]);
		let res = self.send_json_request::<OutputListing>("get_unspent_outputs", &params)?;
		// We asked for unspent outputs via the api but defensively filter out spent outputs just in case.
		for out in res.outputs.into_iter().filter(|out| out.spent == false) {
			let (is_coinbase, is_multisig) = match out.output_type {
				api::OutputType::Coinbase => (true, false),
				api::OutputType::Transaction => (false, false),
				api::OutputType::Multisig => (false, true),
			};
			let range_proof = match out.range_proof() {
				Ok(r) => r,
				Err(e) => {
					let msg = format!(
						"Unexpected error in returned output (missing range proof): {:?}. {:?}, {}",
						out.commit, out, e
					);
					error!("{}", msg);
					return Err(libwallet::ErrorKind::ClientCallback(msg).into());
				}
			};
			let block_height = match out.block_height {
				Some(h) => h,
				None => {
					let msg = format!(
						"Unexpected error in returned output (missing block height): {:?}. {:?}",
						out.commit, out
					);
					error!("{}", msg);
					return Err(libwallet::ErrorKind::ClientCallback(msg).into());
				}
			};
			api_outputs.push((
				out.commit,
				range_proof,
				is_coinbase,
				is_multisig,
				block_height,
				out.mmr_index,
			));
		}
		Ok((res.highest_index, res.last_retrieved_index, api_outputs))
	}

	fn height_range_to_pmmr_indices(
		&self,
		start_height: u64,
		end_height: Option<u64>,
	) -> Result<(u64, u64), libwallet::Error> {
		let params = json!([start_height, end_height]);
		let res = self.send_json_request::<OutputListing>("get_pmmr_indices", &params)?;

		Ok((res.last_retrieved_index, res.highest_index))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::core::core::{KernelFeatures, OutputFeatures, OutputIdentifier};
	use crate::core::libtx::build;
	use crate::core::libtx::ProofBuilder;
	use crate::keychain::{ExtKeychain, Keychain};

	// JSON api for "push_transaction" between wallet->node currently only supports "feature and commit" inputs.
	// We will need to revisit this if we decide to support "commit only" inputs (no features) at wallet level.
	fn tx1i1o_v2_compatible() -> Transaction {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
		let tx = build::transaction(
			KernelFeatures::Plain { fee: 2.into() },
			&[build::input(5, key_id1), build::output(3, key_id2)],
			&keychain,
			&builder,
		)
		.unwrap();

		let inputs: Vec<_> = tx.inputs().into();
		let inputs: Vec<_> = inputs
			.iter()
			.map(|input| OutputIdentifier {
				features: OutputFeatures::Plain,
				commit: input.commitment(),
			})
			.collect();
		Transaction {
			body: tx.body.replace_inputs(inputs.as_slice().into()),
			..tx
		}
	}

	// Wallet will "push" a transaction to node, serializing the transaction as json.
	// We are testing the json structure is what we expect here.
	#[test]
	fn test_transaction_json_ser_deser() {
		let tx1 = tx1i1o_v2_compatible();
		let value = serde_json::to_value(&tx1).unwrap();

		assert!(value["offset"].is_string());
		assert_eq!(value["body"]["inputs"][0]["features"], "Plain");
		assert!(value["body"]["inputs"][0]["commit"].is_string());
		assert_eq!(value["body"]["outputs"][0]["features"], "Plain");
		assert!(value["body"]["outputs"][0]["commit"].is_string());
		assert!(value["body"]["outputs"][0]["proof"].is_string());

		// Note: Tx kernel "features" serialize in a slightly unexpected way.
		assert_eq!(value["body"]["kernels"][0]["features"]["Plain"]["fee"], 2);
		assert!(value["body"]["kernels"][0]["excess"].is_string());
		assert!(value["body"]["kernels"][0]["excess_sig"].is_string());

		let tx2: Transaction = serde_json::from_value(value).unwrap();
		assert_eq!(tx1, tx2);

		let str = serde_json::to_string(&tx1).unwrap();
		println!("{}", str);
		let tx2: Transaction = serde_json::from_str(&str).unwrap();
		assert_eq!(tx1, tx2);
	}
}
