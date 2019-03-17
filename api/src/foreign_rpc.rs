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

//! JSON-RPC Stub generation for the Foreign API

use crate::keychain::Keychain;
use crate::libwallet::slate::Slate;
use crate::libwallet::types::{BlockFees, CbData, NodeClient, WalletBackend};
use crate::libwallet::ErrorKind;
use crate::Foreign;
use easy_jsonrpc;

/// Public definition used to generate jsonrpc api for Foreign.
#[easy_jsonrpc::rpc]
pub trait ForeignRpc {
	/**
	Networked version of [Foreign::build_coinbase](struct.Foreign.html#method.build_coinbase).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "build_coinbase",
		"params": [
			{
				"fees": 0,
				"height": 0,
				"key_id": null
			}
		],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind>;

	/**
	Networked version of [Foreign::verify_slate_messages](struct.Foreign.html#method.verify_slate_messages).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"params": [
			{
				"version_info": {
					"version": 2,
					"orig_version": 2,
					"min_compat_version": 0
				},
				"amount": 0,
				"fee": 0,
				"height": 0,
				"id": "414bad48-3386-4fa7-8483-72384c886ba3",
				"lock_height": 0,
				"num_participants": 2,
				"participant_data": [],
				"tx": {
					"body": {
						"inputs": [],
						"kernels": [],
						"outputs": []
					},
					"offset": "0000000000000000000000000000000000000000000000000000000000000000"
				}
			}
		],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		},
		"id": 1
	}
	# );
	```
	 */
	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind>;

	/**
	Networked version of [Foreign::receive_tx](struct.Foreign.html#method.receive_tx).

	# Json rpc example

	```ignore //TODO: No idea why this isn't expanding properly, check as we adjust the API
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "receive_tx",
		"params": [
			{
				"version_info": {
					"version": 2,
					"orig_version": 2,
					"min_compat_version": 0
				},
				"amount": 0,
				"fee": 0,
				"height": 0,
				"id": "414bad48-3386-4fa7-8483-72384c886ba3",
				"lock_height": 0,
				"num_participants": 2,
				"participant_data": [],
				"tx": {
					"body": {
						"inputs": [],
						"kernels": [],
						"outputs": []
					},
					"offset": "0000000000000000000000000000000000000000000000000000000000000000"
				}
			},
			null,
			null
		],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn receive_tx(
		&self,
		slate: Slate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<Slate, ErrorKind>;
}

impl<W: ?Sized, C, K> ForeignRpc for Foreign<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind> {
		Foreign::build_coinbase(self, block_fees).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind> {
		Foreign::verify_slate_messages(self, slate).map_err(|e| e.kind())
	}

	fn receive_tx(
		&self,
		mut slate: Slate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<Slate, ErrorKind> {
		Foreign::receive_tx(
			self,
			&mut slate,
			dest_acct_name.as_ref().map(String::as_str),
			message,
		)
		.map_err(|e| e.kind())?;
		Ok(slate)
	}
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:tt, $expected_response:tt) => {
		// create temporary wallet, run jsonrpc request on api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		fn rpc_owner_result(
			request: serde_json::Value,
		) -> Result<Option<serde_json::Value>, String> {
			use easy_jsonrpc::Handler;
			use grin_keychain::ExtKeychain;
			use grin_util::Mutex;
			use grin_wallet_api::{Foreign, ForeignRpc};
			use grin_wallet_config::WalletConfig;
			use grin_wallet_impls::{HTTPNodeClient, LMDBBackend};
			use grin_wallet_libwallet::types::WalletBackend;
			use serde_json;
			use std::sync::Arc;
			use tempfile::tempdir;

			let dir = tempdir().map_err(|e| format!("{:#?}", e))?;
				{
				let mut wallet_config = WalletConfig::default();
				wallet_config.data_file_dir = dir
					.path()
					.to_str()
					.ok_or("Failed to convert tmpdir path to string.".to_owned())?
					.to_owned();
				let node_client =
					HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
				let wallet: Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> =
					Arc::new(Mutex::new(
						LMDBBackend::new(wallet_config.clone(), "", node_client)
							.map_err(|e| format!("{:#?}", e))?,
					));
				let api_foreign = *Foreign::new(wallet);
				let foreign_api = &api_foreign as &dyn ForeignRpc;
				Ok(foreign_api.handle_request(request))
				}
			}

		let response = rpc_owner_result(serde_json::json!($request))
			.unwrap()
			.unwrap();
		let expected_response = serde_json::json!($expected_response);

		if response != expected_response {
			panic!(
				"(left != right) \nleft: {}\nright: {}",
				serde_json::to_string_pretty(&response).unwrap(),
				serde_json::to_string_pretty(&expected_response).unwrap()
				);
			}
	};
}
