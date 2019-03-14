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

//! Main interface into all wallet API functions.
//! Wallet APIs are split into two seperate blocks of functionality
//! called the 'Owner' and 'Foreign' APIs:
//! * The 'Owner' API is intended to expose methods that are to be
//! used by the wallet owner only. It is vital that this API is not
//! exposed to anyone other than the owner of the wallet (i.e. the
//! person with access to the seed and password.
//! * The 'Foreign' API contains methods that other wallets will
//! use to interact with the owner's wallet. This API can be exposed
//! to the outside world, with the consideration as to how that can
//! be done securely up to the implementor.
//!
//! Methods in both APIs are intended to be 'single use', that is to say each
//! method will 'open' the wallet (load the keychain with its master seed), perform
//! its operation, then 'close' the wallet (unloading references to the keychain and master
//! seed).

use uuid::Uuid;

use crate::core::core::Transaction;
use crate::keychain::{Keychain, Identifier};
use crate::libwallet::slate::Slate;
use crate::libwallet::types::{
	AcctPathMapping, NodeClient, OutputData, TxLogEntry,
	WalletBackend, WalletInfo,
};
use crate::libwallet::ErrorKind;
use crate::util::secp::pedersen;
use crate::Owner;
use easy_jsonrpc;

/// Public definition used to generate jsonrpc api for APIOwner.
#[easy_jsonrpc::rpc]
pub trait OwnerRpc {
	/**
	Networked version of [APIOwner::accounts](struct.APIOwner.html#method.accounts).

	# Json rpc example

	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": [],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				{
					"label": "default",
					"path": "0200000000000000000000000000000000"
				}
			]
		},
		"id": 1
	}
	# );
	```
	 */
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind>;

	/**
	Networked version of [APIOwner::create_account_path](struct.APIOwner.html#method.create_account_path).

	# Json rpc example

	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": ["account1"],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": "0200000001000000000000000000000000"
		},
		"id": 1
	}
	# );
	```
	 */
	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind>;

	/**
	Networked version of [APIOwner::set_active_account](struct.APIOwner.html#method.set_active_account).

	# Json rpc example

	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": ["default"],
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
	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIOwner::retrieve_outputs](struct.APIOwner.html#method.retrieve_outputs).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": [false, false, null],
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
	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<(OutputData, pedersen::Commitment)>), ErrorKind>;

	/**
	Networked version of [APIOwner::retrieve_txs](struct.APIOwner.html#method.retrieve_txs).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "retrieve_txs",
		"params": [false, null, null],
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
	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind>;

	/**
	Networked version of [APIOwner::retrieve_summary_info](struct.APIOwner.html#method.retrieve_summary_info).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": [false, 1],
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
	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind>;

	/**
	Networked version of [APIOwner::estimate_initiate_tx](struct.APIOwner.html#method.estimate_initiate_tx).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "estimate_initiate_tx",
		"params": [null, 0, 0, 10, 0, false],
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
	fn estimate_initiate_tx(
		&self,
		src_acct_name: Option<String>,
		amount: u64,
		minimum_confirmations: u64,
		max_outputs: usize,
		num_change_outputs: usize,
		selection_strategy_is_use_all: bool,
	) -> Result<(/* total */ u64, /* fee */ u64), ErrorKind>;

	/**
	Networked version of [APIOwner::finalize_tx](struct.APIOwner.html#method.finalize_tx).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"params": [{
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
		}],
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
	fn finalize_tx(&self, slate: Slate) -> Result<Slate, ErrorKind>;

	/**
	Networked version of [APIOwner::cancel_tx](struct.APIOwner.html#method.cancel_tx).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": [null, null],
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
	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIOwner::get_stored_tx](struct.APIOwner.html#method.get_stored_tx).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"params": [
			{
				"amount_credited": 0,
				"amount_debited": 0,
				"confirmation_ts": null,
				"confirmed": false,
				"creation_ts": "2019-03-05T20:49:59.444095Z",
				"fee": null,
				"id": 10,
				"messages": null,
				"num_inputs": 0,
				"num_outputs": 0,
				"parent_key_id": "0000000000000000000000000000000000",
				"stored_tx": null,
				"tx_slate_id": null,
				"tx_type": "TxReceived"
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
	fn get_stored_tx(&self, entry: &TxLogEntry) -> Result<Option<Transaction>, ErrorKind>;

	/**
	Networked version of [APIOwner::post_tx](struct.APIOwner.html#method.post_tx).

	```no_run
    # // This test currently fails on travis
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "post_tx",
		"params": [
			{
				"body": {
					"inputs": [],
					"kernels": [],
					"outputs": []
				},
				"offset": "0000000000000000000000000000000000000000000000000000000000000000"
			},
			false
		],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"ClientCallback": "Posting transaction to node: Request error: Cannot make request: an error occurred trying to connect: Connection refused (os error 61)"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIOwner::verify_slate_messages](struct.APIOwner.html#method.verify_slate_messages).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"params": [{
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
		}],
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
	Networked version of [APIOwner::restore](struct.APIOwner.html#method.restore).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "restore",
		"params": [],
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
	fn restore(&self) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIOwner::check_repair](struct.APIOwner.html#method.check_repair).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "check_repair",
		"params": [false],
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
	fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIOwner::node_height](struct.APIOwner.html#method.node_height).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "node_height",
		"params": [],
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
	fn node_height(&self) -> Result<(u64, bool), ErrorKind>;
}

impl<W: ?Sized, C, K> OwnerRpc for Owner<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind> {
		Owner::accounts(self).map_err(|e| e.kind())
	}

	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind> {
		Owner::create_account_path(self, label).map_err(|e| e.kind())
	}

	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind> {
		Owner::set_active_account(self, label).map_err(|e| e.kind())
	}

	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<(OutputData, pedersen::Commitment)>), ErrorKind> {
		Owner::retrieve_outputs(self, include_spent, refresh_from_node, tx_id)
			.map_err(|e| e.kind())
	}

	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind> {
		Owner::retrieve_txs(self, refresh_from_node, tx_id, tx_slate_id).map_err(|e| e.kind())
	}

	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind> {
		Owner::retrieve_summary_info(self, refresh_from_node, minimum_confirmations)
			.map_err(|e| e.kind())
	}

	fn estimate_initiate_tx(
		&self,
		src_acct_name: Option<String>,
		amount: u64,
		minimum_confirmations: u64,
		max_outputs: usize,
		num_change_outputs: usize,
		selection_strategy_is_use_all: bool,
	) -> Result<(/* total */ u64, /* fee */ u64), ErrorKind> {
		Owner::estimate_initiate_tx(
			self,
			src_acct_name.as_ref().map(String::as_str),
			amount,
			minimum_confirmations,
			max_outputs,
			num_change_outputs,
			selection_strategy_is_use_all,
		)
		.map_err(|e| e.kind())
	}

	fn finalize_tx(&self, mut slate: Slate) -> Result<Slate, ErrorKind> {
		Owner::finalize_tx(self, &mut slate).map_err(|e| e.kind())?;
		Ok(slate)
	}

	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind> {
		Owner::cancel_tx(self, tx_id, tx_slate_id).map_err(|e| e.kind())
	}

	fn get_stored_tx(&self, entry: &TxLogEntry) -> Result<Option<Transaction>, ErrorKind> {
		Owner::get_stored_tx(self, entry).map_err(|e| e.kind())
	}

	fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), ErrorKind> {
		Owner::post_tx(self, tx, fluff).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind> {
		Owner::verify_slate_messages(self, slate).map_err(|e| e.kind())
	}

	fn restore(&self) -> Result<(), ErrorKind> {
		Owner::restore(self).map_err(|e| e.kind())
	}

	fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), ErrorKind> {
		Owner::check_repair(self, delete_unconfirmed).map_err(|e| e.kind())
	}

	fn node_height(&self) -> Result<(u64, bool), ErrorKind> {
		Owner::node_height(self).map_err(|e| e.kind())
	}
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:tt, $expected_response:tt) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		fn rpc_owner_result(
			request: serde_json::Value,
		) -> Result<Option<serde_json::Value>, String> {
			use easy_jsonrpc::Handler;
			use grin_apiwallet::api::{Owner, OwnerApi};
			use grin_keychain::ExtKeychain;
			use grin_refwallet::{HTTPNodeClient, LMDBBackend, WalletBackend};
			use grin_util::Mutex;
			use grin_wallet_config::WalletConfig;
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
				let api_owner = Owner::new(wallet);
				let owner_api = &api_owner as &dyn OwnerApi;
				Ok(owner_api.handle_request(request))
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
