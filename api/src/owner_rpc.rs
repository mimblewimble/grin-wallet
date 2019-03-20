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

//! JSON-RPC Stub generation for the Owner API
use uuid::Uuid;

use crate::core::core::Transaction;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::slate::Slate;
use crate::libwallet::types::{
	AcctPathMapping, NodeClient, OutputCommitMapping, TxLogEntry, WalletBackend, WalletInfo,
};
use crate::libwallet::ErrorKind;
use crate::Owner;
use easy_jsonrpc;

/// Public definition used to generate jsonrpc api for Owner.
#[easy_jsonrpc::rpc]
pub trait OwnerRpc {
	/**
	Networked version of [Owner::accounts](struct.Owner.html#method.accounts).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
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
	# "#
	# , 4);
	```
	*/
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind>;

	/**
	Networked version of [Owner::create_account_path](struct.Owner.html#method.create_account_path).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": ["account1"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": "0200000001000000000000000000000000"
		},
		"id": 1
	}
	# "#
	# ,4);
	```
	 */
	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind>;

	/**
	Networked version of [Owner::set_active_account](struct.Owner.html#method.set_active_account).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": ["default"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		},
		"id": 1
	}
	# "#
	# , 4);
	```
	 */
	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_outputs](struct.Owner.html#method.retrieve_outputs).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": [false, true, null],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				[
					{
						"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
						"output": {
							"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
							"height": "1",
							"is_coinbase": true,
							"key_id": "0300000000000000000000000000000000",
							"lock_height": "4",
							"mmr_index": null,
							"n_child": 0,
							"root_key_id": "0200000000000000000000000000000000",
							"status": "Unspent",
							"tx_log_entry": 0,
							"value": "60000000000"
						}
					},
					{
						"commit": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
						"output": {
							"commit": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
							"height": "2",
							"is_coinbase": true,
							"key_id": "0300000000000000000000000100000000",
							"lock_height": "5",
							"mmr_index": null,
							"n_child": 1,
							"root_key_id": "0200000000000000000000000000000000",
							"status": "Unspent",
							"tx_log_entry": 1,
							"value": "60000000000"
						}
					}
				]
			]
		}
	}
	# "#
	# , 2);
	```
	*/
	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_txs](struct.Owner.html#method.retrieve_txs).

	# Json rpc example

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "retrieve_txs",
			"params": [true, null, null],
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"jsonrpc": "2.0",
	  "result": {
		"Ok": [
		  true,
		  [
			{
			  "amount_credited": "60000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-03-20T11:46:16.414656770Z",
			  "confirmed": true,
			  "creation_ts": "2019-03-20T11:46:16.414651989Z",
			  "fee": null,
			  "id": 0,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "tx_slate_id": null,
			  "tx_type": "ConfirmedCoinbase"
			},
			{
			  "amount_credited": "60000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-03-20T11:46:16.415354355Z",
			  "confirmed": true,
			  "creation_ts": "2019-03-20T11:46:16.415349934Z",
			  "fee": null,
			  "id": 1,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "tx_slate_id": null,
			  "tx_type": "ConfirmedCoinbase"
			}
		  ]
		]
	  }
	}
	# "#
	# , 2);
	```
	*/

	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_summary_info](struct.Owner.html#method.retrieve_summary_info).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": [true, 1],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
	"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				{
					"amount_awaiting_confirmation": "0",
					"amount_awaiting_finalization": "0",
					"amount_currently_spendable": "60000000000",
					"amount_immature": "180000000000",
					"amount_locked": "0",
					"last_confirmed_height": "4",
					"minimum_confirmations": "1",
					"total": "240000000000"
				}
			]
		}
	}
	# "#
	# ,4 );
	```
	 */

	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind>;

	/**
	Networked version of [Owner::estimate_initiate_tx](struct.Owner.html#method.initiate_tx).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "initiate_tx",
		"params": [null, 0, 0, 10, 0, false, "my message", null],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# "#
	# , 4);
	```
	 */

	fn initiate_tx(
		&self,
		src_acct_name: Option<String>,
		amount: u64,
		minimum_confirmations: u64,
		max_outputs: usize,
		num_change_outputs: usize,
		selection_strategy_is_use_all: bool,
		message: Option<String>,
		target_slate_version: Option<u16>,
	) -> Result<Slate, ErrorKind>;

	/**
	Networked version of [Owner::estimate_initiate_tx](struct.Owner.html#method.estimate_initiate_tx).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	Networked version of [Owner::tx_lock_outputs](struct.Owner.html#method.tx_lock_outputs).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
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
	fn tx_lock_outputs(&self, slate: Slate) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::finalize_tx](struct.Owner.html#method.finalize_tx).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	Networked version of [Owner::cancel_tx](struct.Owner.html#method.cancel_tx).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	Networked version of [Owner::get_stored_tx](struct.Owner.html#method.get_stored_tx).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	Networked version of [Owner::post_tx](struct.Owner.html#method.post_tx).

	```no_run
	# // This test currently fails on travis
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	Networked version of [Owner::verify_slate_messages](struct.Owner.html#method.verify_slate_messages).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	Networked version of [Owner::restore](struct.Owner.html#method.restore).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	Networked version of [Owner::check_repair](struct.Owner.html#method.check_repair).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	Networked version of [Owner::node_height](struct.Owner.html#method.node_height).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
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
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind> {
		Owner::retrieve_outputs(self, include_spent, refresh_from_node, tx_id).map_err(|e| e.kind())
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

	fn initiate_tx(
		&self,
		src_acct_name: Option<String>,
		amount: u64,
		minimum_confirmations: u64,
		max_outputs: usize,
		num_change_outputs: usize,
		selection_strategy_is_use_all: bool,
		message: Option<String>,
		target_slate_version: Option<u16>,
	) -> Result<Slate, ErrorKind> {
		Owner::initiate_tx(
			self,
			src_acct_name.as_ref().map(String::as_str),
			amount,
			minimum_confirmations,
			max_outputs,
			num_change_outputs,
			selection_strategy_is_use_all,
			message,
			target_slate_version,
		)
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

	fn tx_lock_outputs(&self, mut slate: Slate) -> Result<(), ErrorKind> {
		Owner::tx_lock_outputs(self, &mut slate).map_err(|e| e.kind())
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

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest(
	request: serde_json::Value,
	test_dir: &str,
	blocks_to_mine: u64,
) -> Result<Option<serde_json::Value>, String> {
	use crate::{Owner, OwnerRpc};
	use easy_jsonrpc::Handler;
	use grin_keychain::ExtKeychain;
	use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};

	use crate::core::global;
	use crate::core::global::ChainTypes;
	use grin_util as util;

	use std::fs;
	use std::thread;

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_mining_mode(ChainTypes::AutomatedTesting);

	let mut wallet_proxy: WalletProxy<LocalWalletClient, ExtKeychain> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	let rec_phrase_1 =
		"fat twenty mean degree forget shell check candy immense awful \
		 flame next during february bulb bike sun wink theory day kiwi embrace peace lunch";
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let wallet1 = test_framework::create_wallet(
		&format!("{}/wallet1", test_dir),
		client1.clone(),
		Some(rec_phrase_1),
	);
	wallet_proxy.add_wallet("wallet1", client1.get_send_instance(), wallet1.clone());

	let rec_phrase_2 =
		"hour kingdom ripple lunch razor inquiry coyote clay stamp mean \
		 sell finish magic kid tiny wage stand panther inside settle feed song hole exile";
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	let wallet2 = test_framework::create_wallet(
		&format!("{}/wallet2", test_dir),
		client2.clone(),
		Some(rec_phrase_2),
	);
	wallet_proxy.add_wallet("wallet2", client2.get_send_instance(), wallet2.clone());

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Mine a few blocks to wallet 1 so there's something to send
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), blocks_to_mine as usize);

	let api_owner = Owner::new(wallet1.clone());
	let owner_api = &api_owner as &dyn OwnerRpc;
	Ok(owner_api.handle_request(request))
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:expr, $expected_response:expr, $blocks_to_mine:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		use grin_wallet_api::run_doctest;
		use serde_json;
		use serde_json::Value;
		use tempfile::tempdir;

		let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
		let dir = dir
			.path()
			.to_str()
			.ok_or("Failed to convert tmpdir path to string.".to_owned())
			.unwrap();

		let request_val: Value = serde_json::from_str($request).unwrap();
		let expected_response: Value = serde_json::from_str($expected_response).unwrap();

		let response = run_doctest(request_val, dir, $blocks_to_mine)
			.unwrap()
			.unwrap();

		if response != expected_response {
			panic!(
				"(left != right) \nleft: {}\nright: {}",
				serde_json::to_string_pretty(&response).unwrap(),
				serde_json::to_string_pretty(&expected_response).unwrap()
				);
			}
	};
}
