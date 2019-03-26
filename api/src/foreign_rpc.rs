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
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "build_coinbase",
		"id": 1,
		"params": [
			{
				"fees": 0,
				"height": 0,
				"key_id": null
			}
		]
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"kernel": {
					"excess": "08dfe86d732f2dd24bac36aa7502685221369514197c26d33fac03041d47e4b490",
					"excess_sig": "c025d08939971fabac95f3266cc920c669735ab21eb258cc3479ba595c78eadfcd6c58562be8ee4d9968f8c51db8540a9fc7d2bc2b1d8483c1d0622ed75a9958",
					"features": "Coinbase",
					"fee": "0",
					"lock_height": "0"
				},
				"key_id": "0300000000000000000000000400000000",
				"output": {
					"commit": "08fe198e525a5937d0c5d01fa354394d2679be6df5d42064a0f7550c332fce3d9d",
					"features": "Coinbase",
					"proof": "9166dc13a374a50d99f16ddfb228ce6010ea22d1676de755c34123402b5a8e68871b37d716c14e07be14ceb0771cca62a302358aa82922fa87f1387cff3a4507027f04f3fcf54ed16bd97e40a06c6f969139188daca366bb78ccbc7ff0203de62e30077f8b4a8b314901666205d24ca93d54581aa082e37c370e178dea267ff11fa4669756a31c026348255108c4de4b7abe3636ebdd67f25387c9c2868d16fab9209ebee6d19c6395eaf313da67f164d8e997ed97de9478ddb24c34d8a0dcedc24c5d0a9d1c9f15de3264323fc768271d7981b1e2ae1e59675537115fdcd1ea7d60a7bd276865698d1c1598b7c22a1a6e212db4d0a0ba98706a746f63f2d8460a9d28b4e8a7d2ad1f531b32046e2285a034c2d49f7896026fa186f9665766ae158435157f94bd31b8ebf5c0637a9d72036348c1d1fb70659b6ca5e64427a9eb51569074311e970316fd370373149067a0781cd49cc450e80e14a84f9818ae8caf6c02877f15ab11397d60309249658e5a03f49354dce3873118be6f43ca436aa81165ca44d624fd6f504b8d186bca2ef7e3c5ff2b85db86b29ddd0fb58173960caf2b437c8190511685303ab0eb1b5a757e1509529063a145f5242350edb8e1a1807f505866fdb5689fd39d4595cf5084d30a1ba2af882969bf64aecad342926b16930a3d93781dcebc839b7bf5762146e0016c502aad33d24c9e708c810505bd9c6648bd8303ddbbe5c5cf82eb420784223182e1b59286249e38458c885f089e9211b3aafe7c6f85097878679775287423ebca7557cd3be9e44bb454c6b1914b9012e100d601d7a2ecb0c2a07b5e6f0c293b671e45a425d97169eb793834a40a0a64277e68b2809ca4556eed7d130c2ea973021fda08a01c771111b1cc12b647029fe19f1018486a0ef82bbe5ca7ff484c71d52f3238766d771eaf4204793809dc27"
				}
			}
		}
	}
	# "#
	# , 4, false, false, false);
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

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_foreign(
	request: serde_json::Value,
	test_dir: &str,
	blocks_to_mine: u64,
	perform_tx: bool,
	lock_tx: bool,
	finalize_tx: bool,
) -> Result<Option<serde_json::Value>, String> {
	use crate::{Foreign, ForeignRpc};
	use easy_jsonrpc::Handler;
	use grin_keychain::ExtKeychain;
	use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use grin_wallet_libwallet::api_impl;

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
	for _ in 0..blocks_to_mine {
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 1 as usize, false);
		//update local outputs after each block, so transaction IDs stay consistent
		let mut w = wallet1.lock();
		w.open_with_credentials().unwrap();
		let (wallet_refreshed, _) =
			api_impl::owner::retrieve_summary_info(&mut *w, true, 1).unwrap();
		assert!(wallet_refreshed);
		w.close().unwrap();
	}

	if perform_tx {
		let amount = 60_000_000_000;
		let mut w = wallet1.lock();
		w.open_with_credentials().unwrap();
		let mut slate = api_impl::owner::initiate_tx(
			&mut *w, None,   // account
			amount, // amount
			2,      // minimum confirmations
			500,    // max outputs
			1,      // num change outputs
			true,   // select all outputs
			None, None, true,
		)
		.unwrap();
		{
			let mut w2 = wallet2.lock();
			w2.open_with_credentials().unwrap();
			api_impl::foreign::receive_tx(&mut *w2, &mut slate, None, None, true).unwrap();
			w2.close().unwrap();
		}
		println!("RECIPIENT SLATE");
		// Spit out slate for input to finalize_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		if lock_tx {
			api_impl::owner::tx_lock_outputs(&mut *w, &slate).unwrap();
		}
		if finalize_tx {
			api_impl::owner::finalize_tx(&mut *w, &slate).unwrap();
		}
		w.close().unwrap();
	}

	if perform_tx && lock_tx && finalize_tx {
		// mine to move the chain on
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 3 as usize, false);
	}

	let mut api_foreign = Foreign::new(wallet1.clone());
	api_foreign.doctest_mode = true;
	let foreign_api = &api_foreign as &dyn ForeignRpc;
	Ok(foreign_api.handle_request(request))
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:expr, $expected_response:expr, $blocks_to_mine:expr, $perform_tx:expr, $lock_tx:expr, $finalize_tx:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		use grin_wallet_api::run_doctest_foreign;
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

		let response = run_doctest_foreign(
			request_val,
			dir,
			$blocks_to_mine,
			$perform_tx,
			$lock_tx,
			$finalize_tx,
			)
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
