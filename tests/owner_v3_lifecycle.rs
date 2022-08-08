// Copyright 2021 The Grin Developers
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

#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;

extern crate grin_wallet;

use grin_wallet_api::{ECDHPubkey, JsonId};
use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};

use clap::App;
use std::thread;
use std::time::Duration;

use grin_keychain::ExtKeychain;
use grin_wallet_impls::DefaultLCProvider;
use grin_wallet_libwallet::{InitTxArgs, Slate, SlateVersion, VersionedSlate};
use serde_json;

use grin_util::Mutex;
use std::path::PathBuf;
use std::sync::Arc;

#[macro_use]
mod common;
use common::{
	clean_output_dir, derive_ecdh_key, execute_command, execute_command_no_setup,
	initial_setup_wallet, instantiate_wallet, send_request, send_request_enc, setup,
	setup_global_chain_type, RetrieveSummaryInfoResp,
};

#[test]
fn owner_v3_lifecycle() -> Result<(), grin_wallet_controller::Error> {
	setup_global_chain_type();

	let test_dir = "target/test_output/owner_v3_lifecycle";
	setup(test_dir);

	let yml = load_yaml!("../src/bin/grin-wallet.yml");
	let app = App::from_yaml(yml);

	// Create a new proxy to simulate server and wallet responses
	let wallet_proxy_a: Arc<
		Mutex<
			WalletProxy<
				DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
				LocalWalletClient,
				ExtKeychain,
			>,
		>,
	> = Arc::new(Mutex::new(WalletProxy::new(test_dir)));
	let (chain, wallet2, mask2_i) = {
		let mut wallet_proxy = wallet_proxy_a.lock();
		let chain = wallet_proxy.chain.clone();

		// Create wallet 2 manually, which will mine a bit and insert some
		// grins into the equation
		let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
		let arg_vec = vec!["grin-wallet", "-p", "password", "init", "-h"];
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;

		let config2 = initial_setup_wallet(test_dir, "wallet2");
		let wallet_config2 = config2.clone().members.unwrap().wallet;
		//config2.api_listen_port = 23415;
		let (wallet2, mask2_i) = instantiate_wallet(
			wallet_config2.clone(),
			client2.clone(),
			"password",
			"default",
		)?;
		wallet_proxy.add_wallet(
			"wallet2",
			client2.get_send_instance(),
			wallet2.clone(),
			mask2_i.clone(),
		);

		// start up the owner api with wallet created
		let arg_vec = vec!["grin-wallet", "owner_api", "-l", "43420", "--run_foreign"];
		// should create new wallet file
		let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());

		let p = wallet_proxy_a.clone();

		thread::spawn(move || {
			let yml = load_yaml!("../src/bin/grin-wallet.yml");
			let app = App::from_yaml(yml);
			execute_command_no_setup(
				&app,
				test_dir,
				"wallet1",
				&client1,
				arg_vec.clone(),
				|wallet_inst| {
					let mut wallet_proxy = p.lock();
					wallet_proxy.add_wallet(
						"wallet1",
						client1.get_send_instance(),
						wallet_inst,
						None,
					);
				},
			)
			.unwrap();
		});
		(chain, wallet2, mask2_i)
	};
	// give a bit for wallet to init and populate proxy with wallet via callback in thread above
	thread::sleep(Duration::from_millis(500));
	let mask2 = (&mask2_i).as_ref();
	let wallet_proxy = wallet_proxy_a.clone();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		let mut p = wallet_proxy.lock();
		if let Err(e) = p.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// mine into wallet 2 a bit
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet2.clone(), mask2, bh as usize, false);

	// We have an owner API with no wallet initialized. Init the secure API
	let sec_key_str = "e00dcc4a009e3427c6b1e1a550c538179d46f3827a13ed74c759c860761caf1e";
	let req = include_str!("data/v3_reqs/init_secure_api.req.json");
	let res = send_request(1, "http://127.0.0.1:43420/v3/owner", req)?;
	println!("RES 1: {:?}", res);

	assert!(res.is_ok());
	let value: ECDHPubkey = res.unwrap();
	let shared_key = derive_ecdh_key(sec_key_str, &value.ecdh_pubkey);

	// 2) get the top level directory, should default to ~/.grin/auto
	let req = include_str!("data/v3_reqs/get_top_level.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 2: {:?}", res);
	assert!(res.is_ok());
	assert!(res.unwrap().contains("auto"));

	// 3) now set the top level directory to our test wallet dir
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "set_top_level_directory",
		"params": {
			"dir": format!("{}/wallet1", test_dir)
		}
	});
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	println!("RES 3: {:?}", res);
	assert!(res.is_ok());

	// 4) create a configuration file in top level directory
	let req = include_str!("data/v3_reqs/create_config.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 4: {:?}", res);
	assert!(res.is_ok());
	let pb = PathBuf::from(format!("{}/wallet1/grin-wallet.toml", test_dir));
	assert!(pb.exists());

	// 5) Try and perform an operation without having a wallet open
	let req = include_str!("data/v3_reqs/retrieve_info.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 5: {:?}", res);
	assert!(res.is_err());

	// 6) Create a wallet
	let req = include_str!("data/v3_reqs/create_wallet.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 6: {:?}", res);
	assert!(res.is_ok());

	// 7) Try and create a wallet when one exists
	let req = include_str!("data/v3_reqs/create_wallet.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 7: {:?}", res);
	assert!(res.is_err());

	// 8) Open the wallet
	let req = include_str!("data/v3_reqs/open_wallet.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 8: {:?}", res);
	assert!(res.is_ok());
	let token = res.unwrap();

	// 9) Send a request with our new token
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "retrieve_summary_info",
		"params": {
			"token": token,
			"refresh_from_node": true,
			"minimum_confirmations": 1
		}
	});

	let res = send_request_enc::<RetrieveSummaryInfoResp>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	println!("RES 9: {:?}", res);
	assert!(res.is_ok());

	// 10) Send same request with no token (even though one is expected)
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "retrieve_summary_info",
		"params": {
			"token": null,
			"refresh_from_node": true,
			"minimum_confirmations": 1
		}
	});

	let res = send_request_enc::<RetrieveSummaryInfoResp>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	println!("RES 10: {:?}", res);
	assert!(res.is_err());

	// 11) Close the wallet
	let req = include_str!("data/v3_reqs/close_wallet.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 11: {:?}", res);
	assert!(res.is_ok());

	// 12) Wallet is closed
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "retrieve_summary_info",
		"params": {
			"token": token,
			"refresh_from_node": true,
			"minimum_confirmations": 1
		}
	});

	let res = send_request_enc::<RetrieveSummaryInfoResp>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	println!("RES 12: {:?}", res);
	assert!(res.is_err());

	// 13) Open the wallet again
	let req = include_str!("data/v3_reqs/open_wallet.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 13: {:?}", res);
	assert!(res.is_ok());
	let token = res.unwrap();

	// 14) Send a request with our new token
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "retrieve_summary_info",
		"params": {
			"token": token,
			"refresh_from_node": true,
			"minimum_confirmations": 1
		}
	});
	let res = send_request_enc::<RetrieveSummaryInfoResp>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	println!("RES 14: {:?}", res);
	assert!(res.is_ok());

	//15) Ask wallet 2 for some grins
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "issue_invoice_tx",
		"params": {
			"token": token,
			"args": {
				"amount": "6000000000",
				"message": "geez a block of grins",
				"dest_acct_name": null,
				"target_slate_version": null
			}
		}
	});
	let res = send_request_enc::<VersionedSlate>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	println!("RES 15: {:?}", res);
	assert!(res.is_ok());
	let mut slate: Slate = res.unwrap().into();

	// give this slate over to wallet 2 manually
	grin_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 1,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: false,
				..Default::default()
			};
			let res = api.process_invoice_tx(m, &slate, args);
			assert!(res.is_ok());
			slate = res.unwrap();
			api.tx_lock_outputs(m, &slate)?;
			Ok(())
		},
	)?;

	//16) Finalize the invoice tx (to foreign api)
	// (Tests that foreign API on same port also has its stored mask updated)
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "finalize_tx",
		"params": {
			"slate": VersionedSlate::into_version(slate, SlateVersion::V4)?,
		}
	});
	let res =
		send_request::<VersionedSlate>(1, "http://127.0.0.1:43420/v2/foreign", &req.to_string())?;
	println!("RES 16: {:?}", res);
	assert!(res.is_ok());

	//17) Change the password
	let req = include_str!("data/v3_reqs/close_wallet.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 17: {:?}", res);
	assert!(res.is_ok());

	let req = include_str!("data/v3_reqs/change_password.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 17a: {:?}", res);
	assert!(res.is_ok());

	// 18) trying to open with old password should fail
	let req = include_str!("data/v3_reqs/open_wallet.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 18: {:?}", res);
	assert!(res.is_err());

	// 19) Open with new password
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "open_wallet",
		"params": {
			"name": null,
			"password": "password"
		}
	});
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	println!("RES 19: {:?}", res);
	assert!(res.is_ok());
	let token = res.unwrap();

	// 20) Send a request with new token with changed password, ensure balances are still there and
	// therefore seed is the same
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "retrieve_summary_info",
		"params": {
			"token": token,
			"refresh_from_node": true,
			"minimum_confirmations": 1
		}
	});

	let res = send_request_enc::<RetrieveSummaryInfoResp>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	println!("RES 20: {:?}", res);

	thread::sleep(Duration::from_millis(200));
	assert_eq!(res.unwrap().1.amount_awaiting_finalization, 6000000000);

	// 21) Start the automatic updater, let it run for a bit
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "start_updater",
		"params": {
			"token": token,
			"frequency": 3000,
		}
	});

	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	assert!(res.is_ok());
	println!("RES 21: {:?}", res);
	thread::sleep(Duration::from_millis(5000));

	// 22) Retrieve some messages about updater status
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "get_updater_messages",
		"params": {
			"count": 1000,
		}
	});

	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	assert!(res.is_ok());
	println!("RES 22: {:?}", res);

	// 23) Stop Updater
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "stop_updater",
		"params": null
	});

	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	assert!(res.is_ok());
	println!("RES 23: {:?}", res);

	// 24) Delete the wallet (close first)
	let req = include_str!("data/v3_reqs/close_wallet.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	assert!(res.is_ok());

	let req = include_str!("data/v3_reqs/delete_wallet.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 24: {:?}", res);
	assert!(res.is_ok());

	// 25) Wallet should be gone
	let req = include_str!("data/v3_reqs/open_wallet.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 25: {:?}", res);
	assert!(res.is_err());

	// 26) Try to create a wallet with an invalid mnemonic
	let req = include_str!("data/v3_reqs/create_wallet_invalid_mn.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 26: {:?}", res);
	assert!(res.is_err());

	// 27) Try to create a wallet with an valid mnemonic
	let req = include_str!("data/v3_reqs/create_wallet_valid_mn.req.json");
	let res = send_request_enc::<String>(
		&JsonId::StrId(String::from("1")),
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req,
		&shared_key,
	)?;
	println!("RES 27: {:?}", res);
	assert!(res.is_ok());

	clean_output_dir(test_dir);

	Ok(())
}
