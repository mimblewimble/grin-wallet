// Copyright 2019 The Grin Developers
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

use grin_wallet_api::ECDHPubkey;
use grin_wallet_impls::test_framework::{LocalWalletClient, WalletProxy};

use clap::App;
use std::thread;
use std::time::Duration;

use grin_wallet_impls::DefaultLCProvider;
use grin_wallet_util::grin_keychain::ExtKeychain;
use serde_json;

use grin_wallet_util::grin_util::Mutex;
use std::path::PathBuf;
use std::sync::Arc;

#[macro_use]
mod common;
use common::{
	clean_output_dir, derive_ecdh_key, execute_command_no_setup, send_request, send_request_enc,
	setup, RetrieveSummaryInfoResp,
};

#[test]
fn owner_v3_lifecycle() -> Result<(), grin_wallet_controller::Error> {
	let test_dir = "target/test_output/owner_v3_lifecycle";
	setup(test_dir);

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
	{
		let wallet_proxy = wallet_proxy_a.lock();
		let _chain = wallet_proxy.chain.clone();

		// start up the owner api with wallet created
		let arg_vec = vec!["grin-wallet", "owner_api", "-l", "43420"];
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
	}
	// give a bit for wallet to init and populate proxy with wallet via callback in thread above
	thread::sleep(Duration::from_millis(500));
	let wallet_proxy = wallet_proxy_a.clone();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		let mut p = wallet_proxy.lock();
		if let Err(e) = p.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

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
	let res =
		send_request_enc::<String>(1, 1, "http://127.0.0.1:43420/v3/owner", &req, &shared_key)?;
	println!("RES 2: {:?}", res);
	assert!(res.is_ok());
	assert!(res.unwrap().contains(".grin/auto"));

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
		1,
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	println!("RES 3: {:?}", res);
	assert!(res.is_ok());

	// 4) create a configuration file in top level directory
	let req = include_str!("data/v3_reqs/create_config.req.json");
	let res =
		send_request_enc::<String>(1, 1, "http://127.0.0.1:43420/v3/owner", &req, &shared_key)?;
	println!("RES 4: {:?}", res);
	assert!(res.is_ok());
	let pb = PathBuf::from(format!("{}/wallet1/grin-wallet.toml", test_dir));
	assert!(pb.exists());

	// 5) Try and perform an operation without having a wallet open
	let req = include_str!("data/v3_reqs/retrieve_info.req.json");
	let res =
		send_request_enc::<String>(1, 1, "http://127.0.0.1:43420/v3/owner", &req, &shared_key)?;
	println!("RES 5: {:?}", res);
	assert!(res.is_err());

	// 6) Create a wallet
	let req = include_str!("data/v3_reqs/create_wallet.req.json");
	let res =
		send_request_enc::<String>(1, 1, "http://127.0.0.1:43420/v3/owner", &req, &shared_key)?;
	println!("RES 6: {:?}", res);
	assert!(res.is_ok());

	// 7) Try and create a wallet when one exists
	let req = include_str!("data/v3_reqs/create_wallet.req.json");
	let res =
		send_request_enc::<String>(1, 1, "http://127.0.0.1:43420/v3/owner", &req, &shared_key)?;
	println!("RES 7: {:?}", res);
	assert!(res.is_err());

	// 8) Open the wallet
	let req = include_str!("data/v3_reqs/open_wallet.req.json");
	let res =
		send_request_enc::<String>(1, 1, "http://127.0.0.1:43420/v3/owner", &req, &shared_key)?;
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
		1,
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
		1,
		1,
		"http://127.0.0.1:43420/v3/owner",
		&req.to_string(),
		&shared_key,
	)?;
	println!("RES 10: {:?}", res);
	assert!(res.is_err());

	thread::sleep(Duration::from_millis(200));
	clean_output_dir(test_dir);

	Ok(())
}
