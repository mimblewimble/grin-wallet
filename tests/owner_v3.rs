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

use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};

use clap::App;
use std::thread;
use std::time::Duration;

use grin_wallet_impls::DefaultLCProvider;
use grin_wallet_util::grin_keychain::ExtKeychain;

mod common;
use common::{setup, execute_command, initial_setup_wallet, instantiate_wallet, post};
use url::Url;

use serde_json::{json, Value};

#[test]
fn owner_v3() -> Result<(), grin_wallet_controller::Error> {
	let test_dir = "target/test_output/owner_v3";
	setup(test_dir);

	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy: WalletProxy<
		DefaultLCProvider<LocalWalletClient, ExtKeychain>,
		LocalWalletClient,
		ExtKeychain,
	> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	// load app yaml. If it don't exist, just say so and exit
	let yml = load_yaml!("../src/bin/grin-wallet.yml");
	let app = App::from_yaml(yml);

	// wallet init
	let arg_vec = vec!["grin-wallet", "-p", "password", "init", "-h"];
	// should create new wallet file
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone())?;

	// add wallet to proxy
	let config1 = initial_setup_wallet(test_dir, "wallet1");
	//config1.owner_api_listen_port = Some(13420);
	let (wallet1, mask1_i) =
		instantiate_wallet(config1.clone(), client1.clone(), "password", "default")?;
	let mask1 = (&mask1_i).as_ref();
	wallet_proxy.add_wallet(
		"wallet1",
		client1.get_send_instance(),
		wallet1.clone(),
		mask1_i.clone(),
	);

	// Create wallet 2, which will run a listener
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;

	let config2 = initial_setup_wallet(test_dir, "wallet2");
	//config2.api_listen_port = 23415;
	let (wallet2, mask2_i) =
		instantiate_wallet(config2.clone(), client2.clone(), "password", "default")?;
	wallet_proxy.add_wallet(
		"wallet2",
		client2.get_send_instance(),
		wallet2.clone(),
		mask2_i.clone(),
	);

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// add some blocks manually
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// run the owner listener on wallet 1
	let arg_vec = vec!["grin-wallet", "-p", "password", "owner_api"];
	// Set running
	thread::spawn(move || {
		let yml = load_yaml!("../src/bin/grin-wallet.yml");
		let app = App::from_yaml(yml);
		execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone()).unwrap();
	});

	// run the foreign listener for wallet 2
	let arg_vec = vec!["grin-wallet", "-p", "password", "listen"];
	// Set owner listener running
	thread::spawn(move || {
		let yml = load_yaml!("../src/bin/grin-wallet.yml");
		let app = App::from_yaml(yml);
		execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone()).unwrap();
	});

	thread::sleep(Duration::from_millis(200));

	// Send simple retrieve_info request to owner listener
	let owner_url = Url::parse("http://127.0.0.1:3420/v3/owner").unwrap();
	//let req_raw = include_str!("data/retrieve_info.req.json");
	//println!("Request Raw: {}", req_raw);
	let req = json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "retrieve_summary_info",
		"params": {
			"token": null,
			"refresh_from_node": true,
			"minimum_confirmations": 1
		},
	});
	println!("Request in: {}", req);
	let res: String = post(&owner_url, None, &req).map_err(|e| {
		let err_string = format!("{}", e);
		println!("{}", err_string);
		thread::sleep(Duration::from_millis(200));
		grin_wallet_controller::ErrorKind::GenericError(err_string)
	})?;
	let res: Value = serde_json::from_str(&res).unwrap();
	println!("Response: {}", res);
	Ok(())
}
