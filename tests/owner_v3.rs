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

#[macro_use]
mod common;
use common::RetrieveSummaryInfoResp;
use common::{execute_command, initial_setup_wallet, instantiate_wallet, send_request, setup};

#[test]
fn owner_v3() -> Result<(), grin_wallet_controller::Error> {
	let test_dir = "target/test_output/owner_v3";
	setup(test_dir);

	setup_proxy!(test_dir, chain, wallet1, client1, mask1, wallet2, client2, _mask2);

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
	let req = include_str!("data/retrieve_info.req.json");
	let res = send_request(1, "http://127.0.0.1:3420/v3/owner", req)?;
	assert!(res.is_ok());
	let value: RetrieveSummaryInfoResp = res.unwrap();
	assert_eq!(value.1.amount_currently_spendable, 420000000000);
	println!("Response: {:?}", value);
	Ok(())
}
