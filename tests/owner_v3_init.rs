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
use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};

use clap::App;
use std::thread;
use std::time::Duration;

use grin_wallet_impls::DefaultLCProvider;
use grin_wallet_util::grin_keychain::ExtKeychain;
use grin_wallet_util::grin_util::secp::key::{PublicKey, SecretKey};
use grin_wallet_util::grin_util::{from_hex, static_secp_instance, to_hex};
use rand::thread_rng;

#[macro_use]
mod common;
use common::{execute_command, execute_command_no_setup, instantiate_wallet, send_request, setup};

#[test]
fn owner_v3_init() -> Result<(), grin_wallet_controller::Error> {
	let test_dir = "target/test_output/owner_v3_init";
	setup(test_dir);
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy: WalletProxy<
		DefaultLCProvider<LocalWalletClient, ExtKeychain>,
		LocalWalletClient,
		ExtKeychain,
	> = WalletProxy::new(test_dir);

	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());

	// run a wallet owner listener without setting up a wallet
	let arg_vec = vec!["grin-wallet", "owner_api"];
	thread::spawn(move || {
		let yml = load_yaml!("../src/bin/grin-wallet.yml");
		let app = App::from_yaml(yml);
		execute_command_no_setup(&app, test_dir, "wallet1", &client1, arg_vec.clone()).unwrap();
	});

	// use in all tests
	let sec_key_str = "e00dcc4a009e3427c6b1e1a550c538179d46f3827a13ed74c759c860761caf1e";
	let _pub_key_str = "03b3c18c9a38783d105e238953b1638b021ba7456d87a5c085b3bdb75777b4c490";

	thread::sleep(Duration::from_millis(200));
	let req = include_str!("data/v3_reqs/init_secure_api.req.json");
	let res = send_request(1, "http://127.0.0.1:3420/v3/owner", req)?;
	assert!(res.is_ok());
	let value: ECDHPubkey = res.unwrap();

	let shared_key = {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();

		let sec_key_bytes = from_hex(sec_key_str.to_owned()).unwrap();
		let sec_key = SecretKey::from_slice(&secp, &sec_key_bytes).unwrap();

		let mut shared_pubkey = value.ecdh_pubkey.clone();
		shared_pubkey.mul_assign(&secp, &sec_key).unwrap();

		let x_coord = shared_pubkey.serialize_vec(&secp, true);
		SecretKey::from_slice(&secp, &x_coord[1..]).unwrap()
	};

	println!("SHARED KEY CLIENT: {:?}", shared_key);

	Ok(())
}
