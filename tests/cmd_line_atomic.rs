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

//! Test wallet command line works as expected
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
use common::{clean_output_dir, execute_command, initial_setup_wallet, instantiate_wallet, setup};

fn command_line_test_impl(test_dir: &str) -> Result<(), grin_wallet_controller::Error> {
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
	let arg_vec = vec!["grin-wallet", "-p", "password1", "init", "-h"];
	// should create new wallet file
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone())?;

	// trying to init twice - should fail
	assert!(execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone()).is_err());
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());

	// add wallet to proxy
	//let wallet1 = test_framework::create_wallet(&format!("{}/wallet1", test_dir), client1.clone());
	let config1 = initial_setup_wallet(test_dir, "wallet1");
	let wallet_config1 = config1.clone().members.unwrap().wallet;

	let (wallet1, mask1_i) = instantiate_wallet(
		wallet_config1.clone(),
		client1.clone(),
		"password1",
		"default",
	)?;
	wallet_proxy.add_wallet(
		"wallet1",
		client1.get_send_instance(),
		wallet1.clone(),
		mask1_i.clone(),
	);

	// Create wallet 2
	let arg_vec = vec!["grin-wallet", "-p", "password2", "init", "-h"];
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;

	let config2 = initial_setup_wallet(test_dir, "wallet2");
	let wallet_config2 = config2.clone().members.unwrap().wallet;
	let (wallet2, mask2_i) = instantiate_wallet(
		wallet_config2.clone(),
		client2.clone(),
		"password2",
		"default",
	)?;
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

	// Create some accounts in wallet 1
	let arg_vec = vec!["grin-wallet", "-p", "password1", "account", "-c", "mining"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"account",
		"-c",
		"account_1",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// Create some accounts in wallet 2
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password2",
		"account",
		"-c",
		"account_1",
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;

	// Mine a bit into wallet 1 so we have something to send
	let wallet_config1 = config1.clone().members.unwrap().wallet;
	let (wallet1, mask1_i) =
		instantiate_wallet(wallet_config1, client1.clone(), "password1", "default")?;
	let mask1 = (&mask1_i).as_ref();
	grin_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.set_active_account(m, "mining")?;
			Ok(())
		},
	)?;

	// Mine a bit into wallet 2 so we have something to send
	let wallet_config2 = config2.clone().members.unwrap().wallet;
	let (wallet2, mask2_i) =
		instantiate_wallet(wallet_config2, client2.clone(), "password2", "default")?;
	let mask2 = (&mask2_i).as_ref();
	grin_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			api.set_active_account(m, "account_1")?;
			Ok(())
		},
	)?;

	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet2.clone(), mask2, bh as usize, false);

	// Update info and check
	let arg_vec = vec!["grin-wallet", "-p", "password1", "-a", "mining", "info"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// create multisig output funding transaction
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"--multisig",
		"5",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	let arg_vec = vec!["grin-wallet", "-a", "mining", "-p", "password1", "txs"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b00.M1.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"receive",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;

	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b00.M2.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"process_multisig",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b00.M3.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-a",
		"account_1",
		"-p",
		"password2",
		"finalize",
		"-n",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b00.M4.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"finalize",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// mine some more coins to add confirmations to the multisig transaction
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	let arg_vec = vec!["grin-wallet", "-a", "mining", "-p", "password1", "txs"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec!["grin-wallet", "-a", "account_1", "-p", "password2", "txs"];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// create atomic swap refund transaction
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send_atomic",
		"-r", // create a refund transaction
		"--multisig_path",
		"m/2622924661/3526545887/2606926411/331176156",
		"--min_conf",
		"0",
		"4.9875",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	let arg_vec = vec!["grin-wallet", "-a", "mining", "-p", "password1", "txs"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b01.A1.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"receive_atomic",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec.clone())?;

	// shouldn't be allowed to receive twice
	assert!(execute_command(&app, test_dir, "wallet2", &client2, arg_vec).is_err());

	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b01.A2.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"countersign_atomic",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b01.A3.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-a",
		"account_1",
		"-p",
		"password2",
		"finalize_atomic",
		"-n", // don't post the refund transaction
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// create atomic swap main transaction
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"send_atomic",
		"--multisig_path",
		"m/2622924661/3526545887/2606926411/331176156",
		"--min_conf",
		"0",
		"4.9875",
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;
	let arg_vec = vec!["grin-wallet", "-a", "account_1", "-p", "password2", "txs"];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b02.A1.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"receive_atomic",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone())?;

	// shouldn't be allowed to receive twice
	assert!(execute_command(&app, test_dir, "wallet1", &client1, arg_vec).is_err());

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b02.A2.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"countersign_atomic",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b02.A3.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-a",
		"mining",
		"-p",
		"password1",
		"finalize_atomic",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b02.A4.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-a",
		"account_1",
		"-p",
		"password2",
		"recover_atomic_secret",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	let arg_vec = vec![
		"grin-wallet",
		"-a",
		"account_1",
		"-p",
		"password2",
		"get_atomic_secrets",
		"-i",
		"1", // atomic ID
		"--amount",
		"4.9875",
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn wallet_command_line() {
	let test_dir = "target/test_output/command_line_atomic";
	if let Err(e) = command_line_test_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
}
