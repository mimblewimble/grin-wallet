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

/// command line tests
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
	// already exists
	assert!(execute_command(&app, test_dir, "wallet2", &client2, arg_vec).is_err());

	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password2",
		"account",
		"-c",
		"account_2",
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// let's see those accounts
	let arg_vec = vec!["grin-wallet", "-p", "password1", "account"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// let's see those accounts
	let arg_vec = vec!["grin-wallet", "-p", "password2", "account"];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// Mine a bit into wallet 1 so we have something to send
	// (TODO: Be able to stop listeners so we can test this better)
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

	let mut bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Update info and check
	let arg_vec = vec!["grin-wallet", "-p", "password1", "-a", "mining", "info"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// try a file exchange
	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b00.S1.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"10",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	let arg_vec = vec!["grin-wallet", "-a", "mining", "-p", "password1", "txs"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

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

	// shouldn't be allowed to receive twice
	assert!(execute_command(&app, test_dir, "wallet2", &client2, arg_vec).is_err());

	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b00.S2.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-a",
		"mining",
		"-p",
		"password1",
		"finalize",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	bh += 1;

	let wallet_config1 = config1.clone().members.unwrap().wallet;
	let (wallet1, mask1_i) = instantiate_wallet(
		wallet_config1.clone(),
		client1.clone(),
		"password1",
		"default",
	)?;
	let mask1 = (&mask1_i).as_ref();

	// Check our transaction log, should have 10 entries
	grin_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.set_active_account(m, "mining")?;
			let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
			assert!(refreshed);
			assert_eq!(txs.len(), bh as usize);
			for t in txs {
				assert!(t.kernel_excess.is_some());
			}
			Ok(())
		},
	)?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false);
	bh += 10;

	// update info for each
	let arg_vec = vec!["grin-wallet", "-p", "password1", "-a", "mining", "info"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec!["grin-wallet", "-p", "password2", "-a", "account_1", "info"];
	execute_command(&app, test_dir, "wallet2", &client1, arg_vec)?;

	// check results in wallet 2
	let wallet_config2 = config2.clone().members.unwrap().wallet;
	let (wallet2, mask2_i) = instantiate_wallet(
		wallet_config2.clone(),
		client2.clone(),
		"password2",
		"default",
	)?;
	let mask2 = (&mask2_i).as_ref();

	grin_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			api.set_active_account(m, "account_1")?;
			let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.amount_currently_spendable, 10_000_000_000);
			Ok(())
		},
	)?;

	// Send encrypted from wallet 1 to wallet 2
	// output wallet 2's address for test creation purposes,
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"address",
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// Send encrypted to wallet 2
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"-d",
		"tgrin1ak8aaxpjg6ct5uje4lgzvjp65l0nrmgxndp5xjy74sumzp7wasysje3kmf",
		"10",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b01.S1.slatepack",
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
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b01.S2.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-a",
		"mining",
		"-p",
		"password1",
		"finalize",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	bh += 1;

	// Check our transaction log, should have bh entries
	let wallet_config1 = config1.clone().members.unwrap().wallet;
	let (wallet1, mask1_i) = instantiate_wallet(
		wallet_config1.clone(),
		client1.clone(),
		"password1",
		"default",
	)?;
	let mask1 = (&mask1_i).as_ref();

	grin_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.set_active_account(m, "mining")?;
			let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
			assert!(refreshed);
			assert_eq!(txs.len(), bh as usize);
			Ok(())
		},
	)?;

	// Send to self
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"-o",
		"3",
		"-s",
		"smallest",
		"10",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b02.S1.slatepack",
		test_dir
	);
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"receive",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec.clone())?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b02.S2.slatepack",
		test_dir
	);

	let arg_vec = vec![
		"grin-wallet",
		"-a",
		"mining",
		"-p",
		"password1",
		"finalize",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	bh += 1;

	// Check our transaction log, should have bh entries + 1 for self-seld
	let wallet_config1 = config1.clone().members.unwrap().wallet;
	let (wallet1, mask1_i) = instantiate_wallet(
		wallet_config1.clone(),
		client1.clone(),
		"password1",
		"default",
	)?;
	let mask1 = (&mask1_i).as_ref();

	grin_wallet_controller::controller::owner_single_use(
		Some(wallet1.clone()),
		mask1,
		None,
		|api, m| {
			api.set_active_account(m, "mining")?;
			let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
			assert!(refreshed);
			assert_eq!(txs.len(), bh as usize + 1);
			Ok(())
		},
	)?;

	// Another file exchange, don't send, but unlock with repair command
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"10",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec!["grin-wallet", "-p", "password1", "scan", "-d"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// Another file exchange, cancel this time
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"10",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec!["grin-wallet", "-a", "mining", "-p", "password1", "txs"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"cancel",
		"-i",
		"25",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// issue an invoice tx, wallet 2
	let arg_vec = vec!["grin-wallet", "-p", "password2", "invoice", "65"];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;
	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b05.I1.slatepack",
		test_dir
	);

	// now pay the invoice tx, wallet 1
	let arg_vec = vec![
		"grin-wallet",
		"-a",
		"mining",
		"-p",
		"password1",
		"pay",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b05.I2.slatepack",
		test_dir
	);

	// and finalize, wallet 2
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password2",
		"finalize",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// bit more mining
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 5, false);
	//bh += 5;

	// txs and outputs (mostly spit out for a visual in test logs)
	let arg_vec = vec!["grin-wallet", "-p", "password1", "-a", "mining", "txs"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// message output (mostly spit out for a visual in test logs)
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"txs",
		"-i",
		"10",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// txs and outputs (mostly spit out for a visual in test logs)
	let arg_vec = vec!["grin-wallet", "-p", "password1", "-a", "mining", "outputs"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec!["grin-wallet", "-p", "password2", "txs"];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	let arg_vec = vec!["grin-wallet", "-p", "password2", "outputs"];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// get tx output via -tx parameter
	let mut tx_id = "".to_string();
	grin_wallet_controller::controller::owner_single_use(
		Some(wallet2.clone()),
		mask2,
		None,
		|api, m| {
			api.set_active_account(m, "default")?;
			let (_, txs) = api.retrieve_txs(m, true, None, None)?;
			let some_tx_id = txs[0].tx_slate_id.clone();
			assert!(some_tx_id.is_some());
			tx_id = some_tx_id.unwrap().to_hyphenated().to_string().clone();
			Ok(())
		},
	)?;
	let arg_vec = vec!["grin-wallet", "-p", "password2", "txs", "-t", &tx_id[..]];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn wallet_command_line() {
	let test_dir = "target/test_output/command_line";
	if let Err(e) = command_line_test_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
}
