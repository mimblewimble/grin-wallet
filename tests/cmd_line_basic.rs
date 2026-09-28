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
use std::io::Write;
use std::process::{Command, Stdio};

use clap::App;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use grin_keychain::ExtKeychain;
use grin_wallet_impls::DefaultLCProvider;

mod common;
use common::{clean_output_dir, execute_command, initial_setup_wallet, instantiate_wallet, setup};
use grin_wallet_api::Owner;
use grin_wallet_libwallet::{OutputStatus, TxLogEntryType};

/// command line tests
fn command_line_test_impl(test_dir: &str) -> Result<(), grin_wallet_controller::Error> {
	let (logs_tx, logs_rx) = mpsc::sync_channel(100);
	let panic_hook = std::panic::take_hook();
	grin_util::init_logger(
		Some(grin_util::logger::LoggingConfig {
			log_to_file: false,
			stdout_log_level: log::Level::Error,
			tui_running: Some(true),
			..Default::default()
		}),
		Some(logs_tx),
	);
	std::panic::set_hook(panic_hook);
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
	let wallet_config1 = config1.clone().members.wallet;
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
	let wallet_config2 = config2.clone().members.wallet;
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

	// Check account selection through the CLI loop
	let mut cli = Command::new(env!("CARGO_BIN_EXE_grin-wallet"))
		.args([
			"-t",
			&format!("{}/wallet2", test_dir),
			"-p",
			"password2",
			"-a",
			"account_1",
			"-r",
			"http://127.0.0.1:1",
			"cli",
		])
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	cli.stdin.take().unwrap().write_all(
		b"open\naddress\nclose\n-a default open\naddress\naccount -a account_1\naddress\nexit\n",
	).unwrap();
	let output = cli.wait_with_output().unwrap();
	assert!(output.status.success());
	let output = String::from_utf8(output.stdout).unwrap();
	let accounts: Vec<_> = output
		.lines()
		.filter_map(|line| line.strip_prefix("Address for account - "))
		.collect();
	assert_eq!(accounts, ["account_1", "default", "account_1"]);

	// let's see those accounts
	let arg_vec = vec!["grin-wallet", "-p", "password1", "account"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// let's see those accounts
	let arg_vec = vec!["grin-wallet", "-p", "password2", "account"];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// Return an explained error when trying to send max amount on empty wallet.
	let arg_vec = vec!["grin-wallet", "-p", "password2", "send", "max"];
	let err = execute_command(&app, test_dir, "wallet2", &client2, arg_vec).unwrap_err();
	assert!(format!("{}", err).contains("No spendable funds"));

	// Mine a bit into wallet 1 so we have something to send
	// (TODO: Be able to stop listeners so we can test this better)
	let wallet_config1 = config1.clone().members.wallet;
	let (wallet1, mask1_i) =
		instantiate_wallet(wallet_config1, client1.clone(), "password1", "default")?;
	let mask1 = (&mask1_i).as_ref();
	let api1 = Owner::new(wallet1.clone(), None, config1.config_file_path.clone());

	api1.set_active_account(mask1, "mining")?;

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
	// Reuse startup args as in interactive mode
	{
		let start = app
			.clone()
			.get_matches_from(vec!["grin-wallet", "-a", "default", "cli"]);
		let global_args =
			grin_wallet::cmd::wallet_args::parse_global_args(&wallet_config2, &start).unwrap();
		let mut api = Owner::new(wallet2.clone(), None, config2.config_file_path.clone());
		for command in [
			vec!["grin-wallet", "account", "-a", "account_1"],
			vec!["grin-wallet", "address"],
			vec!["grin-wallet", "receive", "-i", &file_name],
		] {
			let args = app.clone().get_matches_from(command);
			grin_wallet::cmd::wallet_args::parse_and_execute(
				&mut api,
				mask2_i.clone(),
				&wallet_config2,
				config2.tor_config(),
				&global_args,
				&args,
				true,
				true,
			)?;
		}
		let (_, txs) = api.retrieve_txs(mask2_i.as_ref(), false, None, None, None)?;
		assert_eq!(txs.len(), 1);
		api.set_active_account(mask2_i.as_ref(), "default")?;
	}

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

	let wallet_config1 = config1.clone().members.wallet;
	let (wallet1, mask1_i) = instantiate_wallet(
		wallet_config1.clone(),
		client1.clone(),
		"password1",
		"default",
	)?;
	let mask1 = (&mask1_i).as_ref();
	let api1 = Owner::new(wallet1.clone(), None, config1.config_file_path.clone());

	// Check our transaction log, should have 10 entries
	api1.set_active_account(mask1, "mining")?;
	let (refreshed, txs) = api1.retrieve_txs(mask1, true, None, None, None)?;
	assert!(refreshed);
	assert_eq!(txs.len(), bh as usize);
	for t in txs {
		assert!(t.kernel_excess.is_some());
	}

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false);
	bh += 10;

	// update info for each
	let arg_vec = vec!["grin-wallet", "-p", "password1", "-a", "mining", "info"];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let arg_vec = vec!["grin-wallet", "-p", "password2", "-a", "account_1", "info"];
	execute_command(&app, test_dir, "wallet2", &client1, arg_vec)?;

	// check results in wallet 2
	let wallet_config2 = config2.clone().members.wallet;
	let (wallet2, mask2_i) = instantiate_wallet(
		wallet_config2.clone(),
		client2.clone(),
		"password2",
		"default",
	)?;
	let mask2 = (&mask2_i).as_ref();
	let api2 = Owner::new(wallet2.clone(), None, config2.config_file_path.clone());

	api2.set_active_account(mask2, "account_1")?;
	let (_, wallet1_info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert_eq!(wallet1_info.last_confirmed_height, bh);
	assert_eq!(wallet1_info.amount_currently_spendable, 10_000_000_000);

	// Send to wallet 2 with --amount_includes_fee
	api1.set_active_account(mask1, "mining")?;
	let (_, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
	let old_balance = wallet1_info.amount_currently_spendable;
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"--amount_includes_fee",
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

	// Mine some blocks to confirm the transaction
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false);
	bh += 10;

	// Check the new balance of wallet 1 reduced by EXACTLY the tx amount (instead of amount + fee)
	// This confirms that the TX amount was correctly computed to allow for the fee
	api1.set_active_account(mask1, "mining")?;
	let (_, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
	// make sure the new balance is exactly equal to the old balance - the tx amount + the amount mined since then
	let amt_mined = 10 * 60_000_000_000;
	assert_eq!(
		wallet1_info.amount_currently_spendable + 10_000_000_000,
		old_balance + amt_mined
	);

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
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b02.S1.slatepack",
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
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b02.S2.slatepack",
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
	let wallet_config1 = config1.clone().members.wallet;
	let (wallet1, mask1_i) = instantiate_wallet(
		wallet_config1.clone(),
		client1.clone(),
		"password1",
		"default",
	)?;
	let mask1 = (&mask1_i).as_ref();
	let api1 = Owner::new(wallet1.clone(), None, config1.config_file_path.clone());

	api1.set_active_account(mask1, "mining")?;
	let (refreshed, txs) = api1.retrieve_txs(mask1, true, None, None, None)?;
	assert!(refreshed);
	assert_eq!(txs.len(), bh as usize);

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
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b03.S1.slatepack",
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
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b03.S2.slatepack",
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
	let wallet_config1 = config1.clone().members.wallet;
	let (wallet1, mask1_i) = instantiate_wallet(
		wallet_config1.clone(),
		client1.clone(),
		"password1",
		"default",
	)?;
	let mask1 = (&mask1_i).as_ref();
	let api1 = Owner::new(wallet1.clone(), None, config1.config_file_path.clone());

	api1.set_active_account(mask1, "mining")?;
	let (refreshed, txs) = api1.retrieve_txs(mask1, true, None, None, None)?;
	assert!(refreshed);
	assert_eq!(txs.len(), bh as usize + 1);

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
		"36",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// set default account for wallet2
	let arg_vec = vec!["grin-wallet", "-p", "password2", "account", "-a", "default"];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// issue an invoice tx, wallet 2
	let arg_vec = vec!["grin-wallet", "-p", "password2", "invoice", "65"];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;
	let file_name = format!(
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b06.I1.slatepack",
		test_dir
	);

	// receive and finalize should point to pay
	for cmd in ["receive", "finalize"] {
		let arg_vec = vec![
			"grin-wallet",
			"-a",
			"mining",
			"-p",
			"password1",
			cmd,
			"-i",
			&file_name,
		];
		let e = execute_command(&app, test_dir, "wallet1", &client1, arg_vec).unwrap_err();
		assert!(e.to_string().contains("'pay'"), "{}", e);
	}

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
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b06.I2.slatepack",
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
	api2.set_active_account(mask2, "default")?;
	let (_, txs) = api2.retrieve_txs(mask2, true, None, None, None)?;
	let some_tx_id = txs[0].tx_slate_id.clone();
	assert!(some_tx_id.is_some());
	let tx_id = some_tx_id.unwrap().to_string().clone();
	let arg_vec = vec!["grin-wallet", "-p", "password2", "txs", "-t", &tx_id[..]];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// a bit of mining
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false);

	// Test wallet sweep
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"-a",
		"mining",
		"send",
		"max",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	let file_name = format!(
		"{}/wallet1/slatepack/0436430c-2b02-624c-2032-570501212b07.S1.slatepack",
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
		"{}/wallet2/slatepack/0436430c-2b02-624c-2032-570501212b07.S2.slatepack",
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

	// Mine some blocks to confirm the transaction
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false);

	// Check wallet 1 is now empty, except for immature coinbase outputs from recent mining),
	// and recently matured coinbase outputs, which were not mature at time of spending.
	// This confirms that the TX amount was correctly computed to allow for the fee
	api1.set_active_account(mask1, "mining")?;
	let (_, wallet1_info) = api1.retrieve_summary_info(mask1, true, 10)?;
	// Entire 'spendable' wallet balance should have been swept, except the coinbase outputs
	// which matured in the last batch of mining. Check that the new spendable balance is
	// exactly equal to those matured coins.
	let amt_mined = 10 * 60_000_000_000;
	assert_eq!(wallet1_info.amount_currently_spendable, amt_mined);

	// Failed send, with --late-lock, make sure outputs not locked (amount not changed).
	api2.set_active_account(mask2, "account_1")?;
	let (_, txs_before) = api2.retrieve_txs(mask2, false, None, None, None)?;
	let (_, wallet1_info) = api2.retrieve_summary_info(mask2, true, 1)?;
	let old_balance = wallet1_info.amount_currently_spendable;
	let mut arg_vec = vec![
		"grin-wallet",
		"-p",
		"password2",
		"-a",
		"account_1",
		"send",
		"-d",
		"tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp",
		"1",
		"--late-lock",
	];
	let args = app.clone().get_matches_from(arg_vec.clone());
	let mut config = initial_setup_wallet(test_dir, "wallet2");
	config.members.tor = Some(grin_wallet_config::TorConfig {
		use_integrated: Some(false),
		socks_proxy_addr: "invalid".into(),
		..Default::default()
	});
	let send = |args: &clap::ArgMatches| -> Result<(), grin_wallet_controller::Error> {
		logs_rx.try_iter().for_each(drop);
		grin_wallet::cmd::wallet_args::wallet_command(
			args,
			config.clone(),
			client2.clone(),
			false,
			|_| {},
		)?;
		assert!(logs_rx.try_iter().any(|entry| {
			entry.log.contains("Error sending slate sync:") && entry.log.contains("AddrParseError")
		}));
		Ok(())
	};
	send(&args)?;
	api2.set_active_account(mask2, "account_1")?;
	let (_, txs_after) = api2.retrieve_txs(mask2, false, None, None, None)?;
	assert_eq!(txs_before.len(), txs_after.len());
	let (_, wallet1_info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert_eq!(old_balance, wallet1_info.amount_currently_spendable);

	// The same failure without late locking leaves one transaction and locked outputs
	arg_vec.pop();
	let args = app.clone().get_matches_from(arg_vec);
	send(&args)?;
	let (_, txs_after) = api2.retrieve_txs(mask2, false, None, None, None)?;
	assert_eq!(txs_after.len(), txs_before.len() + 1);
	let tx = txs_after
		.iter()
		.find(|tx| !txs_before.iter().any(|before| before.id == tx.id))
		.unwrap();
	assert_eq!(tx.tx_type, TxLogEntryType::TxSent);
	assert!(tx.tx_slate_id.is_some());
	let (_, outputs) = api2.retrieve_outputs(mask2, false, false, Some(tx.id))?;
	assert!(outputs
		.iter()
		.any(|output| output.output.status == OutputStatus::Locked));
	let (_, wallet_info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert!(wallet_info.amount_currently_spendable < old_balance);

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn wallet_command_line() {
	let test_dir = "target/test_output/command_line";
	if let Err(e) = command_line_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
}
