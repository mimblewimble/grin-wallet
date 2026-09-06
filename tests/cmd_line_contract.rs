// Copyright 2022 The Grin Developers
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

//! Test the contract command line works as expected
#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;

extern crate grin_wallet;

use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};

use clap::App;
use std::thread;
use std::time::Duration;

use grin_core::core::Transaction;
use grin_keychain::ExtKeychain;
use grin_wallet_impls::DefaultLCProvider;
use grin_wallet_libwallet::contract::types::{PaymentMemo, ProofType};

mod common;
use common::{clean_output_dir, execute_command, initial_setup_wallet, instantiate_wallet, setup};

/// Return the single slatepack file a wallet has written
fn only_slatepack(test_dir: &str, wallet_name: &str) -> String {
	let dir = format!("{}/{}/slatepack", test_dir, wallet_name);
	let mut found: Vec<String> = std::fs::read_dir(&dir)
		.unwrap_or_else(|e| panic!("no slatepack dir {}: {}", dir, e))
		.filter_map(|e| e.ok())
		.map(|e| e.path().to_string_lossy().to_string())
		.filter(|p| p.ends_with(".slatepack"))
		.collect();
	assert_eq!(found.len(), 1, "expected one slatepack in {}", dir);
	found.pop().unwrap()
}

fn contract_command_test_impl(test_dir: &str) -> Result<(), grin_wallet_controller::Error> {
	setup(test_dir);
	let mut wallet_proxy: WalletProxy<
		DefaultLCProvider<LocalWalletClient, ExtKeychain>,
		LocalWalletClient,
		ExtKeychain,
	> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	let yml = load_yaml!("../src/bin/grin-wallet.yml");
	let app = App::from_yaml(yml);

	// Two wallets, as a contract has two parties
	let arg_vec = vec!["grin-wallet", "-p", "password1", "init", "-h"];
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	let config1 = initial_setup_wallet(test_dir, "wallet1");
	let (wallet1, mask1_i) = instantiate_wallet(
		config1.clone().members.wallet,
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

	let arg_vec = vec!["grin-wallet", "-p", "password2", "init", "-h"];
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;
	let config2 = initial_setup_wallet(test_dir, "wallet2");
	let (wallet2, mask2_i) = instantiate_wallet(
		config2.clone().members.wallet,
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

	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Mine into wallet 1 so it has something to send
	let mask1 = (&mask1_i).as_ref();
	let mask2 = (&mask2_i).as_ref();
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 5, false);
	let fee_rate = 2 * grin_core::global::get_accept_fee_base();
	let expected_fee = Transaction::weight_by_iok(1, 1, 0) * fee_rate
		+ (Transaction::weight_by_iok(0, 0, 1) * fee_rate).div_ceil(2);
	let fee_rate = fee_rate.to_string();
	let file_name = format!("{}/wallet1/contract.slatepack", test_dir);

	// Wallet 1 opens a contract sending 1 grin, leaving an unencrypted slatepack because
	// no --encrypt-for was given
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"contract",
		"new",
		"--send",
		"1",
		"--min_conf",
		"1",
		"--fee_rate",
		&fee_rate,
		"--outfile",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;
	assert!(std::path::Path::new(&file_name).is_file());

	// Wallet 2 views the contract before signing it
	grin_wallet_controller::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		std::path::PathBuf::from(test_dir),
		|api, m| {
			let message = std::fs::read_to_string(&file_name)?;
			let slate = api.slate_from_slatepack_message(m, message, vec![0])?;
			assert_eq!(slate.fee_fields.fee(), expected_fee);
			Ok(())
		},
	)?;
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password2",
		"contract",
		"view",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// Wallet 1 can view its own contract too
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"contract",
		"view",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	// Wallet 2 can also view a proof-bearing slatepack encrypted for its address
	let mut recipient = None;
	grin_wallet_controller::controller::owner_single_use(
		wallet2.clone(),
		mask2,
		std::path::PathBuf::from(test_dir),
		|api, m| {
			recipient = Some(api.get_slatepack_address(m, 0)?.to_string());
			Ok(())
		},
	)?;
	std::fs::remove_file(file_name).unwrap();
	let recipient = recipient.unwrap();
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"contract",
		"new",
		"--receive",
		"1",
		"--no-payjoin",
		"--min_conf",
		"1",
		"--encrypt-for",
		&recipient,
		"--proof-type",
		"sender-nonce",
		"--memo",
		"CLI payment",
	];
	execute_command(&app, test_dir, "wallet1", &client1, arg_vec)?;

	let file_name = only_slatepack(test_dir, "wallet1");
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password2",
		"contract",
		"view",
		"-i",
		&file_name,
	];
	execute_command(&app, test_dir, "wallet2", &client2, arg_vec)?;

	// A file that isn't there is reported, not panicked on
	let arg_vec = vec![
		"grin-wallet",
		"-p",
		"password1",
		"contract",
		"view",
		"-i",
		"no/such/file.slatepack",
	];
	assert!(execute_command(&app, test_dir, "wallet1", &client1, arg_vec).is_err());

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_contract_command_line() {
	let test_dir = "target/test_output/contract_command_line";
	if let Err(e) = contract_command_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn rejects_conflicting_input_options() {
	let yml = load_yaml!("../src/bin/grin-wallet.yml");
	let app = App::from_yaml(yml);
	let account = "default".to_string();
	let args = app
		.clone()
		.get_matches_from_safe(vec![
			"grin-wallet",
			"contract",
			"new",
			"--send",
			"1",
			"--no-payjoin",
			"--use-inputs",
			"commitment",
		])
		.unwrap();
	let contract = args.subcommand_matches("contract").unwrap();
	let new_args = contract.subcommand_matches("new").unwrap();

	assert!(grin_wallet::cmd::wallet_args::parse_contract_new_args(new_args, &account).is_err());

	let args = app
		.get_matches_from_safe(vec![
			"grin-wallet",
			"contract",
			"sign",
			"--no-payjoin",
			"--use-inputs",
			"commitment",
		])
		.unwrap();
	let contract = args.subcommand_matches("contract").unwrap();
	let sign_args = contract.subcommand_matches("sign").unwrap();
	assert!(grin_wallet::cmd::wallet_args::parse_contract_setup_args(sign_args).is_err());
}

#[test]
fn parses_contract_options() {
	let yml = load_yaml!("../src/bin/grin-wallet.yml");
	let app = App::from_yaml(yml);
	let account = "default".to_string();
	let args = app
		.clone()
		.get_matches_from_safe(vec![
			"grin-wallet",
			"contract",
			"new",
			"--receive",
			"1",
			"--min_conf",
			"3",
			"--fee_rate",
			"2",
			"--ttl_blocks",
			"20",
			"--outfile",
			"new.slatepack",
			"--proof-type",
			"sender-nonce",
			"--memo",
			"new payment",
		])
		.unwrap();
	let contract = args.subcommand_matches("contract").unwrap();
	let new_args = contract.subcommand_matches("new").unwrap();
	let parsed =
		grin_wallet::cmd::wallet_args::parse_contract_new_args(new_args, &account).unwrap();
	assert_eq!(parsed.minimum_confirmations, 3);
	assert_eq!(parsed.fee_rate, Some(2));
	assert_eq!(parsed.ttl_blocks, Some(20));
	assert_eq!(parsed.outfile.as_deref(), Some("new.slatepack"));
	assert_eq!(parsed.proof_type, Some(ProofType::SenderNonce));
	assert_eq!(
		parsed.memo.as_ref().map(PaymentMemo::as_str),
		Some("new payment")
	);
	let memo = "a".repeat(PaymentMemo::MAX_LEN + 1);
	let args = app
		.clone()
		.get_matches_from_safe(vec![
			"grin-wallet",
			"contract",
			"new",
			"--receive",
			"1",
			"--proof-type",
			"invoice",
			"--memo",
			&memo,
		])
		.unwrap();
	let new_args = args
		.subcommand_matches("contract")
		.unwrap()
		.subcommand_matches("new")
		.unwrap();
	assert!(matches!(
		grin_wallet::cmd::wallet_args::parse_contract_new_args(new_args, &account),
		Err(grin_wallet::cmd::wallet_args::ParseError::ArgumentError(message))
			if message.contains("Payment memo exceeds 1024 bytes")
	));

	let expected = grin_wallet_libwallet::contract::types::DEFAULT_MINIMUM_CONFIRMATIONS;
	let args = app
		.clone()
		.get_matches_from_safe(vec!["grin-wallet", "contract", "new", "--send", "1"])
		.unwrap();
	let contract = args.subcommand_matches("contract").unwrap();
	let new_args = contract.subcommand_matches("new").unwrap();
	let parsed =
		grin_wallet::cmd::wallet_args::parse_contract_new_args(new_args, &account).unwrap();
	assert_eq!(parsed.minimum_confirmations, expected);
	assert_eq!(parsed.fee_rate, None);
	assert_eq!(parsed.ttl_blocks, None);
	let args = app
		.clone()
		.get_matches_from_safe(vec!["grin-wallet", "contract", "new", "-s", "1", "-b", "0"])
		.unwrap();
	let contract = args.subcommand_matches("contract").unwrap();
	let new_args = contract.subcommand_matches("new").unwrap();
	let err = match grin_wallet::cmd::wallet_args::parse_contract_new_args(new_args, &account) {
		Err(err) => err,
		Ok(_) => panic!("zero contract TTL accepted"),
	};
	assert_eq!(
		err,
		grin_wallet::cmd::wallet_args::ParseError::ArgumentError(
			"Contract TTL must be at least 1 block".to_string()
		)
	);
	for (rate, message) in [
		("0", "Contract fee rate must be at least 1"),
		("4294967296", "Contract fee rate is too large"),
	] {
		let args = app
			.clone()
			.get_matches_from_safe(vec![
				"grin-wallet",
				"contract",
				"new",
				"-s",
				"1",
				"--fee_rate",
				rate,
			])
			.unwrap();
		let new_args = args
			.subcommand_matches("contract")
			.unwrap()
			.subcommand_matches("new")
			.unwrap();
		let err = grin_wallet::cmd::wallet_args::parse_contract_new_args(new_args, &account)
			.err()
			.expect("invalid contract fee rate accepted");
		assert_eq!(
			err,
			grin_wallet::cmd::wallet_args::ParseError::ArgumentError(message.to_string())
		);
	}

	let args = app
		.clone()
		.get_matches_from_safe(vec!["grin-wallet", "contract", "sign"])
		.unwrap();
	let contract = args.subcommand_matches("contract").unwrap();
	let sign_args = contract.subcommand_matches("sign").unwrap();
	let parsed = grin_wallet::cmd::wallet_args::parse_contract_setup_args(sign_args).unwrap();
	assert_eq!(parsed.minimum_confirmations, None);
	assert_eq!(parsed.fee_rate, None);

	let args = app
		.clone()
		.get_matches_from_safe(vec![
			"grin-wallet",
			"contract",
			"sign",
			"--receive",
			"1",
			"--use-inputs",
			"commitment",
			"--min_conf",
			"3",
			"--fee_rate",
			"2",
			"--outfile",
			"sign.slatepack",
			"--proof-type",
			"invoice",
			"--memo",
			"sign payment",
		])
		.unwrap();
	let contract = args.subcommand_matches("contract").unwrap();
	let sign_args = contract.subcommand_matches("sign").unwrap();
	let parsed = grin_wallet::cmd::wallet_args::parse_contract_setup_args(sign_args).unwrap();
	assert_eq!(parsed.minimum_confirmations, Some(3));
	assert_eq!(parsed.fee_rate, Some(2));
	assert_eq!(parsed.outfile.as_deref(), Some("sign.slatepack"));
	assert_eq!(parsed.use_inputs.as_deref(), Some("commitment"));
	assert_eq!(parsed.proof_type, Some(ProofType::Invoice));
	assert_eq!(
		parsed.memo.as_ref().map(PaymentMemo::as_str),
		Some("sign payment")
	);

	let args = app
		.get_matches_from_safe(vec![
			"grin-wallet",
			"contract",
			"revoke",
			"--tx-id",
			"1",
			"--outfile",
			"revoke.slatepack",
		])
		.unwrap();
	let contract = args.subcommand_matches("contract").unwrap();
	let revoke_args = contract.subcommand_matches("revoke").unwrap();
	let parsed = grin_wallet::cmd::wallet_args::parse_contract_revoke_args(revoke_args).unwrap();
	assert_eq!(parsed.outfile.as_deref(), Some("revoke.slatepack"));
}

#[test]
fn selection_locks_early() {
	let yml = load_yaml!("../src/bin/grin-wallet.yml");
	let app = App::from_yaml(yml);
	let account = "default".to_string();
	let parse = |extra: &[&str]| {
		let mut command = vec!["grin-wallet", "contract", "new", "--send", "1"];
		command.extend_from_slice(extra);
		let args = app.clone().get_matches_from_safe(command).unwrap();
		let contract = args.subcommand_matches("contract").unwrap();
		let new_args = contract.subcommand_matches("new").unwrap();
		grin_wallet::cmd::wallet_args::parse_contract_new_args(new_args, &account).unwrap()
	};

	assert!(!parse(&[]).add_outputs);
	let selected = parse(&["--use-inputs", "commitment"]);
	assert!(selected.add_outputs);
	assert_eq!(selected.use_inputs.as_deref(), Some("commitment"));
	assert!(parse(&["--make-outputs", "1"]).add_outputs);
}
