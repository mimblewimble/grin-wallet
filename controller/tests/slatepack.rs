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

//! Test a wallet file send/recieve
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_core as core;
use grin_wallet_config::GlobalWalletConfig;
use grin_wallet_libwallet as libwallet;
use std::path::PathBuf;

use impls::test_framework::{self, LocalWalletClient};
use impls::{PathToSlatepack, SlatePutter as _};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use grin_wallet_libwallet::{
	InitTxArgs, InitTxSendArgs, IssueInvoiceTxArgs, Slate, Slatepack, SlatepackAddress,
	Slatepacker, SlatepackerArgs,
};

use ed25519_dalek::SigningKey as edDalekSecretKey;
use ed25519_dalek::VerifyingKey as edDalekPublicKey;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

fn output_slatepack(
	slate: &Slate,
	file: &str,
	armored: bool,
	use_bin: bool,
	sender: Option<SlatepackAddress>,
	recipients: Vec<SlatepackAddress>,
) -> Result<(), libwallet::Error> {
	let packer = Slatepacker::new(SlatepackerArgs {
		sender,
		recipients,
		dec_key: None,
	});
	let mut file = file.into();
	if armored {
		file = format!("{}.armored", file);
	}
	PathToSlatepack::new(file.into(), &packer, armored).put_tx(&slate, use_bin)
}

fn slate_from_packed(
	file: &str,
	armored: bool,
	dec_key: Option<&edDalekSecretKey>,
) -> Result<(Slatepack, Slate), libwallet::Error> {
	let packer = Slatepacker::new(SlatepackerArgs {
		sender: None,
		recipients: vec![],
		dec_key,
	});
	let mut file = file.into();
	if armored {
		file = format!("{}.armored", file);
	}
	let slatepack = PathToSlatepack::new(file.into(), &packer, armored).get_slatepack(true)?;
	Ok((slatepack.clone(), packer.get_slate(&slatepack)?))
}

/// self send impl
fn slatepack_exchange_test_impl(
	test_dir: &'static str,
	use_bin: bool,
	use_armored: bool,
	use_encryption: bool,
) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	// Create a new wallet test client, and set its queues to communicate with the
	// proxy
	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		false,
		api1
	);
	let mask1 = (&mask1_i).as_ref();
	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		false,
		api2
	);
	let mask2 = (&mask2_i).as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::REWARD;

	// add some accounts
	api1.create_account_path(mask1, "mining")?;
	api1.create_account_path(mask1, "listener")?;

	api2.create_account_path(mask2, "account1")?;
	api2.create_account_path(mask2, "account2")?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_account_by_name("mining")?;
	}
	let mut bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	let (recipients_1, dec_key_1, sender_1) = match use_encryption {
		true => {
			let sec_key = api1.get_slatepack_secret_key(mask1, 0)?;
			let pub_key = edDalekPublicKey::from(&sec_key);
			let rec_address = SlatepackAddress::new(&pub_key);
			(
				vec![rec_address.clone()],
				Some(sec_key),
				Some(rec_address.clone()),
			)
		}
		false => (vec![], None, None),
	};

	let (recipients_2, dec_key_2, sender_2) = match use_encryption {
		true => {
			let sec_key = api2.get_slatepack_secret_key(mask2, 0)?;
			let pub_key = edDalekPublicKey::from(&sec_key);
			let rec_address = SlatepackAddress::new(&pub_key);
			(
				vec![rec_address.clone()],
				Some(sec_key),
				Some(rec_address.clone()),
			)
		}
		false => (vec![], None, None),
	};

	let (send_file, receive_file, final_file) = match use_bin {
		false => (
			format!("{}/standard_S1.slatepack", test_dir),
			format!("{}/standard_S2.slatepack", test_dir),
			format!("{}/standard_S3.slatepack", test_dir),
		),
		true => (
			format!("{}/standard_S1.slatepackbin", test_dir),
			format!("{}/standard_S2.slatepackbin", test_dir),
			format!("{}/standard_S3.slatepackbin", test_dir),
		),
	};

	let (wallet1_refreshed, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
	assert!(wallet1_refreshed);
	assert_eq!(wallet1_info.last_confirmed_height, bh);
	assert_eq!(wallet1_info.total, bh * reward);
	// send to send
	let args = InitTxArgs {
		src_acct_name: Some("mining".to_owned()),
		amount: reward * 2,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: true,
		..Default::default()
	};
	let slate = api1.init_send_tx(mask1, args)?;
	// output tx file
	output_slatepack(
		&slate,
		&send_file,
		use_armored,
		use_bin,
		sender_1.clone(),
		recipients_2.clone(),
	)?;
	api1.tx_lock_outputs(mask1, &slate)?;

	// Get some mining done
	{
		wallet_inst!(wallet2, w);
		w.set_account_by_name("account1")?;
	}

	let (mut slatepack, mut slate) =
		slate_from_packed(&send_file, use_armored, (&dec_key_2).as_ref())?;

	// wallet 2 receives file, completes, sends file back
	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = api.receive_tx(&slate, None, None)?;
			output_slatepack(
				&slate,
				&receive_file,
				use_armored,
				use_bin,
				// re-encrypt for sender!
				sender_2.clone(),
				match slatepack.sender.clone() {
					Some(s) => vec![s.clone()],
					None => vec![],
				},
			)?;
			Ok(())
		},
	)?;

	// wallet 1 finalizes and posts
	let (_, mut slate) = slate_from_packed(&receive_file, use_armored, (&dec_key_1).as_ref())?;
	slate = api1.finalize_tx(mask1, &slate)?;
	// Output final file for reference
	output_slatepack(&slate, &final_file, use_armored, use_bin, None, vec![])?;
	api1.post_tx(mask1, &slate, false)?;
	bh += 1;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// Check total in mining account
	let (wallet1_refreshed, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
	assert!(wallet1_refreshed);
	assert_eq!(wallet1_info.last_confirmed_height, bh);
	assert_eq!(wallet1_info.total, bh * reward - reward * 2);

	// Check total in 'wallet 2' account
	let (wallet2_refreshed, wallet2_info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert!(wallet2_refreshed);
	assert_eq!(wallet2_info.last_confirmed_height, bh);
	assert_eq!(wallet2_info.total, 2 * reward);

	// Now other types of exchange, for reference
	// Invoice transaction
	let (send_file, receive_file, final_file) = match use_bin {
		false => (
			format!("{}/invoice_I1.slatepack", test_dir),
			format!("{}/invoice_I2.slatepack", test_dir),
			format!("{}/invoice_I3.slatepack", test_dir),
		),
		true => (
			format!("{}/invoice_I1.slatepackbin", test_dir),
			format!("{}/invoice_I2.slatepackbin", test_dir),
			format!("{}/invoice_I3.slatepackbin", test_dir),
		),
	};

	let args = IssueInvoiceTxArgs {
		amount: 1000000000,
		..Default::default()
	};
	let mut slate = api2.issue_invoice_tx(mask2, args)?;
	output_slatepack(
		&slate,
		&send_file,
		use_armored,
		use_bin,
		sender_2.clone(),
		recipients_1.clone(),
	)?;

	let args = InitTxArgs {
		src_acct_name: None,
		amount: slate.amount,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: true,
		..Default::default()
	};
	let res = slate_from_packed(&send_file, use_armored, (&dec_key_1).as_ref())?;
	slatepack = res.0;
	slate = res.1;
	slate = api1.process_invoice_tx(mask1, &slate, args)?;
	api1.tx_lock_outputs(mask1, &slate)?;
	output_slatepack(
		&slate,
		&receive_file,
		use_armored,
		use_bin,
		sender_1.clone(),
		match slatepack.sender.clone() {
			Some(s) => vec![s.clone()],
			None => vec![],
		},
	)?;
	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			// Wallet 2 receives the invoice transaction
			let res = slate_from_packed(&receive_file, use_armored, (&dec_key_2).as_ref())?;
			slate = res.1;
			slate = api.finalize_tx(&slate, false)?;
			output_slatepack(&slate, &final_file, use_armored, use_bin, None, vec![])?;
			Ok(())
		},
	)?;
	api1.post_tx(mask1, &slate, false)?;

	// Standard, with payment proof
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	let (send_file, receive_file, final_file) = match use_bin {
		false => (
			format!("{}/standard_pp_S1.slatepack", test_dir),
			format!("{}/standard_pp_S2.slatepack", test_dir),
			format!("{}/standard_pp_S3.slatepack", test_dir),
		),
		true => (
			format!("{}/standard_pp_S1.slatepackbin", test_dir),
			format!("{}/standard_pp_S2.slatepackbin", test_dir),
			format!("{}/standard_pp_S3.slatepackbin", test_dir),
		),
	};

	let address = Some(api2.get_slatepack_address(mask2, 0)?);

	// send to send
	let args = InitTxArgs {
		src_acct_name: Some("mining".to_owned()),
		amount: reward,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: true,
		payment_proof_recipient_address: address.clone(),
		..Default::default()
	};
	let mut slate = api1.init_send_tx(mask1, args)?;
	output_slatepack(
		&slate,
		&send_file,
		use_armored,
		use_bin,
		sender_1,
		recipients_2.clone(),
	)?;
	api1.tx_lock_outputs(mask1, &slate)?;

	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			let res = slate_from_packed(&send_file, use_armored, (&dec_key_2).as_ref())?;
			let slatepack = res.0;
			slate = res.1;
			slate = api.receive_tx(&slate, None, None)?;
			output_slatepack(
				&slate,
				&receive_file,
				use_armored,
				use_bin,
				sender_2,
				match slatepack.sender {
					Some(s) => vec![s.clone()],
					None => vec![],
				},
			)?;
			Ok(())
		},
	)?;

	// wallet 1 finalizes and posts
	let res = slate_from_packed(&receive_file, use_armored, (&dec_key_1).as_ref())?;
	slate = res.1;
	slate = api1.finalize_tx(mask1, &slate)?;
	// Output final file for reference
	output_slatepack(&slate, &final_file, use_armored, use_bin, None, vec![])?;
	api1.post_tx(mask1, &slate, false)?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

/// Exercise slate encryption/decryption via the API,
/// Since doctests don't cover encryption
fn slatepack_api_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	// Create a new wallet test client, and set its queues to communicate with the
	// proxy
	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		false,
		api1
	);
	let mask1 = (&mask1_i).as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::REWARD;

	// Get some mining done
	let bh = 6u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	let args = InitTxArgs {
		src_acct_name: Some("mining".to_owned()),
		amount: reward * 2,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: true,
		..Default::default()
	};
	let slate = api1.init_send_tx(mask1, args)?;
	// create an encrypted slatepack (just encrypted for self)
	let enc_addr = api1.get_slatepack_address(mask1, 0)?;
	let slatepack = api1.create_slatepack_message(mask1, &slate, Some(0), vec![enc_addr])?;
	println!("{}", slatepack);
	let slatepack_raw = api1.decode_slatepack_message(mask1, slatepack.clone(), vec![0])?;
	println!("{}", slatepack_raw);
	let decoded_slate = api1.slate_from_slatepack_message(mask1, slatepack, vec![0])?;
	println!("{}", decoded_slate);

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

/// Do not create transaction for invalid or wrong network Slatepack address.
fn slatepack_address_validation(test_dir: &'static str) -> Result<(), libwallet::Error> {
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();
	let config_path = PathBuf::from(test_dir).join("grin-wallet.toml");
	GlobalWalletConfig::for_chain(&core::global::ChainTypes::AutomatedTesting, &config_path)
		.write_to_file(config_path.to_str().unwrap(), false, None, None)?;

	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		false,
		api1
	);
	let mask1 = (&mask1_i).as_ref();

	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		false,
		api2
	);
	let mask2 = (&mask2_i).as_ref();

	let proxy_thread = thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	let reward = core::consensus::REWARD;
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 6, false);
	let slate = api2.issue_invoice_tx(
		mask2,
		IssueInvoiceTxArgs {
			amount: reward,
			..Default::default()
		},
	)?;

	let args = InitTxArgs {
		src_acct_name: Some("mining".to_owned()),
		amount: reward,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: true,
		..Default::default()
	};

	let mut wrong_net_args = args.clone();
	wrong_net_args.send_args = Some(InitTxSendArgs {
		dest: "grin1dvge9z4uqgqlpspmljrd7smh3grrw9xu2r9lkz3u67s3emj3ud2sd5gk9p".to_string(),
		post_tx: false,
		fluff: false,
		skip_tor: Some(true),
	});
	assert!(api1.init_send_tx(mask1, wrong_net_args.clone()).is_err());
	assert!(api1
		.process_invoice_tx(mask1, &slate, wrong_net_args)
		.is_err());

	let mut invalid_args = args.clone();
	invalid_args.send_args = Some(InitTxSendArgs {
		dest: "tgrinaddr10qlk22rxjap2ny8qltc2tl996kenxr3hhwuu6hrzs6tdq08yaqgqnlumr7".to_string(),
		post_tx: false,
		fluff: false,
		skip_tor: Some(true),
	});
	assert!(api1.init_send_tx(mask1, invalid_args.clone()).is_err());
	assert!(api1
		.process_invoice_tx(mask1, &slate, invalid_args)
		.is_err());

	let mut valid_args = args;
	valid_args.send_args = Some(InitTxSendArgs {
		dest: "tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp".to_string(),
		post_tx: false,
		fluff: false,
		skip_tor: Some(true),
	});
	api1.process_invoice_tx(mask1, &slate, valid_args.clone())?;
	api1.init_send_tx(mask1, valid_args)?;

	stopper.store(false, Ordering::Relaxed);
	proxy_thread.join().expect("wallet proxy thread panicked");
	Ok(())
}

#[test]
fn slatepack_exchange_json() {
	let test_dir = "test_output/slatepack_exchange_json";
	setup(test_dir);
	// JSON output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, false, false, false) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_exchange_bin() {
	let test_dir = "test_output/slatepack_exchange_bin";
	setup(test_dir);
	// Bin output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, true, false, false) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_exchange_armored() {
	let test_dir = "test_output/slatepack_exchange_armored";
	setup(test_dir);
	// Bin output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, true, true, true) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_exchange_json_enc() {
	let test_dir = "test_output/slatepack_exchange_json_enc";
	setup(test_dir);
	// JSON output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, false, false, true) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_exchange_bin_enc() {
	let test_dir = "test_output/slatepack_exchange_bin_enc";
	setup(test_dir);
	// Bin output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, true, false, true) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_exchange_armored_enc() {
	let test_dir = "test_output/slatepack_exchange_armored_enc";
	setup(test_dir);
	// Bin output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, true, true, true) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_api() {
	let test_dir = "test_output/slatepack_api";
	setup(test_dir);
	// JSON output
	if let Err(e) = slatepack_api_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_address() {
	let test_dir = "test_output/slatepack_address";
	setup(test_dir);
	if let Err(e) = slatepack_address_validation(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
