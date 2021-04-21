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

use grin_wallet_libwallet as libwallet;
use grin_wallet_util::grin_core as core;

use impls::test_framework::{self, LocalWalletClient};
use impls::{PathToSlatepack, SlatePutter as _};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use grin_wallet_libwallet::{
	InitTxArgs, IssueInvoiceTxArgs, Slate, Slatepack, SlatepackAddress, Slatepacker,
	SlatepackerArgs, TxFlow,
};

use ed25519_dalek::PublicKey as edDalekPublicKey;
use ed25519_dalek::SecretKey as edDalekSecretKey;

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
		false
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
		false
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
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "mining")?;
		api.create_account_path(m, "listener")?;
		Ok(())
	})?;

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		api.create_account_path(m, "account1")?;
		api.create_account_path(m, "account2")?;
		Ok(())
	})?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let mut bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	let (recipients_1, dec_key_1, sender_1) = match use_encryption {
		true => {
			let mut rec_address = SlatepackAddress::random();
			let mut sec_key = edDalekSecretKey::from_bytes(&[0u8; 32]).unwrap();
			wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
				sec_key = api.get_slatepack_secret_key(m, 0)?;
				let pub_key = edDalekPublicKey::from(&sec_key);
				rec_address = SlatepackAddress::new(&pub_key);
				Ok(())
			})?;
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
			let mut rec_address = SlatepackAddress::random();
			let mut sec_key = edDalekSecretKey::from_bytes(&[0u8; 32]).unwrap();
			wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
				sec_key = api.get_slatepack_secret_key(m, 0)?;
				let pub_key = edDalekPublicKey::from(&sec_key);
				rec_address = SlatepackAddress::new(&pub_key);
				Ok(())
			})?;
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

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
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
		let slate = api.init_send_tx(m, args)?;
		// output tx file
		output_slatepack(
			&slate,
			&send_file,
			use_armored,
			use_bin,
			sender_1.clone(),
			recipients_2.clone(),
		)?;
		api.tx_lock_outputs(m, &slate)?;
		Ok(())
	})?;

	// Get some mining done
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("account1")?;
	}

	let (mut slatepack, mut slate) =
		slate_from_packed(&send_file, use_armored, (&dec_key_2).as_ref())?;

	// wallet 2 receives file, completes, sends file back
	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
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
	})?;

	// wallet 1 finalises and posts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_, mut slate) = slate_from_packed(&receive_file, use_armored, (&dec_key_1).as_ref())?;
		slate = api.finalize_tx(m, &slate)?;
		// Output final file for reference
		output_slatepack(&slate, &final_file, use_armored, use_bin, None, vec![])?;
		api.post_tx(m, &slate, false)?;
		bh += 1;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// Check total in mining account
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward - reward * 2);
		Ok(())
	})?;

	// Check total in 'wallet 2' account
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, bh);
		assert_eq!(wallet2_info.total, 2 * reward);
		Ok(())
	})?;

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

	let mut slate = Slate::blank(2, TxFlow::Invoice);

	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let args = IssueInvoiceTxArgs {
			amount: 1000000000,
			..Default::default()
		};
		slate = api.issue_invoice_tx(m, args)?;
		output_slatepack(
			&slate,
			&send_file,
			use_armored,
			use_bin,
			sender_2.clone(),
			recipients_1.clone(),
		)?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
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
		slate = api.process_invoice_tx(m, &slate, args)?;
		api.tx_lock_outputs(m, &slate)?;
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
		Ok(())
	})?;
	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
		// Wallet 2 receives the invoice transaction
		let res = slate_from_packed(&receive_file, use_armored, (&dec_key_2).as_ref())?;
		slate = res.1;
		slate = api.finalize_tx(&slate, false)?;
		output_slatepack(&slate, &final_file, use_armored, use_bin, None, vec![])?;
		Ok(())
	})?;
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.post_tx(m, &slate, false)?;
		Ok(())
	})?;

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

	let mut slate = Slate::blank(2, TxFlow::Invoice);
	let mut address = None;
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		address = Some(api.get_slatepack_address(m, 0)?);
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
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
		let slate = api.init_send_tx(m, args)?;
		output_slatepack(
			&slate,
			&send_file,
			use_armored,
			use_bin,
			sender_1,
			recipients_2.clone(),
		)?;
		api.tx_lock_outputs(m, &slate)?;
		Ok(())
	})?;

	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
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
	})?;

	// wallet 1 finalises and posts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let res = slate_from_packed(&receive_file, use_armored, (&dec_key_1).as_ref())?;
		slate = res.1;
		slate = api.finalize_tx(m, &slate)?;
		// Output final file for reference
		output_slatepack(&slate, &final_file, use_armored, use_bin, None, vec![])?;
		api.post_tx(m, &slate, false)?;
		bh += 1;
		Ok(())
	})?;

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
		false
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

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let args = InitTxArgs {
			src_acct_name: Some("mining".to_owned()),
			amount: reward * 2,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate = api.init_send_tx(m, args)?;
		// create an encrypted slatepack (just encrypted for self)
		let enc_addr = api.get_slatepack_address(m, 0)?;
		let slatepack = api.create_slatepack_message(m, &slate, Some(0), vec![enc_addr])?;
		println!("{}", slatepack);
		let slatepack_raw = api.decode_slatepack_message(m, slatepack.clone(), vec![0])?;
		println!("{}", slatepack_raw);
		let decoded_slate = api.slate_from_slatepack_message(m, slatepack, vec![0])?;
		println!("{}", decoded_slate);
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn slatepack_exchange_json() {
	let test_dir = "test_output/slatepack_exchange_json";
	setup(test_dir);
	// Json output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, false, false, false) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_exchange_bin() {
	let test_dir = "test_output/slatepack_exchange_bin";
	setup(test_dir);
	// Bin output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, true, false, false) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_exchange_armored() {
	let test_dir = "test_output/slatepack_exchange_armored";
	setup(test_dir);
	// Bin output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, true, true, true) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_exchange_json_enc() {
	let test_dir = "test_output/slatepack_exchange_json_enc";
	setup(test_dir);
	// Json output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, false, false, true) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_exchange_bin_enc() {
	let test_dir = "test_output/slatepack_exchange_bin_enc";
	setup(test_dir);
	// Bin output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, true, false, true) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_exchange_armored_enc() {
	let test_dir = "test_output/slatepack_exchange_armored_enc";
	setup(test_dir);
	// Bin output
	if let Err(e) = slatepack_exchange_test_impl(test_dir, true, true, true) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}

#[test]
fn slatepack_api() {
	let test_dir = "test_output/slatepack_api";
	setup(test_dir);
	// Json output
	if let Err(e) = slatepack_api_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}
