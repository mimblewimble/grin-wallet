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
use grin_wallet_libwallet as libwallet;
use std::path::PathBuf;

use impls::test_framework::{self, LocalWalletClient};
use impls::{PathToSlate, SlateGetter as _, SlatePutter as _};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use grin_wallet_libwallet::{InitTxArgs, IssueInvoiceTxArgs};

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// self send impl
fn file_exchange_test_impl(test_dir: &'static str, use_bin: bool) -> Result<(), libwallet::Error> {
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

	// add some accounts
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

	let (send_file, receive_file, final_file) = match use_bin {
		false => (
			format!("{}/standard_S1.tx", test_dir),
			format!("{}/standard_S2.tx", test_dir),
			format!("{}/standard_S3.tx", test_dir),
		),
		true => (
			format!("{}/standard_S1.txbin", test_dir),
			format!("{}/standard_S2.txbin", test_dir),
			format!("{}/standard_S3.txbin", test_dir),
		),
	};

	// Should have 5 in account1 (5 spendable), 5 in account (2 spendable)
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
	PathToSlate((&send_file).into()).put_tx(&slate, use_bin)?;
	api1.tx_lock_outputs(mask1, &slate)?;

	// Get some mining done
	{
		wallet_inst!(wallet2, w);
		w.set_account_by_name("account1")?;
	}

	let mut slate = PathToSlate((&send_file).into()).get_tx()?.0;

	// wallet 2 receives file, completes, sends file back
	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = api.receive_tx(&slate, None, None)?;
			PathToSlate((&receive_file).into()).put_tx(&slate, use_bin)?;
			Ok(())
		},
	)?;

	// wallet 1 finalizes and posts
	let mut slate = PathToSlate(receive_file.into()).get_tx()?.0;
	slate = api1.finalize_tx(mask1, &slate)?;
	// Output final file for reference
	PathToSlate((&final_file).into()).put_tx(&slate, use_bin)?;
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
			format!("{}/invoice_I1.tx", test_dir),
			format!("{}/invoice_I2.tx", test_dir),
			format!("{}/invoice_I3.tx", test_dir),
		),
		true => (
			format!("{}/invoice_I1.txbin", test_dir),
			format!("{}/invoice_I2.txbin", test_dir),
			format!("{}/invoice_I3.txbin", test_dir),
		),
	};

	let args = IssueInvoiceTxArgs {
		amount: 1000000000,
		..Default::default()
	};
	let mut slate = api2.issue_invoice_tx(mask2, args)?;
	PathToSlate((&send_file).into()).put_tx(&slate, use_bin)?;

	let args = InitTxArgs {
		src_acct_name: None,
		amount: slate.amount,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: true,
		..Default::default()
	};
	slate = PathToSlate((&send_file).into()).get_tx()?.0;
	slate = api1.process_invoice_tx(mask1, &slate, args)?;
	api1.tx_lock_outputs(mask1, &slate)?;
	PathToSlate((&receive_file).into()).put_tx(&slate, use_bin)?;

	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			// Wallet 2 receives the invoice transaction
			slate = PathToSlate((&receive_file).into()).get_tx()?.0;
			slate = api.finalize_tx(&slate, false)?;
			PathToSlate((&final_file).into()).put_tx(&slate, use_bin)?;
			Ok(())
		},
	)?;

	api1.post_tx(mask1, &slate, false)?;

	// Standard, with payment proof
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	let (send_file, receive_file, final_file) = match use_bin {
		false => (
			format!("{}/standard_pp_S1.tx", test_dir),
			format!("{}/standard_pp_S2.tx", test_dir),
			format!("{}/standard_pp_S3.tx", test_dir),
		),
		true => (
			format!("{}/standard_pp_S1.txbin", test_dir),
			format!("{}/standard_pp_S2.txbin", test_dir),
			format!("{}/standard_pp_S3.txbin", test_dir),
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
	PathToSlate((&send_file).into()).put_tx(&slate, use_bin)?;
	api1.tx_lock_outputs(mask1, &slate)?;

	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			slate = PathToSlate((&send_file).into()).get_tx()?.0;
			slate = api.receive_tx(&slate, None, None)?;
			PathToSlate((&receive_file).into()).put_tx(&slate, use_bin)?;
			Ok(())
		},
	)?;

	// wallet 1 finalizes and posts
	slate = PathToSlate(receive_file.into()).get_tx()?.0;
	slate = api1.finalize_tx(mask1, &slate)?;
	// Output final file for reference
	PathToSlate((&final_file).into()).put_tx(&slate, use_bin)?;
	api1.post_tx(mask1, &slate, false)?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_file_exchange_json() {
	let test_dir = "test_output/file_exchange_json";
	setup(test_dir);
	// Json output
	if let Err(e) = file_exchange_test_impl(test_dir, false) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn wallet_file_exchange_bin() {
	let test_dir = "test_output/file_exchange_bin";
	setup(test_dir);
	if let Err(e) = file_exchange_test_impl(test_dir, true) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
