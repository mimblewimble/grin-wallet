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

//! Test a wallet sending to self
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_wallet_libwallet as libwallet;
use grin_wallet_util::grin_core as core;

use impls::test_framework::{self, LocalWalletClient};
use libwallet::{InitTxArgs, IssueInvoiceTxArgs, Slate};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// self send impl
fn invoice_tx_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		true
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
		true
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

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let mut bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Sanity check wallet 1 contents
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward);
		Ok(())
	})?;

	let mut slate = Slate::blank(2);

	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		// Wallet 2 inititates an invoice transaction, requesting payment
		let args = IssueInvoiceTxArgs {
			amount: reward * 2,
			..Default::default()
		};
		slate = api.issue_invoice_tx(m, args)?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// Wallet 1 receives the invoice transaction
		let args = InitTxArgs {
			src_acct_name: None,
			amount: slate.amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		slate = api.process_invoice_tx(m, &slate, args)?;
		api.tx_lock_outputs(m, &slate, 0)?;
		Ok(())
	})?;

	// wallet 2 finalizes and posts
	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
		// Wallet 2 receives the invoice transaction
		slate = api.finalize_invoice_tx(&slate)?;
		Ok(())
	})?;

	// wallet 1 posts so wallet 2 doesn't get the mined amount
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.post_tx(m, slate.tx_or_err()?, false)?;
		Ok(())
	})?;
	bh += 1;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// Check transaction log for wallet 2
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (_, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
		assert!(refreshed);
		assert!(txs.len() == 1);
		println!(
			"last confirmed height: {}, bh: {}",
			wallet2_info.last_confirmed_height, bh
		);
		assert!(refreshed);
		assert_eq!(wallet2_info.amount_currently_spendable, slate.amount);
		Ok(())
	})?;

	// Check transaction log for wallet 1, ensure only 1 entry
	// exists
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
		assert!(refreshed);
		assert_eq!(txs.len() as u64, bh + 1);
		println!(
			"Wallet 1: last confirmed height: {}, bh: {}",
			wallet1_info.last_confirmed_height, bh
		);
		Ok(())
	})?;

	// Test self-sending
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// Wallet 1 inititates an invoice transaction, requesting payment
		let args = IssueInvoiceTxArgs {
			amount: reward * 2,
			..Default::default()
		};
		slate = api.issue_invoice_tx(m, args)?;
		// Wallet 1 receives the invoice transaction
		let args = InitTxArgs {
			src_acct_name: None,
			amount: slate.amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		slate = api.process_invoice_tx(m, &slate, args)?;
		api.tx_lock_outputs(m, &slate, 0)?;
		Ok(())
	})?;

	// wallet 1 finalizes and posts
	wallet::controller::foreign_single_use(wallet1.clone(), mask1_i.clone(), |api| {
		// Wallet 2 receives the invoice transaction
		slate = api.finalize_invoice_tx(&slate)?;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	//bh += 3;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn wallet_invoice_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/invoice_tx";
	setup(test_dir);
	invoice_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
