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

//! Test sender transaction with no change output
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_core as core;
use std::path::PathBuf;

use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use libwallet::{InitTxArgs, IssueInvoiceTxArgs};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

fn no_change_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
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

	// Mine into wallet 1
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 4, false);
	let fee = core::libtx::tx_fee(1, 1, 1);

	// send a single block's worth of transactions with minimal strategy
	let args = InitTxArgs {
		src_acct_name: None,
		amount: reward - fee,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: false,
		..Default::default()
	};
	let mut slate = api1.init_send_tx(mask1, args)?;
	slate = client1.send_tx_slate_direct("wallet2", &slate)?;
	api1.tx_lock_outputs(mask1, &slate)?;
	slate = api1.finalize_tx(mask1, &slate)?;
	println!("Posted Slate: {:?}", slate);
	let mut stored_excess = Some(slate.tx.as_ref().unwrap().body.kernels[0].excess);
	api1.post_tx(mask1, &slate, false)?;

	// ensure stored excess is correct in both wallets
	// Wallet 1 calculated the excess with the full slate // Wallet 2 only had the excess provided by
	// wallet 1

	// Refresh and check transaction log for wallet 1
	let (refreshed, txs) = api1.retrieve_txs(mask1, true, None, Some(slate.id), None)?;
	assert!(refreshed);
	let tx = txs[0].clone();
	println!("SIMPLE SEND - SENDING WALLET");
	println!("{:?}", tx);
	println!();
	assert!(tx.confirmed);
	assert_eq!(stored_excess, tx.kernel_excess);

	// Refresh and check transaction log for wallet 2
	let (refreshed, txs) = api2.retrieve_txs(mask2, true, None, Some(slate.id), None)?;
	assert!(refreshed);
	let tx = txs[0].clone();
	println!("SIMPLE SEND - RECEIVING WALLET");
	println!("{:?}", tx);
	println!();
	assert!(tx.confirmed);
	assert_eq!(stored_excess, tx.kernel_excess);

	// ensure invoice TX works as well with no change
	// Wallet 2 initiates an invoice transaction, requesting payment
	let args = IssueInvoiceTxArgs {
		amount: reward - fee,
		..Default::default()
	};
	slate = api2.issue_invoice_tx(mask2, args)?;

	// Wallet 1 receives the invoice transaction
	let args = InitTxArgs {
		src_acct_name: None,
		amount: slate.amount,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: false,
		..Default::default()
	};
	slate = api1.process_invoice_tx(mask1, &slate, args)?;
	api1.tx_lock_outputs(mask1, &slate)?;

	// wallet 2 finalizes and posts
	wallet::controller::foreign_single_use(
		wallet2.clone(),
		PathBuf::from(test_dir),
		mask2_i.clone(),
		|api| {
			// Wallet 2 receives the invoice transaction
			slate = api.finalize_tx(&slate, false)?;
			Ok(())
		},
	)?;
	println!("Invoice Posted TX: {}", slate);
	stored_excess = Some(slate.tx.as_ref().unwrap().body.kernels[0].excess);
	api2.post_tx(mask2, &slate, false)?;

	// check wallet 2's version
	let (refreshed, txs) = api2.retrieve_txs(mask2, true, None, Some(slate.id), None)?;
	assert!(refreshed);
	for tx in txs {
		stored_excess = tx.kernel_excess;
		println!("Wallet 2: {:?}", tx);
		println!();
		assert!(tx.confirmed);
		assert_eq!(stored_excess, tx.kernel_excess);
	}

	// Refresh and check transaction log for wallet 1
	let (refreshed, txs) = api1.retrieve_txs(mask1, true, None, Some(slate.id), None)?;
	assert!(refreshed);
	for tx in txs {
		println!("Wallet 1: {:?}", tx);
		println!();
		assert_eq!(stored_excess, tx.kernel_excess);
		assert!(tx.confirmed);
	}

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn no_change() {
	let test_dir = "test_output/no_change";
	setup(test_dir);
	if let Err(e) = no_change_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
