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

//! Test sender transaction with no change output
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_wallet_util::grin_core as core;

use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use libwallet::{InitTxArgs, IssueInvoiceTxArgs, Slate};
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

	// Mine into wallet 1
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 4, false);
	let fee = core::libtx::tx_fee(1, 1, 1, None);

	// send a single block's worth of transactions with minimal strategy
	let mut slate = Slate::blank(2);
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let args = InitTxArgs {
			src_acct_name: None,
			amount: reward - fee,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: false,
			..Default::default()
		};
		slate = api.init_send_tx(m, args)?;
		slate = client1.send_tx_slate_direct("wallet2", &slate)?;
		api.tx_lock_outputs(m, &slate, 0)?;
		slate = api.finalize_tx(m, &slate)?;
		api.post_tx(m, slate.tx_or_err()?, false)?;
		Ok(())
	})?;

	// Refresh and check transaction log for wallet 1
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask2, None, |api, m| {
		let (refreshed, txs) = api.retrieve_txs(m, true, None, Some(slate.id))?;
		assert!(refreshed);
		let tx = txs[0].clone();
		println!("{:?}", tx);
		assert!(tx.confirmed);
		Ok(())
	})?;

	// ensure invoice TX works as well with no change
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		// Wallet 2 inititates an invoice transaction, requesting payment
		let args = IssueInvoiceTxArgs {
			amount: reward - fee,
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
			selection_strategy_is_use_all: false,
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
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask1, None, |api, m| {
		api.post_tx(m, slate.tx_or_err()?, false)?;
		Ok(())
	})?;

	// Refresh and check transaction log for wallet 1
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask2, None, |api, m| {
		let (refreshed, txs) = api.retrieve_txs(m, true, None, Some(slate.id))?;
		assert!(refreshed);
		for tx in txs {
			println!("{:?}", tx);
			assert!(tx.confirmed);
		}
		Ok(())
	})?;

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
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}
