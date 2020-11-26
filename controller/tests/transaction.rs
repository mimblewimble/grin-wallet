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

//! tests for transactions building within core::libtx
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;

use grin_wallet_util::grin_core as core;

use self::core::core::transaction;
use self::core::global;
use self::libwallet::{InitTxArgs, OutputStatus, Slate, SlateState};
use impls::test_framework::{self, LocalWalletClient};
use std::convert::TryInto;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// Exercises the Transaction API fully with a test NodeClient operating
/// directly on a chain instance
/// Callable with any type of wallet
fn basic_transaction_api(test_dir: &'static str) -> Result<(), libwallet::Error> {
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
	println!("Mask1: {:?}", mask1);
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
	println!("Mask2: {:?}", mask2);

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::REWARD;
	let cm = global::coinbase_maturity();
	// mine a few blocks
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false);

	// Check wallet 1 contents are as expected
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		debug!(
			"Wallet 1 Info Pre-Transaction, after {} blocks: {:?}",
			wallet1_info.last_confirmed_height, wallet1_info
		);
		assert!(wallet1_refreshed);
		assert_eq!(
			wallet1_info.amount_currently_spendable,
			(wallet1_info.last_confirmed_height - cm) * reward
		);
		assert_eq!(wallet1_info.amount_immature, cm * reward);
		Ok(())
	})?;

	// assert wallet contents
	// and a single use api for a send command
	let amount = 60_000_000_000;
	let mut slate = Slate::blank(1, false);
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = sender_api.init_send_tx(m, args)?;

		assert_eq!(slate_i.state, SlateState::Standard1);

		// Check we are creating a tx with the expected lock_height of 0.
		// We will check this produces a Plain kernel later.
		assert_eq!(0, slate.kernel_features);

		slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
		assert_eq!(slate.state, SlateState::Standard2);
		sender_api.tx_lock_outputs(m, &slate)?;
		slate = sender_api.finalize_tx(m, &slate)?;
		assert_eq!(slate.state, SlateState::Standard3);

		// Check we have a single kernel and that it is a Plain kernel (no lock_height).
		// fees for 7 inputs, 2 outputs, 1 kernel (weight 52)
		assert_eq!(slate.tx_or_err()?.kernels().len(), 1);
		assert_eq!(
			slate
				.tx_or_err()?
				.kernels()
				.first()
				.map(|k| k.features)
				.unwrap(),
			transaction::KernelFeatures::Plain {
				fee: 26_000_000.into()
			}
		);

		Ok(())
	})?;

	// Check transaction log for wallet 1
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
		assert!(refreshed);
		let fee = core::libtx::tx_fee(
			wallet1_info.last_confirmed_height as usize - cm as usize,
			2,
			1,
		);
		// we should have a transaction entry for this slate
		let tx = txs.iter().find(|t| t.tx_slate_id == Some(slate.id));
		assert!(tx.is_some());
		let tx = tx.unwrap();
		assert!(!tx.confirmed);
		assert!(tx.confirmation_ts.is_none());
		assert_eq!(tx.amount_debited - tx.amount_credited, fee + amount);
		println!("tx: {:?}", tx);
		assert_eq!(Some(fee.try_into().unwrap()), tx.fee);
		Ok(())
	})?;

	// Check transaction log for wallet 2
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
		assert!(refreshed);
		// we should have a transaction entry for this slate
		let tx = txs.iter().find(|t| t.tx_slate_id == Some(slate.id));
		assert!(tx.is_some());
		let tx = tx.unwrap();
		assert!(!tx.confirmed);
		assert!(tx.confirmation_ts.is_none());
		assert_eq!(amount, tx.amount_credited);
		assert_eq!(0, tx.amount_debited);
		assert_eq!(None, tx.fee);
		Ok(())
	})?;

	// post transaction
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.post_tx(m, &slate, false)?;
		Ok(())
	})?;

	// Check wallet 1 contents are as expected
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		debug!(
			"Wallet 1 Info Post Transaction, after {} blocks: {:?}",
			wallet1_info.last_confirmed_height, wallet1_info
		);
		let fee = core::libtx::tx_fee(
			wallet1_info.last_confirmed_height as usize - 1 - cm as usize,
			2,
			1,
		);
		assert!(wallet1_refreshed);
		// wallet 1 received fees, so amount should be the same
		assert_eq!(
			wallet1_info.total,
			amount * wallet1_info.last_confirmed_height - amount
		);
		assert_eq!(
			wallet1_info.amount_currently_spendable,
			(wallet1_info.last_confirmed_height - cm) * reward - amount - fee
		);
		assert_eq!(wallet1_info.amount_immature, cm * reward + fee);

		// check tx log entry is confirmed
		let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
		assert!(refreshed);
		let tx = txs.iter().find(|t| t.tx_slate_id == Some(slate.id));
		assert!(tx.is_some());
		let tx = tx.unwrap();
		assert!(tx.confirmed);
		assert!(tx.confirmation_ts.is_some());

		Ok(())
	})?;

	// mine a few more blocks
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);

	// refresh wallets and retrieve info/tests for each wallet after maturity
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		debug!("Wallet 1 Info: {:?}", wallet1_info);
		assert!(wallet1_refreshed);
		assert_eq!(
			wallet1_info.total,
			amount * wallet1_info.last_confirmed_height - amount
		);
		assert_eq!(
			wallet1_info.amount_currently_spendable,
			(wallet1_info.last_confirmed_height - cm - 1) * reward
		);
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.amount_currently_spendable, amount);

		// check tx log entry is confirmed
		let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
		assert!(refreshed);
		let tx = txs.iter().find(|t| t.tx_slate_id == Some(slate.id));
		assert!(tx.is_some());
		let tx = tx.unwrap();
		assert!(tx.confirmed);
		assert!(tx.confirmation_ts.is_some());
		Ok(())
	})?;

	// Estimate fee and locked amount for a transaction
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		let init_args = InitTxArgs {
			src_acct_name: None,
			amount: amount * 2,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			estimate_only: Some(true),
			..Default::default()
		};
		let est = sender_api.init_send_tx(m, init_args)?;
		assert_eq!(est.amount, 600_000_000_000);
		// fees for 5 inputs, 2 outputs, 1 kernel (weight 50)
		assert_eq!(est.fee_fields.fee(0), 25_000_000);

		let init_args = InitTxArgs {
			src_acct_name: None,
			amount: amount * 2,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: false, //select smallest number
			estimate_only: Some(true),
			..Default::default()
		};
		let est = sender_api.init_send_tx(m, init_args)?;
		assert_eq!(est.amount, 180_000_000_000);
		// fees for 3 inputs, 2 outputs, 1 kernel (weight 48)
		assert_eq!(est.fee_fields.fee(0), 24_000_000);

		Ok(())
	})?;

	// Send another transaction, but don't post to chain immediately and use
	// the stored transaction instead
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount * 2,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = sender_api.init_send_tx(m, args)?;
		slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
		sender_api.tx_lock_outputs(m, &slate)?;
		slate = sender_api.finalize_tx(m, &slate)?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		let (refreshed, _wallet1_info) = sender_api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		let (_, txs) = sender_api.retrieve_txs(m, true, None, None)?;
		// find the transaction
		let tx = txs
			.iter()
			.find(|t| t.tx_slate_id == Some(slate.id))
			.unwrap();
		let stored_tx_slate = sender_api
			.get_stored_tx(m, None, Some(&tx.tx_slate_id.unwrap()))?
			.unwrap();
		sender_api.post_tx(m, &stored_tx_slate, false)?;
		let (_, wallet1_info) = sender_api.retrieve_summary_info(m, true, 1)?;
		// should be mined now
		assert_eq!(
			wallet1_info.total,
			amount * wallet1_info.last_confirmed_height - amount * 3
		);
		Ok(())
	})?;

	// mine a few more blocks
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);

	// check wallet2 has stored transaction
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.amount_currently_spendable, amount * 3);

		// check tx log entry is confirmed
		let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
		assert!(refreshed);
		let tx = txs.iter().find(|t| t.tx_slate_id == Some(slate.id));
		assert!(tx.is_some());
		let tx = tx.unwrap();
		assert!(tx.confirmed);
		assert!(tx.confirmation_ts.is_some());
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

/// Test rolling back transactions and outputs when a transaction is never
/// posted to a chain
fn tx_rollback(test_dir: &'static str) -> Result<(), libwallet::Error> {
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
	let cm = global::coinbase_maturity(); // assume all testing precedes soft fork height
									  // mine a few blocks
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 5, false);

	let amount = 30_000_000_000;
	let mut slate = Slate::blank(1, false);
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};

		let slate_i = sender_api.init_send_tx(m, args)?;
		slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
		sender_api.tx_lock_outputs(m, &slate)?;
		slate = sender_api.finalize_tx(m, &slate)?;
		Ok(())
	})?;

	// Check transaction log for wallet 1
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		println!(
			"last confirmed height: {}",
			wallet1_info.last_confirmed_height
		);
		assert!(refreshed);
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		// we should have a transaction entry for this slate
		let tx = txs.iter().find(|t| t.tx_slate_id == Some(slate.id));
		assert!(tx.is_some());
		let mut locked_count = 0;
		let mut unconfirmed_count = 0;
		// get the tx entry, check outputs are as expected
		let (_, output_mappings) = api.retrieve_outputs(m, true, false, Some(tx.unwrap().id))?;
		for m in output_mappings.clone() {
			if m.output.status == OutputStatus::Locked {
				locked_count = locked_count + 1;
			}
			if m.output.status == OutputStatus::Unconfirmed {
				unconfirmed_count = unconfirmed_count + 1;
			}
		}
		assert_eq!(output_mappings.len(), 3);
		assert_eq!(locked_count, 2);
		assert_eq!(unconfirmed_count, 1);

		Ok(())
	})?;

	// Check transaction log for wallet 2
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (refreshed, txs) = api.retrieve_txs(m, true, None, None)?;
		assert!(refreshed);
		let mut unconfirmed_count = 0;
		let tx = txs.iter().find(|t| t.tx_slate_id == Some(slate.id));
		assert!(tx.is_some());
		// get the tx entry, check outputs are as expected
		let (_, outputs) = api.retrieve_outputs(m, true, false, Some(tx.unwrap().id))?;
		for m in outputs.clone() {
			if m.output.status == OutputStatus::Unconfirmed {
				unconfirmed_count = unconfirmed_count + 1;
			}
		}
		assert_eq!(outputs.len(), 1);
		assert_eq!(unconfirmed_count, 1);
		let (refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		assert_eq!(wallet2_info.amount_currently_spendable, 0,);
		assert_eq!(wallet2_info.amount_awaiting_finalization, amount);
		Ok(())
	})?;

	// wallet 1 is bold and doesn't ever post the transaction
	// mine a few more blocks
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 5, false);

	// Wallet 1 decides to roll back instead
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// can't roll back coinbase
		let res = api.cancel_tx(m, Some(1), None);
		assert!(res.is_err());
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		let tx = txs
			.iter()
			.find(|t| t.tx_slate_id == Some(slate.id))
			.unwrap();
		api.cancel_tx(m, Some(tx.id), None)?;
		let (refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		println!(
			"last confirmed height: {}",
			wallet1_info.last_confirmed_height
		);
		// check all eligible inputs should be now be spendable
		println!("cm: {}", cm);
		assert_eq!(
			wallet1_info.amount_currently_spendable,
			(wallet1_info.last_confirmed_height - cm) * reward
		);
		// can't roll back again
		let res = api.cancel_tx(m, Some(tx.id), None);
		assert!(res.is_err());

		Ok(())
	})?;

	// Wallet 2 rolls back
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		let tx = txs
			.iter()
			.find(|t| t.tx_slate_id == Some(slate.id))
			.unwrap();
		api.cancel_tx(m, Some(tx.id), None)?;
		let (refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		// check all eligible inputs should be now be spendable
		assert_eq!(wallet2_info.amount_currently_spendable, 0,);
		assert_eq!(wallet2_info.total, 0,);
		// can't roll back again
		let res = api.cancel_tx(m, Some(tx.id), None);
		assert!(res.is_err());

		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn db_wallet_basic_transaction_api() {
	let test_dir = "test_output/basic_transaction_api";
	setup(test_dir);
	if let Err(e) = basic_transaction_api(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}

#[test]
fn db_wallet_tx_rollback() {
	let test_dir = "test_output/tx_rollback";
	setup(test_dir);
	if let Err(e) = tx_rollback(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}
