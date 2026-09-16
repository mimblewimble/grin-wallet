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

//! Test a wallet sending to self
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_core as core;
use grin_wallet_libwallet as libwallet;
use std::path::PathBuf;

use impls::test_framework::{self, LocalWalletClient};
use libwallet::{InitTxArgs, IssueInvoiceTxArgs, SlateState};
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
		true,
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
		true,
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

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let mut _bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, _bh as usize, false);

	// Sanity check wallet 1 contents
	let (wallet1_refreshed, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
	assert!(wallet1_refreshed);
	assert_eq!(wallet1_info.last_confirmed_height, _bh);
	assert_eq!(wallet1_info.total, _bh * reward);

	let error = api2
		.issue_invoice_tx(
			mask2,
			IssueInvoiceTxArgs {
				amount: 0,
				..Default::default()
			},
		)
		.unwrap_err();
	assert_eq!(error, libwallet::Error::InvalidAmount);

	// Wallet 2 initiates an invoice transaction, requesting payment
	let args = IssueInvoiceTxArgs {
		amount: reward * 2,
		..Default::default()
	};
	let mut slate = api2.issue_invoice_tx(mask2, args)?;
	assert_eq!(slate.state, SlateState::Invoice1);

	let receive_result = wallet::controller::foreign_single_use(
		wallet1.clone(),
		PathBuf::from(test_dir),
		mask1_i.clone(),
		|api| api.receive_tx(&slate, None, None).map(|_| ()),
	);
	assert_eq!(receive_result, Err(libwallet::Error::SlateState));
	let (_, txs) = api1.retrieve_txs(mask1, false, None, Some(slate.id), None)?;
	assert!(txs.is_empty());

	// receive must reject every slate state except S1
	for state in [
		SlateState::Unknown,
		SlateState::Standard2,
		SlateState::Standard3,
		SlateState::Invoice1,
		SlateState::Invoice2,
		SlateState::Invoice3,
	] {
		let mut bad_slate = slate.clone();
		bad_slate.state = state.clone();
		let res = wallet::controller::foreign_single_use(
			wallet1.clone(),
			PathBuf::from(test_dir),
			mask1_i.clone(),
			|api| api.receive_tx(&bad_slate, None, None).map(|_| ()),
		);
		assert_eq!(res, Err(libwallet::Error::SlateState), "state {}", state);
	}

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
	let mut zero_amount_slate = slate.clone();
	zero_amount_slate.amount = 0;
	assert_eq!(
		api1.process_invoice_tx(mask1, &zero_amount_slate, args.clone())
			.unwrap_err(),
		libwallet::Error::InvalidAmount
	);
	slate = api1.process_invoice_tx(mask1, &slate, args)?;
	api1.tx_lock_outputs(mask1, &slate)?;
	assert_eq!(slate.state, SlateState::Invoice2);

	assert_eq!(
		api2.tx_lock_outputs(mask2, &slate),
		Err(libwallet::Error::SlateState)
	);
	let (_, txs) = api2.retrieve_txs(mask2, false, None, None, None)?;
	assert_eq!(txs.len(), 1);
	assert_eq!(txs[0].tx_type, libwallet::TxLogEntryType::TxReceived);

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
	assert_eq!(slate.state, SlateState::Invoice3);

	// wallet 1 posts so wallet 2 doesn't get the mined amount
	api1.post_tx(mask1, &slate, false)?;
	_bh += 1;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	_bh += 3;

	// Check transaction log for wallet 2
	let (_, wallet2_info) = api2.retrieve_summary_info(mask2, true, 1)?;
	let (refreshed, txs) = api2.retrieve_txs(mask2, true, None, None, None)?;
	assert!(refreshed);
	assert_eq!(txs.len(), 1);
	println!(
		"last confirmed height: {}, bh: {}",
		wallet2_info.last_confirmed_height, _bh
	);
	assert!(refreshed);

	// Check transaction log for wallet 1, ensure only 1 entry
	// exists
	let (_, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
	let (refreshed, txs) = api1.retrieve_txs(mask1, true, None, None, None)?;
	assert!(refreshed);
	assert_eq!(txs.len() as u64, _bh + 1);
	println!(
		"Wallet 1: last confirmed height: {}, bh: {}",
		wallet1_info.last_confirmed_height, _bh
	);

	// Test self-sending
	// Wallet 1 initiates an invoice transaction, requesting payment
	let args = IssueInvoiceTxArgs {
		amount: reward * 2,
		..Default::default()
	};
	slate = api1.issue_invoice_tx(mask1, args)?;
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
	println!("Self invoice slate init: {}", slate);
	slate = api1.process_invoice_tx(mask1, &slate, args)?;
	api1.tx_lock_outputs(mask1, &slate)?;

	println!("Self invoice slate after process: {}", slate);

	// wallet 1 finalizes and posts
	wallet::controller::foreign_single_use(
		wallet1.clone(),
		PathBuf::from(test_dir),
		mask1_i.clone(),
		|api| {
			// Wallet 2 receives the invoice transaction
			slate = api.finalize_tx(&slate, false)?;
			Ok(())
		},
	)?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);

	// Wallet 2 initiates an invoice transaction, requesting payment
	let args = IssueInvoiceTxArgs {
		amount: reward * 2,
		..Default::default()
	};
	slate = api2.issue_invoice_tx(mask2, args)?;
	assert_eq!(slate.state, SlateState::Invoice1);

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
	slate = api1.process_invoice_tx(mask1, &slate, args)?;
	api1.tx_lock_outputs(mask1, &slate)?;
	assert_eq!(slate.state, SlateState::Invoice2);

	// Wallet 2 receives and finalizes via owner API
	slate = api2.finalize_tx(mask2, &slate)?;
	assert_eq!(slate.state, SlateState::Invoice3);

	// test that payee can only cancel once
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	_bh += 3;

	// Wallet 2 initiates an invoice transaction, requesting payment
	let args = IssueInvoiceTxArgs {
		amount: reward * 2,
		..Default::default()
	};
	slate = api2.issue_invoice_tx(mask2, args)?;
	assert_eq!(slate.state, SlateState::Invoice1);

	let orig_slate = slate.clone();

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
	slate = api1.process_invoice_tx(mask1, &slate, args.clone())?;
	api1.tx_lock_outputs(mask1, &slate)?;

	// Wallet 1 cancels the invoice transaction
	api1.cancel_tx(mask1, None, Some(slate.id))?;

	// Wallet 1 attempts to repay again
	let res = api1.process_invoice_tx(mask1, &orig_slate, args);
	assert!(res.is_err());
	assert_eq!(slate.state, SlateState::Invoice2);

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
