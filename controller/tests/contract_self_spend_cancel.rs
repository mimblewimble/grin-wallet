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

//! Test a wallet doing contract self-spend flow
// #[macro_use]
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate log;

use grin_wallet_libwallet as libwallet;

use libwallet::contract::types::{ContractNewArgsAPI, ContractSetupArgsAPI};
use libwallet::{RetrieveTxQueryArgs, Slate, SlateState, TxLogEntryType};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};
use std::path::PathBuf;

/// contract self-spend flow
fn contract_self_spend_cancel_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// create a single wallet and mine 4 blocks
	let (wallets, _chain, stopper, _bh) =
		create_wallets(vec![vec![("default", 4)]], test_dir).unwrap();
	let send_wallet = wallets[0].0.clone();
	let send_mask = wallets[0].1.as_ref();

	let mut slate = Slate::blank(0, true); // this gets overriden below

	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			// Send wallet initiates a standard transaction with --send=0
			let args = &ContractNewArgsAPI {
				setup_args: ContractSetupArgsAPI {
					selection_args: common::contract_selection_args(),
					net_change: Some(0),
					num_participants: 1,
					..Default::default()
				},
				..Default::default()
			};
			slate = api.contract_new(m, args)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard1);

	// Send wallet finalizes and posts
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			api.cancel_tx(m, None, Some(slate.id))?;
			Ok(())
		},
	)?;

	// Assert tx log has been cancelled
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let query_args = libwallet::RetrieveTxQueryArgs {
				exclude_cancelled: Some(false),
				..Default::default()
			};
			let (refreshed, txs) = api.retrieve_txs(m, true, None, None, Some(query_args))?;
			assert!(refreshed);
			assert_eq!(txs.len() as u64, 5); // send wallet didn't mine 4 blocks and made 1 tx
			let tx_log = common::tx_log_for_slate(api, m, &slate)?;
			assert_eq!(tx_log.tx_type, TxLogEntryType::TxSelfSpendCancelled);
			for query in [
				RetrieveTxQueryArgs {
					include_sent_only: Some(true),
					..Default::default()
				},
				RetrieveTxQueryArgs {
					include_received_only: Some(true),
					..Default::default()
				},
				RetrieveTxQueryArgs {
					include_self_spend_only: Some(true),
					..Default::default()
				},
			] {
				let (_, filtered) = api.retrieve_txs(m, false, None, None, Some(query))?;
				assert_eq!(filtered.len(), 1);
				assert_eq!(filtered[0].tx_type, TxLogEntryType::TxSelfSpendCancelled);
			}
			Ok(())
		},
	)?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

/// Find the stored transaction a signed contract wrote
fn find_stored_tx(test_dir: &str) -> std::path::PathBuf {
	fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
		if let Ok(entries) = std::fs::read_dir(dir) {
			for e in entries.filter_map(|e| e.ok()) {
				let p = e.path();
				if p.is_dir() {
					walk(&p, out);
				} else if p.extension().map(|x| x == "grintx").unwrap_or(false) {
					out.push(p);
				}
			}
		}
	}
	let mut found = vec![];
	walk(std::path::Path::new(test_dir), &mut found);
	assert_eq!(found.len(), 1, "expected one stored tx under {}", test_dir);
	found.pop().unwrap()
}

/// save_step writes the signed transaction to a file after the wallet state batch has
/// committed, so that write can fail with the tx log entry and the input locks already
/// persisted. The documented way out is to cancel, which does not read the stored tx;
/// this checks that holds by removing the file and cancelling.
fn contract_self_spend_cancel_missing_stored_tx_impl(
	test_dir: &'static str,
) -> Result<(), libwallet::Error> {
	let (wallets, _chain, stopper, _bh) =
		create_wallets(vec![vec![("default", 4)]], test_dir).unwrap();
	let send_wallet = wallets[0].0.clone();
	let send_mask = wallets[0].1.as_ref();

	let mut slate = Slate::blank(0, true);
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let args = &ContractNewArgsAPI {
				setup_args: ContractSetupArgsAPI {
					selection_args: common::contract_selection_args(),
					net_change: Some(0),
					num_participants: 1,
					..Default::default()
				},
				..Default::default()
			};
			slate = api.contract_new(m, args)?;
			Ok(())
		},
	)?;

	// Signing a self-spend completes the slate, so the transaction is stored
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let args = &ContractSetupArgsAPI {
				selection_args: common::contract_selection_args(),
				..Default::default()
			};
			slate = api.contract_sign(m, &slate, args)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard2);

	// Signing locked our inputs, so the cancel below has something to release, and the
	// entry records where the transaction was stored, as a standard send does
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, info) = api.retrieve_summary_info(m, true, 1)?;
			assert!(info.amount_locked > 0);
			let (_, txs) = api.retrieve_txs(m, true, None, Some(slate.id), None)?;
			assert_eq!(
				txs.last().unwrap().stored_tx,
				Some(format!("{}.grintx", slate.id))
			);
			Ok(())
		},
	)?;

	// Stand in for the file write having failed. The transaction has not been posted:
	// contract_sign returns before the caller broadcasts.
	let stored = find_stored_tx(test_dir);
	std::fs::remove_file(&stored).unwrap();

	// Cancelling still releases the inputs
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			api.cancel_tx(m, None, Some(slate.id))?;
			Ok(())
		},
	)?;

	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let query_args = libwallet::RetrieveTxQueryArgs {
				exclude_cancelled: Some(false),
				..Default::default()
			};
			let (_, txs) = api.retrieve_txs(m, true, None, None, Some(query_args))?;
			let tx_log = txs.last().unwrap();
			assert_eq!(tx_log.tx_type, TxLogEntryType::TxSelfSpendCancelled);
			// The spendable balance is back to the mined total
			let (_, info) = api.retrieve_summary_info(m, true, 1)?;
			assert_eq!(info.amount_locked, 0);
			Ok(())
		},
	)?;

	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_contract_self_spend_cancel() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_self_spend_cancel";
	setup(test_dir);
	contract_self_spend_cancel_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn wallet_contract_self_spend_cancel_missing_stored_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_self_spend_cancel_missing_stored_tx";
	setup(test_dir);
	contract_self_spend_cancel_missing_stored_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
