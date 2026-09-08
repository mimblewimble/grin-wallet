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

use impls::test_framework::{self};
use libwallet::contract::my_fee_contribution;
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
fn contract_self_spend_tx_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// create a single wallet and mine 4 blocks
	let (wallets, chain, stopper, mut bh) =
		create_wallets(vec![vec![("default", 4)]], test_dir).unwrap();
	let send_wallet = wallets[0].0.clone();
	let send_mask = wallets[0].1.as_ref();

	let mut slate = Slate::blank(0, true); // this gets overriden below

	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			// Send wallet inititates a standard transaction with --send=0
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
			let args = &ContractSetupArgsAPI {
				selection_args: common::contract_selection_args(),
				..Default::default()
			};
			slate = api.contract_sign(m, &slate, args)?;
			Ok(())
		},
	)?;
	// In the case of a self-spend, we just finish the slate when it's in the Standard2 state
	assert_eq!(slate.state, SlateState::Standard2);

	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			api.post_tx(m, &slate, false)?;
			Ok(())
		},
	)?;
	bh += 1;

	let _ =
		test_framework::award_blocks_to_wallet(&chain, send_wallet.clone(), send_mask, 3, false);
	bh += 3;

	// Assert changes in send wallet
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, wallet_info) = api.retrieve_summary_info(m, true, 1)?;
			let (refreshed, txs) = api.retrieve_txs(m, true, None, None, None)?;
			assert_eq!(wallet_info.last_confirmed_height, bh);
			assert!(refreshed);
			assert_eq!(txs.len() as u64, bh + 1); // send wallet didn't mine 4 blocks and made 1 tx
			let tx_log = common::tx_log_for_slate(api, m, &slate)?;
			assert_eq!(tx_log.tx_type, TxLogEntryType::TxSelfSpend);
			assert_eq!(tx_log.amount_credited, 0);
			assert_eq!(tx_log.amount_debited, 0);
			assert_eq!(tx_log.num_inputs, 1);
			assert_eq!(tx_log.num_outputs, 1);
			assert_eq!(tx_log.fee, Some(my_fee_contribution(1, 1, 1, 1)?));

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
				assert_eq!(filtered[0].tx_type, TxLogEntryType::TxSelfSpend);
			}
			Ok(())
		},
	)?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

fn contract_fee_floor_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	let (wallets, _, stopper, _) = create_wallets(vec![vec![("default", 4)]], test_dir).unwrap();
	let wallet = wallets[0].0.clone();
	let mask = wallets[0].1.as_ref();

	wallet::controller::owner_single_use(wallet, mask, PathBuf::from(test_dir), |api, m| {
		let slate = api.contract_new(
			m,
			&ContractNewArgsAPI {
				setup_args: ContractSetupArgsAPI {
					selection_args: common::contract_selection_args(),
					net_change: Some(0),
					num_participants: 1,
					fee_rate: Some(1),
					..Default::default()
				},
				..Default::default()
			},
		)?;
		let (_, txs) = api.retrieve_txs(m, false, None, Some(slate.id), None)?;
		let (_, outputs) = api.retrieve_outputs(m, false, false, None)?;
		let err = api
			.contract_sign(m, &slate, &ContractSetupArgsAPI::default())
			.unwrap_err();
		assert!(matches!(
			err,
			libwallet::Error::Fee(ref message) if message.starts_with("Fee Dispute Error:")
		));
		let (_, current_txs) = api.retrieve_txs(m, false, None, Some(slate.id), None)?;
		let (_, current_outputs) = api.retrieve_outputs(m, false, false, None)?;
		assert_eq!(
			serde_json::to_value(current_txs).unwrap(),
			serde_json::to_value(txs).unwrap()
		);
		assert_eq!(
			serde_json::to_value(current_outputs).unwrap(),
			serde_json::to_value(outputs).unwrap()
		);
		Ok(())
	})?;

	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_contract_self_spend_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_self_spend_tx";
	setup(test_dir);
	contract_self_spend_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn contract_fee_floor() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_fee_floor";
	setup(test_dir);
	contract_fee_floor_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
