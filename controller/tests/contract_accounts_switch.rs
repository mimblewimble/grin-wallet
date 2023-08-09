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

//! Test a wallet doing contracts with different accounts and switching between them
// #[macro_use]
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate log;

use grin_core as core;
use grin_wallet_libwallet as libwallet;
use libwallet::contract::my_fee_contribution;
use libwallet::contract::types::{ContractNewArgsAPI, ContractSetupArgsAPI};
use libwallet::{Slate, SlateState};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};

/// contract accounts testing when switching between accounts during transaction building
fn contract_accounts_switch_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// create two wallets with some extra accounts and don't mine anything in them
	let (wallets, _chain, stopper, _bh) = create_wallets(
		vec![
			vec![("default", 0), ("account1", 1), ("account2", 2)],
			vec![("default", 0), ("account1", 3), ("account2", 4)],
		],
		test_dir,
	)
	.unwrap();
	let wallet1 = wallets[0].0.clone();
	let mask1 = wallets[0].1.as_ref();
	let wallet2 = wallets[1].0.clone();
	let mask2 = wallets[1].1.as_ref();

	let reward = core::consensus::REWARD;

	// wallet1::account1 should have 1 in account1 (1 spendable)
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account1")?;
	}
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 10);
		assert_eq!(wallet1_info.total, 1 * reward);
		assert_eq!(wallet1_info.amount_currently_spendable, 1 * reward);
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(txs.len(), 1);
		Ok(())
	})?;

	// wallet1::account2 should have 2 in account1 (2 spendable)
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account2")?;
	}
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// check last confirmed height on this account is different from above (should be 0)
		let (_, wallet1_info) = api.retrieve_summary_info(m, false, 1)?;
		assert_eq!(wallet1_info.last_confirmed_height, 3);
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 10);
		assert_eq!(wallet1_info.total, 2 * reward);
		assert_eq!(wallet1_info.amount_currently_spendable, 2 * reward);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(txs.len(), 2);
		Ok(())
	})?;

	// Make a transaction by sending 5 coins from wallet1::account1 -> wallet2::account2
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account1")?;
	}

	let mut slate = Slate::blank(0, true); // this gets overriden below

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// Send wallet inititates a standard transaction with --send=5
		let args = &ContractNewArgsAPI {
			setup_args: ContractSetupArgsAPI {
				net_change: Some(-5_000_000_000),
				..Default::default()
			},
			..Default::default()
		};
		slate = api.contract_new(m, args)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Standard1);

	// Receiver gets their coins on account2 where they can payjoin
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("account2")?;
	}
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		// Receive wallet calls --receive=5
		let args = &mut ContractSetupArgsAPI {
			net_change: Some(5_000_000_000),
			..Default::default()
		};
		args.proof_args.suppress_proof = true;
		slate = api.contract_sign(m, &slate, args)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Standard2);

	// Switch account for wallet1 to account2 and finish the transaction (should use account1 to complete)
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account2")?;
	}
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let args = &ContractSetupArgsAPI {
			..Default::default()
		};
		slate = api.contract_sign(m, &slate, args)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Standard3);

	// post tx and mine a block to wallet1::account2
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.post_tx(m, &slate, false)?;
		Ok(())
	})?;

	// The currently set account (account2) should not be affected by this transaction because they weren't a part of it,
	// but it did mine a block and pick the transaction fees
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 11);
		assert_eq!(
			wallet1_info.total,
			3 * reward + core::libtx::tx_fee(2, 2, 1) // we have received a block reward and the tx fee (payjoin)
		);
		assert_eq!(wallet1_info.amount_currently_spendable, 2 * reward);
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(txs.len(), 3);
		Ok(())
	})?;

	// Switch to wallet1::account1 and check that it sent 5 coins
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account1")?;
	}
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 11);
		assert_eq!(
			wallet1_info.total,
			1 * reward - 5_000_000_000 - my_fee_contribution(1, 1, 1, 2)?.fee() // we subtract also our fee contribution
		);
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(txs.len(), 2);
		Ok(())
	})?;

	// Switch to wallet2::account2 and check that it received 5 coins
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("account2")?;
	}
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, 11);
		assert_eq!(
			wallet2_info.total,
			4 * reward + 5_000_000_000 - my_fee_contribution(1, 1, 1, 2)?.fee() // we subtract also our fee contribution for a payjoin
		);
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(txs.len(), 5);
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn wallet_contract_accounts_switch() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_accounts_switch";
	setup(test_dir);
	contract_accounts_switch_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
