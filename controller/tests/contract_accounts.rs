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

//! Test a wallet doing contracts with different accounts
// #[macro_use]
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate log;

use grin_core as core;
use grin_keychain as keychain;

use self::core::global;
use self::keychain::{ExtKeychain, Keychain};
use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self};
use libwallet::contract::types::{ContractNewArgsAPI, ContractSetupArgsAPI};
use libwallet::{Slate, SlateState};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};

/// contract accounts testing (mostly the same as accounts.rs)
fn contract_accounts_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// create two wallets with some extra accounts and don't mine anything in them
	let (wallets, chain, stopper, _bh) = create_wallets(
		vec![
			vec![
				("default", 0),
				("account1", 0),
				("account2", 0),
				("account3", 0),
			],
			vec![("default", 0), ("listener_account", 0)],
		],
		test_dir,
	)
	.unwrap();
	let wallet1 = wallets[0].0.clone();
	let mask1 = wallets[0].1.as_ref();
	let wallet2 = wallets[1].0.clone();
	let mask2 = wallets[1].1.as_ref();

	// few values to keep things shorter
	let reward = core::consensus::REWARD;
	let cm = global::coinbase_maturity(); // assume all testing precedes soft fork height

	// Default wallet 2 to listen on that account
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("listener_account")?;
	}

	// Mine into two different accounts in the same wallet
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account1")?;
		assert_eq!(w.parent_key_id(), ExtKeychain::derive_key_id(2, 1, 0, 0, 0));
	}
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 7, false);

	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account2")?;
		assert_eq!(w.parent_key_id(), ExtKeychain::derive_key_id(2, 2, 0, 0, 0));
	}
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 5, false);

	// Should have 5 in account1 (5 spendable), 5 in account (2 spendable)
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 12);
		assert_eq!(wallet1_info.total, 5 * reward);
		assert_eq!(wallet1_info.amount_currently_spendable, (5 - cm) * reward);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(txs.len(), 5);
		Ok(())
	})?;

	// now check second account
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account1")?;
	}

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// check last confirmed height on this account is different from above (should be 0)
		let (_, wallet1_info) = api.retrieve_summary_info(m, false, 1)?;
		assert_eq!(wallet1_info.last_confirmed_height, 0);
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 12);
		assert_eq!(wallet1_info.total, 7 * reward);
		assert_eq!(wallet1_info.amount_currently_spendable, 7 * reward);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(txs.len(), 7);
		Ok(())
	})?;

	// should be nothing in default account
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("default")?;
	}
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_, wallet1_info) = api.retrieve_summary_info(m, false, 1)?;
		assert_eq!(wallet1_info.last_confirmed_height, 0);
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 12);
		assert_eq!(wallet1_info.total, 0,);
		assert_eq!(wallet1_info.amount_currently_spendable, 0,);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(txs.len(), 0);
		Ok(())
	})?;

	// TODO: check what send_tx_slate_direct call does in accounts.rs test
	// TODO: check that you can't call send on the default account because you have no funds

	// Send a tx from wallet1::account1 -> wallet2::listener_account
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

	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		// Receive wallet calls --receive=5
		let args = &ContractSetupArgsAPI {
			net_change: Some(5_000_000_000),
			..Default::default()
		};
		slate = api.contract_sign(m, &slate, args)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Standard2);

	// Send wallet finalizes and posts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let args = &ContractSetupArgsAPI {
			..Default::default()
		};
		slate = api.contract_sign(m, &slate, args)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Standard3);

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.post_tx(m, &slate, false)?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 13);
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(txs.len(), 9);
		Ok(())
	})?;

	// other account should be untouched
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account2")?;
	}
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_, wallet1_info) = api.retrieve_summary_info(m, false, 1)?;
		assert_eq!(wallet1_info.last_confirmed_height, 12);
		let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert_eq!(wallet1_info.last_confirmed_height, 13);
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		println!("{:?}", txs);
		assert_eq!(txs.len(), 5);
		Ok(())
	})?;

	// wallet 2 should only have this tx on the listener account
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, 13);
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(txs.len(), 1);
		Ok(())
	})?;
	// Default account on wallet 2 should be untouched
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("default")?;
	}
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (_, wallet2_info) = api.retrieve_summary_info(m, false, 1)?;
		assert_eq!(wallet2_info.last_confirmed_height, 0);
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, 13);
		assert_eq!(wallet2_info.total, 0,);
		assert_eq!(wallet2_info.amount_currently_spendable, 0,);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		assert_eq!(txs.len(), 0);
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn wallet_contract_accounts() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_accounts";
	setup(test_dir);
	contract_accounts_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
