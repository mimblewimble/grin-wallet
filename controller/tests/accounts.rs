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

//! tests differing accounts in the same wallet
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_core as core;
use grin_keychain as keychain;

use self::core::global;
use self::keychain::{ExtKeychain, Keychain};
use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use libwallet::InitTxArgs;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// Various tests on accounts within the same wallet
fn accounts_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
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
	let cm = global::coinbase_maturity(); // assume all testing precedes soft fork height

	// test default accounts exist
	{
		let accounts = api1.accounts(mask1)?;
		assert_eq!(accounts[0].label, "default");
		assert_eq!(accounts[0].path, ExtKeychain::derive_key_id(2, 0, 0, 0, 0));
	}

	// add some accounts
	{
		let new_path = api1.create_account_path(mask1, "account1").unwrap();
		assert_eq!(new_path, ExtKeychain::derive_key_id(2, 1, 0, 0, 0));
		let new_path = api1.create_account_path(mask1, "account2").unwrap();
		assert_eq!(new_path, ExtKeychain::derive_key_id(2, 2, 0, 0, 0));
		let new_path = api1.create_account_path(mask1, "account3").unwrap();
		assert_eq!(new_path, ExtKeychain::derive_key_id(2, 3, 0, 0, 0));
		// trying to add same label again should fail
		let res = api1.create_account_path(mask1, "account1");
		assert!(res.is_err());
	}

	// add account to wallet 2
	{
		let new_path = api2.create_account_path(mask2, "listener_account").unwrap();
		assert_eq!(new_path, ExtKeychain::derive_key_id(2, 1, 0, 0, 0));
	}

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
	{
		let (wallet1_refreshed, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 12);
		assert_eq!(wallet1_info.total, 5 * reward);
		assert_eq!(wallet1_info.amount_currently_spendable, (5 - cm) * reward);
		// check tx log as well
		let (_, txs) = api1.retrieve_txs(mask1, true, None, None, None)?;
		assert_eq!(txs.len(), 5);
	}

	// now check second account
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account1")?;
	}

	{
		let labels: Vec<_> = api1.accounts(mask1)?.into_iter().map(|a| a.label).collect();
		assert_eq!(labels, ["account1", "default", "account2", "account3"]);
		// check last confirmed height on this account is different from above (should be 0)
		let (_, wallet1_info) = api1.retrieve_summary_info(mask1, false, 1)?;
		assert_eq!(wallet1_info.last_confirmed_height, 0);
		let (wallet1_refreshed, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 12);
		assert_eq!(wallet1_info.total, 7 * reward);
		assert_eq!(wallet1_info.amount_currently_spendable, 7 * reward);
		// check tx log as well
		let (_, txs) = api1.retrieve_txs(mask1, true, None, None, None)?;
		assert_eq!(txs.len(), 7);
	}
	// should be nothing in default account
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("default")?;
	}
	{
		let (_, wallet1_info) = api1.retrieve_summary_info(mask1, false, 1)?;
		assert_eq!(wallet1_info.last_confirmed_height, 0);
		let (wallet1_refreshed, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 12);
		assert_eq!(wallet1_info.total, 0,);
		assert_eq!(wallet1_info.amount_currently_spendable, 0,);
		// check tx log as well
		let (_, txs) = api1.retrieve_txs(mask1, true, None, None, None)?;
		assert_eq!(txs.len(), 0);
	}

	// Send a tx to another wallet
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account1")?;
	}
	{
		let args = InitTxArgs {
			src_acct_name: None,
			amount: reward,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let mut slate = api1.init_send_tx(mask1, args)?;
		slate = client1.send_tx_slate_direct("wallet2", &slate)?;
		api1.tx_lock_outputs(mask1, &slate)?;
		slate = api1.finalize_tx(mask1, &slate)?;
		api1.post_tx(mask1, &slate, false)?;
	}

	{
		let (wallet1_refreshed, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, 13);
		let (_, txs) = api1.retrieve_txs(mask1, true, None, None, None)?;
		assert_eq!(txs.len(), 9);
	}
	// Use the requested account's stored height
	{
		wallet_inst!(wallet1, w);
		assert_eq!(w.parent_key_id(), ExtKeychain::derive_key_id(2, 1, 0, 0, 0));
		let account2 = ExtKeychain::derive_key_id(2, 2, 0, 0, 0);
		let account2_info = libwallet::retrieve_info(w, &account2, 1)?;
		assert_eq!(account2_info.last_confirmed_height, 12);
	}

	// other account should be untouched
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account2")?;
	}
	{
		let (_, wallet1_info) = api1.retrieve_summary_info(mask1, false, 1)?;
		assert_eq!(wallet1_info.last_confirmed_height, 12);
		let (_, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
		assert_eq!(wallet1_info.last_confirmed_height, 13);
		let (_, txs) = api1.retrieve_txs(mask1, true, None, None, None)?;
		println!("{:?}", txs);
		assert_eq!(txs.len(), 5);
	}

	// wallet 2 should only have this tx on the listener account
	{
		let (wallet2_refreshed, wallet2_info) = api2.retrieve_summary_info(mask2, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, 13);
		let (_, txs) = api2.retrieve_txs(mask2, true, None, None, None)?;
		assert_eq!(txs.len(), 1);
	}
	// Default account on wallet 2 should be untouched
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("default")?;
	}
	{
		let (_, wallet2_info) = api2.retrieve_summary_info(mask2, false, 1)?;
		assert_eq!(wallet2_info.last_confirmed_height, 0);
		let (wallet2_refreshed, wallet2_info) = api2.retrieve_summary_info(mask2, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, 13);
		assert_eq!(wallet2_info.total, 0,);
		assert_eq!(wallet2_info.amount_currently_spendable, 0,);
		// check tx log as well
		let (_, txs) = api2.retrieve_txs(mask2, true, None, None, None)?;
		assert_eq!(txs.len(), 0);
	}

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn accounts() {
	let test_dir = "test_output/accounts";
	setup(test_dir);
	if let Err(e) = accounts_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
