// Copyright 2018 The Grin Developers
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

//! Test a wallet repost command
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;

use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_keychain as keychain;
use grin_wallet_util::grin_util as util;

use self::core::global;
use self::core::global::ChainTypes;
use self::keychain::ExtKeychain;
use self::libwallet::{InitTxArgs, Slate};
use impls::test_framework::{self, LocalWalletClient, WalletProxy};
use impls::{PathToSlate, SlateGetter as _, SlatePutter as _};
use std::fs;
use std::thread;
use std::time::Duration;

fn clean_output_dir(test_dir: &str) {
	let _ = fs::remove_dir_all(test_dir);
}

fn setup(test_dir: &str) {
	util::init_test_logger();
	clean_output_dir(test_dir);
	global::set_mining_mode(ChainTypes::AutomatedTesting);
}

/// self send impl
fn file_repost_test_impl(test_dir: &str) -> Result<(), libwallet::Error> {
	setup(test_dir);
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy: WalletProxy<LocalWalletClient, ExtKeychain> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let wallet1 =
		test_framework::create_wallet(&format!("{}/wallet1", test_dir), client1.clone(), None);
	wallet_proxy.add_wallet("wallet1", client1.get_send_instance(), wallet1.clone());

	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	let wallet2 =
		test_framework::create_wallet(&format!("{}/wallet2", test_dir), client2.clone(), None);
	wallet_proxy.add_wallet("wallet2", client2.get_send_instance(), wallet2.clone());

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::REWARD;

	// add some accounts
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		api.create_account_path("mining")?;
		api.create_account_path("listener")?;
		Ok(())
	})?;

	// add some accounts
	wallet::controller::owner_single_use(wallet2.clone(), |api| {
		api.create_account_path("account1")?;
		api.create_account_path("account2")?;
		Ok(())
	})?;

	// Get some mining done
	{
		let mut w = wallet1.lock();
		w.set_parent_key_id_by_name("mining")?;
	}
	let mut bh = 10u64;
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), bh as usize, false);

	let send_file = format!("{}/part_tx_1.tx", test_dir);
	let receive_file = format!("{}/part_tx_2.tx", test_dir);

	let mut slate = Slate::blank(2);

	// Should have 5 in account1 (5 spendable), 5 in account (2 spendable)
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward);
		// send to send
		let args = InitTxArgs {
			src_acct_name: Some("mining".to_owned()),
			amount: reward * 2,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate = api.init_send_tx(args)?;
		PathToSlate((&send_file).into()).put_tx(&slate)?;
		api.tx_lock_outputs(&slate, 0)?;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 3, false);
	bh += 3;

	// wallet 1 receives file to different account, completes
	{
		let mut w = wallet1.lock();
		w.set_parent_key_id_by_name("listener")?;
	}

	wallet::controller::foreign_single_use(wallet1.clone(), |api| {
		slate = PathToSlate((&send_file).into()).get_tx()?;
		slate = api.receive_tx(&slate, None, None)?;
		PathToSlate((&receive_file).into()).put_tx(&slate)?;
		Ok(())
	})?;

	// wallet 1 receives file to different account, completes
	{
		let mut w = wallet1.lock();
		w.set_parent_key_id_by_name("mining")?;
	}

	// wallet 1 finalize
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		slate = PathToSlate((&receive_file).into()).get_tx()?;
		slate = api.finalize_tx(&slate)?;
		Ok(())
	})?;

	// Now repost from cached
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let (_, txs) = api.retrieve_txs(true, None, Some(slate.id))?;
		let stored_tx = api.get_stored_tx(&txs[0])?;
		api.post_tx(&stored_tx.unwrap(), false)?;
		bh += 1;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 3, false);
	bh += 3;

	// update/test contents of both accounts
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward - reward * 2);
		Ok(())
	})?;

	{
		let mut w = wallet1.lock();
		w.set_parent_key_id_by_name("listener")?;
	}

	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, bh);
		assert_eq!(wallet2_info.total, 2 * reward);
		Ok(())
	})?;

	// as above, but syncronously
	{
		let mut w = wallet1.lock();
		w.set_parent_key_id_by_name("mining")?;
	}
	{
		let mut w = wallet2.lock();
		w.set_parent_key_id_by_name("account1")?;
	}

	let mut slate = Slate::blank(2);
	let amount = 60_000_000_000;

	wallet::controller::owner_single_use(wallet1.clone(), |sender_api| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: reward * 2,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = sender_api.init_send_tx(args)?;
		slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
		sender_api.tx_lock_outputs(&slate, 0)?;
		slate = sender_api.finalize_tx(&mut slate)?;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 3, false);
	bh += 3;

	// Now repost from cached
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let (_, txs) = api.retrieve_txs(true, None, Some(slate.id))?;
		let stored_tx = api.get_stored_tx(&txs[0])?;
		api.post_tx(&stored_tx.unwrap(), false)?;
		bh += 1;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 3, false);
	bh += 3;
	//
	// update/test contents of both accounts
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward - reward * 4);
		Ok(())
	})?;

	wallet::controller::owner_single_use(wallet2.clone(), |api| {
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, bh);
		assert_eq!(wallet2_info.total, 2 * amount);
		Ok(())
	})?;

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_file_repost() {
	let test_dir = "test_output/file_repost";
	if let Err(e) = file_repost_test_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
}
