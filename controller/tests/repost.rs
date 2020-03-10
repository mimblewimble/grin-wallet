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

//! Test a wallet repost command
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;

use grin_wallet_util::grin_core as core;

use self::libwallet::{InitTxArgs, Slate};
use impls::test_framework::{self, LocalWalletClient};
use impls::{PathToSlate, SlateGetter as _, SlatePutter as _};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// self send impl
fn file_repost_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	// Create a new wallet test client, and set its queues to communicate with the
	// proxy
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

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "mining")?;
		api.create_account_path(m, "listener")?;
		Ok(())
	})?;

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		api.create_account_path(m, "account1")?;
		api.create_account_path(m, "account2")?;
		Ok(())
	})?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let mut bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	let send_file = format!("{}/part_tx_1.tx", test_dir);
	let receive_file = format!("{}/part_tx_2.tx", test_dir);

	let mut slate = Slate::blank(2);

	// Should have 5 in account1 (5 spendable), 5 in account (2 spendable)
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
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
		let slate = api.init_send_tx(m, args)?;
		PathToSlate((&send_file).into()).put_tx(&slate)?;
		api.tx_lock_outputs(m, &slate, 0)?;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// wallet 1 receives file to different account, completes
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("listener")?;
	}

	wallet::controller::foreign_single_use(wallet1.clone(), mask1_i.clone(), |api| {
		slate = PathToSlate((&send_file).into()).get_tx()?;
		slate = api.receive_tx(&slate, None, None)?;
		PathToSlate((&receive_file).into()).put_tx(&slate)?;
		Ok(())
	})?;

	// wallet 1 receives file to different account, completes
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}

	// wallet 1 finalize
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		slate = PathToSlate((&receive_file).into()).get_tx()?;
		slate = api.finalize_tx(m, &slate)?;
		Ok(())
	})?;

	// Now repost from cached
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_, txs) = api.retrieve_txs(m, true, None, Some(slate.id))?;
		let stored_tx = api.get_stored_tx(m, &txs[0])?;
		api.post_tx(m, &stored_tx.unwrap(), false)?;
		bh += 1;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// update/test contents of both accounts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward - reward * 2);
		Ok(())
	})?;

	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("listener")?;
	}

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, bh);
		assert_eq!(wallet2_info.total, 2 * reward);
		Ok(())
	})?;

	// as above, but syncronously
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("account1")?;
	}

	let mut slate = Slate::blank(2);
	let amount = 60_000_000_000;

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
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
		let slate_i = sender_api.init_send_tx(m, args)?;
		slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
		sender_api.tx_lock_outputs(m, &slate, 0)?;
		slate = sender_api.finalize_tx(m, &slate)?;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// Now repost from cached
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_, txs) = api.retrieve_txs(m, true, None, Some(slate.id))?;
		let stored_tx = api.get_stored_tx(m, &txs[0])?;
		api.post_tx(m, &stored_tx.unwrap(), false)?;
		bh += 1;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;
	//
	// update/test contents of both accounts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward - reward * 4);
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, bh);
		assert_eq!(wallet2_info.total, 2 * amount);
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_file_repost() {
	let test_dir = "test_output/file_repost";
	setup(test_dir);
	if let Err(e) = file_repost_test_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}
