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

//! Test a wallet repost command
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;

use grin_core as core;
use std::path::PathBuf;

use self::libwallet::InitTxArgs;
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

	// add some accounts
	api1.create_account_path(mask1, "mining")?;
	api1.create_account_path(mask1, "listener")?;

	api2.create_account_path(mask2, "account1")?;
	api2.create_account_path(mask2, "account2")?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_account_by_name("mining")?;
	}
	let mut bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	let send_file = format!("{}/part_tx_1.tx", test_dir);
	let receive_file = format!("{}/part_tx_2.tx", test_dir);

	// Should have 5 in account1 (5 spendable), 5 in account (2 spendable)
	let (wallet1_refreshed, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
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
	let mut slate = api1.init_send_tx(mask1, args)?;
	PathToSlate((&send_file).into()).put_tx(&slate, false)?;
	api1.tx_lock_outputs(mask1, &slate)?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// wallet 1 receives file to different account, completes
	{
		wallet_inst!(wallet1, w);
		w.set_account_by_name("listener")?;
	}

	wallet::controller::foreign_single_use(
		wallet1.clone(),
		PathBuf::from(test_dir),
		mask1_i.clone(),
		|api| {
			slate = PathToSlate((&send_file).into()).get_tx()?.0;
			slate = api.receive_tx(&slate, None, None)?;
			PathToSlate((&receive_file).into()).put_tx(&slate, false)?;
			Ok(())
		},
	)?;

	// wallet 1 receives file to different account, completes
	{
		wallet_inst!(wallet1, w);
		w.set_account_by_name("mining")?;
	}

	// wallet 1 finalize
	slate = PathToSlate((&receive_file).into()).get_tx()?.0;
	slate = api1.finalize_tx(mask1, &slate)?;

	// Now repost from cached
	let (_, txs) = api1.retrieve_txs(mask1, true, None, Some(slate.id), None)?;
	println!("TXS[0]: {:?}", txs[0]);
	let stored_tx = api1.get_stored_tx(mask1, None, Some(&txs[0].tx_slate_id.unwrap()))?;
	println!("Stored tx: {:?}", stored_tx);
	api1.post_tx(mask1, &slate, false)?;
	bh += 1;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// update/test contents of both accounts
	let (wallet1_refreshed, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
	assert!(wallet1_refreshed);
	assert_eq!(wallet1_info.last_confirmed_height, bh);
	assert_eq!(wallet1_info.total, bh * reward - reward * 2);

	{
		wallet_inst!(wallet1, w);
		w.set_account_by_name("listener")?;
	}

	let (wallet1_refreshed, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
	assert!(wallet1_refreshed);
	assert_eq!(wallet1_info.last_confirmed_height, bh);
	assert_eq!(wallet1_info.total, 2 * reward);

	// as above, but synchronously
	{
		wallet_inst!(wallet1, w);
		w.set_account_by_name("mining")?;
	}
	{
		wallet_inst!(wallet2, w);
		w.set_account_by_name("account1")?;
	}

	let amount = 60_000_000_000;

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
	let slate_i = api1.init_send_tx(mask1, args)?;
	slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
	api1.tx_lock_outputs(mask1, &slate)?;
	slate = api1.finalize_tx(mask1, &slate)?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// Now repost from cached
	let (_, txs) = api1.retrieve_txs(mask1, true, None, Some(slate.id), None)?;
	let stored_tx_slate = api1.get_stored_tx(mask1, Some(txs[0].id), None)?.unwrap();
	api1.post_tx(mask1, &stored_tx_slate, false)?;
	bh += 1;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// update/test contents of both accounts
	let (wallet1_refreshed, wallet1_info) = api1.retrieve_summary_info(mask1, true, 1)?;
	assert!(wallet1_refreshed);
	assert_eq!(wallet1_info.last_confirmed_height, bh);
	assert_eq!(wallet1_info.total, bh * reward - reward * 4);

	let (wallet2_refreshed, wallet2_info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert!(wallet2_refreshed);
	assert_eq!(wallet2_info.last_confirmed_height, bh);
	assert_eq!(wallet2_info.total, 2 * amount);

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
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
