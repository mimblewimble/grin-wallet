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

//! Test a wallet file send/recieve
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_wallet_libwallet as libwallet;
use grin_wallet_util::grin_core as core;

use impls::test_framework::{self, LocalWalletClient};
use impls::{PathToSlate, SlateGetter as _, SlatePutter as _};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use grin_wallet_libwallet::InitTxArgs;

use serde_json;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// self send impl
fn file_exchange_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
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

	// test optional message
	let message = "sender test message, sender test message";

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
			message: Some(message.to_owned()),
			..Default::default()
		};
		let slate = api.init_send_tx(m, args)?;
		// output tx file
		PathToSlate((&send_file).into()).put_tx(&slate)?;
		api.tx_lock_outputs(m, &slate, 0)?;
		Ok(())
	})?;

	// Get some mining done
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("account1")?;
	}

	let mut slate = PathToSlate((&send_file).into()).get_tx()?;
	let mut naughty_slate = slate.clone();
	naughty_slate.participant_data[0].message = Some("I changed the message".to_owned());

	// verify messages on slate match
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.verify_slate_messages(m, &slate)?;
		assert!(api.verify_slate_messages(m, &naughty_slate).is_err());
		Ok(())
	})?;

	let sender2_message = "And this is sender 2's message".to_owned();

	// wallet 2 receives file, completes, sends file back
	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
		slate = api.receive_tx(&slate, None, Some(sender2_message.clone()))?;
		PathToSlate((&receive_file).into()).put_tx(&slate)?;
		Ok(())
	})?;

	// wallet 1 finalises and posts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let mut slate = PathToSlate(receive_file.into()).get_tx()?;
		api.verify_slate_messages(m, &slate)?;
		slate = api.finalize_tx(m, &slate)?;
		api.post_tx(m, slate.tx_or_err()?, false)?;
		bh += 1;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// Check total in mining account
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward - reward * 2);
		Ok(())
	})?;

	// Check total in 'wallet 2' account
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (wallet2_refreshed, wallet2_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet2_refreshed);
		assert_eq!(wallet2_info.last_confirmed_height, bh);
		assert_eq!(wallet2_info.total, 2 * reward);
		Ok(())
	})?;

	// Check messages, all participants should have both
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_, tx) = api.retrieve_txs(m, true, None, Some(slate.id))?;
		assert_eq!(
			tx[0].clone().messages.unwrap().messages[0].message,
			Some(message.to_owned())
		);
		assert_eq!(
			tx[0].clone().messages.unwrap().messages[1].message,
			Some(sender2_message.to_owned())
		);

		let msg_json = serde_json::to_string_pretty(&tx[0].clone().messages.unwrap()).unwrap();
		println!("{}", msg_json);
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		let (_, tx) = api.retrieve_txs(m, true, None, Some(slate.id))?;
		assert_eq!(
			tx[0].clone().messages.unwrap().messages[0].message,
			Some(message.to_owned())
		);
		assert_eq!(
			tx[0].clone().messages.unwrap().messages[1].message,
			Some(sender2_message)
		);
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_file_exchange() {
	let test_dir = "test_output/file_exchange";
	setup(test_dir);
	if let Err(e) = file_exchange_test_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}
