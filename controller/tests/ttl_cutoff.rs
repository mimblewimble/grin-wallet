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

//! tests ttl_cutoff blocks
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_util;

use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use libwallet::{InitTxArgs, Slate, TxLogEntryType};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// Test cutoff block times
fn ttl_cutoff_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
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

	// Do some mining
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	let amount = 60_000_000_000;
	let mut slate = Slate::blank(1);
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			ttl_blocks: Some(2),
			..Default::default()
		};
		let slate_i = sender_api.init_send_tx(m, args)?;

		slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
		sender_api.tx_lock_outputs(m, &slate, 0)?;

		let (_, txs) = sender_api.retrieve_txs(m, true, None, Some(slate.id))?;
		let tx = txs[0].clone();

		assert_eq!(tx.ttl_cutoff_height, Some(12));
		Ok(())
	})?;

	// Now mine past the block, and check again. Transaction should be gone.
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 2, false);

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		let (_, txs) = sender_api.retrieve_txs(m, true, None, Some(slate.id))?;
		let tx = txs[0].clone();

		assert_eq!(tx.ttl_cutoff_height, Some(12));
		assert!(tx.tx_type == TxLogEntryType::TxSentCancelled);
		Ok(())
	})?;

	// Should also be gone in wallet 2, and output gone
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |sender_api, m| {
		let (_, txs) = sender_api.retrieve_txs(m, true, None, Some(slate.id))?;
		let tx = txs[0].clone();
		let outputs = sender_api.retrieve_outputs(m, false, true, None)?.1;
		assert_eq!(outputs.len(), 0);

		assert_eq!(tx.ttl_cutoff_height, Some(12));
		assert!(tx.tx_type == TxLogEntryType::TxReceivedCancelled);
		Ok(())
	})?;

	// try again, except try and send off the transaction for completion beyond the expiry
	let mut slate = Slate::blank(1);
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			ttl_blocks: Some(2),
			..Default::default()
		};
		let slate_i = sender_api.init_send_tx(m, args)?;
		sender_api.tx_lock_outputs(m, &slate_i, 0)?;
		slate = slate_i;

		let (_, txs) = sender_api.retrieve_txs(m, true, None, Some(slate.id))?;
		let tx = txs[0].clone();

		assert_eq!(tx.ttl_cutoff_height, Some(14));
		Ok(())
	})?;

	// Mine past the ttl block and try to send
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 2, false);

	// Wallet 2 will need to have updated past the TTL
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |sender_api, m| {
		let (_, _) = sender_api.retrieve_txs(m, true, None, Some(slate.id))?;
		Ok(())
	})?;

	// And when wallet 1 sends, should be rejected
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |_sender_api, _m| {
		let res = client1.send_tx_slate_direct("wallet2", &slate);
		println!("Send after TTL result is: {:?}", res);
		assert!(res.is_err());
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn ttl_cutoff() {
	let test_dir = "test_output/ttl_cutoff";
	setup(test_dir);
	if let Err(e) = ttl_cutoff_test_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}
