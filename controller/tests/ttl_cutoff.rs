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

//! tests ttl_cutoff blocks
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_util;

use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use libwallet::{InitTxArgs, TxLogEntryType};
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

	// Do some mining
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	let amount = 60_000_000_000;
	// note this will increment the block count as part of the transaction "Posting"
	let args = InitTxArgs {
		src_acct_name: None,
		amount,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: true,
		ttl_blocks: Some(2),
		..Default::default()
	};
	let slate_i = api1.init_send_tx(mask1, args)?;

	let mut slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
	api1.tx_lock_outputs(mask1, &slate)?;

	let (_, txs) = api1.retrieve_txs(mask1, true, None, Some(slate.id), None)?;
	let tx = txs[0].clone();

	assert_eq!(tx.ttl_cutoff_height, Some(12));

	// Now mine past the block, and check again. Transaction should be gone.
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 2, false);

	let (_, txs) = api1.retrieve_txs(mask1, true, None, Some(slate.id), None)?;
	let tx = txs[0].clone();

	assert_eq!(tx.ttl_cutoff_height, Some(12));
	assert_eq!(tx.tx_type, TxLogEntryType::TxSentCancelled);

	// Should also be gone in wallet 2, and output gone
	let (_, txs) = api2.retrieve_txs(mask2, true, None, Some(slate.id), None)?;
	let tx = txs[0].clone();
	let outputs = api2.retrieve_outputs(mask2, false, true, None)?.1;
	assert_eq!(outputs.len(), 0);

	assert_eq!(tx.ttl_cutoff_height, Some(12));
	assert_eq!(tx.tx_type, TxLogEntryType::TxReceivedCancelled);

	// try again, except try and send off the transaction for completion beyond the expiry
	// note this will increment the block count as part of the transaction "Posting"
	let args = InitTxArgs {
		src_acct_name: None,
		amount,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: true,
		ttl_blocks: Some(2),
		..Default::default()
	};
	let slate_i = api1.init_send_tx(mask1, args)?;
	api1.tx_lock_outputs(mask1, &slate_i)?;
	slate = slate_i;

	let (_, txs) = api1.retrieve_txs(mask1, true, None, Some(slate.id), None)?;
	let tx = txs[0].clone();

	assert_eq!(tx.ttl_cutoff_height, Some(14));

	// Mine past the ttl block and try to send
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 2, false);

	// Wallet 2 will need to have updated past the TTL
	let (_, _) = api2.retrieve_txs(mask2, true, None, Some(slate.id), None)?;

	// And when wallet 1 sends, should be rejected
	let res = client1.send_tx_slate_direct("wallet2", &slate);
	println!("Send after TTL result is: {:?}", res);
	assert!(res.is_err());

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
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
