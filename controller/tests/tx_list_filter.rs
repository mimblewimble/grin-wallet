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

//! tests of advanced TX filtering

#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;

use grin_core as core;
use grin_keychain as keychain;
use grin_util as util;
use libwallet::{RetrieveTxQueryArgs, RetrieveTxQuerySortField};

use self::libwallet::{InitTxArgs, Slate};
use impls::test_framework::{self, LocalWalletClient};
use std::sync::{atomic::Ordering, Arc};
use std::thread;
use std::time::Duration;
use util::secp::key::SecretKey;
use util::Mutex;

use self::keychain::ExtKeychain;
use self::libwallet::WalletInst;
use impls::DefaultLCProvider;

mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

fn test_wallet_tx_filtering(
	wallet: Arc<
		Mutex<
			Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>,
		>,
	>,
	mask: Option<&SecretKey>,
) -> Result<(), libwallet::Error> {
	wallet::controller::owner_single_use(Some(wallet.clone()), mask, None, |api, _m| {
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.min_id = Some(5);

		// Min ID
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results[0].id, 5);
		assert_eq!(tx_results[tx_results.len() - 1].id, 33);

		// Max ID
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.min_id = Some(5);
		tx_query_args.max_id = Some(20);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results[0].id, 5);
		assert_eq!(tx_results[tx_results.len() - 1].id, 20);

		// Exclude 1 cancelled
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.exclude_cancelled = Some(true);
		tx_query_args.min_id = Some(5);
		tx_query_args.max_id = Some(50);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results.len(), 28);

		// Exclude 1 cancelled, show confirmed only
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.exclude_cancelled = Some(true);
		tx_query_args.include_confirmed_only = Some(true);
		tx_query_args.min_id = Some(5);
		tx_query_args.max_id = Some(50);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results.len(), 14);

		// show outstanding only (including cancelled)
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.exclude_cancelled = Some(false);
		tx_query_args.include_outstanding_only = Some(true);
		tx_query_args.min_id = Some(5);
		tx_query_args.max_id = Some(50);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results.len(), 15);

		// outstanding only and confirmed only should give empty set
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.exclude_cancelled = Some(false);
		tx_query_args.include_outstanding_only = Some(true);
		tx_query_args.include_confirmed_only = Some(true);
		tx_query_args.min_id = Some(5);
		tx_query_args.max_id = Some(50);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results.len(), 0);

		// include sent only
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.include_sent_only = Some(true);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results.len(), 15);

		// include received only (none in this set)
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.include_received_only = Some(true);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results.len(), 0);

		// include reverted only (none in this set)
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.include_reverted_only = Some(true);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results.len(), 0);

		// include coinbase only
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.include_coinbase_only = Some(true);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results.len(), 19);

		// Amounts
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.min_amount = Some(60_000_000_000 - 59_963_300_000);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results.len(), 27);

		// amount, should see as above with coinbases excluded
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.min_amount = Some(60_000_000_000 - 59_963_300_000);
		tx_query_args.max_amount = Some(60_000_000_000 - 1);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results.len(), 8);

		// Amount - should only see coinbase (incoming)
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.min_amount = Some(60_000_000_000);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results.len(), 19);

		// sort order
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.sort_order = Some(libwallet::RetrieveTxQuerySortOrder::Desc);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;

		assert_eq!(tx_results[0].id, 33);
		assert_eq!(tx_results[tx_results.len() - 1].id, 0);

		// change sort field to amount desc, should have coinbases first
		let mut tx_query_args = RetrieveTxQueryArgs::default();
		tx_query_args.sort_order = Some(libwallet::RetrieveTxQuerySortOrder::Desc);
		tx_query_args.sort_field = Some(RetrieveTxQuerySortField::TotalAmount);
		let tx_results = api
			.retrieve_txs(mask, true, None, None, Some(tx_query_args))?
			.1;
		assert_eq!(tx_results[0].amount_credited, 60_000_000_000);

		/*for entry in tx_results.iter() {
			println!("{:?}", entry);
		}*/

		Ok(())
	})?;
	Ok(())
}

/// Builds a wallet + chain with a few transactions, and return wallet for further testing
fn build_chain_for_tx_filtering(
	test_dir: &'static str,
	block_height: usize,
) -> Result<(), libwallet::Error> {
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
		true
	);
	let mask1 = (&mask1_i).as_ref();
	debug!("Mask1: {:?}", mask1);
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
	debug!("Mask2: {:?}", mask2);

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Stop the scanning updater threads because it extends the time needed to build the chain
	// exponentially
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, _m| {
		api.stop_updater()?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, _m| {
		api.stop_updater()?;
		Ok(())
	})?;

	// few values to keep things shorter
	let reward = core::consensus::REWARD;

	// Start off with a few blocks
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);

	for i in 0..block_height {
		let mut wallet_1_has_funds = false;

		// Check wallet 1 contents
		wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
			let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
			debug!(
				"Wallet 1 spendable - {}",
				wallet1_info.amount_currently_spendable
			);
			if wallet1_info.amount_currently_spendable > reward {
				wallet_1_has_funds = true;
			}
			Ok(())
		})?;

		if !wallet_1_has_funds {
			let _ =
				test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 1, false);
			continue;
		}

		// send a random tx
		let num_txs = 1;
		for _ in 0..num_txs {
			let amount: u64 = i as u64 * 1_000_000;
			let mut slate = Slate::blank(1, false);
			debug!("Creating TX for {}", amount);
			wallet::controller::owner_single_use(
				Some(wallet1.clone()),
				mask1,
				None,
				|sender_api, m| {
					// note this will increment the block count as part of the transaction "Posting"
					let args = InitTxArgs {
						src_acct_name: None,
						amount: amount,
						minimum_confirmations: 1,
						max_outputs: 500,
						num_change_outputs: 1,
						selection_strategy_is_use_all: false,
						..Default::default()
					};
					let slate_i = sender_api.init_send_tx(m, args)?;
					slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
					sender_api.tx_lock_outputs(m, &slate)?;
					slate = sender_api.finalize_tx(m, &slate)?;
					Ok(())
				},
			)?;
		}
	}

	// Cancel a tx for filtering testing
	let amount: u64 = 1_000_000;
	let mut slate = Slate::blank(1, false);
	debug!("Creating TX for {}", amount);
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount,
			minimum_confirmations: 1,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: false,
			..Default::default()
		};
		let slate_i = sender_api.init_send_tx(m, args)?;
		slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
		sender_api.tx_lock_outputs(m, &slate)?;
		sender_api.cancel_tx(m, Some(33), None)?;
		Ok(())
	})?;

	// Perform actual testing
	test_wallet_tx_filtering(wallet1, mask1)?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_tx_filtering() {
	let test_dir = "test_output/advanced_tx_filtering";
	clean_output_dir(test_dir);
	setup(test_dir);
	if let Err(e) = build_chain_for_tx_filtering(test_dir, 30) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
