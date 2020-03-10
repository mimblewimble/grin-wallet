// Copyright 2020 The Grin Developers
//
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

#[macro_use]
mod common;

use common::{clean_output_dir, create_wallet_proxy, setup};
use grin_wallet_controller::controller::owner_single_use as owner;
use grin_wallet_impls::test_framework::*;
use grin_wallet_impls::{DefaultLCProvider, PathToSlate, SlatePutter};
use grin_wallet_libwallet as libwallet;
use grin_wallet_libwallet::api_impl::types::InitTxArgs;
use grin_wallet_libwallet::WalletInst;
use grin_wallet_util::grin_chain as chain;
use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_core::core::hash::Hashed;
use grin_wallet_util::grin_core::core::Transaction;
use grin_wallet_util::grin_core::global;
use grin_wallet_util::grin_keychain::ExtKeychain;
use grin_wallet_util::grin_util::secp::key::SecretKey;
use grin_wallet_util::grin_util::Mutex;
use log::error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

type Wallet = Arc<
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
>;

fn revert(
	test_dir: &'static str,
) -> Result<
	(
		Arc<chain::Chain>,
		Arc<AtomicBool>,
		u64,
		u64,
		Transaction,
		Wallet,
		Option<SecretKey>,
		Wallet,
		Option<SecretKey>,
	),
	libwallet::Error,
> {
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let stopper = wallet_proxy.running.clone();
	let chain = wallet_proxy.chain.clone();
	let test_dir2 = format!("{}/chain2", test_dir);
	let wallet_proxy2 = create_wallet_proxy(&test_dir2);
	let chain2 = wallet_proxy2.chain.clone();
	let stopper2 = wallet_proxy2.running.clone();

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
	let mask1 = mask1_i.as_ref();

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
	let mask2 = mask2_i.as_ref();

	// Set the wallet proxy listener running
	std::thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	owner(Some(wallet1.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "a")?;
		api.set_active_account(m, "a")?;
		Ok(())
	})?;

	owner(Some(wallet2.clone()), mask2, None, |api, m| {
		api.create_account_path(m, "b")?;
		api.set_active_account(m, "b")?;
		Ok(())
	})?;

	let reward = core::consensus::REWARD;
	let cm = global::coinbase_maturity() as u64;
	let sent = reward * 2;

	// Mine some blocks
	let bh = 10u64;
	award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false)?;

	// Sanity check contents
	owner(Some(wallet1.clone()), mask1, None, |api, m| {
		let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.last_confirmed_height, bh);
		assert_eq!(info.total, bh * reward);
		assert_eq!(info.amount_currently_spendable, (bh - cm) * reward);
		assert_eq!(info.amount_reverted, 0);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		let (c, _) = libwallet::TxLogEntry::sum_confirmed(&txs);
		assert_eq!(info.total, c);
		assert_eq!(txs.len(), bh as usize);
		Ok(())
	})?;

	owner(Some(wallet2.clone()), mask2, None, |api, m| {
		let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.last_confirmed_height, bh);
		assert_eq!(info.total, 0);
		assert_eq!(info.amount_currently_spendable, 0);
		assert_eq!(info.amount_reverted, 0);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		assert_eq!(txs.len(), 0);
		Ok(())
	})?;

	// Send some funds
	let mut tx = None;
	owner(Some(wallet1.clone()), mask1, None, |api, m| {
		// send to send
		let args = InitTxArgs {
			src_acct_name: None,
			amount: sent,
			minimum_confirmations: cm,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: false,
			..Default::default()
		};
		let slate = api.init_send_tx(m, args)?;
		// output tx file
		let send_file = format!("{}/part_tx_1.tx", test_dir);
		PathToSlate(send_file.into()).put_tx(&slate)?;
		api.tx_lock_outputs(m, &slate, 0)?;
		let slate = client1.send_tx_slate_direct("wallet2", &slate)?;
		let slate = api.finalize_tx(m, &slate)?;
		tx = Some(slate.tx);

		Ok(())
	})?;
	let tx = tx.unwrap();

	// Check funds have been received
	owner(Some(wallet2.clone()), mask2, None, |api, m| {
		let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.last_confirmed_height, bh);
		assert_eq!(info.total, 0);
		assert_eq!(info.amount_currently_spendable, 0);
		assert_eq!(info.amount_reverted, 0);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		assert_eq!(txs.len(), 1);
		let tx = &txs[0];
		assert_eq!(tx.tx_type, libwallet::TxLogEntryType::TxReceived);
		assert!(!tx.confirmed);
		Ok(())
	})?;

	// Update parallel chain
	assert_eq!(chain2.head_header().unwrap().height, 0);
	for i in 0..bh {
		let hash = chain.get_header_by_height(i + 1).unwrap().hash();
		let block = chain.get_block(&hash).unwrap();
		process_block(&chain2, block);
	}
	assert_eq!(chain2.head_header().unwrap().height, bh);

	// Build 2 blocks at same height: 1 with the tx, 1 without
	let head = chain.head_header().unwrap();
	let block_with = create_block_for_wallet(
		&chain,
		head.clone(),
		vec![&tx.as_ref().unwrap()],
		wallet1.clone(),
		mask1,
	)?;
	let block_without = create_block_for_wallet(&chain, head, vec![], wallet1.clone(), mask1)?;

	// Add block with tx to the chain
	process_block(&chain, block_with.clone());
	assert_eq!(chain.head_header().unwrap(), block_with.header);

	// Add block without tx to the parallel chain
	process_block(&chain2, block_without.clone());
	assert_eq!(chain2.head_header().unwrap(), block_without.header);

	let bh = bh + 1;

	// Check funds have been confirmed
	owner(Some(wallet2.clone()), mask2, None, |api, m| {
		let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.last_confirmed_height, bh);
		assert_eq!(info.total, sent);
		assert_eq!(info.amount_currently_spendable, sent);
		assert_eq!(info.amount_reverted, 0);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		assert_eq!(txs.len(), 1);
		let tx = &txs[0];
		assert_eq!(tx.tx_type, libwallet::TxLogEntryType::TxReceived);
		assert!(tx.confirmed);
		assert!(tx.kernel_excess.is_some());
		assert!(tx.reverted_after.is_none());
		Ok(())
	})?;

	// Attach more blocks to the parallel chain, making it the longest one
	award_block_to_wallet(&chain2, vec![], wallet1.clone(), mask1)?;
	assert_eq!(chain2.head_header().unwrap().height, bh + 1);
	let new_head = chain2
		.get_block(&chain2.head_header().unwrap().hash())
		.unwrap();

	// Input blocks from parallel chain to original chain, updating it as well
	// and effectively reverting the transaction
	process_block(&chain, block_without.clone()); // This shouldn't update the head
	assert_eq!(chain.head_header().unwrap(), block_with.header);
	process_block(&chain, new_head.clone()); // But this should!
	assert_eq!(chain.head_header().unwrap(), new_head.header);

	let bh = bh + 1;

	// Check funds have been reverted
	owner(Some(wallet2.clone()), mask2, None, |api, m| {
		api.scan(m, None, false)?;
		let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.last_confirmed_height, bh);
		assert_eq!(info.total, 0);
		assert_eq!(info.amount_currently_spendable, 0);
		assert_eq!(info.amount_reverted, sent);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		assert_eq!(txs.len(), 1);
		let tx = &txs[0];
		assert_eq!(tx.tx_type, libwallet::TxLogEntryType::TxReverted);
		assert!(!tx.confirmed);
		assert!(tx.reverted_after.is_some());
		Ok(())
	})?;

	stopper2.store(false, Ordering::Relaxed);
	Ok((
		chain,
		stopper,
		sent,
		bh,
		tx.unwrap(),
		wallet1,
		mask1_i,
		wallet2,
		mask2_i,
	))
}

fn revert_reconfirm_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	let (chain, stopper, sent, bh, tx, wallet1, mask1_i, wallet2, mask2_i) = revert(test_dir)?;
	let mask1 = mask1_i.as_ref();
	let mask2 = mask2_i.as_ref();

	// Include the tx into the chain again, the tx should no longer be reverted
	award_block_to_wallet(&chain, vec![&tx], wallet1.clone(), mask1)?;

	let bh = bh + 1;

	// Check funds have been confirmed again
	owner(Some(wallet2.clone()), mask2, None, |api, m| {
		let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.last_confirmed_height, bh);
		assert_eq!(info.total, sent);
		assert_eq!(info.amount_currently_spendable, sent);
		assert_eq!(info.amount_reverted, 0);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		assert_eq!(txs.len(), 1);
		let tx = &txs[0];
		assert_eq!(tx.tx_type, libwallet::TxLogEntryType::TxReceived);
		assert!(tx.confirmed);
		assert!(tx.reverted_after.is_none());
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(1000));
	Ok(())
}

fn revert_cancel_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	let (_, stopper, sent, bh, _, _, _, wallet2, mask2_i) = revert(test_dir)?;
	let mask2 = mask2_i.as_ref();

	// Cancelling tx
	owner(Some(wallet2.clone()), mask2, None, |api, m| {
		// Sanity check
		let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.last_confirmed_height, bh);
		assert_eq!(info.total, 0);
		assert_eq!(info.amount_currently_spendable, 0);
		assert_eq!(info.amount_reverted, sent);

		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		assert_eq!(txs.len(), 1);
		let tx = &txs[0];

		// Cancel
		api.cancel_tx(m, Some(tx.id), None)?;

		// Check updated summary info
		let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.last_confirmed_height, bh);
		assert_eq!(info.total, 0);
		assert_eq!(info.amount_currently_spendable, 0);
		assert_eq!(info.amount_reverted, 0);

		// Check updated tx log
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		assert_eq!(txs.len(), 1);
		let tx = &txs[0];
		assert_eq!(tx.tx_type, libwallet::TxLogEntryType::TxReceivedCancelled);
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(1000));
	Ok(())
}

#[test]
fn tx_revert_reconfirm() {
	let test_dir = "test_output/revert_tx";
	setup(test_dir);
	if let Err(e) = revert_reconfirm_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}

#[test]
fn tx_revert_cancel() {
	let test_dir = "test_output/revert_tx_cancel";
	setup(test_dir);
	if let Err(e) = revert_cancel_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}
