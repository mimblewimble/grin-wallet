// Copyright 2021 The Grin Developers
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
use grin_chain as chain;
use grin_core as core;
use grin_core::core::hash::Hashed;
use grin_core::core::Transaction;
use grin_core::global;
use grin_keychain::ExtKeychain;
use grin_util::secp::key::SecretKey;
use grin_util::ToHex;
use grin_wallet_api::Owner;
use grin_wallet_impls::test_framework::*;
use grin_wallet_impls::{DefaultLCProvider, PathToSlate, SlatePutter};
use grin_wallet_libwallet as libwallet;
use grin_wallet_libwallet::api_impl::types::InitTxArgs;
use log::error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{slice, thread};

type Wallet = grin_wallet_libwallet::WalletHandle<
	'static,
	DefaultLCProvider<LocalWalletClient, ExtKeychain>,
	LocalWalletClient,
	ExtKeychain,
>;

// Count node requests
fn node_requests(
	client: &LocalWalletClient,
	action: impl FnOnce() -> Result<(), libwallet::Error>,
) -> Result<Vec<(String, String)>, libwallet::Error> {
	let original = client.proxy_tx.lock().clone();
	let forward = original.clone();
	let (sender, receiver) = std::sync::mpsc::channel();
	*client.proxy_tx.lock() = sender;
	let relay = thread::spawn(move || {
		let mut requests = Vec::new();
		for message in receiver {
			requests.push((message.method.clone(), message.body.clone()));
			forward.send(message).unwrap();
		}
		requests
	});
	let result = action();
	*client.proxy_tx.lock() = original;
	let requests = relay.join().unwrap();
	result?;
	Ok(requests)
}

#[allow(clippy::type_complexity)]
fn revert(
	test_dir: &'static str,
	relocate: bool,
	no_change: bool,
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
		Owner<DefaultLCProvider<LocalWalletClient, ExtKeychain>, LocalWalletClient, ExtKeychain>,
		Owner<DefaultLCProvider<LocalWalletClient, ExtKeychain>, LocalWalletClient, ExtKeychain>,
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
		false,
		api1
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
		false,
		api2
	);
	let mask2 = mask2_i.as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	api1.create_account_path(mask1, "a")?;
	api1.set_active_account(mask1, "a")?;

	api2.create_account_path(mask2, "b")?;
	api2.set_active_account(mask2, "b")?;

	let reward = core::consensus::REWARD;
	let cm = global::coinbase_maturity() as u64;
	let sent = if no_change {
		reward - core::libtx::tx_fee(1, 1, 1)
	} else {
		reward * 2
	};

	// Mine some blocks
	let bh = 10u64;
	award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false)?;

	// Sanity check contents
	let (refreshed, info) = api1.retrieve_summary_info(mask1, true, 1)?;
	assert!(refreshed);
	assert_eq!(info.last_confirmed_height, bh);
	assert_eq!(info.total, bh * reward);
	assert_eq!(info.amount_currently_spendable, (bh - cm) * reward);
	assert_eq!(info.amount_reverted, 0);
	// check tx log as well
	let (_, txs) = api1.retrieve_txs(mask1, true, None, None, None)?;
	let (c, _) = libwallet::TxLogEntry::sum_confirmed(&txs);
	assert_eq!(info.total, c);
	assert_eq!(txs.len(), bh as usize);

	let (refreshed, info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert!(refreshed);
	assert_eq!(info.last_confirmed_height, bh);
	assert_eq!(info.total, 0);
	assert_eq!(info.amount_currently_spendable, 0);
	assert_eq!(info.amount_reverted, 0);
	// check tx log as well
	let (_, txs) = api2.retrieve_txs(mask2, true, None, None, None)?;
	assert_eq!(txs.len(), 0);

	// Send some funds
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
	let slate = api1.init_send_tx(mask1, args)?;
	// output tx file
	let send_file = format!("{}/part_tx_1.tx", test_dir);
	PathToSlate(send_file.into()).put_tx(&slate, false)?;
	api1.tx_lock_outputs(mask1, &slate)?;
	let slate = client1.send_tx_slate_direct("wallet2", &slate)?;
	let slate = api1.finalize_tx(mask1, &slate)?;
	let tx = slate.tx.expect("tx from slate");

	// Check funds have been received
	let (refreshed, info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert!(refreshed);
	assert_eq!(info.last_confirmed_height, bh);
	assert_eq!(info.total, 0);
	assert_eq!(info.amount_currently_spendable, 0);
	assert_eq!(info.amount_reverted, 0);
	// check tx log as well
	let (_, txs) = api2.retrieve_txs(mask2, true, None, None, None)?;
	assert_eq!(txs.len(), 1);
	assert_eq!(txs[0].tx_type, libwallet::TxLogEntryType::TxReceived);
	assert!(!&txs[0].confirmed);
	assert_eq!(txs[0].confirmed_height, None);

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
		std::slice::from_ref(&tx),
		wallet1.clone(),
		mask1,
	)?;
	let block_without = create_block_for_wallet(&chain, head, &[], wallet1.clone(), mask1)?;

	// Add block with tx to the chain
	process_block(&chain, block_with.clone());
	assert_eq!(chain.head_header().unwrap(), block_with.header);

	// Add block without tx to the parallel chain
	process_block(&chain2, block_without.clone());
	assert_eq!(chain2.head_header().unwrap(), block_without.header);

	let bh = bh + 1;

	// Check funds have been confirmed
	let (refreshed, info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert!(refreshed);
	assert_eq!(info.last_confirmed_height, bh);
	assert_eq!(info.total, sent);
	assert_eq!(info.amount_currently_spendable, sent);
	assert_eq!(info.amount_reverted, 0);
	// check tx log as well
	let (_, txs) = api2.retrieve_txs(mask2, true, None, None, None)?;
	assert_eq!(txs.len(), 1);
	assert_eq!(txs[0].tx_type, libwallet::TxLogEntryType::TxReceived);
	assert!(&txs[0].confirmed);
	assert!(&txs[0].kernel_excess.is_some());
	assert!(&txs[0].reverted_after.is_none());
	assert_eq!(txs[0].confirmed_height, Some(bh));

	// Confirm both sides before the fork
	let mut detected = Vec::new();
	for (wallet, mask) in [(&api1, mask1), (&api2, mask2)] {
		let (refreshed, entries) = wallet.retrieve_txs(mask, true, None, None, None)?;
		assert!(refreshed);
		let entry = entries
			.iter()
			.find(|e| e.kernel_excess == Some(tx.kernels()[0].excess))
			.unwrap();
		assert_eq!(entry.confirmed_height, Some(bh));
		detected.push(entry.confirmation_ts);
	}

	let requests = node_requests(&client1, || {
		assert!(api1.retrieve_txs(mask1, true, None, None, None)?.0);
		Ok(())
	})?;
	assert!(!requests
		.iter()
		.any(|(method, _)| method == "get_kernel" || method == "get_header_hash"));

	// Restore an unaffected coinbase and one that will disappear on the fork
	let restored_coinbases = if relocate && no_change {
		{
			wallet_inst!(wallet1, w);
			let outputs: Vec<_> = w
				.iter()?
				.filter(|o| {
					o.is_coinbase
						&& o.status == libwallet::OutputStatus::Unspent
						&& (o.height == bh - 1 || o.height == bh)
				})
				.collect();
			assert_eq!(outputs.len(), 2);
			let mut batch = w.batch(mask1)?;
			for output in outputs {
				batch.delete(&output.key_id, &output.mmr_index)?;
				batch.delete_tx_log_entry(output.tx_log_entry.unwrap(), &output.root_key_id)?;
			}
			batch.commit()?;
		}
		api1.scan(mask1, Some(1), false)?;
		let (_, entries) = api1.retrieve_txs(mask1, false, None, None, None)?;
		let entries: Vec<_> = entries
			.into_iter()
			.filter(|e| {
				e.tx_type == libwallet::TxLogEntryType::ConfirmedCoinbase
					&& e.kernel_excess.is_none()
			})
			.collect();
		assert_eq!(entries.len(), 2);
		entries
	} else {
		Vec::new()
	};

	// Restore the receiver before relocating its transaction
	let restored = if relocate && no_change {
		{
			wallet_inst!(wallet2, w);
			let outputs: Vec<_> = w.iter()?.collect();
			let entries: Vec<_> = w.tx_log_iter()?.collect::<Result<_, _>>()?;
			let mut batch = w.batch(mask2)?;
			for output in outputs {
				batch.delete(&output.key_id, &output.mmr_index)?;
			}
			for entry in entries {
				batch.delete_tx_log_entry(entry.id, &entry.parent_key_id)?;
			}
			batch.commit()?;
		}
		api2.scan(mask2, Some(1), false)?;
		let (_, entries) = api2.retrieve_txs(mask2, true, None, None, None)?;
		assert_eq!(entries.len(), 1);
		assert!(entries[0].kernel_excess.is_none());
		assert!(entries[0].restored_output.is_some());
		assert_eq!(entries[0].confirmed_height, Some(bh));
		detected[1] = entries[0].confirmation_ts;
		Some(entries[0].id)
	} else {
		None
	};

	// Preserve the incoming height after locking its output
	if relocate {
		let slate = api2.init_send_tx(
			mask2,
			InitTxArgs {
				amount: sent / 2,
				minimum_confirmations: 1,
				..Default::default()
			},
		)?;
		api2.tx_lock_outputs(mask2, &slate)?;
	}

	// Attach more blocks to the parallel chain, making it the longest one
	let fork_txs = if relocate { slice::from_ref(&tx) } else { &[] };
	award_block_to_wallet(&chain2, fork_txs, wallet1.clone(), mask1)?;
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

	if relocate {
		// Keep heights and scan progress unchanged on failure
		for failure in ["kernel", "tip", "header", "header_chain", "outputs"] {
			if failure == "outputs" && restored_coinbases.is_empty() {
				continue;
			}
			let scanned_before = {
				wallet_inst!(wallet1, w);
				w.last_scanned_block()?
			};
			let original = client1.proxy_tx.lock().clone();
			let forward = original.clone();
			let reply = client1.tx.clone();
			let (sender, receiver) = std::sync::mpsc::channel();
			*client1.proxy_tx.lock() = sender;
			let relay = thread::spawn(move || {
				let mut queried_kernel = false;
				let mut queried_header = false;
				for mut message in receiver {
					let kernel = message.method == "get_kernel";
					queried_header |= message.method == "get_header_hash";
					let changed_tip =
						failure == "tip" && queried_kernel && message.method == "get_chain_tip";
					queried_kernel |= kernel;
					if (failure == "outputs"
						&& queried_header && message.method == "get_outputs_from_node")
						|| (failure == "kernel" && kernel)
						|| changed_tip || (matches!(failure, "header" | "header_chain")
						&& message.method == "get_header_hash")
					{
						message.body = if changed_tip {
							format!("{},changed-tip", bh)
						} else if failure == "header_chain" {
							serde_json::to_string(&Some("different-header")).unwrap()
						} else {
							"invalid response".to_owned()
						};
						reply.lock().send(message).unwrap();
					} else {
						forward.send(message).unwrap();
					}
				}
			});
			let mut observed = None;
			let result =
				api1.retrieve_txs(mask1, true, None, None, None)
					.map(|(refreshed, entries)| {
						for original in &restored_coinbases {
							let entry = entries.iter().find(|e| e.id == original.id).unwrap();
							assert_eq!(entry.confirmed_height, original.confirmed_height);
						}
						observed = entries
							.iter()
							.find(|e| e.kernel_excess == Some(tx.kernels()[0].excess))
							.map(|e| (refreshed, e.confirmed_height, e.last_known_kernel_height));
					});
			*client1.proxy_tx.lock() = original;
			relay.join().unwrap();
			result?;
			assert_eq!(observed, Some((false, Some(bh - 1), None)));
			let scanned_after = {
				wallet_inst!(wallet1, w);
				w.last_scanned_block()?
			};
			assert_eq!(scanned_after.height, scanned_before.height);
			assert_eq!(scanned_after.hash, scanned_before.hash);
		}
	}

	// Check reorgs across accounts and manual scans
	if relocate {
		api1.set_active_account(mask1, "default")?;
		if no_change {
			api1.scan(mask1, None, false)?;
		} else {
			assert!(api1.retrieve_txs(mask1, true, None, None, None)?.0);
		}
		api1.set_active_account(mask1, "a")?;
	}

	if !restored_coinbases.is_empty() {
		let (_, entries) = api1.retrieve_txs(mask1, false, None, None, None)?;
		for original in &restored_coinbases {
			let entry = entries.iter().find(|e| e.id == original.id).unwrap();
			assert_eq!(
				entry.confirmed_height,
				original.confirmed_height.filter(|h| *h == bh - 2)
			);
			assert_eq!(entry.confirmation_ts, original.confirmation_ts);
			assert_eq!(entry.confirmed, original.confirmed);
		}
	}

	// Repair heights through normal refresh
	for (index, ((wallet, mask), detected_at)) in [(&api1, mask1), (&api2, mask2)]
		.into_iter()
		.zip(detected)
		.enumerate()
	{
		let (refreshed, entries) = wallet.retrieve_txs(mask, true, None, None, None)?;
		assert!(refreshed);
		if index == 1 {
			if let Some(id) = restored {
				let entry = entries.iter().find(|e| e.id == id).unwrap();
				assert!(entry.confirmed);
				assert_eq!(entry.confirmed_height, Some(bh));
				assert_eq!(entry.last_known_kernel_height, None);
				assert_eq!(entry.confirmation_ts, detected_at);
				continue;
			}
		}
		let entry = entries
			.iter()
			.find(|e| e.kernel_excess == Some(tx.kernels()[0].excess))
			.unwrap();
		assert_eq!(
			entry.confirmed_height,
			if relocate { Some(bh) } else { None }
		);
		assert_eq!(
			entry.last_known_kernel_height,
			if relocate { None } else { Some(bh - 1) }
		);
		assert_eq!(entry.confirmation_ts, detected_at);
	}

	if !relocate {
		// Check funds have been reverted
		api2.scan(mask2, None, false)?;
		let (refreshed, info) = api2.retrieve_summary_info(mask2, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.last_confirmed_height, bh);
		assert_eq!(info.total, 0);
		assert_eq!(info.amount_currently_spendable, 0);
		assert_eq!(info.amount_reverted, sent);
		// check tx log as well
		let (_, txs) = api2.retrieve_txs(mask2, true, None, None, None)?;
		assert_eq!(txs.len(), 1);
		let tx = &txs[0];
		assert_eq!(tx.tx_type, libwallet::TxLogEntryType::TxReverted);
		assert!(!tx.confirmed);
		assert_eq!(tx.confirmed_height, None);
		assert!(tx.reverted_after.is_some());
	}
	if relocate {
		let known: Vec<_> = api1
			.retrieve_txs(mask1, false, None, None, None)?
			.1
			.into_iter()
			.filter(|tx| tx.confirmed && tx.confirmed_height.is_some())
			.filter_map(|tx| tx.kernel_excess)
			.map(|excess| excess.0.as_ref().to_hex())
			.collect();
		assert!(!known.is_empty());
		award_block_to_wallet(&chain, &[], wallet1.clone(), mask1)?;
		let requests = node_requests(&client1, || {
			assert!(api1.retrieve_txs(mask1, true, None, None, None)?.0);
			Ok(())
		})?;
		assert!(!requests.iter().any(|(method, body)| method == "get_kernel"
			&& known.iter().any(|excess| body.starts_with(excess))));
		assert_eq!(
			requests
				.iter()
				.filter(|(method, _)| method == "get_header_hash")
				.count(),
			2
		);
	}
	stopper2.store(false, Ordering::Relaxed);
	Ok((
		chain, stopper, sent, bh, tx, wallet1, mask1_i, wallet2, mask2_i, api1, api2,
	))
}

fn revert_reconfirm_impl(test_dir: &'static str, no_change: bool) -> Result<(), libwallet::Error> {
	let (chain, stopper, sent, bh, tx, wallet1, mask1_i, _wallet2, mask2_i, api1, api2) =
		revert(test_dir, false, no_change)?;
	let mask1 = mask1_i.as_ref();
	let mask2 = mask2_i.as_ref();

	let sender_detected = {
		let (_, entries) = api1.retrieve_txs(mask1, false, None, None, None)?;
		let entry = entries
			.iter()
			.find(|e| e.kernel_excess == Some(tx.kernels()[0].excess))
			.unwrap();
		assert_eq!(entry.confirmed_height, None);
		assert_eq!(entry.last_known_kernel_height, Some(bh - 1));
		let detected = entry.confirmation_ts;
		api1.close_wallet(None)?;
		api1.open_wallet(None, grin_util::ZeroingString::from(""), false)?;
		api1.set_active_account(None, "a")?;
		detected
	};
	let client = {
		wallet_inst!(wallet1, w);
		w.w2n_client().clone()
	};
	let requests = node_requests(&client, || {
		assert!(api1.retrieve_txs(mask1, true, None, None, None)?.0);
		Ok(())
	})?;
	assert!(!requests
		.iter()
		.any(|(method, _)| method == "get_kernel" || method == "get_header_hash"));
	let excess = tx.kernels()[0].excess;

	// Include the tx into the chain again, the tx should no longer be reverted
	award_block_to_wallet(&chain, &[tx], wallet1.clone(), mask1)?;

	let bh = bh + 1;

	{
		let (refreshed, entries) = api1.retrieve_txs(mask1, true, None, None, None)?;
		assert!(refreshed);
		let entry = entries
			.iter()
			.find(|e| e.kernel_excess == Some(excess))
			.unwrap();
		assert_eq!(entry.confirmed_height, Some(bh));
		assert_eq!(entry.last_known_kernel_height, None);
		assert_eq!(entry.confirmation_ts, sender_detected);
	}

	// Check funds have been confirmed again
	let (refreshed, info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert!(refreshed);
	assert_eq!(info.last_confirmed_height, bh);
	assert_eq!(info.total, sent);
	assert_eq!(info.amount_currently_spendable, sent);
	assert_eq!(info.amount_reverted, 0);
	// check tx log as well
	let (_, txs) = api2.retrieve_txs(mask2, true, None, None, None)?;
	assert_eq!(txs.len(), 1);
	let tx = &txs[0];
	assert_eq!(tx.tx_type, libwallet::TxLogEntryType::TxReceived);
	assert!(tx.confirmed);
	assert!(tx.reverted_after.is_none());
	assert_eq!(txs[0].confirmed_height, Some(bh));

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(1000));
	Ok(())
}

fn revert_cancel_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	let (_, stopper, sent, bh, _, _, _, wallet2, mask2_i, _api1, api2) =
		revert(test_dir, false, false)?;
	let mask2 = mask2_i.as_ref();

	// Sanity check
	let (refreshed, info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert!(refreshed);
	assert_eq!(info.last_confirmed_height, bh);
	assert_eq!(info.total, 0);
	assert_eq!(info.amount_currently_spendable, 0);
	assert_eq!(info.amount_reverted, sent);

	let (_, txs) = api2.retrieve_txs(mask2, true, None, None, None)?;
	assert_eq!(txs.len(), 1);
	let tx = &txs[0];

	// A shorter node tip requires an explicit scan before normal refresh resumes
	{
		wallet_inst!(wallet2, w);
		let mut scanned = w.last_scanned_block()?;
		scanned.height += 3;
		let mut batch = w.batch(mask2)?;
		batch.save_last_scanned_block(scanned)?;
		batch.commit()?;
	}
	assert!(!api2.retrieve_txs(mask2, true, None, None, None)?.0);
	api2.scan(mask2, Some(1), false)?;
	assert!(api2.retrieve_txs(mask2, true, None, None, None)?.0);

	// Cancel
	api2.cancel_tx(mask2, Some(tx.id), None)?;

	// Check updated summary info
	let (refreshed, info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert!(refreshed);
	assert_eq!(info.last_confirmed_height, bh);
	assert_eq!(info.total, 0);
	assert_eq!(info.amount_currently_spendable, 0);
	assert_eq!(info.amount_reverted, 0);

	// Check updated tx log
	let (_, txs) = api2.retrieve_txs(mask2, true, None, None, None)?;
	assert_eq!(txs.len(), 1);
	let tx = &txs[0];
	assert_eq!(tx.tx_type, libwallet::TxLogEntryType::TxReceivedCancelled);

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(1000));
	Ok(())
}

#[test]
fn tx_revert_reconfirm() {
	for (test_dir, no_change) in [
		("test_output/revert_tx", false),
		("test_output/revert_no_change", true),
	] {
		setup(test_dir);
		if let Err(e) = revert_reconfirm_impl(test_dir, no_change) {
			panic!("Libwallet Error: {}", e);
		}
		clean_output_dir(test_dir);
	}
}

#[test]
fn tx_revert_cancel() {
	let test_dir = "test_output/revert_tx_cancel";
	setup(test_dir);
	if let Err(e) = revert_cancel_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn tx_reorg_relocate() {
	for (test_dir, no_change) in [
		("test_output/relocate_tx", false),
		("test_output/relocate_no_change", true),
	] {
		setup(test_dir);
		let (_, stopper, _, _, _, _, _, _, _, _, _) = revert(test_dir, true, no_change).unwrap();
		stopper.store(false, Ordering::Relaxed);
		thread::sleep(Duration::from_millis(100));
		clean_output_dir(test_dir);
	}
}
