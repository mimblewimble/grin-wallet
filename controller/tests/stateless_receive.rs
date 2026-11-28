// Copyright 2026 The Grin Developers
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

//! Tests for the opt-in stateless receive mode of the Foreign API
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;

use grin_core as core;
use grin_keychain as keychain;
use grin_util as util;

use self::core::core::hash::Hashed;
use self::core::global;
use self::keychain::{ExtKeychain, Keychain};
use self::libwallet::{
	InitTxArgs, OutputStatus, Slate, SlateState, StatelessReceiveConfig, TxLogEntryType,
};
use impls::test_framework::{self, LocalWalletClient};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use util::ZeroingString;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

const STATELESS: Option<StatelessReceiveConfig> = Some(StatelessReceiveConfig {
	enabled: true,
	min_amount: None,
});

fn stateless_receive_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	let seed_phrase = "affair pistol cancel crush garment candy ancient flag work \
	                   market crush dry stand focus mutual weapon offer ceiling rival turn team spring \
	                   where swift";
	let seed_phrase = Some(ZeroingString::from(seed_phrase));
	let no_seed: Option<ZeroingString> = None;

	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	// sender
	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		no_seed,
		&mut wallet_proxy,
		false,
		api1
	);
	let mask1 = (&mask1_i).as_ref();
	// stateless recipient
	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		seed_phrase,
		&mut wallet_proxy,
		false,
		api2
	);
	let mask2 = (&mask2_i).as_ref();
	// same seed as the recipient, restored from the chain later on
	create_wallet_and_add!(
		client3,
		wallet3,
		mask3_i,
		test_dir,
		"wallet3",
		seed_phrase,
		&mut wallet_proxy,
		false,
		api3
	);
	let mask3 = (&mask3_i).as_ref();
	let _ = (&client1, &client2, &client3);

	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	api2.create_account_path(mask2, "named")?;
	{
		// Exercise an embedded receiver on a fresh wallet marker while
		// retaining a known seed for the separate restoration fixture.
		wallet_inst!(wallet2, w);
		let mut batch = w.batch(mask2)?;
		batch.save_init_status(libwallet::WalletInitStatus::InitNoScanning)?;
		batch.commit()?;
	}
	let default_acct = ExtKeychain::derive_key_id(2, 0, 0, 0, 0);
	let named_acct = ExtKeychain::derive_key_id(2, 1, 0, 0, 0);

	let cm = global::coinbase_maturity();
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		cm as usize + 5,
		false,
	);

	let amount = 2_000_000_000;
	let send_args = InitTxArgs {
		src_acct_name: None,
		amount,
		minimum_confirmations: 1,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: false,
		..Default::default()
	};

	// State of the recipient as far as the database is concerned
	macro_rules! recipient_is_empty {
		() => {{
			let (_, txs) = api2.retrieve_txs(mask2, false, None, None, None)?;
			assert!(txs.is_empty(), "unexpected tx log entries: {:?}", txs);
			for acct in &["default", "named"] {
				api2.set_active_account(mask2, acct)?;
				let (_, outputs) = api2.retrieve_outputs(mask2, true, false, None)?;
				assert!(outputs.is_empty(), "unexpected outputs: {:?}", outputs);
			}
			api2.set_active_account(mask2, "default")?;
			wallet_inst!(wallet2, w);
			assert_eq!(w.current_child_index(&default_acct)?, 0);
			assert_eq!(w.current_child_index(&named_acct)?, 0);
		}};
	}

	// 1) An exchange the sender never finalizes leaves nothing behind
	{
		let slate_i = api1.init_send_tx(mask1, send_args.clone())?;
		assert_eq!(slate_i.state, SlateState::Standard1);

		let mut responses: Vec<Slate> = vec![];
		wallet::controller::foreign_single_use(
			wallet2.clone(),
			PathBuf::from(test_dir),
			mask2_i.clone(),
			|api| {
				api.set_stateless_receive(STATELESS);
				// with no state there is no duplicate check, each call builds
				// a response around a fresh output
				responses.push(api.receive_tx(&slate_i, None, None)?);
				responses.push(api.receive_tx(&slate_i, None, None)?);

				// requests below the configured minimum are refused outright
				api.set_stateless_receive(Some(StatelessReceiveConfig {
					enabled: true,
					min_amount: Some(amount + 1),
				}));
				assert_eq!(
					api.receive_tx(&slate_i, None, None).unwrap_err(),
					libwallet::Error::ReceiveAmountTooLow {
						amount,
						minimum: amount + 1
					}
				);

				// as are the requests the stateful path refuses
				api.set_stateless_receive(STATELESS);
				let mut zero_amount = slate_i.clone();
				zero_amount.amount = 0;
				assert_eq!(
					api.receive_tx(&zero_amount, None, None).unwrap_err(),
					libwallet::Error::InvalidAmount
				);
				let mut wrong_state = slate_i.clone();
				wrong_state.state = SlateState::Invoice1;
				assert_eq!(
					api.receive_tx(&wrong_state, None, None).unwrap_err(),
					libwallet::Error::SlateState
				);
				Ok(())
			},
		)?;

		assert_eq!(responses.len(), 2);
		let commits: Vec<_> = responses
			.iter()
			.map(|s| {
				assert_eq!(s.state, SlateState::Standard2);
				let tx = s.tx_or_err().unwrap();
				assert_eq!(tx.outputs().len(), 1);
				tx.outputs()[0].commitment()
			})
			.collect();
		assert_ne!(commits[0], commits[1]);
		{
			wallet_inst!(wallet2, w);
			assert!(matches!(
				w.init_status()?,
				libwallet::WalletInitStatus::InitNeedsScanning
			));
			assert!(w.last_scanned_block()?.hash.is_empty());
		}

		recipient_is_empty!();

		// the sender gives up (it locked nothing, so has nothing to cancel)
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
		let (refreshed, info) = api2.retrieve_summary_info(mask2, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.total, 0);
		{
			wallet_inst!(wallet2, w);
			assert!(matches!(
				w.init_status()?,
				libwallet::WalletInitStatus::InitComplete
			));
			assert!(!w.last_scanned_block()?.hash.is_empty());
		}
		recipient_is_empty!();
	}

	// 2) A finalized exchange shows up once it is on chain
	let commit_default = {
		let slate_i = api1.init_send_tx(mask1, send_args.clone())?;
		let mut slate = Slate::blank(2, false);
		wallet::controller::foreign_single_use(
			wallet2.clone(),
			PathBuf::from(test_dir),
			mask2_i.clone(),
			|api| {
				api.set_stateless_receive(STATELESS);
				slate = api.receive_tx(&slate_i, None, None)?;
				Ok(())
			},
		)?;
		assert_eq!(slate.state, SlateState::Standard2);
		let commit = slate.tx_or_err()?.outputs()[0].commitment();

		api1.tx_lock_outputs(mask1, &slate)?;
		let slate = api1.finalize_tx(mask1, &slate)?;
		assert_eq!(slate.state, SlateState::Standard3);

		// still nothing until the transaction is mined
		recipient_is_empty!();

		api1.post_tx(mask1, &slate, false)?;
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
		commit
	};

	// and into a named account
	let commit_named = {
		let slate_i = api1.init_send_tx(mask1, send_args.clone())?;
		let mut slate = Slate::blank(2, false);
		wallet::controller::foreign_single_use(
			wallet2.clone(),
			PathBuf::from(test_dir),
			mask2_i.clone(),
			|api| {
				api.set_stateless_receive(STATELESS);
				slate = api.receive_tx(&slate_i, Some("named"), None)?;
				Ok(())
			},
		)?;
		let commit = slate.tx_or_err()?.outputs()[0].commitment();
		api1.tx_lock_outputs(mask1, &slate)?;
		let slate = api1.finalize_tx(mask1, &slate)?;
		api1.post_tx(mask1, &slate, false)?;
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
		commit
	};

	// What a wallet holding the recipient's seed should see, whether it took
	// part in the exchange or not
	macro_rules! check_recipient {
		($api:ident, $mask:ident, $wallet:ident $(, $extra:expr)?) => {{
			let accounts = $api.accounts($mask)?;
			let mut paths: Vec<_> = accounts.iter().map(|a| a.path.clone()).collect();
			paths.sort();
			let mut expected = vec![default_acct.clone(), named_acct.clone() $(, $extra.clone())?];
			expected.sort();
			assert_eq!(paths, expected, "accounts: {:?}", accounts);
			for (acct, acct_path, commit) in &[
				("default", &default_acct, &commit_default),
				(
					accounts
						.iter()
						.find(|a| a.path == named_acct)
						.map(|a| a.label.as_str())
						.unwrap(),
					&named_acct,
					&commit_named,
				),
			] {
				$api.set_active_account($mask, acct)?;
				let (refreshed, info) = $api.retrieve_summary_info($mask, true, 1)?;
				assert!(refreshed);
				assert_eq!(info.total, amount);
				assert_eq!(info.amount_currently_spendable, amount);

				let (_, outputs) = $api.retrieve_outputs($mask, false, false, None)?;
				assert_eq!(outputs.len(), 1);
				let o = &outputs[0];
				assert_eq!(o.commit, **commit);
				assert_eq!(o.output.status, OutputStatus::Unspent);
				assert_eq!(o.output.value, amount);
				assert_eq!(&o.output.root_key_id, *acct_path);
				assert!(libwallet::is_stateless_receive_key_id(&o.output.key_id));
				assert_eq!(
					&libwallet::output_parent_key_id(&o.output.key_id),
					*acct_path
				);

				let (_, txs) = $api.retrieve_txs($mask, false, None, None, None)?;
				assert_eq!(txs.len(), 1);
				assert_eq!(txs[0].tx_type, TxLogEntryType::TxReceived);
				assert!(txs[0].confirmed);
				assert_eq!(txs[0].amount_credited, amount);

				// sequential derivation is left where it was
				wallet_inst!($wallet, w);
				assert_eq!(w.current_child_index(acct_path)?, 0);
			}
			$api.set_active_account($mask, "default")?;
		}};
	}

	// the regular update picks the outputs up
	check_recipient!(api2, mask2, wallet2);
	// a full scan changes nothing
	api2.scan(mask2, None, true)?;
	check_recipient!(api2, mask2, wallet2);

	// 3) Recover both a missing output and an older imported receipt whose
	// account metadata was never committed. A separately named account
	// already uses the label the old scanner would have picked.
	let unrelated = ExtKeychain::derive_key_id(2, 7, 0, 0, 0);
	api2.set_active_account(mask2, "named")?;
	let (_, outputs) = api2.retrieve_outputs(mask2, false, false, None)?;
	let mut restored = outputs[0].output.clone();
	let (_, receipts) = api2.retrieve_txs(mask2, false, None, None, None)?;
	let mut receipt = receipts[0].clone();
	{
		wallet_inst!(wallet3, w);
		let mut batch = w.batch(mask3)?;
		let id = batch.next_tx_log_id(&named_acct)?;
		receipt.id = id;
		restored.tx_log_entry = Some(id);
		restored.stateless_origin.as_mut().unwrap().receipt_id = Some(id);
		batch.save_tx_log_entry(receipt, &named_acct)?;
		batch.save(restored.clone())?;
		batch.save_acct_path(libwallet::AcctPathMapping {
			label: "account_2".to_owned(),
			path: unrelated.clone(),
		})?;
		// Simulate a sequential child already recorded but absent from UTXO.
		// Its old next-child index must still be repaired.
		let mut spent = restored;
		spent.root_key_id = unrelated.clone();
		spent.key_id = ExtKeychain::derive_key_id(3, 7, 0, 10, 0);
		spent.n_child = 10;
		spent.mmr_index = None;
		spent.commit = None;
		spent.status = OutputStatus::Spent;
		spent.tx_log_entry = None;
		spent.stateless_origin = None;
		batch.save(spent)?;
		batch.save_child_index(&unrelated, 5)?;
		batch.commit()?;
		assert_eq!(w.current_child_index(&unrelated)?, 5);
	}
	api2.set_active_account(mask2, "default")?;
	api3.scan(mask3, None, true)?;
	check_recipient!(api3, mask3, wallet3, unrelated);
	{
		wallet_inst!(wallet3, w);
		assert_eq!(
			w.get_acct_path("account_2".to_owned())?.unwrap().path,
			unrelated
		);
		assert_eq!(w.current_child_index(&unrelated)?, 11);
		let mut batch = w.batch(mask3)?;
		batch.save_child_index(&unrelated, 25)?;
		batch.commit()?;
	}
	api3.scan(mask3, None, true)?;
	check_recipient!(api3, mask3, wallet3, unrelated);
	{
		wallet_inst!(wallet3, w);
		assert_eq!(w.current_child_index(&unrelated)?, 25);
	}

	// 4) The received output can be spent
	{
		let common_tip = chain.head_header().unwrap();
		let fork_dir = format!("{test_dir}/outgoing_fork");
		let fork = create_wallet_proxy(&fork_dir).chain.clone();
		for height in 1..=common_tip.height {
			let header = chain.get_header_by_height(height).unwrap();
			test_framework::process_block(&fork, chain.get_block(&header.hash()).unwrap());
		}
		assert_eq!(fork.head_header().unwrap().hash(), common_tip.hash());

		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount / 2,
			minimum_confirmations: 1,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = api2.init_send_tx(mask2, args)?;
		let slate = client2.send_tx_slate_direct("wallet1", &slate_i)?;
		api2.tx_lock_outputs(mask2, &slate)?;
		let slate = api2.finalize_tx(mask2, &slate)?;
		let spend_id = slate.id;
		let outgoing = std::slice::from_ref(slate.tx_or_err()?);
		// Mine to wallet1 so that wallet2's balance only contains the payment
		// under test and its change.
		test_framework::award_block_to_wallet(&chain, outgoing, wallet1.clone(), mask1)?;
		let (refreshed, outputs) = api2.retrieve_outputs(mask2, true, true, None)?;
		assert!(refreshed);
		let spent = outputs
			.iter()
			.find(|o| o.commit == commit_default)
			.expect("received output");
		assert_eq!(spent.output.status, OutputStatus::Spent);
		let receipt_id = spent
			.output
			.stateless_origin
			.as_ref()
			.and_then(|origin| origin.receipt_id);
		assert!(
			receipt_id.is_some(),
			"the outgoing lock preserved the original receipt"
		);
		let (_, receipt) = api2.retrieve_txs(mask2, false, receipt_id, None, None)?;
		assert_eq!(receipt.len(), 1);
		assert_eq!(receipt[0].tx_type, TxLogEntryType::TxReceived);
		assert!(
			receipt[0].confirmed,
			"a real spend does not revoke the receipt"
		);
		let fee = slate.fee_fields.fee();
		let change = outputs
			.iter()
			.find(|o| !o.output.is_coinbase && o.output.status == OutputStatus::Unspent)
			.expect("change output");
		assert_eq!(change.output.value, amount - amount / 2 - fee);
		// change came from the regular sequential range
		assert_eq!(change.output.key_id.to_path().depth, 3);
		assert_eq!(change.output.n_child, 0);
		let change_commit = change.commit;
		let (_, outgoing_entry) = api2.retrieve_txs(mask2, false, None, Some(spend_id), None)?;
		assert_eq!(outgoing_entry.len(), 1);
		assert_eq!(outgoing_entry[0].tx_type, TxLogEntryType::TxSent);
		assert!(outgoing_entry[0].confirmed);

		// 5) Replace the spending block while keeping the original payment.
		// The returned input remains reserved until the sender either cancels
		// the outgoing transaction or sees it confirmed again.
		let check_reverted_spend = || -> Result<(), libwallet::Error> {
			let fork_height = fork.head_header().unwrap().height;
			test_framework::award_blocks_to_wallet(&fork, wallet1.clone(), mask1, 2, false)?;
			for height in fork_height + 1..=fork_height + 2 {
				let header = fork.get_header_by_height(height).unwrap();
				test_framework::process_block(&chain, fork.get_block(&header.hash()).unwrap());
			}
			assert_eq!(
				chain.head_header().unwrap().hash(),
				fork.head_header().unwrap().hash()
			);
			assert_eq!(
				chain
					.get_header_by_height(common_tip.height)
					.unwrap()
					.hash(),
				common_tip.hash(),
			);
			assert!(chain.get_unspent(commit_default).unwrap().is_some());
			assert!(chain.get_unspent(change_commit).unwrap().is_none());
			let (refreshed, info) = api2.retrieve_summary_info(mask2, true, 1)?;
			assert!(refreshed);
			assert_eq!(
				info.amount_currently_spendable, 0,
				"removed change is not available"
			);
			assert_eq!(info.amount_locked, amount, "the returned input is reserved");

			let (_, entries) = api2.retrieve_txs(mask2, false, None, Some(spend_id), None)?;
			assert_eq!(entries.len(), 1);
			assert_eq!(entries[0].tx_type, TxLogEntryType::TxSent);
			assert!(!entries[0].confirmed);
			let (_, receipts) = api2.retrieve_txs(mask2, false, receipt_id, None, None)?;
			assert_eq!(receipts.len(), 1);
			assert!(
				receipts[0].confirmed,
				"the incoming payment remains canonical"
			);
			let (_, outputs) = api2.retrieve_outputs(mask2, true, false, None)?;
			let input = outputs
				.iter()
				.find(|row| row.commit == commit_default)
				.unwrap();
			assert_eq!(input.output.status, OutputStatus::Locked);
			assert_eq!(input.output.stateless_absence(), None);
			assert!(!outputs.iter().any(|row| {
				row.commit == change_commit
					&& row.output.eligible_to_spend(info.last_confirmed_height, 1)
			}));
			Ok(())
		};
		check_reverted_spend()?;

		test_framework::award_block_to_wallet(&chain, outgoing, wallet1.clone(), mask1)?;
		let (refreshed, info) = api2.retrieve_summary_info(mask2, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.amount_currently_spendable, change.output.value);
		let (_, outgoing_entry) = api2.retrieve_txs(mask2, false, None, Some(spend_id), None)?;
		assert_eq!(outgoing_entry.len(), 1);
		assert!(outgoing_entry[0].confirmed, "the spend was included again");

		check_reverted_spend()?;
		api2.cancel_tx(mask2, None, Some(spend_id))?;
		let (_, info) = api2.retrieve_summary_info(mask2, false, 1)?;
		assert_eq!(info.amount_currently_spendable, amount);
		assert_eq!(info.amount_locked, 0);
		let (_, receipts) = api2.retrieve_txs(mask2, false, receipt_id, None, None)?;
		assert_eq!(receipts.len(), 1);
		assert!(receipts[0].confirmed);
		let (_, outgoing_entry) = api2.retrieve_txs(mask2, false, None, Some(spend_id), None)?;
		assert_eq!(outgoing_entry.len(), 1);
		assert_eq!(outgoing_entry[0].tx_type, TxLogEntryType::TxSentCancelled);
	}

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn stateless_receive() {
	let test_dir = "test_output/stateless_receive";
	setup(test_dir);
	if let Err(e) = stateless_receive_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn fresh_listener_persists_full_first_scan_before_receiving() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/stateless_initial_scan";
	setup(test_dir);
	{
		let proxy = create_wallet_proxy(test_dir);
		let client = LocalWalletClient::new("fresh", proxy.tx.clone());
		let (wallet, mask, api) =
			common::create_local_wallet(test_dir, "fresh", None, client.clone(), false);
		{
			wallet_inst!(wallet, w);
			assert!(matches!(
				w.init_status()?,
				libwallet::WalletInitStatus::InitNoScanning
			));
			w.prepare_stateless_receive(mask.as_ref())?;
			// Repeated listener startup does not advance the scan cursor.
			w.prepare_stateless_receive(mask.as_ref())?;
		}
		api.close_wallet(None)?;
		drop(api);
		drop(wallet);
		let (wallet, _) = common::open_local_wallet(test_dir, "fresh", client, false);
		wallet_inst!(wallet, w);
		assert!(matches!(
			w.init_status()?,
			libwallet::WalletInitStatus::InitNeedsScanning
		));
		assert_eq!(w.last_scanned_block()?.height, 0);
	}
	clean_output_dir(test_dir);
	Ok(())
}
