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

//! tests differing accounts in the same wallet
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_util as util;

use self::core::consensus;
use self::core::global;
use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use impls::{PathToSlate, SlatePutter as _};
use libwallet::{InitTxArgs, NodeClient};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use util::ZeroingString;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

macro_rules! send_to_dest {
	($a:expr, $m: expr, $b:expr, $c:expr, $d:expr) => {
		test_framework::send_to_dest($a, $m, $b, $c, $d, false)
	};
}

macro_rules! wallet_info {
	($a:expr, $m:expr) => {
		test_framework::wallet_info($a, $m)
	};
}

/// Various tests on checking functionality
fn scan_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
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
	let cm = global::coinbase_maturity() as u64; // assume all testing precedes soft fork height

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "named_account_1")?;
		api.create_account_path(m, "account_2")?;
		api.create_account_path(m, "account_3")?;
		api.set_active_account(m, "named_account_1")?;
		Ok(())
	})?;

	// add account to wallet 2
	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2, None, |api, m| {
		api.create_account_path(m, "account_1")?;
		api.set_active_account(m, "account_1")?;
		Ok(())
	})?;

	// Do some mining
	let bh = 20u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Sanity check contents
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward);
		assert_eq!(wallet1_info.amount_currently_spendable, (bh - cm) * reward);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		let (c, _) = libwallet::TxLogEntry::sum_confirmed(&txs);
		assert_eq!(wallet1_info.total, c);
		assert_eq!(txs.len(), bh as usize);
		Ok(())
	})?;

	// Accidentally delete some outputs
	let mut w1_outputs_commits = vec![];
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		w1_outputs_commits = api.retrieve_outputs(m, false, true, None)?.1;
		Ok(())
	})?;
	let w1_outputs: Vec<libwallet::OutputData> =
		w1_outputs_commits.into_iter().map(|m| m.output).collect();
	{
		wallet_inst!(wallet1, w);
		{
			let mut batch = w.batch(mask1)?;
			batch.delete(&w1_outputs[4].key_id, &None)?;
			batch.delete(&w1_outputs[10].key_id, &None)?;
			let mut accidental_spent = w1_outputs[13].clone();
			accidental_spent.status = libwallet::OutputStatus::Spent;
			batch.save(accidental_spent)?;
			batch.commit()?;
		}
	}

	// check we have a problem now
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		let (_, txs) = api.retrieve_txs(m, true, None, None)?;
		let (c, _) = libwallet::TxLogEntry::sum_confirmed(&txs);
		assert!(wallet1_info.total != c);
		Ok(())
	})?;

	// this should restore our missing outputs
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.scan(m, None, true)?;
		Ok(())
	})?;

	// check our outputs match again
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.total, bh * reward);
		// And check account names haven't been splatted
		let accounts = api.accounts(m)?;
		assert_eq!(accounts.len(), 4);
		assert!(api.set_active_account(m, "account_1").is_err());
		assert!(api.set_active_account(m, "named_account_1").is_ok());
		Ok(())
	})?;

	// perform a transaction, but don't let it finish
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// send to send
		let args = InitTxArgs {
			src_acct_name: None,
			amount: reward * 2,
			minimum_confirmations: cm,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate = api.init_send_tx(m, args)?;
		// output tx file
		let send_file = format!("{}/part_tx_1.tx", test_dir);
		PathToSlate(send_file.into()).put_tx(&slate)?;
		api.tx_lock_outputs(m, &slate, 0)?;
		Ok(())
	})?;

	// check we're all locked
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert!(wallet1_info.amount_currently_spendable == 0);
		Ok(())
	})?;

	// unlock/restore
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.scan(m, None, true)?;
		Ok(())
	})?;

	// check spendable amount again
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert_eq!(wallet1_info.amount_currently_spendable, (bh - cm) * reward);
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

fn two_wallets_one_seed_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	let seed_phrase = "affair pistol cancel crush garment candy ancient flag work \
	                   market crush dry stand focus mutual weapon offer ceiling rival turn team spring \
	                   where swift";
	let seed_phrase = Some(ZeroingString::from(seed_phrase));

	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	// Create a new wallet test client, and set its queues to communicate with the
	// proxy
	create_wallet_and_add!(
		m_client,
		miner,
		miner_mask_i,
		test_dir,
		"miner",
		None,
		&mut wallet_proxy,
		false
	);
	let miner_mask = (&miner_mask_i).as_ref();

	// non-mining recipient wallets
	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		seed_phrase,
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
		seed_phrase,
		&mut wallet_proxy,
		false
	);
	let mask2 = (&mask2_i).as_ref();
	// we'll restore into here
	create_wallet_and_add!(
		client3,
		wallet3,
		mask3_i,
		test_dir,
		"wallet3",
		seed_phrase,
		&mut wallet_proxy,
		false
	);
	let mask3 = (&mask3_i).as_ref();
	// also restore into here
	create_wallet_and_add!(
		client4,
		wallet4,
		mask4_i,
		test_dir,
		"wallet4",
		seed_phrase,
		&mut wallet_proxy,
		false
	);
	let mask4 = (&mask4_i).as_ref();
	// Simulate a recover from seed without restore into here
	create_wallet_and_add!(
		client5,
		wallet5,
		mask5_i,
		test_dir,
		"wallet5",
		seed_phrase,
		&mut wallet_proxy,
		false
	);
	//simulate a recover from seed without restore into here
	let mask5 = (&mask5_i).as_ref();
	create_wallet_and_add!(
		client6,
		wallet6,
		mask6_i,
		test_dir,
		"wallet6",
		seed_phrase,
		&mut wallet_proxy,
		false
	);
	let mask6 = (&mask6_i).as_ref();

	create_wallet_and_add!(
		client7,
		wallet7,
		mask7_i,
		test_dir,
		"wallet7",
		seed_phrase,
		&mut wallet_proxy,
		false
	);
	let mask7 = (&mask7_i).as_ref();
	create_wallet_and_add!(
		client8,
		wallet8,
		mask8_i,
		test_dir,
		"wallet8",
		seed_phrase,
		&mut wallet_proxy,
		false
	);
	let mask8 = (&mask8_i).as_ref();
	create_wallet_and_add!(
		client9,
		wallet9,
		mask9_i,
		test_dir,
		"wallet9",
		seed_phrase,
		&mut wallet_proxy,
		false
	);
	let mask9 = (&mask9_i).as_ref();
	create_wallet_and_add!(
		client10,
		wallet10,
		mask10_i,
		test_dir,
		"wallet10",
		seed_phrase,
		&mut wallet_proxy,
		false
	);
	let mask10 = (&mask10_i).as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let _reward = core::consensus::REWARD;
	let cm = global::coinbase_maturity() as usize; // assume all testing precedes soft fork height

	// Do some mining
	let mut bh = 20u64;
	let base_amount = consensus::GRIN_BASE;
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		miner.clone(),
		miner_mask,
		bh as usize,
		false,
	);

	// send some funds to wallets 1
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet1",
		base_amount * 1
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet1",
		base_amount * 2
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet1",
		base_amount * 3
	)?;
	bh += 3;

	// 0) Check repair when all is okay should leave wallet contents alone
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.scan(m, None, true)?;
		let info = wallet_info!(wallet1.clone(), m)?;
		assert_eq!(info.amount_currently_spendable, base_amount * 6);
		assert_eq!(info.total, base_amount * 6);
		Ok(())
	})?;

	// send some funds to wallet 2
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet2",
		base_amount * 4
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet2",
		base_amount * 5
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet2",
		base_amount * 6
	)?;
	bh += 3;

	let _ = test_framework::award_blocks_to_wallet(&chain, miner.clone(), miner_mask, cm, false);
	bh += cm as u64;

	// confirm balances
	// since info is now performing a partial scan, these should confirm
	// as containing all outputs
	let info = wallet_info!(wallet1.clone(), mask1)?;
	assert_eq!(info.amount_currently_spendable, base_amount * 21);
	assert_eq!(info.total, base_amount * 21);

	let info = wallet_info!(wallet2.clone(), mask2)?;
	assert_eq!(info.amount_currently_spendable, base_amount * 21);
	assert_eq!(info.total, base_amount * 21);

	// Now there should be outputs on the chain using the same
	// seed + BIP32 path.

	// 1) a full restore should recover all of them:
	wallet::controller::owner_single_use(Some(wallet3.clone()), mask3, None, |api, m| {
		api.scan(m, None, false)?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet3.clone()), mask3, None, |api, m| {
		let info = wallet_info!(wallet3.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 6);
		assert_eq!(info.amount_currently_spendable, base_amount * 21);
		assert_eq!(info.total, base_amount * 21);
		Ok(())
	})?;

	// 2) scan should recover them into a single wallet
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.scan(m, None, true)?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let info = wallet_info!(wallet1.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 6);
		assert_eq!(info.amount_currently_spendable, base_amount * 21);
		Ok(())
	})?;

	// 3) If I recover from seed and start using the wallet without restoring,
	// scan should restore the older outputs
	// update, again, since scan is run automatically, balances on both
	// wallets should turn out the same
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet4",
		base_amount * 7
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet4",
		base_amount * 8
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet4",
		base_amount * 9
	)?;
	bh += 3;

	let _ = test_framework::award_blocks_to_wallet(&chain, miner.clone(), miner_mask, cm, false);
	bh += cm as u64;

	wallet::controller::owner_single_use(Some(wallet4.clone()), mask4, None, |api, m| {
		let info = wallet_info!(wallet4.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 9);
		assert_eq!(info.amount_currently_spendable, base_amount * 45);
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet5.clone()), mask5, None, |api, m| {
		api.scan(m, None, false)?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet5.clone()), mask5, None, |api, m| {
		let info = wallet_info!(wallet5.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 9);
		assert_eq!(info.amount_currently_spendable, base_amount * (45));
		Ok(())
	})?;

	// 4) If I recover from seed and start using the wallet without restoring,
	// scan should restore the older outputs
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet6",
		base_amount * 10
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet6",
		base_amount * 11
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet6",
		base_amount * 12
	)?;
	bh += 3;

	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		miner.clone(),
		miner_mask,
		cm as usize,
		false,
	);
	bh += cm as u64;

	wallet::controller::owner_single_use(Some(wallet6.clone()), mask6, None, |api, m| {
		let info = wallet_info!(wallet6.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 12);
		assert_eq!(info.amount_currently_spendable, base_amount * 78);
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet6.clone()), mask6, None, |api, m| {
		api.scan(m, None, true)?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet6.clone()), mask6, None, |api, m| {
		let info = wallet_info!(wallet6.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 12);
		assert_eq!(info.amount_currently_spendable, base_amount * (78));
		Ok(())
	})?;

	// 5) Start using same seed with a different account, amounts should
	// be distinct and restore should return funds from other account

	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet7",
		base_amount * 13
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet7",
		base_amount * 14
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet7",
		base_amount * 15
	)?;
	bh += 3;

	// mix it up a bit
	wallet::controller::owner_single_use(Some(wallet7.clone()), mask7, None, |api, m| {
		api.create_account_path(m, "account_1")?;
		api.set_active_account(m, "account_1")?;
		Ok(())
	})?;

	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet7",
		base_amount * 1
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet7",
		base_amount * 2
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet7",
		base_amount * 3
	)?;
	bh += 3;

	// check balances
	let _ = test_framework::award_blocks_to_wallet(&chain, miner.clone(), miner_mask, cm, false);
	bh += cm as u64;

	wallet::controller::owner_single_use(Some(wallet7.clone()), mask7, None, |api, m| {
		let info = wallet_info!(wallet7.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 3);
		assert_eq!(info.amount_currently_spendable, base_amount * 6);
		api.set_active_account(m, "default")?;
		let info = wallet_info!(wallet7.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 15);
		assert_eq!(info.amount_currently_spendable, base_amount * 120);
		Ok(())
	})?;

	wallet::controller::owner_single_use(Some(wallet8.clone()), mask8, None, |api, m| {
		api.scan(m, None, false)?;
		let info = wallet_info!(wallet8.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 15);
		assert_eq!(info.amount_currently_spendable, base_amount * 120);
		api.set_active_account(m, "account_1")?;
		let info = wallet_info!(wallet8.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 3);
		assert_eq!(info.amount_currently_spendable, base_amount * 6);
		Ok(())
	})?;

	// 6) Start using same seed with a different account, now overwriting
	// ids on account 2 as well, scan should get all outputs created
	// to now into 2 accounts

	wallet::controller::owner_single_use(Some(wallet9.clone()), mask9, None, |api, m| {
		api.create_account_path(m, "account_1")?;
		api.set_active_account(m, "account_1")?;
		Ok(())
	})?;

	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet9",
		base_amount * 4
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet9",
		base_amount * 5
	)?;
	send_to_dest!(
		miner.clone(),
		miner_mask,
		m_client.clone(),
		"wallet9",
		base_amount * 6
	)?;
	bh += 3;
	let _bh = bh;

	wallet::controller::owner_single_use(Some(wallet9.clone()), mask9, None, |api, m| {
		let info = wallet_info!(wallet9.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 6);
		assert_eq!(info.amount_currently_spendable, base_amount * 21);
		api.scan(m, None, true)?;
		let info = wallet_info!(wallet9.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 6);
		assert_eq!(info.amount_currently_spendable, base_amount * 21);

		api.set_active_account(m, "default")?;
		let info = wallet_info!(wallet9.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 15);
		assert_eq!(info.amount_currently_spendable, base_amount * 120);
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, miner.clone(), miner_mask, cm, false);

	// 7) Ensure scan creates missing accounts
	wallet::controller::owner_single_use(Some(wallet10.clone()), mask10, None, |api, m| {
		api.scan(m, None, true)?;
		api.set_active_account(m, "account_1")?;
		let info = wallet_info!(wallet10.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 6);
		assert_eq!(info.amount_currently_spendable, base_amount * 21);

		api.set_active_account(m, "default")?;
		let info = wallet_info!(wallet10.clone(), m)?;
		let outputs = api.retrieve_outputs(m, true, false, None)?.1;
		assert_eq!(outputs.len(), 15);
		assert_eq!(info.amount_currently_spendable, base_amount * 120);
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

// Testing output scanning functionality, easier here as the testing framework
// is all here
fn output_scanning_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
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
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Do some mining
	let bh = 20u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Now some chain scanning
	{
		// Entire range should be correct
		let ranges = client1.height_range_to_pmmr_indices(1, None)?;
		assert_eq!(ranges, (1, 38));
		let outputs = client1.get_outputs_by_pmmr_index(ranges.0, Some(ranges.1), 1000)?;
		assert_eq!(outputs.2.len(), 20);

		// Basic range should be correct
		let ranges = client1.height_range_to_pmmr_indices(1, Some(14))?;
		assert_eq!(ranges, (1, 25));
		let outputs = client1.get_outputs_by_pmmr_index(ranges.0, Some(ranges.1), 1000)?;
		println!(
			"Last Index: {}, Max: {}, Outputs.len: {}",
			outputs.0,
			outputs.1,
			outputs.2.len()
		);
		assert_eq!(outputs.2.len(), 14);

		// mid range
		let ranges = client1.height_range_to_pmmr_indices(5, Some(14))?;
		assert_eq!(ranges, (8, 25));
		let outputs = client1.get_outputs_by_pmmr_index(ranges.0, Some(ranges.1), 1000)?;
		println!(
			"Last Index: {}, Max: {}, Outputs.len: {}",
			outputs.0,
			outputs.1,
			outputs.2.len()
		);
		for o in outputs.2.clone() {
			println!("height: {}, mmr_index: {}", o.3, o.4);
		}
		assert_eq!(outputs.2.len(), 10);

		// end
		let ranges = client1.height_range_to_pmmr_indices(5, None)?;
		assert_eq!(ranges, (8, 38));
		let outputs = client1.get_outputs_by_pmmr_index(ranges.0, Some(ranges.1), 1000)?;
		println!(
			"Last Index: {}, Max: {}, Outputs.len: {}",
			outputs.0,
			outputs.1,
			outputs.2.len()
		);
		for o in outputs.2.clone() {
			println!("height: {}, mmr_index: {}", o.3, o.4);
		}
		assert_eq!(outputs.2.len(), 16);
	}

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn scan() {
	let test_dir = "test_output/scan";
	setup(test_dir);
	if let Err(e) = scan_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}

#[test]
fn two_wallets_one_seed() {
	let test_dir = "test_output/two_wallets_one_seed";
	setup(test_dir);
	if let Err(e) = two_wallets_one_seed_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}

#[test]
fn output_scanning() {
	let test_dir = "test_output/output_scanning";
	setup(test_dir);
	if let Err(e) = output_scanning_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	clean_output_dir(test_dir);
}
