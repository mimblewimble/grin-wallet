// Copyright 2018 The Grin Developers
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
use libwallet::InitTxArgs;
use util::ZeroingString;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{setup, create_wallet_proxy};

macro_rules! send_to_dest {
	($a:expr, $b:expr, $c:expr, $d:expr) => {
		test_framework::send_to_dest($a, $b, $c, $d, false)
	};
}

macro_rules! wallet_info {
	($a:expr) => {
		test_framework::wallet_info($a)
	};
}

/// Various tests on checking functionality
fn check_repair_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	setup(test_dir);

	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();

	// Create a new wallet test client, and set its queues to communicate with the
	// proxy
	create_wallet_and_add!(client1, wallet1, test_dir, "wallet1", None, &mut wallet_proxy);
	create_wallet_and_add!(client2, wallet2, test_dir, "wallet2", None, &mut wallet_proxy);

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
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		api.create_account_path("account_1")?;
		api.create_account_path("account_2")?;
		api.create_account_path("account_3")?;
		api.set_active_account("account_1")?;
		Ok(())
	})?;

	// add account to wallet 2
	wallet::controller::owner_single_use(wallet2.clone(), |api| {
		api.create_account_path("account_1")?;
		api.set_active_account("account_1")?;
		Ok(())
	})?;

	// Do some mining
	let bh = 20u64;
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), bh as usize, false);

	// Sanity check contents
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward);
		assert_eq!(wallet1_info.amount_currently_spendable, (bh - cm) * reward);
		// check tx log as well
		let (_, txs) = api.retrieve_txs(true, None, None)?;
		let (c, _) = libwallet::TxLogEntry::sum_confirmed(&txs);
		assert_eq!(wallet1_info.total, c);
		assert_eq!(txs.len(), bh as usize);
		Ok(())
	})?;

	// Accidentally delete some outputs
	let mut w1_outputs_commits = vec![];
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		w1_outputs_commits = api.retrieve_outputs(false, true, None)?.1;
		Ok(())
	})?;
	let w1_outputs: Vec<libwallet::OutputData> =
		w1_outputs_commits.into_iter().map(|m| m.output).collect();
	{
		wallet_inst!(wallet1, w);
		{
			let mut batch = w.batch()?;
			batch.delete(&w1_outputs[4].key_id, &None)?;
			batch.delete(&w1_outputs[10].key_id, &None)?;
			let mut accidental_spent = w1_outputs[13].clone();
			accidental_spent.status = libwallet::OutputStatus::Spent;
			batch.save(accidental_spent)?;
			batch.commit()?;
		}
	}

	// check we have a problem now
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let (_, wallet1_info) = api.retrieve_summary_info(true, 1)?;
		let (_, txs) = api.retrieve_txs(true, None, None)?;
		let (c, _) = libwallet::TxLogEntry::sum_confirmed(&txs);
		assert!(wallet1_info.total != c);
		Ok(())
	})?;

	// this should restore our missing outputs
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		api.check_repair(true)?;
		Ok(())
	})?;

	// check our outputs match again
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.total, bh * reward);
		Ok(())
	})?;

	// perform a transaction, but don't let it finish
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
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
		let slate = api.init_send_tx(args)?;
		// output tx file
		let send_file = format!("{}/part_tx_1.tx", test_dir);
		PathToSlate(send_file.into()).put_tx(&slate)?;
		api.tx_lock_outputs(&slate, 0)?;
		Ok(())
	})?;

	// check we're all locked
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let (_, wallet1_info) = api.retrieve_summary_info(true, 1)?;
		assert!(wallet1_info.amount_currently_spendable == 0);
		Ok(())
	})?;

	// unlock/restore
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		api.check_repair(true)?;
		Ok(())
	})?;

	// check spendable amount again
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let (_, wallet1_info) = api.retrieve_summary_info(true, 1)?;
		assert_eq!(wallet1_info.amount_currently_spendable, (bh - cm) * reward);
		Ok(())
	})?;

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

fn two_wallets_one_seed_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	setup(test_dir);
	let seed_phrase = "affair pistol cancel crush garment candy ancient flag work \
	                   market crush dry stand focus mutual weapon offer ceiling rival turn team spring \
	                   where swift";
	let seed_phrase = Some(ZeroingString::from(seed_phrase));

	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();

	// Create a new wallet test client, and set its queues to communicate with the
	// proxy
	create_wallet_and_add!(m_client, miner, test_dir, "miner", None, &mut wallet_proxy);

	// non-mining recipient wallets
	create_wallet_and_add!(client1, wallet1, test_dir, "wallet1", seed_phrase, &mut wallet_proxy);
	create_wallet_and_add!(client2, wallet2, test_dir, "wallet2", seed_phrase, &mut wallet_proxy);
	// we'll restore into here
	create_wallet_and_add!(client3, wallet3, test_dir, "wallet3", seed_phrase, &mut wallet_proxy);
	// also restore into here
	create_wallet_and_add!(client4, wallet4, test_dir, "wallet4", seed_phrase, &mut wallet_proxy);
	// Simulate a recover from seed without restore into here
	create_wallet_and_add!(client5, wallet5, test_dir, "wallet5", seed_phrase, &mut wallet_proxy);
	//simulate a recover from seed without restore into here
	create_wallet_and_add!(client6, wallet6, test_dir, "wallet6", seed_phrase, &mut wallet_proxy);

	create_wallet_and_add!(client7, wallet7, test_dir, "wallet7", seed_phrase, &mut wallet_proxy);
	create_wallet_and_add!(client8, wallet8, test_dir, "wallet8", seed_phrase, &mut wallet_proxy);
	create_wallet_and_add!(client9, wallet9, test_dir, "wallet9", seed_phrase, &mut wallet_proxy);
	create_wallet_and_add!(client10, wallet10, test_dir, "wallet10", seed_phrase, &mut wallet_proxy);
	
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
	let _ = test_framework::award_blocks_to_wallet(&chain, miner.clone(), bh as usize, false);

	// send some funds to wallets 1
	test_framework::send_to_dest(miner.clone(), m_client.clone(), "wallet1", base_amount * 1, false)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet1", base_amount * 2)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet1", base_amount * 3)?;
	bh += 3;

	// 0) Check repair when all is okay should leave wallet contents alone
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		api.check_repair(true)?;
		let info = wallet_info!(wallet1.clone())?;
		assert_eq!(info.amount_currently_spendable, base_amount * 6);
		assert_eq!(info.total, base_amount * 6);
		Ok(())
	})?;

	// send some funds to wallet 2
	send_to_dest!(miner.clone(), m_client.clone(), "wallet2", base_amount * 4)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet2", base_amount * 5)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet2", base_amount * 6)?;
	bh += 3;

	let _ = test_framework::award_blocks_to_wallet(&chain, miner.clone(), cm, false);
	bh += cm as u64;

	// confirm balances
	let info = wallet_info!(wallet1.clone())?;
	assert_eq!(info.amount_currently_spendable, base_amount * 6);
	assert_eq!(info.total, base_amount * 6);

	let info = wallet_info!(wallet2.clone())?;
	assert_eq!(info.amount_currently_spendable, base_amount * 15);
	assert_eq!(info.total, base_amount * 15);

	// Now there should be outputs on the chain using the same
	// seed + BIP32 path.

	// 1) a full restore should recover all of them:
	wallet::controller::owner_single_use(wallet3.clone(), |api| {
		api.restore()?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(wallet3.clone(), |api| {
		let info = wallet_info!(wallet3.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 6);
		assert_eq!(info.amount_currently_spendable, base_amount * 21);
		assert_eq!(info.total, base_amount * 21);
		Ok(())
	})?;

	// 2) check_repair should recover them into a single wallet
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		api.check_repair(true)?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let info = wallet_info!(wallet1.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 6);
		assert_eq!(info.amount_currently_spendable, base_amount * 21);
		Ok(())
	})?;

	// 3) If I recover from seed and start using the wallet without restoring,
	// check_repair should restore the older outputs
	send_to_dest!(miner.clone(), m_client.clone(), "wallet4", base_amount * 7)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet4", base_amount * 8)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet4", base_amount * 9)?;
	bh += 3;

	let _ = test_framework::award_blocks_to_wallet(&chain, miner.clone(), cm, false);
	bh += cm as u64;

	wallet::controller::owner_single_use(wallet4.clone(), |api| {
		let info = wallet_info!(wallet4.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 3);
		assert_eq!(info.amount_currently_spendable, base_amount * 24);
		Ok(())
	})?;

	wallet::controller::owner_single_use(wallet5.clone(), |api| {
		api.restore()?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(wallet5.clone(), |api| {
		let info = wallet_info!(wallet5.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 9);
		assert_eq!(info.amount_currently_spendable, base_amount * (45));
		Ok(())
	})?;

	// 4) If I recover from seed and start using the wallet without restoring,
	// check_repair should restore the older outputs
	send_to_dest!(miner.clone(), m_client.clone(), "wallet6", base_amount * 10)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet6", base_amount * 11)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet6", base_amount * 12)?;
	bh += 3;

	let _ = test_framework::award_blocks_to_wallet(&chain, miner.clone(), cm as usize, false);
	bh += cm as u64;

	wallet::controller::owner_single_use(wallet6.clone(), |api| {
		let info = wallet_info!(wallet6.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 3);
		assert_eq!(info.amount_currently_spendable, base_amount * 33);
		Ok(())
	})?;

	wallet::controller::owner_single_use(wallet6.clone(), |api| {
		api.check_repair(true)?;
		Ok(())
	})?;

	wallet::controller::owner_single_use(wallet6.clone(), |api| {
		let info = wallet_info!(wallet6.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 12);
		assert_eq!(info.amount_currently_spendable, base_amount * (78));
		Ok(())
	})?;

	// 5) Start using same seed with a different account, amounts should
	// be distinct and restore should return funds from other account

	send_to_dest!(miner.clone(), m_client.clone(), "wallet7", base_amount * 13)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet7", base_amount * 14)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet7", base_amount * 15)?;
	bh += 3;

	// mix it up a bit
	wallet::controller::owner_single_use(wallet7.clone(), |api| {
		api.create_account_path("account_1")?;
		api.set_active_account("account_1")?;
		Ok(())
	})?;

	send_to_dest!(miner.clone(), m_client.clone(), "wallet7", base_amount * 1)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet7", base_amount * 2)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet7", base_amount * 3)?;
	bh += 3;

	// check balances
	let _ = test_framework::award_blocks_to_wallet(&chain, miner.clone(), cm, false);
	bh += cm as u64;

	wallet::controller::owner_single_use(wallet7.clone(), |api| {
		let info = wallet_info!(wallet7.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 3);
		assert_eq!(info.amount_currently_spendable, base_amount * 6);
		api.set_active_account("default")?;
		let info = wallet_info!(wallet7.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 3);
		assert_eq!(info.amount_currently_spendable, base_amount * 42);
		Ok(())
	})?;

	wallet::controller::owner_single_use(wallet8.clone(), |api| {
		api.restore()?;
		let info = wallet_info!(wallet8.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 15);
		assert_eq!(info.amount_currently_spendable, base_amount * 120);
		api.set_active_account("account_1")?;
		let info = wallet_info!(wallet8.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 3);
		assert_eq!(info.amount_currently_spendable, base_amount * 6);
		Ok(())
	})?;

	// 6) Start using same seed with a different account, now overwriting
	// ids on account 2 as well, check_repair should get all outputs created
	// to now into 2 accounts

	wallet::controller::owner_single_use(wallet9.clone(), |api| {
		api.create_account_path("account_1")?;
		api.set_active_account("account_1")?;
		Ok(())
	})?;

	send_to_dest!(miner.clone(), m_client.clone(), "wallet9", base_amount * 4)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet9", base_amount * 5)?;
	send_to_dest!(miner.clone(), m_client.clone(), "wallet9", base_amount * 6)?;
	bh += 3;
	let _bh = bh;

	wallet::controller::owner_single_use(wallet9.clone(), |api| {
		let info = wallet_info!(wallet9.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 3);
		assert_eq!(info.amount_currently_spendable, base_amount * 15);
		api.check_repair(true)?;
		let info = wallet_info!(wallet9.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 6);
		assert_eq!(info.amount_currently_spendable, base_amount * 21);

		api.set_active_account("default")?;
		let info = wallet_info!(wallet9.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 15);
		assert_eq!(info.amount_currently_spendable, base_amount * 120);
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, miner.clone(), cm, false);

	// 7) Ensure check_repair creates missing accounts
	wallet::controller::owner_single_use(wallet10.clone(), |api| {
		api.check_repair(true)?;
		api.set_active_account("account_1")?;
		let info = wallet_info!(wallet10.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 6);
		assert_eq!(info.amount_currently_spendable, base_amount * 21);

		api.set_active_account("default")?;
		let info = wallet_info!(wallet10.clone())?;
		let outputs = api.retrieve_outputs(true, false, None)?.1;
		assert_eq!(outputs.len(), 15);
		assert_eq!(info.amount_currently_spendable, base_amount * 120);
		Ok(())
	})?;

	// let logging finish
	thread::sleep(Duration::from_millis(200));
	Ok(())
}
#[test]
fn check_repair() {
	let test_dir = "test_output/check_repair";
	if let Err(e) = check_repair_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
}

#[test]
fn two_wallets_one_seed() {
	let test_dir = "test_output/two_wallets_one_seed";
	if let Err(e) = two_wallets_one_seed_impl(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
}
