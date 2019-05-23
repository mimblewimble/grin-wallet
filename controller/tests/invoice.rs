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

//! Test a wallet sending to self
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_keychain as keychain;
use grin_wallet_util::grin_util as util;

use self::core::global;
use self::core::global::ChainTypes;
use self::keychain::ExtKeychain;
use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient, WalletProxy};
use libwallet::{InitTxArgs, IssueInvoiceTxArgs, Slate};
use std::fs;
use std::thread;
use std::time::Duration;

fn clean_output_dir(test_dir: &str) {
	let _ = fs::remove_dir_all(test_dir);
}

fn setup(test_dir: &str) {
	util::init_test_logger();
	clean_output_dir(test_dir);
	global::set_mining_mode(ChainTypes::AutomatedTesting);
}

fn teardown(test_dir: &str) {
	clean_output_dir(test_dir);
}

/// self send impl
fn invoice_tx_impl(test_dir: &str) -> Result<(), libwallet::Error> {
	{
		setup(test_dir);
		// Create a new proxy to simulate server and wallet responses
		let mut wallet_proxy: WalletProxy<LocalWalletClient, ExtKeychain> =
			WalletProxy::new(test_dir);
		let chain = wallet_proxy.chain.clone();

		// Create a new wallet test client, and set its queues to communicate with the proxy
		let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
		let wallet1 =
			test_framework::create_wallet(&format!("{}/wallet1", test_dir), client1.clone(), None);
		wallet_proxy.add_wallet("wallet1", client1.get_send_instance(), wallet1.clone());

		// wallet 2, will be recipient
		let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
		let wallet2 =
			test_framework::create_wallet(&format!("{}/wallet2", test_dir), client2.clone(), None);
		wallet_proxy.add_wallet("wallet2", client2.get_send_instance(), wallet2.clone());

		// Set the wallet proxy listener running
		thread::spawn(move || {
			if let Err(e) = wallet_proxy.run() {
				error!("Wallet Proxy error: {}", e);
			}
		});

		// few values to keep things shorter
		let reward = core::consensus::REWARD;

		// add some accounts
		wallet::controller::owner_single_use(wallet1.clone(), |api| {
			api.create_account_path("mining")?;
			api.create_account_path("listener")?;
			Ok(())
		})?;

		// Get some mining done
		{
			let mut w = wallet1.lock();
			w.set_parent_key_id_by_name("mining")?;
		}
		let mut bh = 10u64;
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), bh as usize, false);

		// Sanity check wallet 1 contents
		wallet::controller::owner_single_use(wallet1.clone(), |api| {
			let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(true, 1)?;
			assert!(wallet1_refreshed);
			assert_eq!(wallet1_info.last_confirmed_height, bh);
			assert_eq!(wallet1_info.total, bh * reward);
			Ok(())
		})?;

		let mut slate = Slate::blank(2);

		wallet::controller::owner_single_use(wallet2.clone(), |api| {
			// Wallet 2 inititates an invoice transaction, requesting payment
			let args = IssueInvoiceTxArgs {
				amount: reward * 2,
				..Default::default()
			};
			slate = api.issue_invoice_tx(args)?;
			Ok(())
		})?;

		wallet::controller::owner_single_use(wallet1.clone(), |api| {
			// Wallet 1 receives the invoice transaction
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			slate = api.process_invoice_tx(&slate, args)?;
			api.tx_lock_outputs(&slate, 0)?;
			Ok(())
		})?;

		// wallet 2 finalizes and posts
		wallet::controller::foreign_single_use(wallet2.clone(), |api| {
			// Wallet 2 receives the invoice transaction
			slate = api.finalize_invoice_tx(&slate)?;
			Ok(())
		})?;

		// wallet 1 posts so wallet 2 doesn't get the mined amount
		wallet::controller::owner_single_use(wallet1.clone(), |api| {
			api.post_tx(&slate.tx, false)?;
			Ok(())
		})?;
		bh += 1;

		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 3, false);
		bh += 3;

		// Check transaction log for wallet 2
		wallet::controller::owner_single_use(wallet2.clone(), |api| {
			let (_, wallet2_info) = api.retrieve_summary_info(true, 1)?;
			let (refreshed, txs) = api.retrieve_txs(true, None, None)?;
			assert!(refreshed);
			assert!(txs.len() == 1);
			println!(
				"last confirmed height: {}, bh: {}",
				wallet2_info.last_confirmed_height, bh
			);
			assert!(refreshed);
			assert_eq!(wallet2_info.amount_currently_spendable, slate.amount);
			Ok(())
		})?;

		// Check transaction log for wallet 1, ensure only 1 entry
		// exists
		wallet::controller::owner_single_use(wallet1.clone(), |api| {
			let (_, wallet1_info) = api.retrieve_summary_info(true, 1)?;
			let (refreshed, txs) = api.retrieve_txs(true, None, None)?;
			assert!(refreshed);
			assert_eq!(txs.len() as u64, bh + 1);
			println!(
				"Wallet 1: last confirmed height: {}, bh: {}",
				wallet1_info.last_confirmed_height, bh
			);
			Ok(())
		})?;

		// Test self-sending
		wallet::controller::owner_single_use(wallet1.clone(), |api| {
			// Wallet 1 inititates an invoice transaction, requesting payment
			let args = IssueInvoiceTxArgs {
				amount: reward * 2,
				..Default::default()
			};
			slate = api.issue_invoice_tx(args)?;
			// Wallet 1 receives the invoice transaction
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			slate = api.process_invoice_tx(&slate, args)?;
			api.tx_lock_outputs(&slate, 0)?;
			Ok(())
		})?;

		// wallet 1 finalizes and posts
		wallet::controller::foreign_single_use(wallet1.clone(), |api| {
			// Wallet 2 receives the invoice transaction
			slate = api.finalize_invoice_tx(&slate)?;
			Ok(())
		})?;

		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 3, false);
		//bh += 3;

		// let logging finish
		thread::sleep(Duration::from_millis(200));
	}

	teardown(test_dir);
	Ok(())
}

#[test]
fn wallet_invoice_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/invoice_tx";
	invoice_tx_impl(test_dir)
}
