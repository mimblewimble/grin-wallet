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

//! Tests and experimentations with late locking
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;

use self::libwallet::InitTxArgs;
use impls::test_framework::{self, LocalWalletClient};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};
use libwallet::InitTxSendArgs;

/// self send impl
fn late_lock_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
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

	// add some accounts
	api1.create_account_path(mask1, "mining")?;
	api2.create_account_path(mask2, "account1")?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("account1")?;
	}

	test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 10, false)?;

	let amount = 100_000_000_000;

	let args = InitTxArgs {
		src_acct_name: Some("mining".to_owned()),
		amount,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: false,
		late_lock: Some(true),
		..Default::default()
	};
	let slate_i = api1.init_send_tx(mask1, args)?;
	println!("S1 SLATE: {}", slate_i);
	let mut slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
	println!("S2 SLATE: {}", slate);

	// Note we don't call `tx_lock_outputs` on the sender side here,
	// as the outputs will only be locked during finalization

	slate = api1.finalize_tx(mask1, &slate)?;
	println!("S3 SLATE: {}", slate);

	// Now post tx to our node for inclusion in the next block.
	api1.post_tx(mask1, &slate, true)?;

	test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false)?;

	// update/test contents of both accounts
	let (wallet1_refreshed, wallet_info) = api1.retrieve_summary_info(mask1, true, 1)?;
	assert!(wallet1_refreshed);
	// Reward from mining 11 blocks, minus the amount sent.
	// Note: We mined the block containing the tx, so fees are effectively refunded.
	assert_eq!(560_000_000_000, wallet_info.amount_currently_spendable);

	// Make sure outputs are not locked on failed send with arguments.
	// Fail sending without starting Tor
	api1.set_tor_config(Some(grin_wallet_config::TorConfig {
		use_integrated: Some(false),
		socks_proxy_addr: "invalid".into(),
		..Default::default()
	}))?;
	let args = InitTxArgs {
		src_acct_name: Some("mining".to_owned()),
		amount,
		minimum_confirmations: 2,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: false,
		late_lock: Some(true),
		send_args: Some(InitTxSendArgs {
			dest: "tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp".into(),
			post_tx: false,
			fluff: false,
			skip_tor: Some(false),
		}),
		..Default::default()
	};
	let slate = api1.init_send_tx(mask1, args)?;
	let (_, txs) = api1.retrieve_txs(mask1, false, None, Some(slate.id), None)?;
	assert!(txs.is_empty());
	// Make sure spendable balance not changed.
	let (wallet1_refreshed, wallet_info) = api1.retrieve_summary_info(mask1, true, 1)?;
	assert!(wallet1_refreshed);
	assert_eq!(560_000_000_000, wallet_info.amount_currently_spendable);

	let (wallet2_refreshed, wallet_info) = api2.retrieve_summary_info(mask2, true, 1)?;
	assert!(wallet2_refreshed);
	assert_eq!(amount, wallet_info.amount_currently_spendable);

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn late_lock() {
	let test_dir = "test_output/late_lock";
	setup(test_dir);
	if let Err(e) = late_lock_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
