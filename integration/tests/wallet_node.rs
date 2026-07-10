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

//! Live node + wallet: mine coinbase into a foreign listener and read summary info.

#[macro_use]
extern crate log;

mod common;

use crate::common::{
	clean_all_output, create_wallet, init_chain, node_config, settle, start_foreign_listener,
	start_node, start_test_miner,
};
use grin_core::consensus;
use grin_core::global;
use grin_util as util;
use grin_wallet_controller as controller;
use std::{thread, time};

/// Start a node, attach a foreign wallet for coinbase, mine, then assert balance.
#[test]
fn mine_to_wallet_and_summary() {
	util::init_test_logger();
	init_chain();

	let test_dir = "mine_to_wallet";
	clean_all_output(test_dir);

	// Node on ports derived from n=5000 → p2p 15000, api 25000
	let n = 5000u16;
	let node = start_node(node_config(n, test_dir));
	let node_url = format!("http://127.0.0.1:{}", 20000 + n);
	let wallet_port = 35000u16;
	let wallet_addr = format!("127.0.0.1:{}", wallet_port);
	let wallet_url = format!("http://{}", wallet_addr);

	let (wallet, mask) = create_wallet(test_dir, "coinbase", &node_url);
	start_foreign_listener(wallet.clone(), mask.clone(), &wallet_addr);

	let miner_stop = start_test_miner(&node, Some(wallet_url));

	// Mine until we have several coinbase outputs.
	let mut waited = 0;
	while node.head().unwrap().height < 5 {
		thread::sleep(time::Duration::from_secs(1));
		waited += 1;
		assert!(waited < 60, "node did not mine enough blocks");
	}
	node.stop_test_miner(miner_stop);
	thread::sleep(time::Duration::from_secs(2));

	let height = node.head().unwrap().height;
	info!("mined to height {}", height);
	assert!(height >= 5);

	// Wallet should see coinbases (maturity rules still apply for spendable).
	let mask_ref = mask.as_ref();
	controller::controller::owner_single_use(Some(wallet.clone()), mask_ref, None, |api, m| {
		// Force a node refresh.
		let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed, "wallet should refresh against live node");
		assert_eq!(info.last_confirmed_height, height);
		// All coinbase from mining goes to this wallet.
		assert_eq!(info.total, height * consensus::REWARD);
		assert!(
			info.amount_currently_spendable < info.total
				|| height > global::coinbase_maturity(),
			"immature coinbase expected until maturity"
		);
		Ok(())
	})
	.expect("owner summary");

	node.stop();
	settle();
}

/// Two wallets against one node: mine to A, send slate to B via foreign API, post tx.
#[test]
fn wallet_send_receive_via_http() {
	util::init_test_logger();
	init_chain();

	let test_dir = "wallet_http_send";
	clean_all_output(test_dir);

	let n = 5100u16;
	let node = start_node(node_config(n, test_dir));
	let node_url = format!("http://127.0.0.1:{}", 20000 + n);

	let sender_port = 35100u16;
	let rec_port = 35101u16;
	let sender_addr = format!("127.0.0.1:{}", sender_port);
	let rec_addr = format!("127.0.0.1:{}", rec_port);

	let (wallet_a, mask_a) = create_wallet(test_dir, "wallet_a", &node_url);
	let (wallet_b, mask_b) = create_wallet(test_dir, "wallet_b", &node_url);

	// Foreign on A for coinbase; foreign on B for receive.
	start_foreign_listener(wallet_a.clone(), mask_a.clone(), &sender_addr);
	start_foreign_listener(wallet_b.clone(), mask_b.clone(), &rec_addr);

	let miner_stop = start_test_miner(&node, Some(format!("http://{}", sender_addr)));

	// Need mature coinbase: AutomatedTesting maturity is 3 blocks.
	let target = global::coinbase_maturity() + 3;
	let mut waited = 0;
	while node.head().unwrap().height < target {
		thread::sleep(time::Duration::from_secs(1));
		waited += 1;
		assert!(waited < 60, "timeout mining for mature coinbase");
	}
	node.stop_test_miner(miner_stop);
	thread::sleep(time::Duration::from_secs(2));

	let amount = consensus::REWARD;
	let mask_a_ref = mask_a.as_ref();
	let mask_b_clone = mask_b.clone();

	controller::controller::owner_single_use(Some(wallet_a.clone()), mask_a_ref, None, |api, m| {
		let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		assert!(info.amount_currently_spendable >= amount);

		use grin_wallet_libwallet::InitTxArgs;
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 1,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: false,
			..Default::default()
		};
		let mut slate = api.init_send_tx(m, args)?;
		api.tx_lock_outputs(m, &slate)?;

		// Receive on B (in-process foreign; same process as HTTP listener but direct call).
		controller::controller::foreign_single_use(wallet_b.clone(), mask_b_clone.clone(), |fapi| {
			slate = fapi.receive_tx(&slate, None, None)?;
			Ok(())
		})?;

		slate = api.finalize_tx(m, &slate)?;
		api.post_tx(m, &slate, false)?;
		Ok(())
	})
	.expect("send/receive");

	// Mine a confirmation block (burn rewards — tx already in pool/chain via post_tx).
	let miner_stop = start_test_miner(&node, None);
	let h0 = node.head().unwrap().height;
	let mut waited = 0;
	while node.head().unwrap().height <= h0 {
		thread::sleep(time::Duration::from_secs(1));
		waited += 1;
		assert!(waited < 30, "timeout mining confirmation");
	}
	node.stop_test_miner(miner_stop);
	thread::sleep(time::Duration::from_secs(2));

	// B should hold the received amount (may still be immature depending on path).
	let mask_b_ref = mask_b.as_ref();
	controller::controller::owner_single_use(Some(wallet_b.clone()), mask_b_ref, None, |api, m| {
		let (refreshed, info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(refreshed);
		assert!(
			info.total >= amount,
			"receiver total {} < {}",
			info.total,
			amount
		);
		Ok(())
	})
	.expect("receiver summary");

	node.stop();
	settle();
}
