// Copyright 2024 The Grin Developers
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

//! Test a wallet sending to self, then creation of comsig request
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_core as core;
use grin_util as util;
use grin_util::secp::key::SecretKey;

use grin_wallet_libwallet as libwallet;
use impls::test_framework::{self, LocalWalletClient};
use libwallet::{mwixnet::MixnetReqCreationParams, InitTxArgs};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// self send impl
fn mwixnet_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
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
		true
	);
	let mask1 = (&mask1_i).as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::REWARD;

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "mining")?;
		api.create_account_path(m, "listener")?;
		Ok(())
	})?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let mut bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Should have 5 in account1 (5 spendable), 5 in account (2 spendable)
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward);
		// send to send
		let args = InitTxArgs {
			src_acct_name: Some("mining".to_owned()),
			amount: reward * 2,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let mut slate = api.init_send_tx(m, args)?;
		api.tx_lock_outputs(m, &slate)?;
		// Send directly to self
		wallet::controller::foreign_single_use(wallet1.clone(), mask1_i.clone(), |api| {
			slate = api.receive_tx(&slate, Some("listener"), None)?;
			Ok(())
		})?;
		slate = api.finalize_tx(m, &slate)?;
		api.post_tx(m, &slate, false)?; // mines a block
		bh += 1;
		Ok(())
	})?;

	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
	bh += 3;

	// Check total in mining account
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward - reward * 2);
		Ok(())
	})?;

	// Check total in 'listener' account
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("listener")?;
	}
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, 2 * reward);
		Ok(())
	})?;

	// Recipient wallet creates a mwixnet request from the last output
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let secp_locked = util::static_secp_instance();
		let secp = secp_locked.lock();
		let server_pubkey_str_1 =
			"97444ae673bb92c713c1a2f7b8882ffbfc1c67401a280a775dce1a8651584332";
		let server_pubkey_str_2 =
			"0c9414341f2140ed34a5a12a6479bf5a6404820d001ab81d9d3e8cc38f049b4e";
		let server_pubkey_str_3 =
			"b58ece97d60e71bb7e53218400b0d67bfe6a3cb7d3b4a67a44f8fb7c525cbca5";
		let server_key_1 =
			SecretKey::from_slice(&secp, &grin_util::from_hex(&server_pubkey_str_1).unwrap())
				.unwrap();
		let server_key_2 =
			SecretKey::from_slice(&secp, &grin_util::from_hex(&server_pubkey_str_2).unwrap())
				.unwrap();
		let server_key_3 =
			SecretKey::from_slice(&secp, &grin_util::from_hex(&server_pubkey_str_3).unwrap())
				.unwrap();
		let params = MixnetReqCreationParams {
			server_keys: vec![server_key_1, server_key_2, server_key_3],
			fee_per_hop: 50_000_000,
		};
		let outputs = api.retrieve_outputs(mask1, false, false, None)?;
		// get last output
		let last_output = outputs.1[outputs.1.len() - 1].clone();

		let mwixnet_req = api.create_mwixnet_req(m, &params, &last_output.commit, true)?;

		println!("MWIXNET REQ: {:?}", mwixnet_req);

		// check output we created comsig for is indeed locked
		let outputs = api.retrieve_outputs(mask1, false, false, None)?;
		// get last output
		let last_output = outputs.1[outputs.1.len() - 1].clone();
		assert!(last_output.output.status == libwallet::OutputStatus::Locked);

		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(1000));
	Ok(())
}

#[test]
fn mwixnet_comsig_test() {
	let test_dir = "test_output/mwixnet";
	setup(test_dir);
	if let Err(e) = mwixnet_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
