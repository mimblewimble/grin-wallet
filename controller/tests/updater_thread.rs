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

//! Test a wallet repost command
#[macro_use]
extern crate log;
extern crate grin_wallet_api as api;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;

use impls::test_framework::{self, LocalWalletClient};
use libwallet::api_impl::owner_updater::{StatusMessage, Updater};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// updater thread test impl
fn updater_thread_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
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
	api1.create_account_path(mask1, "listener")?;

	api2.create_account_path(mask2, "account1")?;
	api2.create_account_path(mask2, "account2")?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	let owner_api = api::Owner::new(wallet1, None, PathBuf::from(test_dir));
	owner_api.start_updater(mask1, Duration::from_secs(5))?;

	// let updater thread run a bit
	thread::sleep(Duration::from_secs(10));

	let messages = owner_api.get_updater_messages(1000)?;
	assert_eq!(messages.len(), 32);

	owner_api.stop_updater()?;
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_secs(2));
	Ok(())
}

#[test]
fn updater_thread() {
	let test_dir = "test_output/updater_thread";
	setup(test_dir);
	if let Err(e) = updater_thread_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}

#[test]
fn updater_retries_a_scan_interrupted_by_a_block() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/updater_scan_interruption";
	setup(test_dir);
	let mut proxy = create_wallet_proxy(test_dir);
	let chain = proxy.chain.clone();
	let stop_proxy = proxy.running.clone();
	create_wallet_and_add!(
		client, wallet, mask, test_dir, "receiver", None, &mut proxy, false, api
	);
	let _ = (client, api);
	test_framework::award_block_to_wallet(&chain, &[], wallet.clone(), mask.as_ref())?;

	let (forward, receiver) = mpsc::channel();
	let requests = std::mem::replace(&mut proxy.rx, receiver);
	let stop_relay = Arc::new(AtomicBool::new(false));
	let relay = {
		let wallet = wallet.clone();
		let stop_relay = stop_relay.clone();
		let mask = mask.clone();
		thread::spawn(move || -> Result<(), libwallet::Error> {
			grin_core::global::set_local_chain_type(
				grin_core::global::ChainTypes::AutomatedTesting,
			);
			let mut added_block = false;
			while !stop_relay.load(Ordering::Relaxed) {
				let Ok(request) = requests.recv_timeout(Duration::from_millis(20)) else {
					continue;
				};
				if !added_block && request.method == "get_outputs_by_pmmr_index" {
					test_framework::award_block_to_wallet(
						&chain,
						&[],
						wallet.clone(),
						mask.as_ref(),
					)?;
					added_block = true;
				}
				if forward.send(request).is_err() {
					break;
				}
			}
			Ok(())
		})
	};
	let proxy_worker = thread::spawn(move || proxy.run());

	let (status_tx, status_rx) = mpsc::channel();
	let running = Arc::new(AtomicBool::new(false));
	let updater = Updater::new(wallet.clone(), running.clone());
	let worker =
		thread::spawn(move || updater.run(Duration::from_millis(30), mask, &Some(status_tx)));

	let deadline = Instant::now() + Duration::from_secs(10);
	let mut saw_interruption = false;
	let mut scanned_new_tip = false;
	while Instant::now() < deadline {
		if let Ok(StatusMessage::UpdateWarning(message)) =
			status_rx.recv_timeout(Duration::from_millis(50))
		{
			saw_interruption |= message.contains("Node body tip changed during scan batch");
		}
		{
			wallet_inst!(wallet, w);
			scanned_new_tip = w.last_scanned_block()?.height == 2;
		}
		if scanned_new_tip {
			break;
		}
	}
	let kept_running = running.swap(false, Ordering::Relaxed);
	let update_result = worker.join().unwrap();
	stop_proxy.store(false, Ordering::Relaxed);
	stop_relay.store(true, Ordering::Relaxed);
	proxy_worker.join().unwrap()?;
	relay.join().unwrap()?;
	update_result?;

	assert!(saw_interruption, "first request must observe the new block");
	assert!(kept_running, "updater stopped after an ordinary new block");
	assert!(scanned_new_tip, "updater did not complete its retry");
	drop(wallet);
	clean_output_dir(test_dir);
	Ok(())
}
