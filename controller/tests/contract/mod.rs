// Copyright 2022 The Grin Developers
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

//! Test contract utils
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_wallet_libwallet as libwallet;
use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_keychain as keychain;
use grin_wallet_util::grin_util as util;

use self::keychain::ExtKeychain;
use self::libwallet::WalletInst;
// use impls::test_framework::{LocalWalletClient, WalletProxy};
use crate::chain::Chain;
use grin_wallet_util::grin_chain as chain;
use impls::{DefaultLCProvider, DefaultWalletImpl};
use std::sync::Arc;
use util::secp::key::SecretKey;
use util::{Mutex, ZeroingString};

use impls::test_framework::{self, LocalWalletClient, WalletProxy};
use libwallet::contract::types::{ContractNewArgsAPI, ContractSetupArgsAPI};
use libwallet::{Slate, SlateState};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

// #[macro_use]
mod common;
use common::{clean_output_dir, create_local_wallet, create_wallet_proxy, setup};

pub fn create_wallets(
	test_dir: &'static str,
) -> (
	Vec<(
		Arc<
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
		>,
		Option<SecretKey>,
	)>,
	Arc<Chain>,      // chain
	Arc<AtomicBool>, // stopper
) {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = common::create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	let mut wallets = vec![];
	for i in 0..2 {
		let name = format!("wallet{}", i + 1);
		let wclient = LocalWalletClient::new(&name, wallet_proxy.tx.clone());
		let (wallet1, mask1) = common::create_local_wallet(
			test_dir,
			&name,
			None,
			// $seed_phrase.clone(),
			wclient.clone(),
			true,
		);
		wallet_proxy.add_wallet(
			&name,
			wclient.get_send_instance(),
			wallet1.clone(),
			mask1.clone(),
		);
		// create_wallet_and_add!(
		//     client1,
		//     wallet1,
		//     mask1_i,
		//     test_dir,
		//     "wallet1",
		//     None,
		//     &mut wallet_proxy,
		//     true
		// );
		wallets.push((wallet1, mask1));
	}
	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});
	(wallets, chain, stopper)

	// let $client = LocalWalletClient::new($name, $proxy.tx.clone());
	// let ($wallet, $mask) = common::create_local_wallet(
	// 	$test_dir,
	// 	$name,
	// 	$seed_phrase.clone(),
	// 	$client.clone(),
	// 	$create_mask,
	// );
	// $proxy.add_wallet(
	// 	$name,
	// 	$client.get_send_instance(),
	// 	$wallet.clone(),
	// 	$mask.clone(),
	// );
}

// #[macro_export]
// macro_rules! create_wallets {
// 	($client:ident, $wallet: ident, $mask: ident, $test_dir: expr, $name: expr, $seed_phrase: expr, $proxy: expr, $create_mask: expr) => {
// 		// Create a new proxy to simulate server and wallet responses
// 		let mut wallet_proxy = create_wallet_proxy(test_dir);
// 		let chain = wallet_proxy.chain.clone();
// 		let stopper = wallet_proxy.running.clone();

// 		let rv = vec![];
// 		for i in 0..wallets.len() {
// 			let name = format!("wallet{}", i + 1);
// 			let wclient = LocalWalletClient::new(name, wallet_proxy.tx.clone());
// 			let (wallet1, mask1) = common::create_local_wallet(
// 				$test_dir,
// 				name,
// 				None,
// 				// $seed_phrase.clone(),
// 				wallet_proxy.clone(),
// 				true,
// 			);
// 			wallet_proxy.add_wallet(
// 				name,
// 				wclient.get_send_instance(),
// 				wallet1.clone(),
// 				mask1.clone(),
// 			);
// 			// create_wallet_and_add!(
// 			//     client1,
// 			//     wallet1,
// 			//     mask1_i,
// 			//     test_dir,
// 			//     "wallet1",
// 			//     None,
// 			//     &mut wallet_proxy,
// 			//     true
// 			// );
// 			rv.push((wallet1, mask1));
// 		}
// 		rv

// 		// let $client = LocalWalletClient::new($name, $proxy.tx.clone());
// 		// let ($wallet, $mask) = common::create_local_wallet(
// 		// 	$test_dir,
// 		// 	$name,
// 		// 	$seed_phrase.clone(),
// 		// 	$client.clone(),
// 		// 	$create_mask,
// 		// );
// 		// $proxy.add_wallet(
// 		// 	$name,
// 		// 	$client.get_send_instance(),
// 		// 	$wallet.clone(),
// 		// 	$mask.clone(),
// 		// );
// 	};
// }

// prepare wallets
// fn create_wallets(
// 	wallets: Vec<u64>,
// 	test_dir: &'static str,
// 	// wallet_proxy: WalletProxy<
// 	// 	'static,
// 	// 	DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
// 	// 	LocalWalletClient,
// 	// 	ExtKeychain,
// 	// >,
// ) -> Vec<(
// 	Arc<
// 		Mutex<
// 			Box<
// 				dyn WalletInst<
// 					'static,
// 					DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
// 					LocalWalletClient,
// 					ExtKeychain,
// 				>,
// 			>,
// 		>,
// 	>,
// 	Option<SecretKey>,
// )> {
// 	// Create a new proxy to simulate server and wallet responses
// 	let mut wallet_proxy = create_wallet_proxy(test_dir);
// 	let chain = wallet_proxy.chain.clone();
// 	let stopper = wallet_proxy.running.clone();

// 	let rv = vec![];
// 	for _ in 0..wallets.len() {
// 		create_wallet_and_add!(
// 			client1,
// 			wallet1,
// 			mask1_i,
// 			test_dir,
// 			"wallet1",
// 			None,
// 			&mut wallet_proxy,
// 			true
// 		);
// 		rv.push((wallet1, mask1_i));
// 	}
// 	rv
// }

// /// prepare two wallets for testing
// fn prepare_wallets(n_wallets: u8, test_dir: &'static str) -> Result<Vec<()>, libwallet::Error> {
// 	// Create a new proxy to simulate server and wallet responses
// 	let mut wallet_proxy = create_wallet_proxy(test_dir);
// 	let chain = wallet_proxy.chain.clone();
// 	let stopper = wallet_proxy.running.clone();

// 	create_wallet_and_add!(
// 		client1,
// 		wallet1,
// 		mask1_i,
// 		test_dir,
// 		"wallet1",
// 		None,
// 		&mut wallet_proxy,
// 		true
// 	);
// 	let mask1 = (&mask1_i).as_ref();
// 	create_wallet_and_add!(
// 		client2,
// 		wallet2,
// 		mask2_i,
// 		test_dir,
// 		"wallet2",
// 		None,
// 		&mut wallet_proxy,
// 		true
// 	);
// 	let mask2 = (&mask2_i).as_ref();

// 	// Set the wallet proxy listener running
// 	thread::spawn(move || {
// 		if let Err(e) = wallet_proxy.run() {
// 			error!("Wallet Proxy error: {}", e);
// 		}
// 	});

// 	// few values to keep things shorter
// 	let reward = core::consensus::REWARD;

// 	// add some accounts
// 	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
// 		api.create_account_path(m, "mining")?;
// 		api.create_account_path(m, "listener")?;
// 		Ok(())
// 	})?;

// 	// Get some mining done
// 	{
// 		wallet_inst!(wallet1, w);
// 		w.set_parent_key_id_by_name("mining")?;
// 	}
// 	let mut bh = 10u64;
// 	let _ =
// 		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

// 	// Sanity check wallet 1 contents
// 	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
// 		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
// 		assert!(wallet1_refreshed);
// 		assert_eq!(wallet1_info.last_confirmed_height, bh);
// 		assert_eq!(wallet1_info.total, bh * reward);
// 		Ok(())
// 	})?;

// 	// let logging finish
// 	stopper.store(false, Ordering::Relaxed);
// 	thread::sleep(Duration::from_millis(200));

// 	Ok(())
// }

// #[test]
// fn wallet_contract_rsr_tx() -> Result<(), libwallet::Error> {
// 	let test_dir = "test_output/contract_rsr_tx";
// 	setup(test_dir);
// 	contract_rsr_tx_impl(test_dir)?;
// 	clean_output_dir(test_dir);
// 	Ok(())
// }
