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

//! common functions for tests (instantiating wallet and proxy, mostly)
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;
extern crate log;

use grin_chain as chain;
use grin_core as core;
use grin_keychain as keychain;
use grin_util as util;

use self::core::core::{FeeFields, Inputs, KernelFeatures, OutputFeatures};
use self::core::global;
use self::core::global::ChainTypes;
use self::keychain::{ExtKeychain, Keychain};
use self::libwallet::WalletInst;
use chain::Chain;
use grin_wallet_controller::Error;
use impls::test_framework::{self, LocalWalletClient, WalletProxy};
use impls::{DefaultLCProvider, DefaultWalletImpl};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use util::secp::key::SecretKey;
use util::{Mutex, ZeroingString};

#[macro_export]
macro_rules! wallet_inst {
	($wallet:ident, $w: ident) => {
		let mut w_lock = $wallet.lock();
		let lc = w_lock.lc_provider()?;
		let $w = lc.wallet_inst()?;
	};
}

#[macro_export]
macro_rules! create_wallet_and_add {
	($client:ident, $wallet: ident, $mask: ident, $test_dir: expr, $name: expr, $seed_phrase: expr, $proxy: expr, $create_mask: expr) => {
		let $client = LocalWalletClient::new($name, $proxy.tx.clone());
		let ($wallet, $mask) = common::create_local_wallet(
			$test_dir,
			$name,
			$seed_phrase.clone(),
			$client.clone(),
			$create_mask,
		);
		$proxy.add_wallet(
			$name,
			$client.get_send_instance(),
			$wallet.clone(),
			$mask.clone(),
		);
	};
}

#[macro_export]
macro_rules! open_wallet_and_add {
	($client:ident, $wallet: ident, $mask: ident, $test_dir: expr, $name: expr, $proxy: expr, $create_mask: expr) => {
		let $client = LocalWalletClient::new($name, $proxy.tx.clone());
		let ($wallet, $mask) =
			common::open_local_wallet($test_dir, $name, $client.clone(), $create_mask);
		$proxy.add_wallet(
			$name,
			$client.get_send_instance(),
			$wallet.clone(),
			$mask.clone(),
		);
	};
}
pub fn clean_output_dir(test_dir: &str) {
	let path = std::path::Path::new(test_dir);
	if path.is_dir() {
		std::fs::remove_dir_all(test_dir).unwrap();
	}
}

#[allow(dead_code)]
pub fn contract_selection_args() -> libwallet::contract::types::OutputSelectionArgs {
	// Contract fixtures mine only a few blocks.
	libwallet::contract::types::OutputSelectionArgs {
		minimum_confirmations: Some(1),
		..Default::default()
	}
}

#[allow(dead_code)]
pub struct ExpectedContractSlate {
	pub amount: u64,
	pub fee: u64,
	pub inputs: usize,
	pub coinbase_inputs: usize,
	pub outputs: usize,
	pub kernels: usize,
	pub num_participants: u8,
	pub participant_data: usize,
	pub signatures: usize,
}

#[allow(dead_code)]
pub fn assert_basic_contract_slate(slate: &libwallet::Slate, expected: ExpectedContractSlate) {
	let tx = slate.tx_or_err().unwrap();
	assert_ne!(expected.fee, 0, "expected fee must be non-zero");
	let expected_fee = FeeFields::new(0, expected.fee).unwrap();
	assert_eq!(slate.amount, expected.amount);
	assert_eq!(slate.fee_fields, expected_fee);
	assert_eq!(slate.kernel_features, 0);
	assert!(slate.kernel_features_args.is_none());
	assert!(slate.payment_proof.is_none());
	assert_eq!(slate.num_participants, expected.num_participants);
	let inputs = tx.inputs();
	assert_eq!(inputs.len(), expected.inputs);
	match inputs {
		Inputs::FeaturesAndCommit(inputs) => assert_eq!(
			inputs
				.iter()
				.filter(|input| input.features == OutputFeatures::Coinbase)
				.count(),
			expected.coinbase_inputs
		),
		Inputs::CommitOnly(_) => panic!("contract inputs must include their features"),
	}
	assert_eq!(tx.outputs().len(), expected.outputs);
	assert!(tx.outputs().iter().all(|output| output.is_plain()));
	assert_eq!(tx.kernels().len(), expected.kernels);
	assert_eq!(slate.participant_data.len(), expected.participant_data);
	assert_eq!(
		slate
			.participant_data
			.iter()
			.filter(|participant| participant.part_sig.is_some())
			.count(),
		expected.signatures
	);
	if expected.kernels != 0 {
		assert_eq!(
			tx.kernels()[0].features,
			KernelFeatures::Plain { fee: expected_fee }
		);
	}
}

#[allow(dead_code)]
pub type TestOwner = grin_wallet_api::Owner<
	DefaultLCProvider<LocalWalletClient, ExtKeychain>,
	LocalWalletClient,
	ExtKeychain,
>;

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub struct WalletProgress {
	child_index: u32,
	tx_count: usize,
}

#[allow(dead_code)]
pub fn wallet_progress(
	api: &TestOwner,
	keychain_mask: Option<&SecretKey>,
) -> Result<WalletProgress, libwallet::Error> {
	let child_index = {
		let mut wallet = api.wallet_inst.lock();
		let wallet = wallet.lc_provider()?.wallet_inst()?;
		let parent = wallet.parent_key_id();
		wallet.current_child_index(&parent)?
	};
	let (_, txs) = api.retrieve_txs(keychain_mask, false, None, None, None)?;
	Ok(WalletProgress {
		child_index,
		tx_count: txs.len(),
	})
}

#[allow(dead_code)]
pub fn tx_log_for_slate(
	api: &TestOwner,
	keychain_mask: Option<&SecretKey>,
	slate: &libwallet::Slate,
) -> Result<libwallet::TxLogEntry, libwallet::Error> {
	let (_, mut txs) = api.retrieve_txs(keychain_mask, false, None, Some(slate.id), None)?;
	assert_eq!(
		txs.len(),
		1,
		"expected one tx log entry for slate {}",
		slate.id
	);
	Ok(txs.pop().unwrap())
}

pub fn setup(test_dir: &str) {
	util::init_test_logger();
	clean_output_dir(test_dir);
	setup_global_chain_type();
}

/// Some tests require the global chain_type to be configured due to threads being spawned internally.
/// It is recommended to avoid relying on this if at all possible as global chain_type
/// leaks across multiple tests and will likely have unintended consequences.
#[allow(dead_code)]
pub fn setup_global_chain_type() {
	global::init_global_chain_type(ChainTypes::AutomatedTesting);
}

pub fn create_wallet_proxy(
	test_dir: &str,
) -> WalletProxy<
	'_,
	DefaultLCProvider<LocalWalletClient, ExtKeychain>,
	LocalWalletClient,
	ExtKeychain,
> {
	WalletProxy::new(test_dir)
}

pub fn create_local_wallet(
	test_dir: &str,
	name: &str,
	mnemonic: Option<ZeroingString>,
	client: LocalWalletClient,
	create_mask: bool,
) -> (
	Arc<
		Mutex<
			Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>,
		>,
	>,
	Option<SecretKey>,
) {
	let mut wallet = Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client).unwrap())
		as Box<
			dyn WalletInst<
				DefaultLCProvider<LocalWalletClient, ExtKeychain>,
				LocalWalletClient,
				ExtKeychain,
			>,
		>;
	let lc = wallet.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/{}", test_dir, name));
	lc.create_wallet(None, mnemonic, 32, ZeroingString::from(""), false)
		.unwrap();
	let mask = lc
		.open_wallet(None, ZeroingString::from(""), create_mask, false)
		.unwrap();
	(Arc::new(Mutex::new(wallet)), mask)
}

#[allow(dead_code)]
pub fn open_local_wallet(
	test_dir: &str,
	name: &str,
	client: LocalWalletClient,
	create_mask: bool,
) -> (
	Arc<
		Mutex<
			Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>,
		>,
	>,
	Option<SecretKey>,
) {
	let mut wallet = Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client).unwrap())
		as Box<
			dyn WalletInst<
				DefaultLCProvider<LocalWalletClient, ExtKeychain>,
				LocalWalletClient,
				ExtKeychain,
			>,
		>;
	let lc = wallet.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/{}", test_dir, name));
	let mask = lc
		.open_wallet(None, ZeroingString::from(""), create_mask, false)
		.unwrap();
	(Arc::new(Mutex::new(wallet)), mask)
}

// Creates the given number of wallets and spawns a thread that runs the wallet proxy
#[allow(dead_code)]
pub fn create_wallets(
	wallets_def: Vec<Vec<(&'static str, u64)>>, // a vector of boolean that represent whether we mine into a wallet
	test_dir: &'static str,
) -> Result<
	(
		Vec<(
			Arc<
				Mutex<
					Box<
						dyn WalletInst<
							'static,
							DefaultLCProvider<LocalWalletClient, ExtKeychain>,
							LocalWalletClient,
							ExtKeychain,
						>,
					>,
				>,
			>,
			Option<SecretKey>,
		)>, // wallets
		Arc<Chain>,      // chain
		Arc<AtomicBool>, // stopper
		u64,             //	block height
	),
	Error,
> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	let mut wallets = vec![];
	for i in 0..wallets_def.len() {
		let name = format!("wallet{}", i + 1);
		let wclient = LocalWalletClient::new(&name, wallet_proxy.tx.clone());
		let (wallet1, mask1) = create_local_wallet(
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
		wallets.push((wallet1, mask1));
	}
	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			log::error!("Wallet Proxy error: {}", e);
		}
	});

	// // Mine values into wallets
	// // few values to keep things shorter
	let reward = core::consensus::REWARD;
	let mut bh = 0u64;

	for (idx, accs) in wallets_def.iter().enumerate() {
		let wallet1 = wallets[idx].0.clone();
		let mask1 = wallets[idx].1.as_ref();

		for (acc_idx, (acc_name, num_mined_blocks)) in accs.iter().enumerate() {
			// create the account
			if acc_name.to_string() != "default" {
				wallet::controller::owner_single_use(
					wallet1.clone(),
					mask1,
					PathBuf::from(test_dir),
					|api, m| {
						let new_path = api.create_account_path(m, acc_name)?;
						assert_eq!(
							new_path,
							ExtKeychain::derive_key_id(2, acc_idx as u32, 0, 0, 0) // NOTE: default should always be at 0 and is already created
						);
						Ok(())
					},
				)?;
			}

			// Get some mining done
			if *num_mined_blocks == 0 {
				continue;
			}
			{
				wallet_inst!(wallet1, w);
				w.set_parent_key_id_by_name(acc_name)?;
			}
			let _ = test_framework::award_blocks_to_wallet(
				&chain,
				wallet1.clone(),
				mask1,
				*num_mined_blocks as usize,
				false,
			);
			bh += num_mined_blocks;

			// Sanity check wallet 1 contents
			wallet::controller::owner_single_use(
				wallet1.clone(),
				mask1,
				PathBuf::from(test_dir),
				|api, m| {
					let (wallet1_refreshed, wallet1_info) =
						api.retrieve_summary_info(m, true, 1)?;
					assert!(wallet1_refreshed);
					assert_eq!(wallet1_info.last_confirmed_height, bh);
					assert_eq!(wallet1_info.total, num_mined_blocks * reward);
					Ok(())
				},
			)?;
		}

		// Sanity check the number of accounts
		wallet::controller::owner_single_use(
			wallet1.clone(),
			mask1,
			PathBuf::from(test_dir),
			|api, m| {
				let accounts = api.accounts(m)?;
				assert_eq!(accounts.len(), accs.len());
				Ok(())
			},
		)?;
		// Set the account on the wallet to "default"
		{
			wallet_inst!(wallet1, w);
			w.set_parent_key_id_by_name("default")?;
		}
	}

	Ok((wallets, chain, stopper, bh))
}
