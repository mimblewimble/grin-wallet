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

use grin_core as core;
use grin_keychain as keychain;
use grin_util as util;
use std::env;
use std::path::PathBuf;

use self::core::global;
use self::core::global::ChainTypes;
use self::keychain::ExtKeychain;
use self::libwallet::WalletInst;
use grin_wallet_api::Owner;
use grin_wallet_config::{initial_setup_wallet, GRIN_WALLET_DIR};
use impls::test_framework::{LocalWalletClient, WalletProxy};
use impls::{DefaultLCProvider, DefaultWalletImpl};
use std::sync::Arc;
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
	($client:ident, $wallet: ident, $mask: ident, $test_dir: expr, $name: expr, $seed_phrase: expr, $proxy: expr, $create_mask: expr, $owner_api: ident) => {
		let $client = LocalWalletClient::new($name, $proxy.tx.clone());
		let ($wallet, $mask, $owner_api) = common::create_local_wallet(
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
	Owner<DefaultLCProvider<LocalWalletClient, ExtKeychain>, LocalWalletClient, ExtKeychain>,
) {
	let mut current_dir;
	current_dir = env::current_dir().unwrap_or_else(|e| {
		panic!("Error creating config file: {}", e);
	});
	current_dir.push(test_dir);
	current_dir.push(name);
	let config =
		initial_setup_wallet(&ChainTypes::AutomatedTesting, Some(current_dir), true).unwrap();
	let mut wallet_config = config.clone().members.wallet;

	let mut wallet = Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client).unwrap())
		as Box<
			dyn WalletInst<
				DefaultLCProvider<LocalWalletClient, ExtKeychain>,
				LocalWalletClient,
				ExtKeychain,
			>,
		>;
	let lc = wallet.lc_provider().unwrap();
	// legacy hack to avoid the need for changes in existing grin-wallet.toml files
	// remove `wallet_data` from end of path as
	// new lifecycle provider assumes grin_wallet.toml is in root of data directory
	let mut top_level_wallet_dir = PathBuf::from(wallet_config.clone().data_file_dir);
	if top_level_wallet_dir.ends_with(GRIN_WALLET_DIR) {
		top_level_wallet_dir.pop();
		wallet_config.data_file_dir = top_level_wallet_dir.to_str().unwrap().into();
	}
	let _ = lc.set_top_level_directory(&wallet_config.data_file_dir);
	lc.create_wallet(None, mnemonic, 32, ZeroingString::from(""), false)
		.unwrap();
	let mask = lc
		.open_wallet(None, ZeroingString::from(""), create_mask, false)
		.unwrap();

	let wallet = Arc::new(Mutex::new(wallet));
	let owner_api = Owner::new(wallet.clone(), None, config.config_file_path.clone());

	(wallet, mask, owner_api)
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
