// Copyright 2026 The Grin Developers
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

extern crate grin_wallet_api as api;
extern crate grin_wallet_config as config;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;

use config::config::{get_global_config, set_global_config};
use config::GlobalWalletConfig;
use impls::test_framework::LocalWalletClient;
use libwallet::{InitTxArgs, InitTxSendArgs};
use std::fs;
use std::path::{Path, PathBuf};

mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

fn snapshot(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
	fn collect(root: &Path, path: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
		for entry in fs::read_dir(path).unwrap() {
			let entry = entry.unwrap();
			let path = entry.path();
			if path.is_dir() {
				collect(root, &path, files);
			} else if path.file_name().and_then(|name| name.to_str()) != Some("lock.mdb") {
				files.push((
					path.strip_prefix(root).unwrap().into(),
					fs::read(path).unwrap(),
				));
			}
		}
	}

	let mut files = vec![];
	collect(path, path, &mut files);
	files.sort_by(|left, right| left.0.cmp(&right.0));
	files
}

#[test]
fn tor_disable() {
	let test_dir = "test_output/config_api_tor";
	setup(test_dir);
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	create_wallet_and_add!(
		client,
		wallet,
		mask,
		test_dir,
		"wallet",
		None,
		&mut wallet_proxy,
		false
	);
	let path = PathBuf::from(test_dir).join("grin-wallet.toml");
	let mut config =
		GlobalWalletConfig::for_chain(&grin_core::global::ChainTypes::AutomatedTesting, &path);
	config
		.write_to_file(path.to_str().unwrap(), false, None, None)
		.unwrap();
	set_global_config(config);
	let contents = fs::read_to_string(&path)
		.unwrap()
		.replace("api_listen_port = 3415", "api_listen_port = 3416");
	fs::write(&path, contents).unwrap();

	let owner = api::Owner::new(wallet.clone(), None, path.clone());
	owner.set_tor_config(None).unwrap();

	let stored_config = GlobalWalletConfig::new(path.clone()).unwrap();
	assert_eq!(stored_config.members.wallet.api_listen_port, 3416);
	let stored = stored_config.tor_config();
	let cached = get_global_config(&path).unwrap().tor_config();
	assert!(!stored.use_tor_listener);
	assert_eq!(stored.skip_send_attempt, Some(true));
	assert_eq!(cached, stored);

	drop(owner);
	drop(wallet);
	drop(wallet_proxy);
	clean_output_dir(test_dir);
}

#[test]
fn send_preflight() {
	let test_dir = "test_output/config_api_send";
	setup(test_dir);
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	create_wallet_and_add!(
		client,
		wallet,
		mask,
		test_dir,
		"wallet",
		None,
		&mut wallet_proxy,
		false
	);
	let owner = api::Owner::new(
		wallet.clone(),
		None,
		PathBuf::from(test_dir).join("missing.toml"),
	);
	let mask = mask.as_ref();
	let (_, before_txs) = owner.retrieve_txs(mask, false, None, None, None).unwrap();
	assert!(before_txs.is_empty());
	let wallet_data = PathBuf::from(test_dir).join("wallet/wallet_data");
	let before_data = snapshot(&wallet_data);
	assert!(before_data.iter().any(|(path, _)| path.starts_with("db")));
	let args = InitTxArgs {
		amount: 1,
		send_args: Some(InitTxSendArgs {
			dest: "unused".into(),
			post_tx: false,
			fluff: false,
			skip_tor: Some(true),
		}),
		..Default::default()
	};

	let error = owner.init_send_tx(mask, args).unwrap_err();
	assert!(error.to_string().contains("Configuration file not found"));

	let (_, after_txs) = owner.retrieve_txs(mask, false, None, None, None).unwrap();
	assert!(after_txs.is_empty());
	assert_eq!(snapshot(&wallet_data), before_data);

	drop(owner);
	drop(wallet);
	drop(wallet_proxy);
	clean_output_dir(test_dir);
}
