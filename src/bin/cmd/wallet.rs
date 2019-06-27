// Copyright 2018 The Grin Developers
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

use crate::cmd::wallet_args;
use crate::config::GlobalWalletConfig;
use clap::ArgMatches;
use grin_wallet_config::WalletConfig;
use grin_wallet_impls::{HTTPNodeClient, WalletSeed, SEED_FILE};
use grin_wallet_libwallet::NodeClient;
use semver::Version;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const MIN_COMPAT_NODE_VERSION: &str = "2.0.0-beta.1";

pub fn _init_wallet_seed(wallet_config: WalletConfig, password: &str) {
	if let Err(_) = WalletSeed::from_file(&wallet_config, password) {
		WalletSeed::init_file(&wallet_config, 32, None, password)
			.expect("Failed to create wallet seed file.");
	};
}

pub fn seed_exists(wallet_config: WalletConfig) -> bool {
	let mut data_file_dir = PathBuf::new();
	data_file_dir.push(wallet_config.data_file_dir);
	data_file_dir.push(SEED_FILE);
	if data_file_dir.exists() {
		true
	} else {
		false
	}
}

pub fn wallet_command(wallet_args: &ArgMatches<'_>, config: GlobalWalletConfig) -> i32 {
	// just get defaults from the global config
	let wallet_config = config.members.unwrap().wallet;

	// Check the node version info, and exit with report if we're not compatible
	let mut node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
	let global_wallet_args = wallet_args::parse_global_args(&wallet_config, &wallet_args)
		.expect("Can't read configuration file");
	node_client.set_node_api_secret(global_wallet_args.node_api_secret.clone());

	// This will also cache the node version info for calls to foreign API check middleware
	if let Some(v) = node_client.clone().get_version_info() {
		// Isn't going to happen just yet (as of 2.0.0) but keep this here for
		// the future. the nodeclient's get_version_info will return 1.0 if
		// it gets a 404 for the version function
		if Version::parse(&v.node_version) < Version::parse(MIN_COMPAT_NODE_VERSION) {
			let version = if v.node_version == "1.0.0" {
				"1.0.x series"
			} else {
				&v.node_version
			};
			println!("Specified Grin Node (version {}) is outdated and incompatible with this wallet version", version);
			println!("Please update the node or use a different one");
			return 1;
		}
	}
	// ... if node isn't available, allow offline functions

	let res = wallet_args::wallet_command(wallet_args, wallet_config, node_client);

	// we need to give log output a chance to catch up before exiting
	thread::sleep(Duration::from_millis(100));

	if let Err(e) = res {
		println!("Wallet command failed: {}", e);
		1
	} else {
		println!(
			"Command '{}' completed successfully",
			wallet_args.subcommand().0
		);
		0
	}
}
