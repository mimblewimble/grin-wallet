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

use crate::cmd::wallet_args;
use crate::config::GlobalWalletConfig;
use clap::ArgMatches;
use grin_wallet_libwallet::NodeClient;
use semver::Version;
use std::thread;
use std::time::Duration;

const MIN_COMPAT_NODE_VERSION: &str = "4.0.0-alpha.1";

pub fn wallet_command<C>(
	wallet_args: &ArgMatches<'_>,
	config: GlobalWalletConfig,
	mut node_client: C,
) -> i32
where
	C: NodeClient + 'static,
{
	// just get defaults from the global config
	let wallet_config = config.members.clone().unwrap().wallet;

	let tor_config = config.members.unwrap().tor;

	// Check the node version info, and exit with report if we're not compatible
	let global_wallet_args = wallet_args::parse_global_args(&wallet_config, &wallet_args)
		.expect("Can't read configuration file");
	node_client.set_node_api_secret(global_wallet_args.node_api_secret.clone());

	// This will also cache the node version info for calls to foreign API check middleware
	if let Some(v) = node_client.clone().get_version_info() {
		if Version::parse(&v.node_version) < Version::parse(MIN_COMPAT_NODE_VERSION) {
			println!("The Grin Node in use (version {}) is outdated and incompatible with this wallet version.", v.node_version);
			println!(
				"Please update the node to version {} or later and try again.",
				MIN_COMPAT_NODE_VERSION
			);
			return 1;
		}
	}
	// ... if node isn't available, allow offline functions

	let res = wallet_args::wallet_command(
		wallet_args,
		wallet_config,
		tor_config,
		node_client,
		false,
		|_| {},
	);

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
