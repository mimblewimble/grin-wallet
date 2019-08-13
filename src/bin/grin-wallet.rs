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

//! Main for building the binary of a Grin Reference Wallet

#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;
use crate::core::global;
use crate::util::init_logger;
use clap::App;
use grin_wallet_config as config;
use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_util as util;
use std::env;

use grin_wallet::cmd;

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub fn info_strings() -> (String, String) {
	(
		format!(
			"This is Grin Wallet version {}{}, built for {} by {}.",
			built_info::PKG_VERSION,
			built_info::GIT_VERSION.map_or_else(|| "".to_owned(), |v| format!(" (git {})", v)),
			built_info::TARGET,
			built_info::RUSTC_VERSION,
		)
		.to_string(),
		format!(
			"Built with profile \"{}\", features \"{}\".",
			built_info::PROFILE,
			built_info::FEATURES_STR,
		)
		.to_string(),
	)
}

fn log_build_info() {
	let (basic_info, detailed_info) = info_strings();
	info!("{}", basic_info);
	debug!("{}", detailed_info);
}

fn main() {
	let exit_code = real_main();
	std::process::exit(exit_code);
}

fn real_main() -> i32 {
	let yml = load_yaml!("grin-wallet.yml");
	let args = App::from_yaml(yml)
		.version(built_info::PKG_VERSION)
		.get_matches();

	let chain_type = if args.is_present("floonet") {
		global::ChainTypes::Floonet
	} else if args.is_present("usernet") {
		global::ChainTypes::UserTesting
	} else {
		global::ChainTypes::Mainnet
	};

	let mut current_dir = None;

	// special cases for certain lifecycle commands
	match args.subcommand() {
		("init", Some(init_args)) => {
			if init_args.is_present("here") {
				current_dir = Some(env::current_dir().unwrap_or_else(|e| {
					panic!("Error creating config file: {}", e);
				}));
			}
		}
		("recover", _) => {}
		_ => {}
	}

	// Load relevant config, try and load a wallet config file
	// Use defaults for configuration if config file not found anywhere
	let mut config = config::initial_setup_wallet(&chain_type, current_dir).unwrap_or_else(|e| {
		panic!("Error loading wallet configuration: {}", e);
	});

	config.members.as_mut().unwrap().wallet.chain_type = Some(chain_type);

	// Load logging config
	let l = config.members.as_mut().unwrap().logging.clone().unwrap();
	init_logger(Some(l));
	info!(
		"Using wallet configuration file at {}",
		config.config_file_path.as_ref().unwrap().to_str().unwrap()
	);

	log_build_info();

	global::set_mining_mode(
		config
			.members
			.as_ref()
			.unwrap()
			.wallet
			.chain_type
			.as_ref()
			.unwrap()
			.clone(),
	);

	cmd::wallet_command(&args, config)
}
