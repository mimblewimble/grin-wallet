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
use grin_wallet_util::grin_api as api;
use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_util as util;
use std::process::exit;

mod cmd;

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
	let args = App::from_yaml(yml).get_matches();

	let chain_type = if args.is_present("floonet") {
		global::ChainTypes::Floonet
	} else if args.is_present("usernet") {
		global::ChainTypes::UserTesting
	} else {
		global::ChainTypes::Mainnet
	};

	// Deal with configuration file creation
	match args.subcommand() {
		// wallet init command should spit out its config file then continue
		// (if desired)
		("init", Some(init_args)) => {
			if init_args.is_present("here") {
				cmd::config_command_wallet(&chain_type, config::WALLET_CONFIG_FILE_NAME);
			}
		}
		_ => {}
	}

	// Load relevant config, try and load a wallet config file
	let mut w = config::initial_setup_wallet(&chain_type).unwrap_or_else(|e| {
		panic!("Error loading wallet configuration: {}", e);
	});

	if !cmd::seed_exists(w.members.as_ref().unwrap().wallet.clone()) {
		if "init" == args.subcommand().0 || "recover" == args.subcommand().0 {
		} else {
			println!("Wallet seed file doesn't exist. Run `grin-wallet init` first");
			exit(1);
		}
	}

	// Load logging config
	let l = w.members.as_mut().unwrap().logging.clone().unwrap();
	init_logger(Some(l));
	info!(
		"Using wallet configuration file at {}",
		w.config_file_path.as_ref().unwrap().to_str().unwrap()
	);

	log_build_info();

	global::set_mining_mode(
		w.members
			.as_ref()
			.unwrap()
			.wallet
			.chain_type
			.as_ref()
			.unwrap()
			.clone(),
	);

	cmd::wallet_command(&args, w)
}
