// Copyright 2019 The Grin Developers
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

//! Common functions for wallet integration tests
extern crate grin_wallet;

use grin_wallet_impls::test_framework::LocalWalletClient;
use grin_wallet_util::grin_util as util;

use clap::{App, ArgMatches};
use std::path::PathBuf;
use std::sync::Arc;
use std::{env, fs};
use util::{Mutex, ZeroingString};

use grin_wallet_config::{GlobalWalletConfig, WalletConfig, GRIN_WALLET_DIR};
use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
use grin_wallet_libwallet::WalletInst;
use grin_wallet_util::grin_core::global::{self, ChainTypes};
use grin_wallet_util::grin_keychain::ExtKeychain;
use util::secp::key::SecretKey;

use grin_wallet::cmd::wallet_args;
use grin_wallet_util::grin_api as api;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::thread;
use std::time::Duration;
use url::Url;

fn clean_output_dir(test_dir: &str) {
	let _ = fs::remove_dir_all(test_dir);
}

pub fn setup(test_dir: &str) {
	util::init_test_logger();
	clean_output_dir(test_dir);
	global::set_mining_mode(ChainTypes::AutomatedTesting);
}

/// Create a wallet config file in the given current directory
pub fn config_command_wallet(
	dir_name: &str,
	wallet_name: &str,
) -> Result<(), grin_wallet_controller::Error> {
	let mut current_dir;
	let mut default_config = GlobalWalletConfig::default();
	current_dir = env::current_dir().unwrap_or_else(|e| {
		panic!("Error creating config file: {}", e);
	});
	current_dir.push(dir_name);
	current_dir.push(wallet_name);
	let _ = fs::create_dir_all(current_dir.clone());
	let mut config_file_name = current_dir.clone();
	config_file_name.push("grin-wallet.toml");
	if config_file_name.exists() {
		return Err(grin_wallet_controller::ErrorKind::ArgumentError(
			"grin-wallet.toml already exists in the target directory. Please remove it first"
				.to_owned(),
		))?;
	}
	default_config.update_paths(&current_dir);
	default_config
		.write_to_file(config_file_name.to_str().unwrap())
		.unwrap_or_else(|e| {
			panic!("Error creating config file: {}", e);
		});

	println!(
		"File {} configured and created",
		config_file_name.to_str().unwrap(),
	);
	Ok(())
}

/// Handles setup and detection of paths for wallet
pub fn initial_setup_wallet(dir_name: &str, wallet_name: &str) -> WalletConfig {
	let mut current_dir;
	current_dir = env::current_dir().unwrap_or_else(|e| {
		panic!("Error creating config file: {}", e);
	});
	current_dir.push(dir_name);
	current_dir.push(wallet_name);
	let _ = fs::create_dir_all(current_dir.clone());
	let mut config_file_name = current_dir.clone();
	config_file_name.push("grin-wallet.toml");
	GlobalWalletConfig::new(config_file_name.to_str().unwrap())
		.unwrap()
		.members
		.unwrap()
		.wallet
}

fn get_wallet_subcommand<'a>(
	wallet_dir: &str,
	wallet_name: &str,
	args: ArgMatches<'a>,
) -> ArgMatches<'a> {
	match args.subcommand() {
		("init", Some(init_args)) => {
			// wallet init command should spit out its config file then continue
			// (if desired)
			if init_args.is_present("here") {
				let _ = config_command_wallet(wallet_dir, wallet_name);
			}
			init_args.to_owned()
		}
		_ => ArgMatches::new(),
	}
}
//
// Helper to create an instance of the LMDB wallet
pub fn instantiate_wallet(
	mut wallet_config: WalletConfig,
	node_client: LocalWalletClient,
	passphrase: &str,
	account: &str,
) -> Result<
	(
		Arc<
			Mutex<
				Box<
					WalletInst<
						'static,
						DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
						LocalWalletClient,
						ExtKeychain,
					>,
				>,
			>,
		>,
		Option<SecretKey>,
	),
	grin_wallet_controller::Error,
> {
	wallet_config.chain_type = None;
	let mut wallet = Box::new(DefaultWalletImpl::<LocalWalletClient>::new(node_client).unwrap())
		as Box<
			WalletInst<
				DefaultLCProvider<'static, LocalWalletClient, ExtKeychain>,
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
	lc.set_wallet_directory(&wallet_config.data_file_dir);
	let keychain_mask = lc
		.open_wallet(None, ZeroingString::from(passphrase), true, false)
		.unwrap();
	let wallet_inst = lc.wallet_inst()?;
	wallet_inst.set_parent_key_id_by_name(account)?;
	Ok((Arc::new(Mutex::new(wallet)), keychain_mask))
}

pub fn execute_command(
	app: &App,
	test_dir: &str,
	wallet_name: &str,
	client: &LocalWalletClient,
	arg_vec: Vec<&str>,
) -> Result<String, grin_wallet_controller::Error> {
	let args = app.clone().get_matches_from(arg_vec);
	let _ = get_wallet_subcommand(test_dir, wallet_name, args.clone());
	let mut config = initial_setup_wallet(test_dir, wallet_name);
	//unset chain type so it doesn't get reset
	config.chain_type = None;
	wallet_args::wallet_command(&args, config.clone(), client.clone(), true)
}

pub fn post<IN>(url: &Url, api_secret: Option<String>, input: &IN) -> Result<String, api::Error>
where
	IN: Serialize,
{
	// TODO: change create_post_request to accept a url instead of a &str
	let req = api::client::create_post_request(url.as_str(), api_secret, input)?;
	let res = api::client::send_request(req)?;
	Ok(res)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletAPIReturnError {
	message: String,
}

pub fn send_request(
	id: u64,
	dest: &str,
	req: &str,
) -> Result<Result<Value, WalletAPIReturnError>, api::Error> {
	let url = Url::parse(dest).unwrap();
	let req: Value = serde_json::from_str(req).unwrap();
	println!("Request in: {}", req);
	let res: String = post(&url, None, &req).map_err(|e| {
		let err_string = format!("{}", e);
		println!("{}", err_string);
		thread::sleep(Duration::from_millis(200));
		e
	})?;
	let res = serde_json::from_str(&res).unwrap();
	let res = easy_jsonrpc::Response::from_json_response(res).unwrap();
	let res = res.outputs.get(&id).unwrap().clone().unwrap();
	if res["Err"] != json!(null) {
		Ok(Err(WalletAPIReturnError {
			message: res["Err"].as_str().unwrap().to_owned(),
		}))
	} else {
		Ok(Ok(res))
	}
}
