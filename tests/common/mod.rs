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
use grin_wallet_libwallet::{WalletInfo, WalletInst};
use grin_wallet_util::grin_core::global::{self, ChainTypes};
use grin_wallet_util::grin_keychain::ExtKeychain;
use util::secp::key::SecretKey;

use grin_wallet::cmd::wallet_args;
use grin_wallet_util::grin_api as api;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::thread;
use std::time::Duration;
use url::Url;

// Set up 2 wallets and launch the test proxy behind them
#[macro_export]
macro_rules! setup_proxy {
	($test_dir: expr, $chain: ident, $wallet1: ident, $client1: ident, $mask1: ident, $wallet2: ident, $client2: ident, $mask2: ident) => {
		// Create a new proxy to simulate server and wallet responses
		let mut wallet_proxy: WalletProxy<
			DefaultLCProvider<LocalWalletClient, ExtKeychain>,
			LocalWalletClient,
			ExtKeychain,
		> = WalletProxy::new($test_dir);
		let $chain = wallet_proxy.chain.clone();

		// load app yaml. If it don't exist, just say so and exit
		let yml = load_yaml!("../src/bin/grin-wallet.yml");
		let app = App::from_yaml(yml);

		// wallet init
		let arg_vec = vec!["grin-wallet", "-p", "password", "init", "-h"];
		// should create new wallet file
		let $client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
		execute_command(&app, $test_dir, "wallet1", &$client1, arg_vec.clone())?;

		// add wallet to proxy
		let config1 = initial_setup_wallet($test_dir, "wallet1");
		//config1.owner_api_listen_port = Some(13420);
		let ($wallet1, mask1_i) =
			instantiate_wallet(config1.clone(), $client1.clone(), "password", "default")?;
		let $mask1 = (&mask1_i).as_ref();
		wallet_proxy.add_wallet(
			"wallet1",
			$client1.get_send_instance(),
			$wallet1.clone(),
			mask1_i.clone(),
			);

		// Create wallet 2, which will run a listener
		let $client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
		execute_command(&app, $test_dir, "wallet2", &$client2, arg_vec.clone())?;

		let config2 = initial_setup_wallet($test_dir, "wallet2");
		//config2.api_listen_port = 23415;
		let ($wallet2, mask2_i) =
			instantiate_wallet(config2.clone(), $client2.clone(), "password", "default")?;
		let $mask2 = (&mask2_i).as_ref();
		wallet_proxy.add_wallet(
			"wallet2",
			$client2.get_send_instance(),
			$wallet2.clone(),
			mask2_i.clone(),
			);

		// Set the wallet proxy listener running
		thread::spawn(move || {
			if let Err(e) = wallet_proxy.run() {
				error!("Wallet Proxy error: {}", e);
				}
			});
	};
}

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

pub fn send_request<OUT>(
	id: u64,
	dest: &str,
	req: &str,
) -> Result<Result<OUT, WalletAPIReturnError>, api::Error>
where
	OUT: DeserializeOwned,
{
	let url = Url::parse(dest).unwrap();
	let req: Value = serde_json::from_str(req).unwrap();
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
		// deserialize result into expected type
		let value: OUT = serde_json::from_value(res["Ok"].clone()).unwrap();
		Ok(Ok(value))
	}
}

// Types to make working with json responses easier
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletAPIReturnError {
	message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetrieveSummaryInfoResp(pub bool, pub WalletInfo);
