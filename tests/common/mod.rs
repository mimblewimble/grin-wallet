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

//! Common functions for wallet integration tests
extern crate grin_wallet;

use grin_util as util;
use grin_wallet_config as config;
use grin_wallet_impls::test_framework::LocalWalletClient;

use clap::{App, ArgMatches};
use std::path::PathBuf;
use std::sync::Arc;
use std::{env, fs};
use util::{Mutex, ZeroingString};

use grin_core::global::{self, ChainTypes};
use grin_keychain::ExtKeychain;
use grin_util::{from_hex, static_secp_instance};
use grin_wallet_api::{EncryptedRequest, EncryptedResponse, JsonId};
use grin_wallet_config::{GlobalWalletConfig, WalletConfig, GRIN_WALLET_DIR};
use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
use grin_wallet_libwallet::{NodeClient, WalletInfo, WalletInst};
use util::secp::key::{PublicKey, SecretKey};

use grin_api as api;
use grin_wallet::cmd::wallet_args;

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

		let target = std::path::PathBuf::from(format!("{}/wallet1/grin-wallet.toml", $test_dir));
		println!("{:?}", target);
		if !target.exists() {
			execute_command(&app, $test_dir, "wallet1", &$client1, arg_vec.clone())?;
		}

		// add wallet to proxy
		let config1 = initial_setup_wallet($test_dir, "wallet1");
		let wallet_config1 = config1.clone().members.unwrap().wallet;
		//config1.owner_api_listen_port = Some(13420);
		let ($wallet1, mask1_i) = instantiate_wallet(
			wallet_config1.clone(),
			$client1.clone(),
			"password",
			"default",
		)?;
		let $mask1 = (&mask1_i).as_ref();
		wallet_proxy.add_wallet(
			"wallet1",
			$client1.get_send_instance(),
			$wallet1.clone(),
			mask1_i.clone(),
		);

		// Create wallet 2, which will run a listener
		let $client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());

		let target = std::path::PathBuf::from(format!("{}/wallet2/grin-wallet.toml", $test_dir));
		if !target.exists() {
			execute_command(&app, $test_dir, "wallet2", &$client2, arg_vec.clone())?;
		}

		let config2 = initial_setup_wallet($test_dir, "wallet2");
		let wallet_config2 = config2.clone().members.unwrap().wallet;
		//config2.api_listen_port = 23415;
		let ($wallet2, mask2_i) = instantiate_wallet(
			wallet_config2.clone(),
			$client2.clone(),
			"password",
			"default",
		)?;
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

#[allow(dead_code)]
pub fn clean_output_dir(test_dir: &str) {
	let _ = remove_dir_all::remove_dir_all(test_dir);
}

#[allow(dead_code)]
pub fn setup(test_dir: &str) {
	util::init_test_logger();
	clean_output_dir(test_dir);
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
}

/// Some tests require the global chain_type to be configured.
/// If tokio is used in any tests we need to ensure any threads spawned
/// have the chain_type configured correctly.
/// It is recommended to avoid relying on this if at all possible as global chain_type
/// leaks across multiple tests and will likely have unintended consequences.
#[allow(dead_code)]
pub fn setup_global_chain_type() {
	global::init_global_chain_type(global::ChainTypes::AutomatedTesting);
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
		return Err(grin_wallet_controller::Error::ArgumentError(
			"grin-wallet.toml already exists in the target directory. Please remove it first"
				.to_owned(),
		))?;
	}
	default_config.update_paths(&current_dir, &current_dir);
	default_config
		.write_to_file(config_file_name.to_str().unwrap(), false, None, None)
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
#[allow(dead_code)]
pub fn initial_setup_wallet(dir_name: &str, wallet_name: &str) -> GlobalWalletConfig {
	let mut current_dir;
	current_dir = env::current_dir().unwrap_or_else(|e| {
		panic!("Error creating config file: {}", e);
	});
	current_dir.push(dir_name);
	current_dir.push(wallet_name);
	let _ = fs::create_dir_all(current_dir.clone());
	let mut config_file_name = current_dir.clone();
	config_file_name.push("grin-wallet.toml");
	GlobalWalletConfig::new(config_file_name.to_str().unwrap()).unwrap()
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
#[allow(dead_code)]
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
	),
	grin_wallet_controller::Error,
> {
	wallet_config.chain_type = None;
	let mut wallet = Box::new(DefaultWalletImpl::<LocalWalletClient>::new(node_client).unwrap())
		as Box<
			dyn WalletInst<
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
	let _ = lc.set_top_level_directory(&wallet_config.data_file_dir);
	let keychain_mask = lc
		.open_wallet(None, ZeroingString::from(passphrase), true, false)
		.unwrap();
	let wallet_inst = lc.wallet_inst()?;
	wallet_inst.set_parent_key_id_by_name(account)?;
	Ok((Arc::new(Mutex::new(wallet)), keychain_mask))
}

#[allow(dead_code)]
pub fn execute_command(
	app: &App,
	test_dir: &str,
	wallet_name: &str,
	client: &LocalWalletClient,
	arg_vec: Vec<&str>,
) -> Result<String, grin_wallet_controller::Error> {
	let args = app.clone().get_matches_from(arg_vec);
	let _ = get_wallet_subcommand(test_dir, wallet_name, args.clone());
	let config = initial_setup_wallet(test_dir, wallet_name);
	let mut wallet_config = config.clone().members.unwrap().wallet;
	let tor_config = config.clone().members.unwrap().tor;
	//unset chain type so it doesn't get reset
	wallet_config.chain_type = None;
	wallet_args::wallet_command(
		&args,
		wallet_config.clone(),
		tor_config,
		client.clone(),
		true,
		|_| {},
	)
}

// as above, but without necessarily setting up the wallet
#[allow(dead_code)]
pub fn execute_command_no_setup<C, F>(
	app: &App,
	test_dir: &str,
	wallet_name: &str,
	client: &C,
	arg_vec: Vec<&str>,
	f: F,
) -> Result<String, grin_wallet_controller::Error>
where
	C: NodeClient + 'static + Clone,
	F: FnOnce(
		Arc<
			Mutex<
				Box<
					dyn WalletInst<
						'static,
						DefaultLCProvider<'static, C, ExtKeychain>,
						C,
						ExtKeychain,
					>,
				>,
			>,
		>,
	),
{
	let args = app.clone().get_matches_from(arg_vec);
	let _ = get_wallet_subcommand(test_dir, wallet_name, args.clone());
	let config = config::initial_setup_wallet(&ChainTypes::AutomatedTesting, None, true).unwrap();
	let mut wallet_config = config.clone().members.unwrap().wallet;
	wallet_config.chain_type = None;
	wallet_config.api_secret_path = None;
	wallet_config.node_api_secret_path = None;
	let tor_config = config.members.unwrap().tor.clone();
	wallet_args::wallet_command(&args, wallet_config, tor_config, client.clone(), true, f)
}

pub fn post<IN>(url: &Url, api_secret: Option<String>, input: &IN) -> Result<String, api::Error>
where
	IN: Serialize,
{
	// TODO: change create_post_request to accept a url instead of a &str
	let req = api::client::create_post_request(url.as_str(), api_secret, input)?;
	let res = api::client::send_request(req, api::client::TimeOut::default())?;
	Ok(res)
}

#[allow(dead_code)]
pub fn send_request<OUT>(
	id: u64,
	dest: &str,
	req: &str,
) -> Result<Result<OUT, WalletAPIReturnError>, api::Error>
where
	OUT: DeserializeOwned,
{
	let url = Url::parse(dest).unwrap();
	let req_val: Value = serde_json::from_str(req).unwrap();
	let res = post(&url, None, &req_val).map_err(|e| {
		let err_string = format!("{}", e);
		println!("{}", err_string);
		thread::sleep(Duration::from_millis(200));
		e
	})?;

	let res_val: Value = serde_json::from_str(&res).unwrap();
	// encryption error, just return the string
	if res_val["error"] != json!(null) {
		return Ok(Err(WalletAPIReturnError {
			message: res_val["error"]["message"].as_str().unwrap().to_owned(),
			code: res_val["error"]["code"].as_i64().unwrap() as i32,
		}));
	}

	let res = serde_json::from_str(&res).unwrap();
	let res = easy_jsonrpc_mw::Response::from_json_response(res).unwrap();
	let res = res.outputs.get(&id).unwrap().clone().unwrap();
	if res["Err"] != json!(null) {
		Ok(Err(WalletAPIReturnError {
			message: res["Err"].as_str().unwrap().to_owned(),
			code: res["error"]["code"].as_i64().unwrap() as i32,
		}))
	} else {
		// deserialize result into expected type
		let value: OUT = serde_json::from_value(res["Ok"].clone()).unwrap();
		Ok(Ok(value))
	}
}

#[allow(dead_code)]
pub fn send_request_enc<OUT>(
	sec_req_id: &JsonId,
	internal_request_id: u32,
	dest: &str,
	req: &str,
	shared_key: &SecretKey,
) -> Result<Result<OUT, WalletAPIReturnError>, api::Error>
where
	OUT: DeserializeOwned,
{
	let url = Url::parse(dest).unwrap();
	let req_val: Value = serde_json::from_str(req).unwrap();
	let req = EncryptedRequest::from_json(sec_req_id, &req_val, &shared_key).unwrap();
	let res = post(&url, None, &req).map_err(|e| {
		let err_string = format!("{}", e);
		println!("{}", err_string);
		thread::sleep(Duration::from_millis(200));
		e
	})?;

	let res_val: Value = serde_json::from_str(&res).unwrap();
	//println!("RES_VAL: {}", res_val);
	// encryption error, just return the string
	if res_val["error"] != json!(null) {
		return Ok(Err(WalletAPIReturnError {
			message: res_val["error"]["message"].as_str().unwrap().to_owned(),
			code: res_val["error"]["code"].as_i64().unwrap() as i32,
		}));
	}

	let enc_resp: EncryptedResponse = serde_json::from_str(&res).unwrap();
	let res = enc_resp.decrypt(shared_key).unwrap();
	if res["error"] != json!(null) {
		return Ok(Err(WalletAPIReturnError {
			message: res["error"]["message"].as_str().unwrap().to_owned(),
			code: res["error"]["code"].as_i64().unwrap() as i32,
		}));
	}
	let res = easy_jsonrpc_mw::Response::from_json_response(res).unwrap();
	let res = res
		.outputs
		.get(&(internal_request_id as u64))
		.unwrap()
		.clone()
		.unwrap();

	//println!("RES: {}", res);
	if res["Err"] != json!(null) {
		Ok(Err(WalletAPIReturnError {
			message: res["Err"].as_str().unwrap().to_owned(),
			code: res_val["error"]["code"].as_i64().unwrap() as i32,
		}))
	} else {
		// deserialize result into expected type
		let raw_value = res["Ok"].clone();
		let raw_value_str = serde_json::to_string_pretty(&raw_value).unwrap();
		//println!("Raw value: {}", raw_value_str);
		let ok_val = serde_json::from_str(&raw_value_str);
		match ok_val {
			Ok(v) => {
				let value: OUT = v;
				Ok(Ok(value))
			}
			Err(_) => {
				//println!("Error deserializing: {:?}", e);
				let value: OUT = serde_json::from_value(json!("Null")).unwrap();
				Ok(Ok(value))
			}
		}
	}
}

#[allow(dead_code)]
pub fn derive_ecdh_key(sec_key_str: &str, other_pubkey: &PublicKey) -> SecretKey {
	let sec_key_bytes = from_hex(sec_key_str).unwrap();
	let sec_key = {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		SecretKey::from_slice(&secp, &sec_key_bytes).unwrap()
	};

	let secp_inst = static_secp_instance();
	let secp = secp_inst.lock();

	let mut shared_pubkey = other_pubkey.clone();
	shared_pubkey.mul_assign(&secp, &sec_key).unwrap();

	let x_coord = shared_pubkey.serialize_vec(&secp, true);
	SecretKey::from_slice(&secp, &x_coord[1..]).unwrap()
}

// Types to make working with json responses easier
#[derive(Clone, Debug, Serialize, Deserialize, thiserror::Error)]
pub struct WalletAPIReturnError {
	pub message: String,
	pub code: i32,
}

impl std::fmt::Display for WalletAPIReturnError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{} - {}", self.code, &self.message)
	}
}

impl From<grin_wallet_controller::Error> for WalletAPIReturnError {
	fn from(error: grin_wallet_controller::Error) -> WalletAPIReturnError {
		WalletAPIReturnError {
			message: error.to_string(),
			code: -1,
		}
	}
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetrieveSummaryInfoResp(pub bool, pub WalletInfo);
