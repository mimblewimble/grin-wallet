// Copyright 2019 The Grin Developers
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

//! Configuration file management

use dirs;
use rand::distributions::{Alphanumeric, Distribution};
use rand::thread_rng;
use std::env;
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::BufReader;
use std::io::Read;
use std::path::PathBuf;
use toml;

use crate::comments::insert_comments;
use crate::core::global;
use crate::types::{ConfigError, GlobalWalletConfig, GlobalWalletConfigMembers};
use crate::types::{TorConfig, WalletConfig};
use crate::util::logger::LoggingConfig;

/// Wallet configuration file name
pub const WALLET_CONFIG_FILE_NAME: &str = "grin-wallet.toml";
const WALLET_LOG_FILE_NAME: &str = "grin-wallet.log";
const GRIN_HOME: &str = ".grin";
/// Wallet data directory
pub const GRIN_WALLET_DIR: &str = "wallet_data";
/// Node API secret
pub const API_SECRET_FILE_NAME: &str = ".api_secret";
/// Owner API secret
pub const OWNER_API_SECRET_FILE_NAME: &str = ".owner_api_secret";

fn get_grin_path(
	chain_type: &global::ChainTypes,
	create_path: bool,
) -> Result<PathBuf, ConfigError> {
	// Check if grin dir exists
	let mut grin_path = match dirs::home_dir() {
		Some(p) => p,
		None => PathBuf::new(),
	};
	grin_path.push(GRIN_HOME);
	grin_path.push(chain_type.shortname());
	// Create if the default path doesn't exist
	if !grin_path.exists() && create_path {
		fs::create_dir_all(grin_path.clone())?;
	}

	if !grin_path.exists() {
		Err(ConfigError::PathNotFoundError(String::from(
			grin_path.to_str().unwrap(),
		)))
	} else {
		Ok(grin_path)
	}
}

fn check_config_current_dir(path: &str) -> Option<PathBuf> {
	let p = env::current_dir();
	let mut c = match p {
		Ok(c) => c,
		Err(_) => {
			return None;
		}
	};
	c.push(path);
	if c.exists() {
		return Some(c);
	}
	None
}

/// Whether a config file exists at the given directory
pub fn config_file_exists(path: &str) -> bool {
	let mut path = PathBuf::from(path);
	path.push(WALLET_CONFIG_FILE_NAME);
	path.exists()
}

/// Create file with api secret
pub fn init_api_secret(api_secret_path: &PathBuf) -> Result<(), ConfigError> {
	let mut api_secret_file = File::create(api_secret_path)?;
	let api_secret: String = Alphanumeric
		.sample_iter(&mut thread_rng())
		.take(20)
		.collect();
	api_secret_file.write_all(api_secret.as_bytes())?;
	Ok(())
}

/// Check if file contains a secret and nothing else
pub fn check_api_secret(api_secret_path: &PathBuf) -> Result<(), ConfigError> {
	let api_secret_file = File::open(api_secret_path)?;
	let buf_reader = BufReader::new(api_secret_file);
	let mut lines_iter = buf_reader.lines();
	let first_line = lines_iter.next();
	if first_line.is_none() || first_line.unwrap().is_err() {
		fs::remove_file(api_secret_path)?;
		init_api_secret(api_secret_path)?;
	}
	Ok(())
}

/// Check that the api secret file exists and is valid
fn check_api_secret_file(
	chain_type: &global::ChainTypes,
	data_path: Option<PathBuf>,
	file_name: &str,
) -> Result<(), ConfigError> {
	let grin_path = match data_path {
		Some(p) => p,
		None => get_grin_path(chain_type, false)?,
	};
	let mut api_secret_path = grin_path;
	api_secret_path.push(file_name);
	if !api_secret_path.exists() {
		init_api_secret(&api_secret_path)
	} else {
		check_api_secret(&api_secret_path)
	}
}

/// Handles setup and detection of paths for wallet
pub fn initial_setup_wallet(
	chain_type: &global::ChainTypes,
	data_path: Option<PathBuf>,
	create_path: bool,
) -> Result<GlobalWalletConfig, ConfigError> {
	if create_path {
		if let Some(p) = data_path.clone() {
			fs::create_dir_all(p)?;
		}
	}
	// Use config file if current directory if it exists, .grin home otherwise
	let (path, config) = if let Some(p) = check_config_current_dir(WALLET_CONFIG_FILE_NAME) {
		let mut path = p.clone();
		path.pop();
		(path, GlobalWalletConfig::new(p.to_str().unwrap())?)
	} else {
		// Check if grin dir exists
		let grin_path = match data_path {
			Some(p) => p,
			None => get_grin_path(chain_type, create_path)?,
		};

		// Get path to default config file
		let mut config_path = grin_path.clone();
		config_path.push(WALLET_CONFIG_FILE_NAME);

		// Return defaults if file doesn't exist
		match config_path.clone().exists() {
			false => {
				let mut default_config = GlobalWalletConfig::for_chain(chain_type);
				default_config.config_file_path = Some(config_path);
				// update paths relative to current dir
				default_config.update_paths(&grin_path);
				(grin_path, default_config)
			}
			true => {
				let mut path = config_path.clone();
				path.pop();
				(
					path,
					GlobalWalletConfig::new(config_path.to_str().unwrap())?,
				)
			}
		}
	};

	check_api_secret_file(chain_type, Some(path.clone()), OWNER_API_SECRET_FILE_NAME)?;
	check_api_secret_file(chain_type, Some(path), API_SECRET_FILE_NAME)?;
	Ok(config)
}

impl Default for GlobalWalletConfigMembers {
	fn default() -> GlobalWalletConfigMembers {
		GlobalWalletConfigMembers {
			logging: Some(LoggingConfig::default()),
			tor: Some(TorConfig::default()),
			wallet: WalletConfig::default(),
		}
	}
}

impl Default for GlobalWalletConfig {
	fn default() -> GlobalWalletConfig {
		GlobalWalletConfig {
			config_file_path: None,
			members: Some(GlobalWalletConfigMembers::default()),
		}
	}
}

impl GlobalWalletConfig {
	/// Same as GlobalConfig::default() but further tweaks parameters to
	/// apply defaults for each chain type
	pub fn for_chain(chain_type: &global::ChainTypes) -> GlobalWalletConfig {
		let mut defaults_conf = GlobalWalletConfig::default();
		let mut defaults = &mut defaults_conf.members.as_mut().unwrap().wallet;
		defaults.chain_type = Some(chain_type.clone());

		match *chain_type {
			global::ChainTypes::Mainnet => {}
			global::ChainTypes::Testnet => {
				defaults.api_listen_port = 13415;
				defaults.check_node_api_http_addr = "http://127.0.0.1:13413".to_owned();
			}
			global::ChainTypes::UserTesting => {
				defaults.api_listen_port = 23415;
				defaults.check_node_api_http_addr = "http://127.0.0.1:23413".to_owned();
			}
			_ => {}
		}
		defaults_conf
	}
	/// Requires the path to a config file
	pub fn new(file_path: &str) -> Result<GlobalWalletConfig, ConfigError> {
		let mut return_value = GlobalWalletConfig::default();
		return_value.config_file_path = Some(PathBuf::from(&file_path));

		// Config file path is given but not valid
		let config_file = return_value.config_file_path.clone().unwrap();
		if !config_file.exists() {
			return Err(ConfigError::FileNotFoundError(String::from(
				config_file.to_str().unwrap(),
			)));
		}

		// Try to parse the config file if it exists, explode if it does exist but
		// something's wrong with it
		return_value.read_config()
	}

	/// Read config
	fn read_config(mut self) -> Result<GlobalWalletConfig, ConfigError> {
		let mut file = File::open(self.config_file_path.as_mut().unwrap())?;
		let mut contents = String::new();
		file.read_to_string(&mut contents)?;
		let fixed = GlobalWalletConfig::fix_warning_level(contents);
		let decoded: Result<GlobalWalletConfigMembers, toml::de::Error> = toml::from_str(&fixed);
		match decoded {
			Ok(gc) => {
				self.members = Some(gc);
				Ok(self)
			}
			Err(e) => Err(ConfigError::ParseError(
				String::from(self.config_file_path.as_mut().unwrap().to_str().unwrap()),
				format!("{}", e),
			)),
		}
	}

	/// Update paths
	pub fn update_paths(&mut self, wallet_home: &PathBuf) {
		let mut wallet_path = wallet_home.clone();
		wallet_path.push(GRIN_WALLET_DIR);
		self.members.as_mut().unwrap().wallet.data_file_dir =
			wallet_path.to_str().unwrap().to_owned();
		let mut secret_path = wallet_home.clone();
		secret_path.push(OWNER_API_SECRET_FILE_NAME);
		self.members.as_mut().unwrap().wallet.api_secret_path =
			Some(secret_path.to_str().unwrap().to_owned());
		let mut node_secret_path = wallet_home.clone();
		node_secret_path.push(API_SECRET_FILE_NAME);
		self.members.as_mut().unwrap().wallet.node_api_secret_path =
			Some(node_secret_path.to_str().unwrap().to_owned());
		let mut log_path = wallet_home.clone();
		log_path.push(WALLET_LOG_FILE_NAME);
		self.members
			.as_mut()
			.unwrap()
			.logging
			.as_mut()
			.unwrap()
			.log_file_path = log_path.to_str().unwrap().to_owned();
		let tor_path = wallet_home.clone();
		self.members
			.as_mut()
			.unwrap()
			.tor
			.as_mut()
			.unwrap()
			.send_config_dir = tor_path.to_str().unwrap().to_owned();
	}

	/// Serialize config
	pub fn ser_config(&mut self) -> Result<String, ConfigError> {
		let encoded: Result<String, toml::ser::Error> =
			toml::to_string(self.members.as_mut().unwrap());
		match encoded {
			Ok(enc) => Ok(enc),
			Err(e) => Err(ConfigError::SerializationError(format!("{}", e))),
		}
	}

	/// Write configuration to a file
	pub fn write_to_file(&mut self, name: &str) -> Result<(), ConfigError> {
		let conf_out = self.ser_config()?;
		let fixed_config = GlobalWalletConfig::fix_log_level(conf_out);
		let commented_config = insert_comments(fixed_config);
		let mut file = File::create(name)?;
		file.write_all(commented_config.as_bytes())?;
		Ok(())
	}

	// For forwards compatibility old config needs `Warning` log level changed to standard log::Level `WARN`
	fn fix_warning_level(conf: String) -> String {
		conf.replace("Warning", "WARN")
	}

	// For backwards compatibility only first letter of log level should be capitalised.
	fn fix_log_level(conf: String) -> String {
		conf.replace("TRACE", "Trace")
			.replace("DEBUG", "Debug")
			.replace("INFO", "Info")
			.replace("WARN", "Warning")
			.replace("ERROR", "Error")
	}
}
