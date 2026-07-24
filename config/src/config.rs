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

//! Configuration file management

use crate::comments::insert_comments;
use crate::core::global;
use crate::types::{
	ConfigError, GlobalWalletConfig, GlobalWalletConfigMembers, TorBridgeConfig, TorProxyConfig,
};
use crate::types::{TorConfig, WalletConfig};
use crate::util::logger::LoggingConfig;
use crate::util::{Mutex, RwLock};

use lazy_static::lazy_static;
use rand::distributions::{Alphanumeric, Distribution};
use rand::{thread_rng, Rng};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::prelude::*;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use toml;
use toml_edit::{DocumentMut, Table};

type ConfigListeners = HashMap<String, Sender<()>>;
type ConfigRegistry = HashMap<PathBuf, (GlobalWalletConfig, ConfigListeners)>;

lazy_static! {
	/// Global configuration instances and change listeners mapped to config path.
	static ref CONFIG_INSTANCES: Arc<RwLock<ConfigRegistry>> =
		Arc::new(RwLock::new(HashMap::new()));
	static ref CONFIG_SAVE_LOCK: Mutex<()> = Mutex::new(());
}

fn cache_loaded_config(
	configs: &mut ConfigRegistry,
	config_path: &Path,
	config: GlobalWalletConfig,
) -> GlobalWalletConfig {
	match configs.entry(config_path.to_path_buf()) {
		Entry::Vacant(entry) => {
			entry.insert((config.clone(), HashMap::new()));
			config
		}
		Entry::Occupied(entry) => entry.get().0.clone(),
	}
}

/// Wallet configuration file name
pub const WALLET_CONFIG_FILE_NAME: &str = "grin-wallet.toml";
/// Wallet logging file name
const WALLET_LOG_FILE_NAME: &str = "grin-wallet.log";
/// .grin folder, usually in home/.grin
pub const GRIN_HOME: &str = ".grin";
/// Wallet data directory
pub const GRIN_WALLET_DIR: &str = "wallet_data";
/// Node API secret
pub const API_SECRET_FILE_NAME: &str = ".foreign_api_secret";
/// Owner API secret
pub const OWNER_API_SECRET_FILE_NAME: &str = ".owner_api_secret";

fn set_global_config(config: GlobalWalletConfig) {
	let mut configs = CONFIG_INSTANCES.write();
	let mut listeners = if let Some((_, l)) = configs.get(&config.config_file_path) {
		l.clone()
	} else {
		HashMap::new()
	};
	// Update config.
	configs.insert(
		config.config_file_path.clone(),
		(config.clone(), listeners.clone()),
	);
	// Notify listeners.
	let mut failed = vec![];
	for l in listeners.clone() {
		match l.1.send(()) {
			Ok(_) => {}
			Err(_) => {
				failed.push(l.0.to_string());
			}
		}
	}
	for f in &failed {
		listeners.remove(f);
	}
	// Update listener list.
	if !failed.is_empty() {
		configs.insert(config.config_file_path.clone(), (config, listeners));
	}
}

/// Reload configuration from disk and update the global instance.
pub fn reload_global_config(config_path: &Path) -> Result<GlobalWalletConfig, ConfigError> {
	let _save_lock = CONFIG_SAVE_LOCK.lock();
	let config = GlobalWalletConfig::new(config_path.to_path_buf())?;
	set_global_config(config.clone());
	Ok(config)
}

/// Get global configuration using provided path.
pub fn get_global_config(config_path: &Path) -> Result<GlobalWalletConfig, ConfigError> {
	{
		let configs = CONFIG_INSTANCES.read();
		if let Some((config, _)) = configs.get(config_path) {
			return Ok(config.clone());
		}
	}
	let config = GlobalWalletConfig::new(config_path.to_path_buf())?;
	let mut configs = CONFIG_INSTANCES.write();
	Ok(cache_loaded_config(&mut configs, config_path, config))
}

/// Load, update and save a configuration as one operation.
pub fn update_global_config<F>(config_path: &Path, update: F) -> Result<(), ConfigError>
where
	F: FnOnce(&mut GlobalWalletConfig) -> Result<(), ConfigError>,
{
	let _save_lock = CONFIG_SAVE_LOCK.lock();
	let mut config = GlobalWalletConfig::new(config_path.to_path_buf())?;
	update(&mut config)?;
	config.save_locked()
}

/// Add listener on config change.
pub fn add_global_config_listener(config_path: &PathBuf, listener_id: &str, tx: Sender<()>) {
	let mut w_l = CONFIG_INSTANCES.write();
	match w_l.get_mut(config_path) {
		None => {}
		Some((_, listeners)) => {
			listeners.insert(listener_id.to_string(), tx);
		}
	}
}

/// Remove listener on config change.
pub fn remove_global_config_listener(config_path: &PathBuf, listener_id: &str) {
	let mut w_l = CONFIG_INSTANCES.write();
	match w_l.get_mut(config_path) {
		None => {}
		Some((_, listeners)) => {
			listeners.remove(listener_id);
		}
	}
}

/// Function to locate the wallet dir and grin-wallet.toml in the order
/// a) config in top-dir if provided, b) in working dir, c) default dir
/// Function to get wallet dir and create dirs if not existing
pub fn get_wallet_path(
	chain_type: &global::ChainTypes,
	create_path: bool,
) -> Result<PathBuf, ConfigError> {
	// A - Detect grin-wallet.toml in working dir
	let mut config_path = env::current_dir()?;
	config_path.push(WALLET_CONFIG_FILE_NAME);
	if create_path == false && config_path.exists() {
		config_path.pop();
		println!("Detected 'grin-wallet.toml' in working dir - opening associated wallet");
		return Ok(config_path);
	};
	// B - Select home directory
	let mut wallet_path = dirs::home_dir().unwrap_or_else(|| PathBuf::new());
	wallet_path.push(GRIN_HOME);
	wallet_path.push(chain_type.shortname());
	// Create if the default path doesn't exist
	if !wallet_path.exists() && create_path {
		fs::create_dir_all(wallet_path.clone())?;
	}
	// Throw an error if the path still does not exist
	if !wallet_path.exists() {
		Err(ConfigError::PathNotFoundError(String::from(
			wallet_path.to_str().unwrap(),
		)))
	} else {
		Ok(wallet_path)
	}
}

/// Smart function to detect the nodes .foreign_api_secret file in the order
/// a) top-dir, b) home directory - create directory if needed
pub fn get_node_path(
	data_path: Option<PathBuf>,
	chain_type: &global::ChainTypes,
) -> Result<PathBuf, ConfigError> {
	let node_path = match data_path {
		// 1) A If top dir provided and api_secret exist, return top dir
		Some(path) => {
			let mut node_path = path;
			node_path.push(GRIN_HOME);
			node_path.push(chain_type.shortname());
			node_path.push(API_SECRET_FILE_NAME);
			if node_path.exists() {
				node_path.pop();
				Ok(node_path)
			// 1) B If top dir exists, but no api_secret, return home dir
			} else {
				let mut node_path = dirs::home_dir().unwrap_or_else(|| PathBuf::new());
				node_path.push(GRIN_HOME);
				node_path.push(chain_type.shortname());
				Ok(node_path)
			}
		}
		// 2) If there is no top_dir provided, always return home dir
		None => {
			let mut node_path = dirs::home_dir().unwrap_or_else(|| PathBuf::new());
			node_path.push(GRIN_HOME);
			node_path.push(chain_type.shortname());
			Ok(node_path)
		}
	};
	node_path
}

/// Checks if config in current working dir
#[allow(dead_code)]
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
		None => get_node_path(data_path, chain_type)?,
	};
	let mut api_secret_path = grin_path;
	api_secret_path.push(file_name);
	if !api_secret_path.exists() {
		init_api_secret(&api_secret_path)
	} else {
		check_api_secret(&api_secret_path)
	}
}

/// Initial wallet setup does the following
/// 1) Load wallet config if run without 'init' 2) create wallet if run with 'init'
/// Try in this order:
/// a) current dir as template,
/// b) in top path, or
/// c) .grin home
/// - load default config values
/// - update the wallet and node dir to the correct paths
/// - if grin-wallet.toml exists, but the wallet data dir does not, load config and continue wallet generation
/// - Automatically detect grin-wallet.toml in current directory
pub fn initial_setup_wallet(
	chain_type: &global::ChainTypes,
	mut data_path: Option<PathBuf>,
	create_path: bool,
) -> Result<GlobalWalletConfig, ConfigError> {
	// Fixing the input path when run with -here or -t (top-dir)
	// - Fix top-dir path to  compensate for bug on Linux to handle "\"
	// - Convert top-dir path to be always absolute for config generation
	// - Fix for Windows 10/11 to strip the '\\?\' prefix added to the path
	if let Some(p) = &data_path {
		if let Some(p_str) = p.to_str() {
			let fixed_str = p_str.replace("\\", "/");
			let fixed_path = PathBuf::from(fixed_str);
			if create_path {
				fs::create_dir_all(&fixed_path)?;
			}
			let absolute_path = if fixed_path.is_absolute() {
				fixed_path.canonicalize()?
			} else {
				env::current_dir()?.join(&fixed_path).canonicalize()?
			};
			let absolute_path = PathBuf::from(absolute_path.to_str().unwrap().replace(r"\\?\", ""));
			data_path = Some(absolute_path); // Store the updated path
		}
	}

	// Get wallet data_dir path if none provided
	let wallet_path = match data_path {
		Some(p) => p,
		None => get_wallet_path(chain_type, create_path)?,
	};
	println!("Wallet path: {}", wallet_path.display());
	// Get path to the node directory,
	let node_path = get_node_path(Some(wallet_path.clone()), chain_type)?;

	// Get config path and data path
	let mut config_path = wallet_path.clone();
	config_path.push(WALLET_CONFIG_FILE_NAME);
	let mut data_dir = wallet_path.clone();
	data_dir.push(GRIN_WALLET_DIR);
	// Check if a config exists in the working dir, if so load it
	let (path, config) = match config_path.clone().exists() {
		// If the config does not exist, load default and updated node and wallet dir
		false => {
			let mut default_config = GlobalWalletConfig::for_chain(chain_type, &config_path);
			default_config.update_paths(&wallet_path, &node_path);

			// Write config file
			let res =
				default_config.write_to_file(config_path.to_str().unwrap(), false, None, None);

			if let Err(e) = res {
				let msg = format!(
					"Error creating config file as ({}): {}",
					config_path.to_str().unwrap(),
					e
				);
				return Err(ConfigError::SerializationError(msg));
			}

			(wallet_path, default_config)
		}

		// Return config if not run with init
		true => {
			// If run with init and seed do not yet exists, continue, else throw error
			if data_dir.exists() && create_path == true {
				let msg = format!(
					"{} already exists in the target directory ({}). Please remove it first",
					config_path.to_str().unwrap(),
					data_dir.to_str().unwrap(),
				);
				return Err(ConfigError::SerializationError(msg));
			} else {
				let config = GlobalWalletConfig::new(config_path)?;
				(wallet_path, config)
			}
		}
	};

	// Set global config instance.
	set_global_config(config.clone());

	// Check API secrets, if ok, return config
	check_api_secret_file(chain_type, Some(path.clone()), OWNER_API_SECRET_FILE_NAME)?;
	check_api_secret_file(chain_type, Some(path), API_SECRET_FILE_NAME)?;

	Ok(config)
}

impl Default for GlobalWalletConfigMembers {
	fn default() -> GlobalWalletConfigMembers {
		GlobalWalletConfigMembers {
			config_file_version: Some(2),
			logging: Some(LoggingConfig::default()),
			tor: Some(TorConfig::default()),
			wallet: WalletConfig::default(),
		}
	}
}

impl GlobalWalletConfig {
	/// Same as GlobalConfig::default() but further tweaks parameters to
	/// apply defaults for each chain type
	pub fn for_chain(chain_type: &global::ChainTypes, file_path: &PathBuf) -> GlobalWalletConfig {
		let mut defaults_conf = GlobalWalletConfig {
			config_file_path: file_path.clone(),
			members: GlobalWalletConfigMembers::default(),
		};
		let defaults = &mut defaults_conf.members.wallet;
		defaults.chain_type = Some(*chain_type);

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

	/// Return the configured Tor settings, resolving the legacy default when the
	/// config file does not yet contain a `[tor]` section.
	pub fn tor_config(&self) -> TorConfig {
		self.members.tor.clone().unwrap_or_else(|| TorConfig {
			send_config_dir: self.members.wallet.data_file_dir.clone(),
			..TorConfig::default()
		})
	}

	/// Requires the path to a config file
	pub fn new(config_file_path: PathBuf) -> Result<GlobalWalletConfig, ConfigError> {
		let return_value = GlobalWalletConfig {
			config_file_path,
			members: GlobalWalletConfigMembers::default(),
		};

		// Config file path is given but not valid
		let config_file = &return_value.config_file_path;
		if !config_file.exists() {
			return Err(ConfigError::FileNotFoundError(
				config_file.display().to_string(),
			));
		}

		// Try to parse the config file if it exists, explode if it does exist but
		// something's wrong with it
		return_value.read_config()
	}

	/// Read config
	fn read_config(mut self) -> Result<GlobalWalletConfig, ConfigError> {
		let config_file_path = &self.config_file_path;
		let contents = fs::read_to_string(config_file_path.clone())?;
		let migrated = GlobalWalletConfig::migrate_config_file_version_none_to_2(
			contents,
			config_file_path.to_owned(),
		)?;
		let fixed = GlobalWalletConfig::fix_warning_level(migrated);
		let decoded: Result<GlobalWalletConfigMembers, toml::de::Error> = toml::from_str(&fixed);
		match decoded {
			Ok(gc) => {
				self.members = gc;
				Ok(self)
			}
			Err(e) => Err(ConfigError::ParseError(
				self.config_file_path.display().to_string(),
				format!("{}", e),
			)),
		}
	}

	/// Update paths
	pub fn update_paths(&mut self, wallet_home: &PathBuf, node_home: &Path) {
		let mut data_file_dir = wallet_home.to_path_buf();
		let mut node_secret_path = node_home.to_path_buf();
		let mut secret_path = wallet_home.to_path_buf();
		let mut log_path = wallet_home.to_path_buf();
		let tor_path = wallet_home.to_path_buf();
		node_secret_path.push(API_SECRET_FILE_NAME);
		data_file_dir.push(GRIN_WALLET_DIR);
		secret_path.push(OWNER_API_SECRET_FILE_NAME);
		log_path.push(WALLET_LOG_FILE_NAME);
		self.members.wallet.data_file_dir = data_file_dir.to_str().unwrap().to_owned();
		self.members.wallet.node_api_secret_path =
			Some(node_secret_path.to_str().unwrap().to_owned());
		self.members.wallet.api_secret_path = Some(secret_path.to_str().unwrap().to_owned());
		self.members.logging.as_mut().unwrap().log_file_path =
			log_path.to_str().unwrap().to_owned();
		self.members.tor.as_mut().unwrap().send_config_dir = tor_path.to_str().unwrap().to_owned();
	}

	/// Serialize config
	pub fn ser_config(&mut self) -> Result<String, ConfigError> {
		let encoded: Result<String, toml::ser::Error> = toml::to_string(&self.members);
		match encoded {
			Ok(enc) => Ok(enc),
			Err(e) => Err(ConfigError::SerializationError(format!("{}", e))),
		}
	}

	/// Write configuration to a file
	pub fn write_to_file(
		&mut self,
		name: &str,
		migration: bool,
		old_config: Option<String>,
		old_version: Option<u32>,
	) -> Result<(), ConfigError> {
		self.write_to_path(Path::new(name), migration, old_config, old_version)
	}

	fn write_to_path(
		&mut self,
		name: &Path,
		migration: bool,
		old_config: Option<String>,
		old_version: Option<u32>,
	) -> Result<(), ConfigError> {
		let conf_out = GlobalWalletConfig::fix_log_level(self.ser_config()?);
		let commented_config = if migration {
			let old_config = old_config.unwrap();
			let new_config = insert_comments(conf_out);
			GlobalWalletConfig::merge_config(&old_config, &new_config, old_version)?
		} else {
			insert_comments(conf_out)
		};
		let mut file = File::create(name)?;
		file.write_all(commented_config.as_bytes())?;
		Ok(())
	}

	fn merge_config(
		old_config: &str,
		new_config: &str,
		old_version: Option<u32>,
	) -> Result<String, ConfigError> {
		fn update(
			current: &mut Table,
			new: &Table,
			known: Option<&Table>,
			path: &str,
			replace_logging_comments: bool,
		) {
			if let Some(known) = known {
				let removed = known
					.iter()
					.filter(|(key, _)| !new.contains_key(key))
					.map(|(key, _)| key.to_owned())
					.collect::<Vec<_>>();
				for key in removed {
					current.remove(&key);
				}
			}

			for (key, new_item) in new {
				let item_path = if path.is_empty() {
					key.to_owned()
				} else {
					format!("{}.{}", path, key)
				};
				if let (Some(current_table), Some(new_table)) = (
					current.get_mut(key).and_then(|item| item.as_table_mut()),
					new_item.as_table(),
				) {
					if replace_logging_comments && item_path == "logging" {
						*current_table.decor_mut() = new_table.decor().clone();
					}
					update(
						current_table,
						new_table,
						known
							.and_then(|table| table.get(key))
							.and_then(|item| item.as_table()),
						&item_path,
						replace_logging_comments,
					);
				} else if let Some(current_item) = current.get_mut(key) {
					let mut replacement = new_item.clone();
					if let (Some(current_value), Some(new_value)) =
						(current_item.as_value(), replacement.as_value_mut())
					{
						*new_value.decor_mut() = current_value.decor().clone();
					}
					*current_item = replacement;
				} else {
					current.insert_formatted(new.key(key).unwrap(), new_item.clone());
				}
			}
		}

		let mut current = old_config
			.parse::<DocumentMut>()
			.map_err(|e| ConfigError::SerializationError(format!("{}", e)))?;
		let new = new_config
			.parse::<DocumentMut>()
			.map_err(|e| ConfigError::SerializationError(format!("{}", e)))?;
		let known_members: GlobalWalletConfigMembers = toml::from_str(
			&GlobalWalletConfig::fix_warning_level(old_config.to_owned()),
		)
		.map_err(|e| ConfigError::SerializationError(format!("{}", e)))?;
		let known = toml::to_string(&known_members)
			.map_err(|e| ConfigError::SerializationError(format!("{}", e)))?
			.parse::<DocumentMut>()
			.map_err(|e| ConfigError::SerializationError(format!("{}", e)))?;
		update(
			current.as_table_mut(),
			new.as_table(),
			Some(known.as_table()),
			"",
			old_version.is_none(),
		);
		Ok(current.to_string())
	}
	/// This migration does the following:
	/// - Adds "config_file_version = 2"
	/// - Introduce new key config_file_version, [tor.bridge] and [tor.proxy]
	/// - Migrate old config key/value and comments while it does not conflict with newly indroduced key and comments
	fn migrate_config_file_version_none_to_2(
		config_str: String,
		config_file_path: PathBuf,
	) -> Result<String, ConfigError> {
		let config: GlobalWalletConfigMembers =
			toml::from_str(&GlobalWalletConfig::fix_warning_level(config_str.clone())).unwrap();
		if config.config_file_version.is_some() {
			return Ok(config_str);
		}
		let adjusted_config = GlobalWalletConfigMembers {
			config_file_version: GlobalWalletConfigMembers::default().config_file_version,
			tor: Some(TorConfig {
				bridge: TorBridgeConfig::default(),
				proxy: TorProxyConfig::default(),
				..config.tor.unwrap_or_default()
			}),
			..config
		};
		let mut gc = GlobalWalletConfig {
			members: adjusted_config,
			config_file_path: config_file_path.clone(),
		};
		gc.write_to_path(
			&config_file_path,
			true,
			Some(config_str),
			config.config_file_version,
		)?;
		let adjusted_config_str = fs::read_to_string(config_file_path)?;
		Ok(adjusted_config_str)
	}

	// For forwards compatibility old config needs `Warning` log level changed to standard log::Level `WARN`
	fn fix_warning_level(conf: String) -> String {
		GlobalWalletConfig::replace_log_levels(conf, &[("Warning", "WARN")])
	}

	// For backwards compatibility only first letter of log level should be capitalised.
	fn fix_log_level(conf: String) -> String {
		GlobalWalletConfig::replace_log_levels(
			conf,
			&[
				("TRACE", "Trace"),
				("DEBUG", "Debug"),
				("INFO", "Info"),
				("WARN", "Warning"),
				("ERROR", "Error"),
			],
		)
	}

	fn replace_log_levels(conf: String, replacements: &[(&str, &str)]) -> String {
		conf.split_inclusive('\n')
			.map(|line| {
				let trimmed = line.trim_start();
				if trimmed.starts_with("stdout_log_level =")
					|| trimmed.starts_with("file_log_level =")
				{
					replacements
						.iter()
						.fold(line.to_owned(), |line, (from, to)| line.replace(from, to))
				} else {
					line.to_owned()
				}
			})
			.collect()
	}

	/// Save config to file and update global state after editing.
	pub fn save(&mut self) -> Result<(), ConfigError> {
		let _save_lock = CONFIG_SAVE_LOCK.lock();
		self.save_locked()
	}

	fn save_locked(&mut self) -> Result<(), ConfigError> {
		let path = self.config_file_path.clone();
		let mut tmp_name = path.as_os_str().to_os_string();
		tmp_name.push(format!("-{}.tmp", thread_rng().gen::<u64>()));
		let tmp_path = PathBuf::from(tmp_name);
		let contents = fs::read_to_string(&path)?;
		let permissions = fs::metadata(&path)?.permissions();

		let save_result = (|| {
			OpenOptions::new()
				.write(true)
				.create_new(true)
				.open(&tmp_path)?;
			fs::set_permissions(&tmp_path, permissions)?;
			self.write_to_path(
				&tmp_path,
				true,
				Some(contents),
				self.members.config_file_version,
			)?;
			fs::rename(&tmp_path, &path)?;
			Ok::<(), ConfigError>(())
		})();
		if save_result.is_err() {
			let _ = fs::remove_file(&tmp_path);
		}
		save_result?;

		set_global_config(self.clone());
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::core::global::ChainTypes;
	use std::sync::{Arc, Barrier};
	use std::thread;
	use tempfile::tempdir;

	#[test]
	fn save_roundtrip() {
		let dir = tempdir().unwrap();
		let path = dir.path().join(WALLET_CONFIG_FILE_NAME);
		let mut config = GlobalWalletConfig::for_chain(&ChainTypes::AutomatedTesting, &path);
		config.members.tor.as_mut().unwrap().proxy.password = Some("secretERROR#[value]".into());
		config.write_to_path(&path, false, None, None).unwrap();

		let contents = fs::read_to_string(&path)
			.unwrap()
			.replace(
				"api_listen_port = 3415",
				"api_listen_port = 3415\n# wallet future\nfuture_setting = \"wallet\"\n# future list\nfuture_values = [\n  1,\n  2,\n]",
			)
			.replace(
				"use_tor_listener = true",
				"# custom key comment\nuse_tor_listener = true # custom inline comment\n# tor future\nfuture_setting = \"tor\"",
			);
		fs::write(&path, format!("{contents}\n# custom trailing comment\n")).unwrap();
		let before = fs::read_to_string(&path).unwrap();

		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
		}

		config.members.tor.as_mut().unwrap().use_tor_listener = false;
		config.members.tor.as_mut().unwrap().proxy.password = Some("secretERROR#value".into());
		config.save().unwrap();

		let contents = fs::read_to_string(&path).unwrap();
		assert_eq!(
			contents,
			before
				.replace("use_tor_listener = true", "use_tor_listener = false")
				.replace("secretERROR#[value]", "secretERROR#value")
		);
		assert!(contents.contains("# custom trailing comment"));
		assert!(contents.contains("# custom key comment"));
		assert!(contents.contains("use_tor_listener = false # custom inline comment"));
		let stored = GlobalWalletConfig::new(path.clone()).unwrap().tor_config();
		assert!(!stored.use_tor_listener);
		assert_eq!(stored.proxy.password.as_deref(), Some("secretERROR#value"));

		config.members.tor.as_mut().unwrap().proxy.transport = Some("socks5".into());
		config.members.tor.as_mut().unwrap().bridge.client_option = Some("option [value]".into());
		config.save().unwrap();
		let stored = GlobalWalletConfig::new(path.clone()).unwrap().tor_config();
		assert_eq!(stored.proxy.transport.as_deref(), Some("socks5"));
		assert_eq!(
			stored.bridge.client_option.as_deref(),
			Some("option [value]")
		);

		config.members.tor.as_mut().unwrap().proxy.transport = None;
		config.members.tor.as_mut().unwrap().bridge.client_option = None;
		config.save().unwrap();
		let stored = GlobalWalletConfig::new(path.clone()).unwrap().tor_config();
		assert_eq!(stored.proxy.transport, None);
		assert_eq!(stored.bridge.client_option, None);

		let legacy =
			fs::read_to_string(&path)
				.unwrap()
				.replacen("config_file_version = 2\n", "", 1);
		let mut legacy = legacy.parse::<DocumentMut>().unwrap();
		let tor = legacy["tor"].as_table_mut().unwrap();
		tor.remove("bridge");
		tor.remove("proxy");
		fs::write(&path, legacy.to_string()).unwrap();
		let migrated = GlobalWalletConfig::new(path.clone()).unwrap();
		assert_eq!(migrated.members.config_file_version, Some(2));
		let migrated = fs::read_to_string(&path).unwrap();
		assert!(migrated.contains("# future list\nfuture_values = [\n  1,\n  2,\n]"));
		assert!(migrated.contains("### TOR BRIDGE"));
		assert!(migrated.contains("### TOR PROXY"));
		assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
			!entry
				.unwrap()
				.file_name()
				.to_string_lossy()
				.ends_with(".tmp")
		}));

		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			assert_eq!(
				fs::metadata(&path).unwrap().permissions().mode() & 0o777,
				0o600
			);
		}
	}

	#[test]
	fn legacy_tor() {
		let path = PathBuf::from("legacy-wallet.toml");
		let mut config = GlobalWalletConfig::for_chain(&ChainTypes::AutomatedTesting, &path);
		config.members.wallet.data_file_dir = "legacy-wallet-data".into();
		config.members.tor = None;

		let resolved = config.tor_config();
		assert_eq!(resolved.send_config_dir, "legacy-wallet-data");
		assert!(resolved.use_tor_listener);

		let disabled = TorConfig {
			use_tor_listener: false,
			skip_send_attempt: Some(true),
			..TorConfig::default()
		};
		config.members.tor = Some(disabled.clone());
		assert_eq!(config.tor_config(), disabled);
	}

	#[test]
	fn cached_config_wins() {
		let path = PathBuf::from("concurrent-wallet.toml");
		let mut cached = GlobalWalletConfig::for_chain(&ChainTypes::AutomatedTesting, &path);
		cached.members.tor.as_mut().unwrap().use_tor_listener = false;
		let loaded = GlobalWalletConfig::for_chain(&ChainTypes::AutomatedTesting, &path);
		let mut configs = HashMap::new();
		configs.insert(path.clone(), (cached.clone(), HashMap::new()));

		let returned = cache_loaded_config(&mut configs, &path, loaded);

		assert_eq!(returned, cached);
		assert_eq!(configs.get(&path).unwrap().0, cached);
	}

	#[test]
	fn concurrent_update() {
		let dir = tempdir().unwrap();
		let path = dir.path().join(WALLET_CONFIG_FILE_NAME);
		let mut config = GlobalWalletConfig::for_chain(&ChainTypes::AutomatedTesting, &path);
		config.write_to_path(&path, false, None, None).unwrap();
		let barrier = Arc::new(Barrier::new(2));

		let handles = [false, true].map(|update_tor| {
			let path = path.clone();
			let barrier = barrier.clone();
			thread::spawn(move || {
				barrier.wait();
				update_global_config(&path, |config| {
					if update_tor {
						config.members.tor.as_mut().unwrap().socks_proxy_addr =
							"127.0.0.1:59051".into();
					} else {
						config.members.wallet.api_listen_port = 3416;
					}
					Ok(())
				})
				.unwrap();
			})
		});
		for handle in handles {
			handle.join().unwrap();
		}

		let stored = GlobalWalletConfig::new(path.clone()).unwrap();
		let cached = get_global_config(&path).unwrap();
		assert_eq!(cached, stored);
		assert_eq!(stored.members.wallet.api_listen_port, 3416);
		assert_eq!(stored.tor_config().socks_proxy_addr, "127.0.0.1:59051");
	}
}
