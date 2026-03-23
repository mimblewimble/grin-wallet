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

//! Default wallet lifecycle provider

use crate::config::{
	config, GlobalWalletConfig, GlobalWalletConfigMembers, TorConfig, WalletConfig, GRIN_WALLET_DIR,
};
use crate::core::global;
use crate::keychain::Keychain;
use crate::libwallet::{Error, NodeClient, WalletBackend, WalletInitStatus, WalletLCProvider};
use crate::lifecycle::seed::WalletSeed;
use crate::util::secp::key::SecretKey;
use crate::util::ZeroingString;
use crate::LMDBBackend;
use grin_util::logger::LoggingConfig;
use std::fs;
use std::path::PathBuf;
use std::path::MAIN_SEPARATOR;

// Helper fuction to format paths according to OS, avoids bugs on Linux
pub fn fmt_path(path: String) -> String {
	let sep = &MAIN_SEPARATOR.to_string();
	let path = path.replace("/", &sep);
	let path = path.replace("\\", &sep);
	path
}

pub struct DefaultLCProvider<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	data_dir: String,
	node_client: C,
	backend: Option<Box<dyn WalletBackend<'a, C, K> + 'a>>,
}

impl<'a, C, K> DefaultLCProvider<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Create new provider
	pub fn new(node_client: C) -> Self {
		DefaultLCProvider {
			node_client,
			data_dir: "default".to_owned(),
			backend: None,
		}
	}
}

impl<'a, C, K> WalletLCProvider<'a, C, K> for DefaultLCProvider<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn set_top_level_directory(&mut self, dir: &str) -> Result<(), Error> {
		self.data_dir = dir.to_owned();
		Ok(())
	}

	fn get_top_level_directory(&self) -> Result<String, Error> {
		let sep = &MAIN_SEPARATOR.to_string();
		let data_dir = self
			.data_dir
			.to_owned()
			.replace("/", &sep)
			.replace("\\", &sep);
		Ok(data_dir)
	}

	fn create_config(
		&self,
		chain_type: &global::ChainTypes,
		file_name: &str,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
	) -> Result<(), Error> {
		let mut default_config = GlobalWalletConfig::for_chain(&chain_type);
		let config_file_version = match default_config.members.as_ref() {
			Some(m) => m.clone().config_file_version,
			None => None,
		};
		let logging = match logging_config {
			Some(l) => Some(l),
			None => match default_config.members.as_ref() {
				Some(m) => m.clone().logging,
				None => None,
			},
		};
		// Check if config was provided, if not load default and set update to "true"
		let (wallet, update) = match wallet_config {
			Some(w) => (w, false),
			None => match default_config.members.as_ref() {
				Some(m) => (m.clone().wallet, true),
				None => (WalletConfig::default(), true),
			},
		};
		let tor = match tor_config {
			Some(t) => Some(t),
			None => match default_config.members.as_ref() {
				Some(m) => m.clone().tor,
				None => Some(TorConfig::default()),
			},
		};
		default_config = GlobalWalletConfig {
			members: Some(GlobalWalletConfigMembers {
				config_file_version,
				wallet,
				tor,
				logging,
			}),
			..default_config
		};
		let mut config_file_name = PathBuf::from(self.data_dir.clone());
		config_file_name.push(file_name);

		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(GRIN_WALLET_DIR);

		if config_file_name.exists() && data_dir_name.exists() {
			let msg = format!(
				"{} already exists in the target directory ({}). Please remove it first",
				file_name,
				config_file_name.to_str().unwrap()
			);
			return Err(Error::Lifecycle(msg));
		}

		// If config exists but the datadir return ok
		if config_file_name.exists() {
			return Ok(());
		}
		// default settings are updated if no config was provided, no support for top_dir/here
		let mut abs_path_node = std::env::current_dir()?;
		abs_path_node.push(self.data_dir.clone());
		let mut absolute_path_wallet = std::env::current_dir()?;
		absolute_path_wallet.push(self.data_dir.clone());

		// if no config provided, update defaults
		if update == true {
			// create top level dir if it doesn't exist
			let dd = PathBuf::from(self.data_dir.clone());
			if !dd.exists() {
				// try create
				fs::create_dir_all(dd)?;
				default_config.update_paths(&abs_path_node, &absolute_path_wallet);
			}
		};
		let res =
			default_config.write_to_file(config_file_name.to_str().unwrap(), false, None, None);
		if let Err(e) = res {
			let msg = format!(
				"Error creating config file as ({}): {}",
				config_file_name.to_str().unwrap(),
				e
			);
			return Err(Error::Lifecycle(msg));
		}

		info!(
			"File {} configured and created",
			config_file_name.to_str().unwrap(),
		);

		let mut api_secret_path = PathBuf::from(self.data_dir.clone());
		api_secret_path.push(PathBuf::from(config::API_SECRET_FILE_NAME));
		if !api_secret_path.exists() {
			config::init_api_secret(&api_secret_path).unwrap();
		} else {
			config::check_api_secret(&api_secret_path).unwrap();
		}

		Ok(())
	}

	fn create_wallet(
		&mut self,
		_name: Option<&str>,
		mnemonic: Option<ZeroingString>,
		mnemonic_length: usize,
		password: ZeroingString,
		test_mode: bool,
	) -> Result<(), Error> {
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(GRIN_WALLET_DIR);
		let data_dir_name = fmt_path((data_dir_name.to_str().unwrap()).to_string());
		let exists = WalletSeed::seed_file_exists(&data_dir_name);
		if !test_mode {
			if let Ok(true) = exists {
				let msg = format!("Wallet seed already exists at4565: {}", data_dir_name);
				return Err(Error::WalletSeedExists(msg));
			}
		}
		WalletSeed::init_file(
			&data_dir_name,
			mnemonic_length,
			mnemonic.clone(),
			password,
			test_mode,
		)
		.map_err(|_| {
			Error::Lifecycle("Error creating wallet seed (is mnemonic valid?)".to_owned())
		})?;
		info!("Wallet seed file created");
		let mut wallet: LMDBBackend<'a, C, K> =
			match LMDBBackend::new(&data_dir_name, self.node_client.clone()) {
				Err(e) => {
					let msg = format!("Error creating wallet: {}, Data Dir: {}", e, &data_dir_name);
					error!("{}", msg);
					return Err(Error::Lifecycle(msg).into());
				}
				Ok(d) => d,
			};
		// Save init status of this wallet, to determine whether it needs a full UTXO scan
		let mut batch = wallet.batch_no_mask()?;
		match mnemonic {
			Some(_) => batch.save_init_status(WalletInitStatus::InitNeedsScanning)?,
			None => batch.save_init_status(WalletInitStatus::InitNoScanning)?,
		};
		batch.commit()?;
		info!("Wallet database backend created at {}", data_dir_name);
		Ok(())
	}

	fn open_wallet(
		&mut self,
		_name: Option<&str>,
		password: ZeroingString,
		create_mask: bool,
		use_test_rng: bool,
	) -> Result<Option<SecretKey>, Error> {
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(GRIN_WALLET_DIR);
		let data_dir_name = fmt_path(data_dir_name.to_str().unwrap().to_string());
		let mut wallet: LMDBBackend<'a, C, K> =
			match LMDBBackend::new(&data_dir_name, self.node_client.clone()) {
				Err(e) => {
					let msg = format!("Error opening wallet: {}, Data Dir: {}", e, &data_dir_name);
					return Err(Error::Lifecycle(msg));
				}
				Ok(d) => d,
			};
		let wallet_seed = WalletSeed::from_file(&data_dir_name, password).map_err(|_| {
			Error::Lifecycle("Error opening wallet (is password correct?)".to_owned())
		})?;
		let keychain = wallet_seed
			.derive_keychain(global::is_testnet())
			.map_err(|_| Error::Lifecycle("Error deriving keychain".to_owned()))?;

		let mask = wallet.set_keychain(Box::new(keychain), create_mask, use_test_rng)?;
		self.backend = Some(Box::new(wallet));
		Ok(mask)
	}

	fn close_wallet(&mut self, _name: Option<&str>) -> Result<(), Error> {
		if let Some(b) = self.backend.as_mut() {
			b.close()?
		}
		self.backend = None;
		Ok(())
	}

	fn wallet_exists(&self, _name: Option<&str>) -> Result<bool, Error> {
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(GRIN_WALLET_DIR);
		let data_dir_name = data_dir_name.to_str().unwrap();
		let res = WalletSeed::seed_file_exists(&data_dir_name)
			.map_err(|_| Error::CallbackImpl("Error checking for wallet existence"))?;
		Ok(res)
	}

	fn get_mnemonic(
		&self,
		_name: Option<&str>,
		password: ZeroingString,
	) -> Result<ZeroingString, Error> {
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(GRIN_WALLET_DIR);
		let data_dir_name = fmt_path(data_dir_name.display().to_string());
		let wallet_seed = WalletSeed::from_file(&data_dir_name, password)
			.map_err(|_| Error::Lifecycle("Error opening wallet seed file".into()))?;
		let res = wallet_seed
			.to_mnemonic()
			.map_err(|_| Error::Lifecycle("Error recovering wallet seed".into()))?;
		Ok(ZeroingString::from(res))
	}

	fn validate_mnemonic(&self, mnemonic: ZeroingString) -> Result<(), Error> {
		match WalletSeed::from_mnemonic(mnemonic) {
			Ok(_) => Ok(()),
			Err(_) => Err(Error::GenericError("Validating mnemonic".into())),
		}
	}

	fn recover_from_mnemonic(
		&self,
		mnemonic: ZeroingString,
		password: ZeroingString,
	) -> Result<(), Error> {
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(GRIN_WALLET_DIR);
		let data_dir_name = data_dir_name.to_str().unwrap();
		WalletSeed::recover_from_phrase(data_dir_name, mnemonic, password)
			.map_err(|_| Error::Lifecycle("Error recovering from mnemonic".into()))?;
		Ok(())
	}

	fn change_password(
		&self,
		_name: Option<&str>,
		old: ZeroingString,
		new: ZeroingString,
	) -> Result<(), Error> {
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(GRIN_WALLET_DIR);
		let data_dir_name = data_dir_name.to_str().unwrap();
		// get seed for later check

		let orig_wallet_seed = WalletSeed::from_file(&data_dir_name, old)
			.map_err(|_| Error::Lifecycle("Error opening wallet seed file".into()))?;
		let orig_mnemonic = orig_wallet_seed
			.to_mnemonic()
			.map_err(|_| Error::Lifecycle("Error recovering mnemonic".into()))?;

		// Back up existing seed, and keep track of filename as we're deleting it
		// once the password change is confirmed
		let backup_name = WalletSeed::backup_seed(data_dir_name)
			.map_err(|_| Error::Lifecycle("Error temporarily backing up existing seed".into()))?;

		// Delete seed file
		WalletSeed::delete_seed_file(data_dir_name).map_err(|_| {
			Error::Lifecycle("Unable to delete seed file for password change".into())
		})?;

		// Init a new file
		let _ = WalletSeed::init_file(
			data_dir_name,
			0,
			Some(ZeroingString::from(orig_mnemonic)),
			new.clone(),
			false,
		);
		info!("Wallet seed file created");

		let new_wallet_seed = WalletSeed::from_file(&data_dir_name, new)
			.map_err(|_| Error::Lifecycle("Error opening wallet seed file".into()))?;

		if orig_wallet_seed != new_wallet_seed {
			let msg =
				"New and Old wallet seeds are not equal on password change, not removing backups."
					.to_string();
			return Err(Error::Lifecycle(msg));
		}
		// Removin
		info!("Password change confirmed, removing old seed file.");
		fs::remove_file(backup_name).map_err(|e| Error::IO(e.to_string()))?;

		Ok(())
	}

	fn delete_wallet(&self, _name: Option<&str>) -> Result<(), Error> {
		let data_dir_name = PathBuf::from(self.data_dir.clone());
		warn!(
			"Removing all wallet data from: {}",
			data_dir_name.to_str().unwrap()
		);
		fs::remove_dir_all(data_dir_name).map_err(|e| Error::IO(e.to_string()))?;
		Ok(())
	}

	fn wallet_inst(&mut self) -> Result<&mut Box<dyn WalletBackend<'a, C, K> + 'a>, Error> {
		match self.backend.as_mut() {
			None => {
				let msg = "Wallet has not been opened".into();
				Err(Error::Lifecycle(msg))
			}
			Some(_) => Ok(&mut *self.backend.as_mut().unwrap()),
		}
	}
}
