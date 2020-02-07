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

//! Default wallet lifecycle provider

use crate::config::{
	config, GlobalWalletConfig, GlobalWalletConfigMembers, TorConfig, WalletConfig, GRIN_WALLET_DIR,
};
use crate::core::global;
use crate::keychain::Keychain;
use crate::libwallet::{
	Error, ErrorKind, NodeClient, WalletBackend, WalletInitStatus, WalletLCProvider,
};
use crate::lifecycle::seed::WalletSeed;
use crate::util::secp::key::SecretKey;
use crate::util::ZeroingString;
use crate::LMDBBackend;
use failure::ResultExt;
use grin_wallet_util::grin_util::logger::LoggingConfig;
use std::fs;
use std::path::PathBuf;

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
		Ok(self.data_dir.to_owned())
	}

	fn create_config(
		&self,
		chain_type: &global::ChainTypes,
		file_name: &str,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
	) -> Result<(), Error> {
		let mut default_config = GlobalWalletConfig::for_chain(chain_type);
		let logging = match logging_config {
			Some(l) => Some(l),
			None => match default_config.members.as_ref() {
				Some(m) => m.clone().logging,
				None => None,
			},
		};
		let wallet = match wallet_config {
			Some(w) => w,
			None => match default_config.members.as_ref() {
				Some(m) => m.clone().wallet,
				None => WalletConfig::default(),
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
				wallet,
				tor,
				logging,
			}),
			..default_config
		};
		let mut config_file_name = PathBuf::from(self.data_dir.clone());
		config_file_name.push(file_name);

		// create top level dir if it doesn't exist
		let dd = PathBuf::from(self.data_dir.clone());
		if !dd.exists() {
			// try create
			fs::create_dir_all(dd)?;
		}

		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(GRIN_WALLET_DIR);

		if config_file_name.exists() && data_dir_name.exists() {
			let msg = format!(
				"{} already exists in the target directory ({}). Please remove it first",
				file_name,
				config_file_name.to_str().unwrap()
			);
			return Err(ErrorKind::Lifecycle(msg).into());
		}

		// just leave as is if file exists but there's no data dir
		if config_file_name.exists() {
			return Ok(());
		}

		let mut abs_path = std::env::current_dir()?;
		abs_path.push(self.data_dir.clone());

		default_config.update_paths(&abs_path);
		let res = default_config.write_to_file(config_file_name.to_str().unwrap());
		if let Err(e) = res {
			let msg = format!(
				"Error creating config file as ({}): {}",
				config_file_name.to_str().unwrap(),
				e
			);
			return Err(ErrorKind::Lifecycle(msg).into());
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
		let data_dir_name = data_dir_name.to_str().unwrap();
		let exists = WalletSeed::seed_file_exists(&data_dir_name);
		if !test_mode {
			if let Ok(true) = exists {
				let msg = format!("Wallet seed already exists at: {}", data_dir_name);
				return Err(ErrorKind::WalletSeedExists(msg).into());
			}
		}
		WalletSeed::init_file(
			&data_dir_name,
			mnemonic_length,
			mnemonic.clone(),
			password,
			test_mode,
		)
		.context(ErrorKind::Lifecycle(
			"Error creating wallet seed (is mnemonic valid?)".into(),
		))?;
		info!("Wallet seed file created");
		let mut wallet: LMDBBackend<'a, C, K> =
			match LMDBBackend::new(&data_dir_name, self.node_client.clone()) {
				Err(e) => {
					let msg = format!("Error creating wallet: {}, Data Dir: {}", e, &data_dir_name);
					error!("{}", msg);
					return Err(ErrorKind::Lifecycle(msg).into());
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
		let data_dir_name = data_dir_name.to_str().unwrap();
		let mut wallet: LMDBBackend<'a, C, K> =
			match LMDBBackend::new(&data_dir_name, self.node_client.clone()) {
				Err(e) => {
					let msg = format!("Error opening wallet: {}, Data Dir: {}", e, &data_dir_name);
					return Err(ErrorKind::Lifecycle(msg).into());
				}
				Ok(d) => d,
			};
		let wallet_seed = WalletSeed::from_file(&data_dir_name, password).context(
			ErrorKind::Lifecycle("Error opening wallet (is password correct?)".into()),
		)?;
		let keychain = wallet_seed
			.derive_keychain(global::is_floonet())
			.context(ErrorKind::Lifecycle("Error deriving keychain".into()))?;

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
		let res = WalletSeed::seed_file_exists(&data_dir_name).context(ErrorKind::CallbackImpl(
			"Error checking for wallet existence",
		))?;
		Ok(res)
	}

	fn get_mnemonic(
		&self,
		_name: Option<&str>,
		password: ZeroingString,
	) -> Result<ZeroingString, Error> {
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(GRIN_WALLET_DIR);
		let data_dir_name = data_dir_name.to_str().unwrap();
		let wallet_seed = WalletSeed::from_file(&data_dir_name, password).context(
			ErrorKind::Lifecycle("Error opening wallet seed file".into()),
		)?;
		let res = wallet_seed
			.to_mnemonic()
			.context(ErrorKind::Lifecycle("Error recovering wallet seed".into()))?;
		Ok(ZeroingString::from(res))
	}

	fn validate_mnemonic(&self, mnemonic: ZeroingString) -> Result<(), Error> {
		match WalletSeed::from_mnemonic(mnemonic) {
			Ok(_) => Ok(()),
			Err(_) => Err(ErrorKind::GenericError("Validating mnemonic".into()).into()),
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
		WalletSeed::recover_from_phrase(data_dir_name, mnemonic, password).context(
			ErrorKind::Lifecycle("Error recovering from mnemonic".into()),
		)?;
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

		let orig_wallet_seed = WalletSeed::from_file(&data_dir_name, old).context(
			ErrorKind::Lifecycle("Error opening wallet seed file".into()),
		)?;
		let orig_mnemonic = orig_wallet_seed
			.to_mnemonic()
			.context(ErrorKind::Lifecycle("Error recovering mnemonic".into()))?;

		// Back up existing seed, and keep track of filename as we're deleting it
		// once the password change is confirmed
		let backup_name = WalletSeed::backup_seed(data_dir_name).context(ErrorKind::Lifecycle(
			"Error temporarily backing up existing seed".into(),
		))?;

		// Delete seed file
		WalletSeed::delete_seed_file(data_dir_name).context(ErrorKind::Lifecycle(
			"Unable to delete seed file for password change".into(),
		))?;

		// Init a new file
		let _ = WalletSeed::init_file(
			data_dir_name,
			0,
			Some(ZeroingString::from(orig_mnemonic)),
			new.clone(),
			false,
		);
		info!("Wallet seed file created");

		let new_wallet_seed = WalletSeed::from_file(&data_dir_name, new).context(
			ErrorKind::Lifecycle("Error opening wallet seed file".into()),
		)?;

		if orig_wallet_seed != new_wallet_seed {
			let msg =
				"New and Old wallet seeds are not equal on password change, not removing backups."
					.to_string();
			return Err(ErrorKind::Lifecycle(msg).into());
		}
		// Removin
		info!("Password change confirmed, removing old seed file.");
		fs::remove_file(backup_name).context(ErrorKind::IO)?;

		Ok(())
	}

	fn delete_wallet(&self, _name: Option<&str>) -> Result<(), Error> {
		let data_dir_name = PathBuf::from(self.data_dir.clone());
		warn!(
			"Removing all wallet data from: {}",
			data_dir_name.to_str().unwrap()
		);
		fs::remove_dir_all(data_dir_name).context(ErrorKind::IO)?;
		Ok(())
	}

	fn wallet_inst(&mut self) -> Result<&mut Box<dyn WalletBackend<'a, C, K> + 'a>, Error> {
		match self.backend.as_mut() {
			None => {
				let msg = "Wallet has not been opened".into();
				Err(ErrorKind::Lifecycle(msg).into())
			}
			Some(_) => Ok(&mut *self.backend.as_mut().unwrap()),
		}
	}
}
