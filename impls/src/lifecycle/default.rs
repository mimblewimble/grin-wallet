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

use crate::config::{config, GlobalWalletConfig, GRIN_WALLET_DIR};
use crate::core::global;
use crate::keychain::Keychain;
use crate::libwallet::{Error, ErrorKind, NodeClient, WalletBackend, WalletLCProvider};
use crate::lifecycle::seed::WalletSeed;
use crate::util::ZeroingString;
use crate::LMDBBackend;
use failure::ResultExt;
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
	fn set_wallet_directory(&mut self, dir: &str) {
		self.data_dir = dir.to_owned();
	}

	fn create_config(&self, chain_type: &global::ChainTypes, file_name: &str) -> Result<(), Error> {
		let mut default_config = GlobalWalletConfig::for_chain(chain_type);
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
			return Err(ErrorKind::Lifecycle(msg).into());
		}

		// just leave as is if file exists but there's no data dir
		if config_file_name.exists() {
			return Ok(());
		}

		default_config.update_paths(&PathBuf::from(self.data_dir.clone()));
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
	) -> Result<(), Error> {
		let mut data_dir_name = PathBuf::from(self.data_dir.clone());
		data_dir_name.push(GRIN_WALLET_DIR);
		let data_dir_name = data_dir_name.to_str().unwrap();
		let _ = WalletSeed::init_file(&data_dir_name, mnemonic_length, mnemonic, password);
		info!("Wallet seed file created");
		let _wallet: LMDBBackend<'a, C, K> =
			match LMDBBackend::new(&data_dir_name, self.node_client.clone()) {
				Err(e) => {
					let msg = format!("Error creating wallet: {}, Data Dir: {}", e, &data_dir_name);
					return Err(ErrorKind::Lifecycle(msg).into());
				}
				Ok(d) => d,
			};
		info!("Wallet database backend created at {}", data_dir_name);
		Ok(())
	}

	fn open_wallet(&mut self, _name: Option<&str>, password: ZeroingString) -> Result<(), Error> {
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
		let wallet_seed = WalletSeed::from_file(&data_dir_name, password)
			.context(ErrorKind::Lifecycle("Error opening wallet".into()))?;
		let keychain = wallet_seed
			.derive_keychain(global::is_floonet())
			.context(ErrorKind::Lifecycle("Error deriving keychain".into()))?;
		wallet.set_keychain(Box::new(keychain));
		self.backend = Some(Box::new(wallet));
		Ok(())
	}

	fn close_wallet(&mut self, _name: Option<&str>) -> Result<(), Error> {
		match self.backend.as_mut() {
			Some(b) => b.close()?,
			None => {}
		};
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
			Err(_) => Err(ErrorKind::GenericError("Validating mnemonic".into()))?,
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

	fn change_password(&self, _old: String, _new: String) -> Result<(), Error> {
		unimplemented!()
	}

	fn delete_wallet(&self, _name: Option<String>, _password: String) -> Result<(), Error> {
		unimplemented!()
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
