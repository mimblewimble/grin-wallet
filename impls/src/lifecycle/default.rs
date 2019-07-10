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

use crate::core::global;
use crate::keychain::Keychain;
use crate::libwallet::{Error, ErrorKind, NodeClient, WalletBackend, WalletLCProvider};
use crate::util;
use crate::LMDBBackend;
use crate::lifecycle::seed::WalletSeed;
use failure::ResultExt;

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

	fn create_config(&self, _data_dir: Option<String>) -> Result<(), Error> {
		unimplemented!()
	}

	fn create_wallet(
		&mut self,
		_name: Option<&str>,
		mnemonic: Option<&str>,
		password: &str,
	) -> Result<(), Error> {
		let z_string = match mnemonic {
			Some(s) => Some(util::ZeroingString::from(s)),
			None => None,
		};
		let _ = WalletSeed::init_file(&self.data_dir, 32, z_string, password);
		let _wallet: LMDBBackend<'a, C, K> =
			LMDBBackend::new(&self.data_dir, self.node_client.clone()).unwrap_or_else(
				|e| panic!("Error creating wallet: {:?} Data Dir: {:?}", e, self.data_dir),
			);
		Ok(())
	}

	fn open_wallet(&mut self, _name: Option<&str>, password: &str) -> Result<(), Error> {
		let mut wallet: LMDBBackend<'a, C, K> =
			LMDBBackend::new(&self.data_dir, self.node_client.clone()).unwrap_or_else(
				|e| panic!("Error creating wallet: {:?} Data Dir: {:?}", e, self.data_dir),
			);
		let wallet_seed = WalletSeed::from_file(&self.data_dir, password)
			.context(ErrorKind::CallbackImpl("Error opening wallet"))?;
		let keychain = wallet_seed.derive_keychain(global::is_floonet())
			.context(ErrorKind::CallbackImpl("Error deriving keychain"))?;
		wallet.set_keychain(Box::new(keychain));
		self.backend = Some(Box::new(wallet));
		Ok(())
	}

	fn close_wallet(&mut self, _name: Option<String>) -> Result<(), Error> {
		match self.backend.as_mut() {
			Some(b) => {
				b.close()?
			},
			None => {}
		};
		self.backend = None;
		Ok(())
	}

	fn get_mnemonic(&self) -> Result<String, Error> {
		unimplemented!()
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
