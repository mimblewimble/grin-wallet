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

//! Concrete implementations of types found in libwallet, organised this
//! way mostly to avoid any circular dependencies of any kind
//! Functions in this crate should not use the wallet api crate directly

use blake2_rfc as blake2;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
use grin_wallet_libwallet as libwallet;
use grin_wallet_util::grin_api as api;
use grin_wallet_util::grin_chain as chain;
use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_keychain as keychain;
use grin_wallet_util::grin_store as store;
use grin_wallet_util::grin_util as util;

use grin_wallet_config as config;

mod adapters;
mod backends;
mod error;
mod lifecycle;
mod node_clients;
pub mod test_framework;

pub use crate::adapters::{
	FileWalletCommAdapter, HTTPWalletCommAdapter, KeybaseWalletCommAdapter, NullWalletCommAdapter,
	WalletCommAdapter,
};
pub use crate::backends::{wallet_db_exists, LMDBBackend};
pub use crate::error::{Error, ErrorKind};
pub use crate::lifecycle::DefaultLCProvider;
pub use crate::node_clients::HTTPNodeClient;

use crate::keychain::{ExtKeychain, Keychain};

use libwallet::{NodeClient, WalletInst, WalletLCProvider};

/// Main wallet instance

pub struct DefaultWalletImpl<'a, C>
where
	C: NodeClient + 'a,
{
	lc_provider: DefaultLCProvider<'a, C, ExtKeychain>,
}

unsafe impl<'a, C> Send for DefaultWalletImpl<'a, C> where C: NodeClient + 'a {}

unsafe impl<'a, C> Sync for DefaultWalletImpl<'a, C> where C: NodeClient + 'a {}

impl<'a, C> DefaultWalletImpl<'a, C>
where
	C: NodeClient + 'a,
{
	pub fn new(
		/*dir: &str,
		wallet_config: config::WalletConfig,*/
		node_client: C /*passphrase: &str,
					   account: &str,*/
	) -> Result<Self, Error> {
		// First test decryption, so we can abort early if we have the wrong password
		/*let _ = WalletSeed::from_file(&wallet_config, passphrase)?;
		let mut db_wallet = LMDBBackend::new(wallet_config.clone(), passphrase, node_client.clone())?;*/
		/*db_wallet.set_parent_key_id_by_name(account)?;*/
		let lc_provider = DefaultLCProvider::new(node_client);
		info!("Using LMDB Backend for wallet");
		Ok(DefaultWalletImpl {
			lc_provider: lc_provider,
		})
	}
}

impl<'a, L, C, K> WalletInst<'a, L, C, K> for DefaultWalletImpl<'a, C>
where
	DefaultLCProvider<'a, C, ExtKeychain>: WalletLCProvider<'a, C, K>,
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn lc_provider(
		&mut self,
	) -> Result<&mut (dyn WalletLCProvider<'a, C, K> + 'a), libwallet::Error> {
		Ok(&mut self.lc_provider)
	}
}
