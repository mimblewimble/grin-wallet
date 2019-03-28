// Copyright 2018 The Grin Developers
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

//! Main interface into all wallet API functions.
//! Wallet APIs are split into two seperate blocks of functionality
//! called the 'Owner' and 'Foreign' APIs:
//!
//! * The 'Foreign' API contains methods that other wallets will
//! use to interact with the owner's wallet. This API can be exposed
//! to the outside world, with the consideration as to how that can
//! be done securely up to the implementor.
//!
//! Methods in both APIs are intended to be 'single use', that is to say each
//! method will 'open' the wallet (load the keychain with its master seed), perform
//! its operation, then 'close' the wallet (unloading references to the keychain and master
//! seed).

use crate::keychain::Keychain;
use crate::libwallet::api_impl::foreign;
use crate::libwallet::slate::Slate;
use crate::libwallet::types::{BlockFees, CbData, NodeClient, WalletBackend};
use crate::libwallet::Error;
use crate::util::Mutex;
use std::marker::PhantomData;
use std::sync::Arc;

/// Wrapper around external API functions, intended to communicate
/// with other parties
pub struct Foreign<W: ?Sized, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	/// Wallet, contains its keychain (TODO: Split these up into 2 traits
	/// perhaps)
	pub wallet: Arc<Mutex<W>>,
	/// Flag to normalize some output during testing. Can mostly be ignored.
	pub doctest_mode: bool,
	phantom: PhantomData<K>,
	phantom_c: PhantomData<C>,
}

impl<'a, W: ?Sized, C, K> Foreign<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	/// Create new API instance
	pub fn new(wallet_in: Arc<Mutex<W>>) -> Self {
		Foreign {
			wallet: wallet_in,
			doctest_mode: false,
			phantom: PhantomData,
			phantom_c: PhantomData,
		}
	}

	/// Build a new (potential) coinbase transaction in the wallet
	pub fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = foreign::build_coinbase(&mut *w, block_fees, self.doctest_mode);
		w.close()?;
		res
	}

	/// Verifies all messages in the slate match their public keys.
	///
	/// The option messages themselves are part of the `participant_data` field within the slate.
	/// Messages are signed with the same key used to sign for the paricipant's inputs, and can thus be
	/// verified with the public key found in the `public_blind_excess` field. This function is a
	/// simple helper to returns whether all signatures in the participant data match their public
	/// keys.
	///
	/// # Arguments
	///
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html).
	///
	/// # Returns
	/// * Ok(()) if successful and the signatures validate
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Foreign.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	///
	/// let mut api_foreign = Foreign::new(wallet.clone());
	///
	/// # let slate = Slate::blank(2);
	/// // Receive a slate via some means
	///
	///	let res = api_foreign.verify_slate_messages(&slate);
	///
	/// if let Err(e) = res {
	///		// Messages don't validate, likely return an error
	///		// ...
	/// } else {
	//		// Slate messages are fine
	/// }
	///
	/// 
	/// ```

	pub fn verify_slate_messages(&self, slate: &Slate) -> Result<(), Error> {
		foreign::verify_slate_messages(slate)
	}

	/// Receive a transaction from a sender
	pub fn receive_tx(
		&self,
		slate: &mut Slate,
		dest_acct_name: Option<&str>,
		message: Option<String>,
	) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = foreign::receive_tx(&mut *w, slate, dest_acct_name, message, self.doctest_mode);
		w.close()?;
		res
	}
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_setup_doc_env_foreign {
	($wallet:ident, $wallet_config:ident) => {
		use grin_wallet_api as api;
		use grin_wallet_config as config;
		use grin_wallet_impls as impls;
		use grin_wallet_libwallet as libwallet;
		use grin_wallet_util::grin_keychain as keychain;
		use grin_wallet_util::grin_util as util;
		use libwallet::slate::Slate;

		use keychain::ExtKeychain;
		use tempfile::tempdir;

		use std::sync::Arc;
		use util::Mutex;

		use api::Foreign;
		use config::WalletConfig;
		use impls::{HTTPNodeClient, LMDBBackend, WalletSeed};
		use libwallet::types::WalletBackend;

		let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
		let dir = dir
			.path()
			.to_str()
			.ok_or("Failed to convert tmpdir path to string.".to_owned())
			.unwrap();
		let mut wallet_config = WalletConfig::default();
		wallet_config.data_file_dir = dir.to_owned();
		let pw = "";

		let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
		let mut $wallet: Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> = Arc::new(
			Mutex::new(LMDBBackend::new(wallet_config.clone(), pw, node_client).unwrap()),
			);
	};
}
