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

//! Foreign API External Definition

use crate::config::TorConfig;
use crate::keychain::Keychain;
use crate::libwallet::api_impl::foreign;
use crate::libwallet::{
	BlockFees, CbData, Error, NodeClient, NodeVersionInfo, Slate, VersionInfo, WalletInst,
	WalletLCProvider,
};
use crate::try_slatepack_sync_workflow;
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;
use std::sync::Arc;

/// ForeignAPI Middleware Check callback
pub type ForeignCheckMiddleware =
	fn(ForeignCheckMiddlewareFn, Option<NodeVersionInfo>, Option<&Slate>) -> Result<(), Error>;

/// Middleware Identifiers for each function
pub enum ForeignCheckMiddlewareFn {
	/// check_version
	CheckVersion,
	/// build_coinbase
	BuildCoinbase,
	/// verify_slate_messages
	VerifySlateMessages,
	/// receive_tx
	ReceiveTx,
	/// finalize_tx
	FinalizeTx,
}

/// Main interface into all wallet API functions.
/// Wallet APIs are split into two seperate blocks of functionality
/// called the ['Owner'](struct.Owner.html) and ['Foreign'](struct.Foreign.html) APIs
///
/// * The 'Foreign' API contains methods that other wallets will
/// use to interact with the owner's wallet. This API can be exposed
/// to the outside world, with the consideration as to how that can
/// be done securely up to the implementor.
///
/// Methods in both APIs are intended to be 'single use', that is to say each
/// method will 'open' the wallet (load the keychain with its master seed), perform
/// its operation, then 'close' the wallet (unloading references to the keychain and master
/// seed).

pub struct Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Wallet instance
	pub wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	/// Flag to normalize some output during testing. Can mostly be ignored.
	pub doctest_mode: bool,
	/// foreign check middleware
	middleware: Option<ForeignCheckMiddleware>,
	/// Stored keychain mask (in case the stored wallet seed is tokenized)
	keychain_mask: Option<SecretKey>,
	/// Optional TOR configuration, holding address of sender and
	/// data directory
	tor_config: Mutex<Option<TorConfig>>,
}

impl<'a, L, C, K> Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Create a new API instance with the given wallet instance. All subsequent
	/// API calls will operate on this instance of the wallet.
	///
	/// Each method will call the [`WalletBackend`](../grin_wallet_libwallet/types/trait.WalletBackend.html)'s
	/// [`open_with_credentials`](../grin_wallet_libwallet/types/trait.WalletBackend.html#tymethod.open_with_credentials)
	/// (initialising a keychain with the master seed), perform its operation, then close the keychain
	/// with a call to [`close`](../grin_wallet_libwallet/types/trait.WalletBackend.html#tymethod.close)
	///
	/// # Arguments
	/// * `wallet_in` - A reference-counted mutex containing an implementation of the
	/// [`WalletBackend`](../grin_wallet_libwallet/types/trait.WalletBackend.html) trait.
	/// * `keychain_mask` - Mask value stored internally to use when calling a wallet
	/// whose seed has been XORed with a token value (such as when running the foreign
	/// and owner listeners in the same instance)
	/// * middleware - Option middleware which containts the NodeVersionInfo and can call
	/// a predefined function with the slate to check if the operation should continue
	///
	/// # Returns
	/// * An instance of the ForeignApi holding a reference to the provided wallet
	///
	/// # Example
	/// ```
	/// use grin_wallet_util::grin_keychain as keychain;
	/// use grin_wallet_util::grin_util as util;
	/// use grin_wallet_util::grin_core;
	/// use grin_wallet_api as api;
	/// use grin_wallet_config as config;
	/// use grin_wallet_impls as impls;
	/// use grin_wallet_libwallet as libwallet;
	///
	/// use keychain::ExtKeychain;
	/// use tempfile::tempdir;
	///
	/// use std::sync::Arc;
	/// use util::{Mutex, ZeroingString};
	///
	/// use grin_core::global;
	///
	/// use api::Foreign;
	/// use config::WalletConfig;
	/// use impls::{DefaultWalletImpl, DefaultLCProvider, HTTPNodeClient};
	/// use libwallet::WalletInst;
	///
	/// global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	///
	/// let mut wallet_config = WalletConfig::default();
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// #   .path()
	/// #   .to_str()
	/// #   .ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// #   .unwrap();
	/// # wallet_config.data_file_dir = dir.to_owned();
	///
	/// // A NodeClient must first be created to handle communication between
	/// // the wallet and the node.
	/// let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None).unwrap();
	///
	/// // impls::DefaultWalletImpl is provided for convenience in instantiating the wallet
	/// // It contains the LMDBBackend, DefaultLCProvider (lifecycle) and ExtKeychain used
	/// // by the reference wallet implementation.
	/// // These traits can be replaced with alternative implementations if desired
	///
	/// let mut wallet = Box::new(DefaultWalletImpl::<'static, HTTPNodeClient>::new(node_client.clone()).unwrap())
	///     as Box<WalletInst<'static, DefaultLCProvider<HTTPNodeClient, ExtKeychain>, HTTPNodeClient, ExtKeychain>>;
	///
	/// // Wallet LifeCycle Provider provides all functions init wallet and work with seeds, etc...
	/// let lc = wallet.lc_provider().unwrap();
	///
	/// // The top level wallet directory should be set manually (in the reference implementation,
	/// // this is provided in the WalletConfig)
	/// let _ = lc.set_top_level_directory(&wallet_config.data_file_dir);
	///
	/// // Wallet must be opened with the password (TBD)
	/// let pw = ZeroingString::from("wallet_password");
	/// lc.open_wallet(None, pw, false, false);
	///
	/// // All wallet functions operate on an Arc::Mutex to allow multithreading where needed
	/// let mut wallet = Arc::new(Mutex::new(wallet));
	///
	/// let api_foreign = Foreign::new(wallet.clone(), None, None, false);
	/// // .. perform wallet operations
	///
	/// ```

	pub fn new(
		wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
		keychain_mask: Option<SecretKey>,
		middleware: Option<ForeignCheckMiddleware>,
		doctest_mode: bool,
	) -> Self {
		Foreign {
			wallet_inst,
			doctest_mode,
			middleware,
			keychain_mask,
			tor_config: Mutex::new(None),
		}
	}

	/// Set the TOR configuration for this instance of the ForeignAPI, used during
	/// `recieve_tx` when a return address is specified
	///
	/// # Arguments
	/// * `tor_config` - The optional [TorConfig](#) to use
	/// # Returns
	/// * Nothing

	pub fn set_tor_config(&self, tor_config: Option<TorConfig>) {
		let mut lock = self.tor_config.lock();
		*lock = tor_config;
	}

	/// Return the version capabilities of the running ForeignApi Node
	/// # Arguments
	/// None
	/// # Returns
	/// * [`VersionInfo`](../grin_wallet_libwallet/api_impl/types/struct.VersionInfo.html)
	/// # Example
	/// Set up as in [`new`](struct.Foreign.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	///
	/// let mut api_foreign = Foreign::new(wallet.clone(), None, None, false);
	///
	/// let version_info = api_foreign.check_version();
	/// // check and proceed accordingly
	/// ```

	pub fn check_version(&self) -> Result<VersionInfo, Error> {
		if let Some(m) = self.middleware.as_ref() {
			let mut w_lock = self.wallet_inst.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			m(
				ForeignCheckMiddlewareFn::CheckVersion,
				w.w2n_client().get_version_info(),
				None,
			)?;
		}
		Ok(foreign::check_version())
	}

	/// Builds a new unconfirmed coinbase output in the wallet, generally for inclusion in a
	/// potential new block's coinbase output during mining.
	///
	/// All potential coinbase outputs are created as 'Unconfirmed' with the coinbase flag set.
	/// If a potential coinbase output is found on the chain after a wallet update, it status
	/// is set to `Unsent` and a [Transaction Log Entry](../grin_wallet_libwallet/types/struct.TxLogEntry.html)
	/// will be created. Note the output will be unspendable until the coinbase maturity period
	/// has expired.
	///
	/// # Arguments
	///
	/// * `block_fees` - A [`BlockFees`](../grin_wallet_libwallet/api_impl/types/struct.BlockFees.html)
	/// struct, set up as follows:
	///
	/// `fees` - should contain the sum of all transaction fees included in the potential
	/// block
	///
	/// `height` - should contain the block height being mined
	///
	/// `key_id` - can optionally contain the corresponding keychain ID in the wallet to use
	/// to create the output's blinding factor. If this is not provided, the next available key
	/// id will be assigned
	///
	/// # Returns
	/// * `Ok`([`cb_data`](../grin_wallet_libwallet/api_impl/types/struct.CbData.html)`)` if successful. This
	/// will contain the corresponding output, kernel and keyID used to create the coinbase output.
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Foreign.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	///
	/// let mut api_foreign = Foreign::new(wallet.clone(), None, None, false);
	///
	/// let block_fees = BlockFees {
	///     fees: 800000,
	///     height: 234323,
	///     key_id: None,
	/// };
	/// // Build a new coinbase output
	///
	/// let res = api_foreign.build_coinbase(&block_fees);
	///
	/// if let Ok(cb_data) = res {
	///     // cb_data is populated with coinbase output info
	///     // ...
	/// }
	/// ```

	pub fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		if let Some(m) = self.middleware.as_ref() {
			m(
				ForeignCheckMiddlewareFn::BuildCoinbase,
				w.w2n_client().get_version_info(),
				None,
			)?;
		}
		foreign::build_coinbase(
			&mut **w,
			(&self.keychain_mask).as_ref(),
			block_fees,
			self.doctest_mode,
		)
	}

	/// Recieve a tranaction created by another party, returning the modified
	/// [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html) object, modified with
	/// the recipient's output for the transaction amount, and public signature data. This slate can
	/// then be sent back to the sender to finalize the transaction via the
	/// [Owner API's `finalize_tx`](struct.Owner.html#method.finalize_tx) method.
	///
	/// This function creates a single output for the full amount, set to a status of
	/// 'Awaiting finalization'. It will remain in this state until the wallet finds the
	/// corresponding output on the chain, at which point it will become 'Unspent'. The slate
	/// will be updated with the results of Signing round 1 and 2, adding the recipient's public
	/// nonce, public excess value, and partial signature to the slate.
	///
	/// Also creates a corresponding [Transaction Log Entry](../grin_wallet_libwallet/types/struct.TxLogEntry.html)
	/// in the wallet's transaction log.
	///
	/// # Arguments
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html).
	/// The slate should contain the results of the sender's round 1 (e.g, public nonce and public
	/// excess value).
	/// * `dest_acct_name` - The name of the account into which the slate should be received. If
	/// `None`, the default account is used.
	/// * `r_addr` - If included, attempt to send the slate back to the sender using the slatepack sync
	/// send (TOR). If providing this argument, check the `state` field of the slate to see if the
	/// sync_send was successful (it should be S3 if the synced send sent successfully).
	///
	/// # Returns
	/// * a result containing:
	/// * `Ok`([`slate`](../grin_wallet_libwallet/slate/struct.Slate.html)`)` if successful,
	/// containing the new slate updated with the recipient's output and public signing information.
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * This method will store a partially completed transaction in the wallet's transaction log.
	///
	/// # Example
	/// Set up as in [new](struct.Foreign.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	///
	/// let mut api_foreign = Foreign::new(wallet.clone(), None, None, false);
	/// # let slate = Slate::blank(2, TxFlow::Standard);
	///
	/// // . . .
	/// // Obtain a sent slate somehow
	/// let result = api_foreign.receive_tx(&slate, None, None);
	///
	/// if let Ok(slate) = result {
	///     // Send back to recipient somehow
	///     // ...
	/// }
	/// ```

	pub fn receive_tx(
		&self,
		slate: &Slate,
		dest_acct_name: Option<&str>,
		r_addr: Option<String>,
	) -> Result<Slate, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		if let Some(m) = self.middleware.as_ref() {
			m(
				ForeignCheckMiddlewareFn::ReceiveTx,
				w.w2n_client().get_version_info(),
				Some(slate),
			)?;
		}
		let ret_slate = foreign::receive_tx(
			&mut **w,
			(&self.keychain_mask).as_ref(),
			slate,
			dest_acct_name,
			self.doctest_mode,
		)?;
		match r_addr {
			Some(a) => {
				let tor_config_lock = self.tor_config.lock();
				let res = try_slatepack_sync_workflow(
					&ret_slate,
					&a,
					tor_config_lock.clone(),
					None,
					true,
					self.doctest_mode,
				);
				match res {
					Ok(s) => return Ok(s.unwrap()),
					Err(_) => return Ok(ret_slate),
				}
			}
			None => Ok(ret_slate),
		}
	}

	/// Receive an atomic swap transaction
	pub fn receive_atomic_tx(
		&self,
		slate: &Slate,
		dest_acct_name: Option<&str>,
		r_addr: Option<String>,
	) -> Result<Slate, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		if let Some(m) = self.middleware.as_ref() {
			m(
				ForeignCheckMiddlewareFn::ReceiveTx,
				w.w2n_client().get_version_info(),
				Some(slate),
			)?;
		}
		let ret_slate = foreign::receive_atomic_tx(
			&mut **w,
			(&self.keychain_mask).as_ref(),
			slate,
			dest_acct_name,
			self.doctest_mode,
		)?;
		match r_addr {
			Some(a) => {
				let tor_config_lock = self.tor_config.lock();
				let res = try_slatepack_sync_workflow(
					&ret_slate,
					&a,
					tor_config_lock.clone(),
					None,
					true,
					self.doctest_mode,
				);
				match res {
					Ok(s) => return Ok(s.unwrap()),
					Err(_) => return Ok(ret_slate),
				}
			}
			None => Ok(ret_slate),
		}
	}

	/// Finalizes a (standard or invoice) transaction initiated by this wallet's Owner api.
	/// This step assumes the paying party has completed round 1 and 2 of slate
	/// creation, and added their partial signatures. This wallet will verify
	/// and add their partial sig, then create the finalized transaction,
	/// ready to post to a node.
	///
	/// This function posts to the node if the `post_automatically`
	/// argument is sent to true. Posting can be done in separately via the
	/// [`post_tx`](struct.Owner.html#method.post_tx) function.
	///
	/// This function also stores the final transaction in the user's wallet files for retrieval
	/// via the [`get_stored_tx`](struct.Owner.html#method.get_stored_tx) function.
	///
	/// # Arguments
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html). The
	/// * `post_automatically` - If true, post the finalized transaction to the configured listening
	/// node
	///
	/// # Returns
	/// * Ok([`slate`](../grin_wallet_libwallet/slate/struct.Slate.html)) if successful,
	/// containing the new finalized slate.
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None);
	/// let mut api_foreign = Foreign::new(wallet.clone(), None, None, false);
	///
	/// // . . .
	/// // Issue the invoice tx via the owner API
	/// let args = IssueInvoiceTxArgs {
	///     amount: 10_000_000_000,
	///     ..Default::default()
	/// };
	/// let result = api_owner.issue_invoice_tx(None, args);
	///
	/// // If result okay, send to payer, who will apply the transaction via their
	/// // owner API, then send back the slate
	/// // ...
	/// # let slate = Slate::blank(2, TxFlow::Invoice);
	///
	/// let slate = api_foreign.finalize_tx(&slate, true);
	/// // if okay, then post via the owner API
	/// ```

	pub fn finalize_tx(&self, slate: &Slate, post_automatically: bool) -> Result<Slate, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let post_automatically = match self.doctest_mode {
			true => false,
			false => post_automatically,
		};
		foreign::finalize_tx(
			&mut **w,
			(&self.keychain_mask).as_ref(),
			slate,
			post_automatically,
		)
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
		use grin_wallet_util::grin_core;
		use grin_wallet_util::grin_keychain as keychain;
		use grin_wallet_util::grin_util as util;

		use grin_core::global;
		use keychain::ExtKeychain;
		use tempfile::tempdir;

		use std::sync::Arc;
		use util::{Mutex, ZeroingString};

		use api::{Foreign, Owner};
		use config::WalletConfig;
		use impls::{DefaultLCProvider, DefaultWalletImpl, HTTPNodeClient};
		use libwallet::{BlockFees, IssueInvoiceTxArgs, Slate, TxFlow, WalletInst};

		// don't run on windows CI, which gives very inconsistent results
		if cfg!(windows) {
			return;
		}

		// Set our local chain_type for testing.
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
		let dir = dir
			.path()
			.to_str()
			.ok_or("Failed to convert tmpdir path to string.".to_owned())
			.unwrap();
		let mut wallet_config = WalletConfig::default();
		wallet_config.data_file_dir = dir.to_owned();
		let pw = ZeroingString::from("");

		let node_client =
			HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None).unwrap();
		let mut wallet = Box::new(
			DefaultWalletImpl::<'static, HTTPNodeClient>::new(node_client.clone()).unwrap(),
		)
			as Box<
				WalletInst<
					'static,
					DefaultLCProvider<HTTPNodeClient, ExtKeychain>,
					HTTPNodeClient,
					ExtKeychain,
				>,
			>;
		let lc = wallet.lc_provider().unwrap();
		let _ = lc.set_top_level_directory(&wallet_config.data_file_dir);
		lc.open_wallet(None, pw, false, false);
		let mut $wallet = Arc::new(Mutex::new(wallet));
	};
}
