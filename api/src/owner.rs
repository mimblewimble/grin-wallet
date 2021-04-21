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

//! Owner API External Definition

use chrono::prelude::*;
use ed25519_dalek::SecretKey as DalekSecretKey;
use uuid::Uuid;

use crate::config::{TorConfig, WalletConfig};
use crate::core::global;
use crate::impls::HttpSlateSender;
use crate::impls::SlateSender as _;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::api_impl::owner_updater::{start_updater_log_thread, StatusMessage};
use crate::libwallet::api_impl::{owner, owner_updater};
use crate::libwallet::{
	AcctPathMapping, Error, InitTxArgs, IssueInvoiceTxArgs, NodeClient, NodeHeightResult,
	OutputCommitMapping, PaymentProof, Slate, Slatepack, SlatepackAddress, TxFlow, TxLogEntry,
	WalletInfo, WalletInst, WalletLCProvider,
};
use crate::util::logger::LoggingConfig;
use crate::util::secp::key::SecretKey;
use crate::util::{from_hex, static_secp_instance, Mutex, ZeroingString};
use grin_wallet_util::OnionV3Address;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Main interface into all wallet API functions.
/// Wallet APIs are split into two seperate blocks of functionality
/// called the ['Owner'](struct.Owner.html) and ['Foreign'](struct.Foreign.html) APIs
///
/// * The 'Owner' API is intended to expose methods that are to be
/// used by the wallet owner only. It is vital that this API is not
/// exposed to anyone other than the owner of the wallet (i.e. the
/// person with access to the seed and password.
///
/// Methods in both APIs are intended to be 'single use', that is to say each
/// method will 'open' the wallet (load the keychain with its master seed), perform
/// its operation, then 'close' the wallet (unloading references to the keychain and master
/// seed).

pub struct Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// contain all methods to manage the wallet
	pub wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
	/// Flag to normalize some output during testing. Can mostly be ignored.
	pub doctest_mode: bool,
	/// retail TLD during doctest
	pub doctest_retain_tld: bool,
	/// Share ECDH key
	pub shared_key: Arc<Mutex<Option<SecretKey>>>,
	/// Update thread
	updater: Arc<Mutex<owner_updater::Updater<'static, L, C, K>>>,
	/// Stop state for update thread
	pub updater_running: Arc<AtomicBool>,
	/// Sender for update messages
	status_tx: Mutex<Option<Sender<StatusMessage>>>,
	/// Holds all update and status messages returned by the
	/// updater process
	updater_messages: Arc<Mutex<Vec<StatusMessage>>>,
	/// Optional TOR configuration, holding address of sender and
	/// data directory
	tor_config: Mutex<Option<TorConfig>>,
}

impl<L, C, K> Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient,
	K: Keychain,
{
	/// Create a new API instance with the given wallet instance. All subsequent
	/// API calls will operate on this instance of the wallet.
	///
	/// Each method will call the [`WalletBackend`](../grin_wallet_libwallet/types/trait.WalletBackend.html)'s
	/// [`open_with_credentials`](../grin_wallet_libwallet/types/trait.WalletBackend.html#tymethod.open_with_credentials)
	/// (initialising a keychain with the master seed,) perform its operation, then close the keychain
	/// with a call to [`close`](../grin_wallet_libwallet/types/trait.WalletBackend.html#tymethod.close)
	///
	/// # Arguments
	/// * `wallet_in` - A reference-counted mutex containing an implementation of the
	/// * `custom_channel` - A custom MPSC Tx/Rx pair to capture status
	/// updates
	/// [`WalletBackend`](../grin_wallet_libwallet/types/trait.WalletBackend.html) trait.
	///
	/// # Returns
	/// * An instance of the OwnerApi holding a reference to the provided wallet
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
	/// use grin_core::global;
	/// use keychain::ExtKeychain;
	/// use tempfile::tempdir;
	///
	/// use std::sync::Arc;
	/// use util::{Mutex, ZeroingString};
	///
	/// use api::Owner;
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
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// // .. perform wallet operations
	///
	/// ```

	pub fn new(
		wallet_inst: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>,
		custom_channel: Option<Sender<StatusMessage>>,
	) -> Self {
		let updater_running = Arc::new(AtomicBool::new(false));
		let updater = Arc::new(Mutex::new(owner_updater::Updater::new(
			wallet_inst.clone(),
			updater_running.clone(),
		)));
		let updater_messages = Arc::new(Mutex::new(vec![]));

		let tx = match custom_channel {
			Some(c) => c,
			None => {
				let (tx, rx) = channel();
				let _ = start_updater_log_thread(rx, updater_messages.clone());
				tx
			}
		};

		Owner {
			wallet_inst,
			doctest_mode: false,
			doctest_retain_tld: false,
			shared_key: Arc::new(Mutex::new(None)),
			updater,
			updater_running,
			status_tx: Mutex::new(Some(tx)),
			updater_messages,
			tor_config: Mutex::new(None),
		}
	}

	/// Set the TOR configuration for this instance of the OwnerAPI, used during
	/// `init_send_tx` when send args are present and a TOR address is specified
	///
	/// # Arguments
	/// * `tor_config` - The optional [TorConfig](#) to use
	/// # Returns
	/// * Nothing

	pub fn set_tor_config(&self, tor_config: Option<TorConfig>) {
		let mut lock = self.tor_config.lock();
		*lock = tor_config;
	}

	/// Returns a list of accounts stored in the wallet (i.e. mappings between
	/// user-specified labels and BIP32 derivation paths.
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	///
	/// # Returns
	/// * Result Containing:
	/// * A Vector of [`AcctPathMapping`](../grin_wallet_libwallet/types/struct.AcctPathMapping.html) data
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * A wallet should always have the path with the label 'default' path defined,
	/// with path m/0/0
	/// * This method does not need to use the wallet seed or keychain.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let result = api_owner.accounts(None);
	///
	/// if let Ok(accts) = result {
	///     //...
	/// }
	/// ```

	pub fn accounts(
		&self,
		keychain_mask: Option<&SecretKey>,
	) -> Result<Vec<AcctPathMapping>, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		// Test keychain mask, to keep API consistent
		let _ = w.keychain(keychain_mask)?;
		owner::accounts(&mut **w)
	}

	/// Creates a new 'account', which is a mapping of a user-specified
	/// label to a BIP32 path
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `label` - A human readable label to which to map the new BIP32 Path
	///
	/// # Returns
	/// * Result Containing:
	/// * A [Keychain Identifier](../grin_keychain/struct.Identifier.html) for the new path
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * Wallets should be initialised with the 'default' path mapped to `m/0/0`
	/// * Each call to this function will increment the first element of the path
	/// so the first call will create an account at `m/1/0` and the second at
	/// `m/2/0` etc. . .
	/// * The account path is used throughout as the parent key for most key-derivation
	/// operations. See [`set_active_account`](struct.Owner.html#method.set_active_account) for
	/// further details.
	///
	/// * This function does not need to use the root wallet seed or keychain.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let result = api_owner.create_account_path(None, "account1");
	///
	/// if let Ok(identifier) = result {
	///     //...
	/// }
	/// ```

	pub fn create_account_path(
		&self,
		keychain_mask: Option<&SecretKey>,
		label: &str,
	) -> Result<Identifier, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		owner::create_account_path(&mut **w, keychain_mask, label)
	}

	/// Sets the wallet's currently active account. This sets the
	/// BIP32 parent path used for most key-derivation operations.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `label` - The human readable label for the account. Accounts can be retrieved via
	/// the [`account`](struct.Owner.html#method.accounts) method
	///
	/// # Returns
	/// * Result Containing:
	/// * `Ok(())` if the path was correctly set
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * Wallet parent paths are 2 path elements long, e.g. `m/0/0` is the path
	/// labelled 'default'. Keys derived from this parent path are 3 elements long,
	/// e.g. the secret keys derived from the `m/0/0` path will be  at paths `m/0/0/0`,
	/// `m/0/0/1` etc...
	///
	/// * This function does not need to use the root wallet seed or keychain.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let result = api_owner.create_account_path(None, "account1");
	///
	/// if let Ok(identifier) = result {
	///     // set the account active
	///     let result2 = api_owner.set_active_account(None, "account1");
	/// }
	/// ```

	pub fn set_active_account(
		&self,
		keychain_mask: Option<&SecretKey>,
		label: &str,
	) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		// Test keychain mask, to keep API consistent
		let _ = w.keychain(keychain_mask)?;
		owner::set_active_account(&mut **w, label)
	}

	/// Returns a list of outputs from the active account in the wallet.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `include_spent` - If `true`, outputs that have been marked as 'spent'
	/// in the wallet will be returned. If `false`, spent outputs will omitted
	/// from the results.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../grin_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain output information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// Note this setting is ignored if the updater process is running via a call to
	/// [`start_updater`](struct.Owner.html#method.start_updater)
	/// * `tx_id` - If `Some(i)`, only return the outputs associated with
	/// the transaction log entry of id `i`.
	///
	/// # Returns
	/// * `(bool, Vec<OutputCommitMapping>)` - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains a vector of
	/// [OutputCommitMapping](../grin_wallet_libwallet/types/struct.OutputCommitMapping.html)
	/// of which each element is a mapping between the wallet's internal
	/// [OutputData](../grin_wallet_libwallet/types/struct.Output.html)
	/// and the Output commitment as identified in the chain's UTXO set
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// let show_spent = false;
	/// let update_from_node = true;
	/// let tx_id = None;
	///
	/// let result = api_owner.retrieve_outputs(None, show_spent, update_from_node, tx_id);
	///
	/// if let Ok((was_updated, output_mappings)) = result {
	///     //...
	/// }
	/// ```

	pub fn retrieve_outputs(
		&self,
		keychain_mask: Option<&SecretKey>,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		let refresh_from_node = match self.updater_running.load(Ordering::Relaxed) {
			true => false,
			false => refresh_from_node,
		};
		owner::retrieve_outputs(
			self.wallet_inst.clone(),
			keychain_mask,
			&tx,
			include_spent,
			refresh_from_node,
			tx_id,
		)
	}

	/// Returns a list of [Transaction Log Entries](../grin_wallet_libwallet/types/struct.TxLogEntry.html)
	/// from the active account in the wallet.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../grin_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// Note this setting is ignored if the updater process is running via a call to
	/// [`start_updater`](struct.Owner.html#method.start_updater)
	/// * `tx_id` - If `Some(i)`, only return the transactions associated with
	/// the transaction log entry of id `i`.
	/// * `tx_slate_id` - If `Some(uuid)`, only return transactions associated with
	/// the given [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html) uuid.
	///
	/// # Returns
	/// * `(bool, Vec<TxLogEntry)` - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains the set of retrieved
	/// [TxLogEntries](../grin_wallet_libwallet/types/struct.TxLogEntry.html)
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = None;
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_txs(None, update_from_node, tx_id, tx_slate_id);
	///
	/// if let Ok((was_updated, tx_log_entries)) = result {
	///     //...
	/// }
	/// ```

	pub fn retrieve_txs(
		&self,
		keychain_mask: Option<&SecretKey>,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		let refresh_from_node = match self.updater_running.load(Ordering::Relaxed) {
			true => false,
			false => refresh_from_node,
		};
		let mut res = owner::retrieve_txs(
			self.wallet_inst.clone(),
			keychain_mask,
			&tx,
			refresh_from_node,
			tx_id,
			tx_slate_id,
		)?;
		if self.doctest_mode {
			res.1 = res
				.1
				.into_iter()
				.map(|mut t| {
					t.confirmation_ts = Some(Utc.ymd(2019, 1, 15).and_hms(16, 1, 26));
					t.creation_ts = Utc.ymd(2019, 1, 15).and_hms(16, 1, 26);
					t
				})
				.collect();
		}
		Ok(res)
	}

	/// Returns summary information from the active account in the wallet.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../grin_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// Note this setting is ignored if the updater process is running via a call to
	/// [`start_updater`](struct.Owner.html#method.start_updater)
	/// * `minimum_confirmations` - The minimum number of confirmations an output
	/// should have before it's included in the 'amount_currently_spendable' total
	///
	/// # Returns
	/// * (`bool`, [`WalletInfo`](../grin_wallet_libwallet/types/struct.WalletInfo.html)) - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains the Summary [`WalletInfo`](../grin_wallet_libwallet/types/struct.WalletInfo.html)
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None);
	/// let update_from_node = true;
	/// let minimum_confirmations=10;
	///
	/// // Return summary info for active account
	/// let result = api_owner.retrieve_summary_info(None, update_from_node, minimum_confirmations);
	///
	/// if let Ok((was_updated, summary_info)) = result {
	///     //...
	/// }
	/// ```

	pub fn retrieve_summary_info(
		&self,
		keychain_mask: Option<&SecretKey>,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		let refresh_from_node = match self.updater_running.load(Ordering::Relaxed) {
			true => false,
			false => refresh_from_node,
		};
		owner::retrieve_summary_info(
			self.wallet_inst.clone(),
			keychain_mask,
			&tx,
			refresh_from_node,
			minimum_confirmations,
		)
	}

	/// Initiates a new transaction as the sender, creating a new
	/// [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html) object containing
	/// the sender's inputs, change outputs, and public signature data. This slate can
	/// then be sent to the recipient to continue the transaction via the
	/// [Foreign API's `receive_tx`](struct.Foreign.html#method.receive_tx) method.
	///
	/// When a transaction is created, the wallet must also lock inputs (and create unconfirmed
	/// outputs) corresponding to the transaction created in the slate, so that the wallet doesn't
	/// attempt to re-spend outputs that are already included in a transaction before the transaction
	/// is confirmed. This method also returns a function that will perform that locking, and it is
	/// up to the caller to decide the best time to call the lock function
	/// (via the [`tx_lock_outputs`](struct.Owner.html#method.tx_lock_outputs) method).
	/// If the exchange method is intended to be synchronous (such as via a direct http call,)
	/// then the lock call can wait until the response is confirmed. If it is asynchronous, (such
	/// as via file transfer,) the lock call should happen immediately (before the file is sent
	/// to the recipient).
	///
	/// If the `send_args` [`InitTxSendArgs`](../grin_wallet_libwallet/types/struct.InitTxSendArgs.html),
	/// of the [`args`](../grin_wallet_libwallet/types/struct.InitTxArgs.html), field is Some, this
	/// function will attempt to send the slate back to the sender using the slatepack sync
	/// send (TOR). If providing this argument, check the `state` field of the slate to see if the
	/// sync_send was successful (it should be S2 if the sync sent successfully). It will also post
	/// the transction if the `post_tx` field is set.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `args` - [`InitTxArgs`](../grin_wallet_libwallet/types/struct.InitTxArgs.html),
	/// transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * a result containing:
	/// * The transaction [Slate](../grin_wallet_libwallet/slate/struct.Slate.html),
	/// which can be forwarded to the recieving party by any means. Once the caller is relatively
	/// certain that the transaction has been sent to the recipient, the associated wallet
	/// transaction outputs should be locked via a call to
	/// [`tx_lock_outputs`](struct.Owner.html#method.tx_lock_outputs). This must be called before calling
	/// [`finalize_tx`](struct.Owner.html#method.finalize_tx).
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * This method requires an active connection to a node, and will fail with error if a node
	/// cannot be contacted to refresh output statuses.
	/// * This method will store a partially completed transaction in the wallet's transaction log,
	/// which will be updated on the corresponding call to [`finalize_tx`](struct.Owner.html#method.finalize_tx).
	///
	/// # Example
	/// Set up as in [new](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None);
	/// // Attempt to create a transaction using the 'default' account
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 2,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	///     None,
	///     args,
	/// );
	///
	/// if let Ok(slate) = result {
	///     // Send slate somehow
	///     // ...
	///     // Lock our outputs if we're happy the slate was (or is being) sent
	///     api_owner.tx_lock_outputs(None, &slate);
	/// }
	/// ```

	pub fn init_send_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		args: InitTxArgs,
	) -> Result<Slate, Error> {
		let send_args = args.send_args.clone();
		let slate = {
			let mut w_lock = self.wallet_inst.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			owner::init_send_tx(&mut **w, keychain_mask, args, self.doctest_mode)?
		};
		// Helper functionality. If send arguments exist, attempt to send sync and
		// finalize
		let skip_tor = match send_args.as_ref() {
			None => false,
			Some(sa) => sa.skip_tor,
		};
		match send_args {
			Some(sa) => {
				let tor_config_lock = self.tor_config.lock();
				let tc = tor_config_lock.clone();
				let tc = match tc {
					Some(mut c) => {
						c.skip_send_attempt = Some(skip_tor);
						Some(c)
					}
					None => None,
				};
				let res = try_slatepack_sync_workflow(
					&slate,
					&sa.dest,
					tc,
					None,
					false,
					self.doctest_mode,
				);
				match res {
					Ok(Some(s)) => {
						if sa.post_tx {
							self.tx_lock_outputs(keychain_mask, &s)?;
							let ret_slate = self.finalize_tx(keychain_mask, &s)?;
							let result = self.post_tx(keychain_mask, &ret_slate, sa.fluff);
							match result {
								Ok(_) => {
									info!("Tx sent ok",);
									return Ok(ret_slate);
								}
								Err(e) => {
									error!("Tx sent fail: {}", e);
									return Err(e);
								}
							}
						} else {
							self.tx_lock_outputs(keychain_mask, &s)?;
							let ret_slate = self.finalize_tx(keychain_mask, &s)?;
							return Ok(ret_slate);
						}
					}
					Ok(None) => Ok(slate),
					Err(_) => Ok(slate),
				}
			}
			None => Ok(slate),
		}
	}

	/// Issues a new invoice transaction slate, essentially a `request for payment`.
	/// The slate created by this function will contain the amount, an output for the amount,
	/// as well as round 1 of singature creation complete. The slate should then be send
	/// to the payer, who should add their inputs and signature data and return the slate
	/// via the [Foreign API's `finalize_tx`](struct.Foreign.html#method.finalize_tx) method.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `args` - [`IssueInvoiceTxArgs`](../grin_wallet_libwallet/types/struct.IssueInvoiceTxArgs.html),
	/// invoice transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * ``Ok([`slate`](../grin_wallet_libwallet/slate/struct.Slate.html))` if successful,
	/// containing the updated slate.
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None);
	///
	/// let args = IssueInvoiceTxArgs {
	///     amount: 60_000_000_000,
	///     ..Default::default()
	/// };
	/// let result = api_owner.issue_invoice_tx(None, args);
	///
	/// if let Ok(slate) = result {
	///     // if okay, send to the payer to add their inputs
	///     // . . .
	/// }
	/// ```
	pub fn issue_invoice_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		args: IssueInvoiceTxArgs,
	) -> Result<Slate, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		owner::issue_invoice_tx(&mut **w, keychain_mask, args, self.doctest_mode)
	}

	/// Processes an invoice tranaction created by another party, essentially
	/// a `request for payment`. The incoming slate should contain a requested
	/// amount, an output created by the invoicer convering the amount, and
	/// part 1 of signature creation completed. This function will add inputs
	/// equalling the amount + fees, as well as perform round 1 and 2 of signature
	/// creation.
	///
	/// Callers should note that no prompting of the user will be done by this function
	/// it is up to the caller to present the request for payment to the user
	/// and verify that payment should go ahead.
	///
	/// If the `send_args` [`InitTxSendArgs`](../grin_wallet_libwallet/types/struct.InitTxSendArgs.html),
	/// of the [`args`](../grin_wallet_libwallet/types/struct.InitTxArgs.html), field is Some, this
	/// function will attempt to send the slate back to the initiator using the slatepack sync
	/// send (TOR). If providing this argument, check the `state` field of the slate to see if the
	/// sync_send was successful (it should be I3 if the sync sent successfully).
	///
	/// This function also stores the final transaction in the user's wallet files for retrieval
	/// via the [`get_stored_tx`](struct.Owner.html#method.get_stored_tx) function.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html). The
	/// payer should have filled in round 1 and 2.
	/// * `args` - [`InitTxArgs`](../grin_wallet_libwallet/types/struct.InitTxArgs.html),
	/// transaction initialization arguments. See struct documentation for further detail.
	///
	/// # Returns
	/// * ``Ok([`slate`](../grin_wallet_libwallet/slate/struct.Slate.html))` if successful,
	/// containing the updated slate.
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None);
	///
	/// // . . .
	/// // The slate has been recieved from the invoicer, somehow
	/// # let slate = Slate::blank(2, TxFlow::Invoice);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: slate.amount,
	///     minimum_confirmations: 2,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     ..Default::default()
	/// };
	///
	/// let result = api_owner.process_invoice_tx(None, &slate, args);
	///
	/// if let Ok(slate) = result {
	/// // If result okay, send back to the invoicer
	/// // . . .
	/// }
	/// ```

	pub fn process_invoice_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		slate: &Slate,
		args: InitTxArgs,
	) -> Result<Slate, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let send_args = args.send_args.clone();
		let slate =
			owner::process_invoice_tx(&mut **w, keychain_mask, slate, args, self.doctest_mode)?;
		// Helper functionality. If send arguments exist, attempt to send
		match send_args {
			Some(sa) => {
				let tor_config_lock = self.tor_config.lock();
				let tc = tor_config_lock.clone();
				let tc = match tc {
					Some(mut c) => {
						c.skip_send_attempt = Some(sa.skip_tor);
						Some(c)
					}
					None => None,
				};
				let res = try_slatepack_sync_workflow(
					&slate,
					&sa.dest,
					tc,
					None,
					true,
					self.doctest_mode,
				);
				match res {
					Ok(s) => Ok(s.unwrap()),
					Err(_) => Ok(slate),
				}
			}
			None => Ok(slate),
		}
	}

	/// Locks the outputs associated with the inputs to the transaction in the given
	/// [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html),
	/// making them unavailable for use in further transactions. This function is called
	/// by the sender, (or more generally, all parties who have put inputs into the transaction,)
	/// and must be called before the corresponding call to [`finalize_tx`](struct.Owner.html#method.finalize_tx)
	/// that completes the transaction.
	///
	/// Outputs will generally remain locked until they are removed from the chain,
	/// at which point they will become `Spent`. It is commonplace for transactions not to complete
	/// for various reasons over which a particular wallet has no control. For this reason,
	/// [`cancel_tx`](struct.Owner.html#method.cancel_tx) can be used to manually unlock outputs
	/// and return them to the `Unspent` state.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html). All
	/// * `participant_id` - The participant id, generally 0 for the party putting in funds, 1 for the
	/// party receiving.
	/// elements in the `input` vector of the `tx` field that are found in the wallet's currently
	/// active account will be set to status `Locked`
	///
	/// # Returns
	/// * Ok(()) if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 10,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	///     None,
	///     args,
	/// );
	///
	/// if let Ok(slate) = result {
	///     // Send slate somehow
	///     // ...
	///     // Lock our outputs if we're happy the slate was (or is being) sent
	///     api_owner.tx_lock_outputs(None, &slate);
	/// }
	/// ```

	pub fn tx_lock_outputs(
		&self,
		keychain_mask: Option<&SecretKey>,
		slate: &Slate,
	) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		owner::tx_lock_outputs(&mut **w, keychain_mask, slate)
	}

	/// Finalizes a transaction, after all parties
	/// have filled in both rounds of Slate generation. This step adds
	/// all participants partial signatures to create the final signature,
	/// resulting in a final transaction that is ready to post to a node.
	///
	/// Note that this function DOES NOT POST the transaction to a node
	/// for validation. This is done in separately via the
	/// [`post_tx`](struct.Owner.html#method.post_tx) function.
	///
	/// This function also stores the final transaction in the user's wallet files for retrieval
	/// via the [`get_stored_tx`](struct.Owner.html#method.get_stored_tx) function.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html). All
	/// participants must have filled in both rounds, and the sender should have locked their
	/// outputs (via the [`tx_lock_outputs`](struct.Owner.html#method.tx_lock_outputs) function).
	///
	/// # Returns
	/// * ``Ok([`slate`](../grin_wallet_libwallet/slate/struct.Slate.html))` if successful,
	/// containing the new finalized slate.
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 10,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	///     None,
	///     args,
	/// );
	///
	/// if let Ok(slate) = result {
	///     // Send slate somehow
	///     // ...
	///     // Lock our outputs if we're happy the slate was (or is being) sent
	///     let res = api_owner.tx_lock_outputs(None, &slate);
	///     //
	///     // Retrieve slate back from recipient
	///     //
	///     let res = api_owner.finalize_tx(None, &slate);
	/// }
	/// ```

	pub fn finalize_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		slate: &Slate,
	) -> Result<Slate, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		owner::finalize_tx(&mut **w, keychain_mask, slate)
	}

	/// Posts a completed transaction to the listening node for validation and inclusion in a block
	/// for mining.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `tx` - A completed [`Transaction`](../grin_core/core/transaction/struct.Transaction.html),
	/// typically the `tx` field in the transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html).
	/// * `fluff` - Instruct the node whether to use the Dandelion protocol when posting the
	/// transaction. If `true`, the node should skip the Dandelion phase and broadcast the
	/// transaction to all peers immediately. If `false`, the node will follow dandelion logic and
	/// initiate the stem phase.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 10,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	///     None,
	///     args,
	/// );
	///
	/// if let Ok(slate) = result {
	///     // Send slate somehow
	///     // ...
	///     // Lock our outputs if we're happy the slate was (or is being) sent
	///     let res = api_owner.tx_lock_outputs(None, &slate);
	///     //
	///     // Retrieve slate back from recipient
	///     //
	///     let res = api_owner.finalize_tx(None, &slate);
	///     let res = api_owner.post_tx(None, &slate, true);
	/// }
	/// ```

	pub fn post_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		slate: &Slate,
		fluff: bool,
	) -> Result<(), Error> {
		let client = {
			let mut w_lock = self.wallet_inst.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			// Test keychain mask, to keep API consistent
			let _ = w.keychain(keychain_mask)?;
			w.w2n_client().clone()
		};
		owner::post_tx(&client, slate.tx_or_err()?, fluff)
	}

	/// Cancels a transaction. This entails:
	/// * Setting the transaction status to either `TxSentCancelled` or `TxReceivedCancelled`
	/// * Deleting all change outputs or recipient outputs associated with the transaction
	/// * Setting the status of all assocatied inputs from `Locked` to `Spent` so they can be
	/// used in new transactions.
	///
	/// Transactions can be cancelled by transaction log id or slate id (call with either set to
	/// Some, not both)
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `tx_id` - If present, cancel by the [`TxLogEntry`](../grin_wallet_libwallet/types/struct.TxLogEntry.html) id
	/// for the transaction.
	///
	/// * `tx_slate_id` - If present, cancel by the Slate id.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 10,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	///     None,
	///     args,
	/// );
	///
	/// if let Ok(slate) = result {
	///     // Send slate somehow
	///     // ...
	///     // Lock our outputs if we're happy the slate was (or is being) sent
	///     let res = api_owner.tx_lock_outputs(None, &slate);
	///     //
	///     // We didn't get the slate back, or something else went wrong
	///     //
	///     let res = api_owner.cancel_tx(None, None, Some(slate.id.clone()));
	/// }
	/// ```

	pub fn cancel_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		owner::cancel_tx(
			self.wallet_inst.clone(),
			keychain_mask,
			&tx,
			tx_id,
			tx_slate_id,
		)
	}

	/// Retrieves the stored transaction associated with a TxLogEntry. Can be used even after the
	/// transaction has completed. Either the Transaction Log ID or the Slate UUID must be supplied.
	/// If both are supplied, the Transaction Log ID is preferred.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `tx_id` - The id of the transaction in the wallet's Transaction Log. Either this or
	/// `slate_id` must be provided.
	/// * `slate_id` - The UUID of the Transaction Slate to find. Either this or `tx_id` must be
	/// provided
	///
	/// # Returns
	/// * Ok(Some([Slate](../grin_wallet_libwallet/slate/struct.Slate.html)) containing the stored
	/// transaction, if successful. Note that this Slate will not contain all of the fields used by
	/// the original Slate that resulted in the transaction.
	/// * Ok(None) if the stored Transaction isn't found.
	/// * [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = None;
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_txs(None, update_from_node, tx_id, tx_slate_id);
	///
	/// if let Ok((was_updated, tx_log_entries)) = result {
	///     let stored_tx = api_owner.get_stored_tx(None, Some(tx_log_entries[0].id), None).unwrap();
	///     //...
	/// }
	/// ```

	pub fn get_stored_tx(
		&self,
		keychain_mask: Option<&SecretKey>,
		tx_id: Option<u32>,
		slate_id: Option<&Uuid>,
	) -> Result<Option<Slate>, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		// Test keychain mask, to keep API consistent
		let _ = w.keychain(keychain_mask)?;
		owner::get_stored_tx(&**w, tx_id, slate_id)
	}

	/// Scans the entire UTXO set from the node, identify which outputs belong to the given wallet
	/// update the wallet state to be consistent with what's currently in the UTXO set.
	///
	/// This function can be used to repair wallet state, particularly by restoring outputs that may
	/// be missing if the wallet owner has cancelled transactions locally that were then successfully
	/// posted to the chain.
	///
	/// This operation scans the entire chain, and is expected to be time intensive. It is imperative
	/// that no other processes should be trying to use the wallet at the same time this function is
	/// running.
	///
	/// When an output is found that doesn't exist in the wallet, a corresponding
	/// [TxLogEntry](../grin_wallet_libwallet/types/struct.TxLogEntry.html) is created.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `start_height` - If provided, the height of the first block from which to start scanning.
	/// The scan will start from block 1 if this is not provided.
	/// * `delete_unconfirmed` - if `false`, the scan process will be non-destructive, and
	/// mostly limited to restoring missing outputs. It will leave unconfirmed transaction logs entries
	/// and unconfirmed outputs intact. If `true`, the process will unlock all locked outputs,
	/// restore all missing outputs, and mark any outputs that have been marked 'Spent' but are still
	/// in the UTXO set as 'Unspent' (as can happen during a fork). It will also attempt to cancel any
	/// transaction log entries associated with any locked outputs or outputs incorrectly marked 'Spent'.
	/// Note this completely removes all outstanding transactions, so users should be very aware what
	/// will happen if this flag is set. Note that if transactions/outputs are removed that later
	/// confirm on the chain, another call to this function will restore them.
	///
	/// # Returns
	/// * `Ok(())` if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.

	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None);
	/// let result = api_owner.scan(
	///     None,
	///     Some(20000),
	///     false,
	/// );
	///
	/// if let Ok(_) = result {
	///     // Wallet outputs should be consistent with what's on chain
	///     // ...
	/// }
	/// ```

	pub fn scan(
		&self,
		keychain_mask: Option<&SecretKey>,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		owner::scan(
			self.wallet_inst.clone(),
			keychain_mask,
			start_height,
			delete_unconfirmed,
			&tx,
		)
	}

	/// Retrieves the last known height known by the wallet. This is determined as follows:
	/// * If the wallet can successfully contact its configured node, the reported node
	/// height is returned, and the `updated_from_node` field in the response is `true`
	/// * If the wallet cannot contact the node, this function returns the maximum height
	/// of all outputs contained within the wallet, and the `updated_from_node` fields
	/// in the response is set to false.
	///
	/// Clients should generally ensure the `updated_from_node` field is returned as
	/// `true` before assuming the height for any operation.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	///
	/// # Returns
	/// * Ok with a  [`NodeHeightResult`](../grin_wallet_libwallet/types/struct.NodeHeightResult.html)
	/// if successful. If the height result was obtained from the configured node,
	/// `updated_from_node` will be set to `true`
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// let result = api_owner.node_height(None);
	///
	/// if let Ok(node_height_result) = result {
	///     if node_height_result.updated_from_node {
	///          //we can assume node_height_result.height is relatively safe to use
	///
	///     }
	///     //...
	/// }
	/// ```

	pub fn node_height(
		&self,
		keychain_mask: Option<&SecretKey>,
	) -> Result<NodeHeightResult, Error> {
		{
			let mut w_lock = self.wallet_inst.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			// Test keychain mask, to keep API consistent
			let _ = w.keychain(keychain_mask)?;
		}
		let mut res = owner::node_height(self.wallet_inst.clone(), keychain_mask)?;
		if self.doctest_mode {
			// return a consistent hash for doctest
			res.header_hash =
				"d4b3d3c40695afd8c7760f8fc423565f7d41310b7a4e1c4a4a7950a66f16240d".to_owned();
		}
		Ok(res)
	}

	// LIFECYCLE FUNCTIONS

	/// Retrieve the top-level directory for the wallet. This directory should contain the
	/// `grin-wallet.toml` file and the `wallet_data` directory that contains the wallet
	/// seed + data files. Future versions of the wallet API will support multiple wallets
	/// within the top level directory.
	///
	/// The top level directory defaults to (in order of precedence):
	///
	/// 1) The current directory, from which `grin-wallet` or the main process was run, if it
	/// contains a `grin-wallet.toml` file.
	/// 2) ~/.grin/<chaintype>/ otherwise
	///
	/// # Arguments
	///
	/// * None
	///
	/// # Returns
	/// * Ok with a String value representing the full path to the top level wallet dierctory
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// let result = api_owner.get_top_level_directory();
	///
	/// if let Ok(dir) = result {
	///     println!("Top level directory is: {}", dir);
	///     //...
	/// }
	/// ```

	pub fn get_top_level_directory(&self) -> Result<String, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		if self.doctest_mode && !self.doctest_retain_tld {
			Ok("/doctest/dir".to_owned())
		} else {
			lc.get_top_level_directory()
		}
	}

	/// Set the top-level directory for the wallet. This directory can be empty, and will be created
	/// during a subsequent calls to [`create_config`](struct.Owner.html#method.create_config)
	///
	/// Set [`get_top_level_directory`](struct.Owner.html#method.get_top_level_directory) for a
	/// description of the top level directory and default paths.
	///
	/// # Arguments
	///
	/// * `dir`: The new top-level directory path (either relative to current directory or
	/// absolute.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let dir = "path/to/wallet/dir";
	///
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// #   .path()
	/// #   .to_str()
	/// #   .ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// #   .unwrap();
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// let result = api_owner.set_top_level_directory(dir);
	///
	/// if let Ok(dir) = result {
	///    //...
	/// }
	/// ```

	pub fn set_top_level_directory(&self, dir: &str) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.set_top_level_directory(dir)
	}

	/// Create a `grin-wallet.toml` configuration file in the top-level directory for the
	/// specified chain type.
	/// A custom [`WalletConfig`](../grin_wallet_config/types/struct.WalletConfig.html)
	/// and/or grin `LoggingConfig` may optionally be provided, otherwise defaults will be used.
	///
	/// Paths in the configuration file will be updated to reflect the top level directory, so
	/// path-related values in the optional configuration structs will be ignored.
	///
	/// # Arguments
	///
	/// * `chain_type`: The chain type to use in creation of the configuration file. This can be
	///     * `AutomatedTesting`
	///     * `UserTesting`
	///     * `Testnet`
	///     * `Mainnet`
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// let dir = "path/to/wallet/dir";
	///
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// #   .path()
	/// #   .to_str()
	/// #   .ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// #   .unwrap();
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// let _ = api_owner.set_top_level_directory(dir);
	///
	/// let result = api_owner.create_config(&ChainTypes::Mainnet, None, None, None);
	///
	/// if let Ok(_) = result {
	///    //...
	/// }
	/// ```

	pub fn create_config(
		&self,
		chain_type: &global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
	) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.create_config(
			chain_type,
			"grin-wallet.toml",
			wallet_config,
			logging_config,
			tor_config,
		)
	}

	/// Creates a new wallet seed and empty wallet database in the `wallet_data` directory of
	/// the top level directory.
	///
	/// Paths in the configuration file will be updated to reflect the top level directory, so
	/// path-related values in the optional configuration structs will be ignored.
	///
	/// The wallet files must not already exist, and ~The `grin-wallet.toml` file must exist
	/// in the top level directory (can be created via a call to
	/// [`create_config`](struct.Owner.html#method.create_config))
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	/// * `mnemonic`: If present, restore the wallet seed from the given mnemonic instead of creating
	/// a new random seed.
	/// * `mnemonic_length`: Desired length of mnemonic in bytes (16 or 32, either 12 or 24 words).
	/// Use 0 if mnemonic isn't being used.
	/// * `password`: The password used to encrypt/decrypt the `wallet.seed` file
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // note that the WalletInst struct does not necessarily need to contain an
	/// // instantiated wallet
	///
	/// let dir = "path/to/wallet/dir";
	///
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// #   .path()
	/// #   .to_str()
	/// #   .ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// #   .unwrap();
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// let _ = api_owner.set_top_level_directory(dir);
	///
	/// // Create configuration
	/// let result = api_owner.create_config(&ChainTypes::Mainnet, None, None, None);
	///
	/// // create new wallet wirh random seed
	/// let pw = ZeroingString::from("my_password");
	/// let result = api_owner.create_wallet(None, None, 0, pw);
	///
	/// if let Ok(r) = result {
	///     //...
	/// }
	/// ```

	pub fn create_wallet(
		&self,
		name: Option<&str>,
		mnemonic: Option<ZeroingString>,
		mnemonic_length: u32,
		password: ZeroingString,
	) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.create_wallet(
			name,
			mnemonic,
			mnemonic_length as usize,
			password,
			self.doctest_mode,
		)
	}

	/// `Opens` a wallet, populating the internal keychain with the encrypted seed, and optionally
	/// returning a `keychain_mask` token to the caller to provide in all future calls.
	/// If using a mask, the seed will be stored in-memory XORed against the `keychain_mask`, and
	/// will not be useable if the mask is not provided.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	/// * `password`: The password to use to open the wallet
	/// a new random seed.
	/// * `use_mask`: Whether to create and return a mask which much be provided in all future
	/// API calls.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // note that the WalletInst struct does not necessarily need to contain an
	/// // instantiated wallet
	/// let dir = "path/to/wallet/dir";
	///
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// #   .path()
	/// #   .to_str()
	/// #   .ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// #   .unwrap();
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// let _ = api_owner.set_top_level_directory(dir);
	///
	/// // Create configuration
	/// let result = api_owner.create_config(&ChainTypes::Mainnet, None, None, None);
	///
	/// // create new wallet wirh random seed
	/// let pw = ZeroingString::from("my_password");
	/// let _ = api_owner.create_wallet(None, None, 0, pw.clone());
	///
	/// let result = api_owner.open_wallet(None, pw, true);
	///
	/// if let Ok(m) = result {
	///     // use this mask in all subsequent calls
	///     let mask = m;
	/// }
	/// ```

	pub fn open_wallet(
		&self,
		name: Option<&str>,
		password: ZeroingString,
		use_mask: bool,
	) -> Result<Option<SecretKey>, Error> {
		// just return a representative string for doctest mode
		if self.doctest_mode {
			let secp_inst = static_secp_instance();
			let secp = secp_inst.lock();
			return Ok(Some(SecretKey::from_slice(
				&secp,
				&from_hex("d096b3cb75986b3b13f80b8f5243a9edf0af4c74ac37578c5a12cfb5b59b1868")
					.unwrap(),
			)?));
		}
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.open_wallet(name, password, use_mask, self.doctest_mode)
	}

	/// `Close` a wallet, removing the master seed from memory.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let res = api_owner.close_wallet(None);
	///
	/// if let Ok(_) = res {
	///     // ...
	/// }
	/// ```

	pub fn close_wallet(&self, name: Option<&str>) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.close_wallet(name)
	}

	/// Return the BIP39 mnemonic for the given wallet. This function will decrypt
	/// the wallet's seed file with the given password, and thus does not need the
	/// wallet to be open.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	/// * `password`: The password used to encrypt the seed file.
	///
	/// # Returns
	/// * Ok(BIP-39 mneminc) if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let pw = ZeroingString::from("my_password");
	/// let res = api_owner.get_mnemonic(None, pw);
	///
	/// if let Ok(mne) = res {
	///     // ...
	/// }
	/// ```
	pub fn get_mnemonic(
		&self,
		name: Option<&str>,
		password: ZeroingString,
	) -> Result<ZeroingString, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.get_mnemonic(name, password)
	}

	/// Changes a wallet's password, meaning the old seed file is decrypted with the old password,
	/// and a new seed file is created with the same mnemonic and encrypted with the new password.
	///
	/// This function temporarily backs up the old seed file until a test-decryption of the new
	/// file is confirmed to contain the same seed as the original seed file, at which point the
	/// backup is deleted. If this operation fails for an unknown reason, the backup file will still
	/// exist in the wallet's data directory encrypted with the old password.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	/// * `old`: The password used to encrypt the existing seed file (i.e. old password)
	/// * `new`: The password to be used to encrypt the new seed file
	///
	/// # Returns
	/// * Ok(()) if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let old = ZeroingString::from("my_password");
	/// let new = ZeroingString::from("new_password");
	/// let res = api_owner.change_password(None, old, new);
	///
	/// if let Ok(mne) = res {
	///     // ...
	/// }
	/// ```
	pub fn change_password(
		&self,
		name: Option<&str>,
		old: ZeroingString,
		new: ZeroingString,
	) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.change_password(name, old, new)
	}

	/// Deletes a wallet, removing the config file, seed file and all data files.
	/// Obviously, use with extreme caution and plenty of user warning
	///
	/// Highly recommended that the wallet be explicitly closed first via the `close_wallet`
	/// function.
	///
	/// # Arguments
	///
	/// * `name`: Reserved for future use, use `None` for the time being.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let res = api_owner.delete_wallet(None);
	///
	/// if let Ok(_) = res {
	///     // ...
	/// }
	/// ```

	pub fn delete_wallet(&self, name: Option<&str>) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let lc = w_lock.lc_provider()?;
		lc.delete_wallet(name)
	}

	/// Starts a background wallet update thread, which performs the wallet update process
	/// automatically at the frequency specified.
	///
	/// The updater process is as follows:
	///
	/// * Reconcile the wallet outputs against the node's current UTXO set, confirming
	/// transactions if needs be.
	/// * Look up transactions by kernel in cases where it's necessary (for instance, when
	/// there are no change outputs for a transaction and transaction status can't be
	/// inferred from the output state.
	/// * Incrementally perform a scan of the UTXO set, correcting outputs and transactions
	/// where their local state differs from what's on-chain. The wallet stores the last
	/// position scanned, and will scan back 100 blocks worth of UTXOs on each update, to
	/// correct any differences due to forks or otherwise.
	///
	/// Note that an update process can take a long time, particularly when the entire
	/// UTXO set is being scanned for correctness. The wallet status can be determined by
	/// calling the [`get_updater_messages`](struct.Owner.html#method.get_updater_messages).
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `frequency`: The frequency at which to call the update process. Note this is
	/// time elapsed since the last successful update process. If calling via the JSON-RPC
	/// api, this represents milliseconds.
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let res = api_owner.start_updater(None, Duration::from_secs(60));
	///
	/// if let Ok(_) = res {
	///   // ...
	/// }
	/// ```

	pub fn start_updater(
		&self,
		keychain_mask: Option<&SecretKey>,
		frequency: Duration,
	) -> Result<(), Error> {
		let updater_inner = self.updater.clone();
		let tx_inner = {
			let t = self.status_tx.lock();
			t.clone()
		};
		let keychain_mask = match keychain_mask {
			Some(m) => Some(m.clone()),
			None => None,
		};
		let _ = thread::Builder::new()
			.name("wallet-updater".to_string())
			.spawn(move || {
				let u = updater_inner.lock();
				if let Err(e) = u.run(frequency, keychain_mask, &tx_inner) {
					error!("Wallet state updater failed with error: {:?}", e);
				}
			})?;
		Ok(())
	}

	/// Stops the background update thread. If the updater is currently updating, the
	/// thread will stop after the next update
	///
	/// # Arguments
	///
	/// * None
	///
	/// # Returns
	/// * Ok if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let res = api_owner.start_updater(None, Duration::from_secs(60));
	///
	/// if let Ok(_) = res {
	///   // ...
	/// }
	///
	/// let res = api_owner.stop_updater();
	/// ```

	pub fn stop_updater(&self) -> Result<(), Error> {
		self.updater_running.store(false, Ordering::Relaxed);
		Ok(())
	}

	/// Retrieve messages from the updater thread, up to `count` number of messages.
	/// The resulting array will be ordered newest messages first. The updater will
	/// store a maximum of 10,000 messages, after which it will start removing the oldest
	/// messages as newer ones are created.
	///
	/// Messages retrieved via this method are removed from the internal queue, so calling
	/// this function at a specified interval should result in a complete message history.
	///
	/// # Arguments
	///
	/// * `count` - The number of messages to retrieve.
	///
	/// # Returns
	/// * Ok with a Vec of [`StatusMessage`](../grin_wallet_libwallet/api_impl/owner_updater/enum.StatusMessage.html)
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let res = api_owner.start_updater(None, Duration::from_secs(60));
	///
	/// let messages = api_owner.get_updater_messages(10000);
	///
	/// if let Ok(_) = res {
	///   // ...
	/// }
	///
	/// ```

	pub fn get_updater_messages(&self, count: usize) -> Result<Vec<StatusMessage>, Error> {
		let mut q = self.updater_messages.lock();
		let index = q.len().saturating_sub(count);
		Ok(q.split_off(index))
	}

	// SLATEPACK

	/// Retrieve the public slatepack address associated with the active account at the
	/// given derivation path.
	///
	/// In this case, an "address" means a Slatepack Address corresponding to
	/// a private key derived as follows:
	///
	/// e.g. The default parent account is at
	///
	/// `m/0/0`
	///
	/// With output blinding factors created as
	///
	/// `m/0/0/0`
	/// `m/0/0/1` etc...
	///
	/// The corresponding public address derivation path would be at:
	///
	/// `m/0/1`
	///
	/// With addresses created as:
	///
	/// `m/0/1/0`
	/// `m/0/1/1` etc...
	///
	/// Note that these addresses correspond to the public keys used in the addresses
	/// of TOR hidden services configured by the wallet listener.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// * `derivation_index` - The index along the derivation path to retrieve an address for
	///
	/// # Returns
	/// * Ok with a SlatepackAddress representing the address
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let res = api_owner.get_slatepack_address(None, 0);
	///
	/// if let Ok(_) = res {
	///   // ...
	/// }
	///
	/// ```

	pub fn get_slatepack_address(
		&self,
		keychain_mask: Option<&SecretKey>,
		derivation_index: u32,
	) -> Result<SlatepackAddress, Error> {
		owner::get_slatepack_address(self.wallet_inst.clone(), keychain_mask, derivation_index)
	}

	/// Retrieve the private ed25519 slatepack key at the given derivation index. Currently
	/// used to decrypt encrypted slatepack messages.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// * `derivation_index` - The index along the derivation path to for which to retrieve the secret key
	///
	/// # Returns
	/// * Ok with an ed25519_dalek::SecretKey if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let res = api_owner.get_slatepack_secret_key(None, 0);
	///
	/// if let Ok(_) = res {
	///   // ...
	/// }
	///
	/// ```
	pub fn get_slatepack_secret_key(
		&self,
		keychain_mask: Option<&SecretKey>,
		derivation_index: u32,
	) -> Result<DalekSecretKey, Error> {
		owner::get_slatepack_secret_key(self.wallet_inst.clone(), keychain_mask, derivation_index)
	}

	/// Create a slatepack from a given slate, optionally encoding the slate with the provided
	/// recipient public keys
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// * `sender_index` - If Some(n), the index along the derivation path to include as the sender
	/// * `recipients` - Optional recipients for which to encrypt the slatepack's payload (i.e. the
	/// slate). If an empty vec, the payload will remain unencrypted
	///
	/// # Returns
	/// * Ok with a String representing an armored slatepack if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	///
	/// let mut api_owner = Owner::new(wallet.clone(), None);
	/// let args = InitTxArgs {
	///     src_acct_name: None,
	///     amount: 2_000_000_000,
	///     minimum_confirmations: 10,
	///     max_outputs: 500,
	///     num_change_outputs: 1,
	///     selection_strategy_is_use_all: false,
	///     ..Default::default()
	/// };
	/// let result = api_owner.init_send_tx(
	///     None,
	///     args,
	/// );
	///
	/// if let Ok(slate) = result {
	///     // Create a slatepack from our slate
	///     let slatepack = api_owner.create_slatepack_message(
	///        None,
	///        &slate,
	///        Some(0),
	///        vec![],
	///     );
	/// }
	///
	/// ```

	pub fn create_slatepack_message(
		&self,
		keychain_mask: Option<&SecretKey>,
		slate: &Slate,
		sender_index: Option<u32>,
		recipients: Vec<SlatepackAddress>,
	) -> Result<String, Error> {
		owner::create_slatepack_message(
			self.wallet_inst.clone(),
			keychain_mask,
			slate,
			sender_index,
			recipients,
		)
	}

	/// Extract the slate from the given slatepack. If the slatepack payload is encrypted, attempting to
	/// decrypt with keys at the given address derivation path indices.
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// * `slatepack` - A string representing an armored slatepack
	/// * `secret_indices` - Indices along this wallet's deriviation path with which to attempt
	/// decryption. This function will attempt to use secret keys at each index along this path
	/// to attempt to decrypt the payload, returning an error if none of the keys match.
	///
	/// # Returns
	/// * Ok with a [Slate](../grin_wallet_libwallet/slate/struct.Slate.html) if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	/// // ... receive a slatepack from somewhere
	/// # let slatepack_string = String::from("");
	///   let res = api_owner.slate_from_slatepack_message(
	///    None,
	///    slatepack_string,
	///    vec![0, 1, 2],
	///   );
	/// ```

	pub fn slate_from_slatepack_message(
		&self,
		keychain_mask: Option<&SecretKey>,
		slatepack: String,
		secret_indices: Vec<u32>,
	) -> Result<Slate, Error> {
		owner::slate_from_slatepack_message(
			self.wallet_inst.clone(),
			keychain_mask,
			slatepack,
			secret_indices,
		)
	}

	/// Decode an armored slatepack, returning a Slatepack object that can be
	/// viewed, manipulated, output as json, etc. The resulting slatepack will be
	/// decrypted by this wallet if possible
	///
	/// # Arguments
	///
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using
	/// * `slatepack` - A string representing an armored slatepack
	/// * `secret_indices` - Indices along this wallet's deriviation path with which to attempt
	/// decryption. If this wallet can't decrypt this slatepack, the payload of the returned
	/// Slatepack will remain encrypted.
	///
	/// # Returns
	/// * Ok with a [Slatepack](../grin_wallet_libwallet/slatepack/types/struct.Slatepack.html) if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// use grin_core::global::ChainTypes;
	///
	/// use std::time::Duration;
	///
	/// // Set up as above
	/// # let api_owner = Owner::new(wallet.clone(), None);
	/// # let slatepack_string = String::from("");
	/// // .. receive a slatepack from somewhere
	/// let res = api_owner.decode_slatepack_message(
	///    None,
	///    slatepack_string,
	///    vec![0, 1, 2],
	/// );
	///
	/// ```

	pub fn decode_slatepack_message(
		&self,
		keychain_mask: Option<&SecretKey>,
		slatepack: String,
		secret_indices: Vec<u32>,
	) -> Result<Slatepack, Error> {
		owner::decode_slatepack_message(
			self.wallet_inst.clone(),
			keychain_mask,
			slatepack,
			secret_indices,
		)
	}

	// PAYMENT PROOFS

	/// Returns a single, exportable [PaymentProof](../grin_wallet_libwallet/api_impl/types/struct.PaymentProof.html)
	/// from a completed transaction within the wallet.
	///
	/// The transaction must have been created with a payment proof, and the transaction must be
	/// complete in order for a payment proof to be returned. Either the `tx_id` or `tx_slate_id`
	/// argument must be provided, or the function will return an error.
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../grin_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// Note this setting is ignored if the updater process is running via a call to
	/// [`start_updater`](struct.Owner.html#method.start_updater)
	/// * `tx_id` - If `Some(i)` return the proof associated with the transaction with id `i`
	/// * `tx_slate_id` - If `Some(uuid)`, return the proof associated with the transaction with the
	/// given `uuid`
	///
	/// # Returns
	/// * Ok([PaymentProof](../grin_wallet_libwallet/api_impl/types/struct.PaymentProof.html)) if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered
	/// or the proof is not present or complete
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = Some(Uuid::parse_str("0436430c-2b02-624c-2032-570501212b00").unwrap());
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_payment_proof(None, update_from_node, tx_id, tx_slate_id);
	///
	/// if let Ok(p) = result {
	///     //...
	/// }
	/// ```

	pub fn retrieve_payment_proof(
		&self,
		keychain_mask: Option<&SecretKey>,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, Error> {
		let tx = {
			let t = self.status_tx.lock();
			t.clone()
		};
		let refresh_from_node = match self.updater_running.load(Ordering::Relaxed) {
			true => false,
			false => refresh_from_node,
		};
		owner::retrieve_payment_proof(
			self.wallet_inst.clone(),
			keychain_mask,
			&tx,
			refresh_from_node,
			tx_id,
			tx_slate_id,
		)
	}

	/// Verifies a [PaymentProof](../grin_wallet_libwallet/api_impl/types/struct.PaymentProof.html)
	/// This process entails:
	///
	/// * Ensuring the kernel identified by the proof's stored excess commitment exists in the kernel set
	/// * Reproducing the signed message `amount|kernel_commitment|sender_address`
	/// * Validating the proof's `recipient_sig` against the message using the recipient's
	/// address as the public key and
	/// * Validating the proof's `sender_sig` against the message using the senders's
	/// address as the public key
	///
	/// This function also checks whether the sender or recipient address belongs to the currently
	/// open wallet, and returns 2 booleans indicating whether the address belongs to the sender and
	/// whether the address belongs to the recipient respectively
	///
	/// # Arguments
	/// * `keychain_mask` - Wallet secret mask to XOR against the stored wallet seed before using, if
	/// being used.
	/// * `proof` A [PaymentProof](../grin_wallet_libwallet/api_impl/types/struct.PaymentProof.html))
	///
	/// # Returns
	/// * Ok((bool, bool)) if the proof is valid. The first boolean indicates whether the sender
	/// address belongs to this wallet, the second whether the recipient address belongs to this
	/// wallet
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered
	/// or the proof is not present or complete
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone(), None);
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = Some(Uuid::parse_str("0436430c-2b02-624c-2032-570501212b00").unwrap());
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_payment_proof(None, update_from_node, tx_id, tx_slate_id);
	///
	/// // The proof will likely be exported as JSON to be provided to another party
	///
	/// if let Ok(p) = result {
	///     let valid = api_owner.verify_payment_proof(None, &p);
	///     if let Ok(_) = valid {
	///       //...
	///     }
	/// }
	/// ```

	pub fn verify_payment_proof(
		&self,
		keychain_mask: Option<&SecretKey>,
		proof: &PaymentProof,
	) -> Result<(bool, bool), Error> {
		owner::verify_payment_proof(self.wallet_inst.clone(), keychain_mask, proof)
	}
}

/// attempt to send slate synchronously with TOR
pub fn try_slatepack_sync_workflow(
	slate: &Slate,
	dest: &str,
	tor_config: Option<TorConfig>,
	tor_sender: Option<HttpSlateSender>,
	send_to_finalize: bool,
	test_mode: bool,
) -> Result<Option<Slate>, libwallet::Error> {
	if let Some(tc) = &tor_config {
		if tc.skip_send_attempt == Some(true) {
			return Ok(None);
		}
	}
	let mut ret_slate = Slate::blank(2, TxFlow::Standard);
	let mut send_sync = |mut sender: HttpSlateSender, method_str: &str| match sender
		.send_tx(&slate, send_to_finalize)
	{
		Ok(s) => {
			ret_slate = s;
			return Ok(());
		}
		Err(e) => {
			debug!(
				"Send ({}): Could not send Slate via {}: {}",
				method_str, method_str, e
			);
			return Err(e);
		}
	};

	// Try parsing Slatepack address
	match SlatepackAddress::try_from(dest) {
		Ok(address) => {
			let tor_addr = OnionV3Address::try_from(&address).unwrap();
			// Try sending to the destination via TOR
			let sender = match tor_sender {
				None => {
					if test_mode {
						None
					} else {
						match HttpSlateSender::with_socks_proxy(
							&tor_addr.to_http_str(),
							&tor_config.as_ref().unwrap().socks_proxy_addr,
							&tor_config.as_ref().unwrap().send_config_dir,
						) {
							Ok(s) => Some(s),
							Err(e) => {
								debug!("Send (TOR): Cannot create TOR Slate sender {:?}", e);
								None
							}
						}
					}
				}
				Some(s) => {
					if test_mode {
						None
					} else {
						Some(s)
					}
				}
			};
			if let Some(s) = sender {
				warn!("Attempting to send transaction via TOR");
				match send_sync(s, "TOR") {
					Ok(_) => return Ok(Some(ret_slate)),
					Err(e) => {
						debug!("Unable to send via TOR: {}", e);
						warn!("Unable to send transaction via TOR");
					}
				}
			}
		}
		Err(e) => {
			debug!("Send (TOR): Destination is not SlatepackAddress {:?}", e);
			warn!("Destination is not a valid Slatepack address. Will output Slatepack.")
		}
	}

	Ok(None)
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_setup_doc_env {
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
		use libwallet::{BlockFees, InitTxArgs, IssueInvoiceTxArgs, Slate, WalletInst};

		use uuid::Uuid;

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
