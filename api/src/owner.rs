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

//! Owner API External Definition

use crate::util::Mutex;
use chrono::prelude::*;
use std::marker::PhantomData;
use std::sync::Arc;
use uuid::Uuid;

use crate::core::core::Transaction;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::api_impl::owner;
use crate::libwallet::slate::Slate;
use crate::libwallet::types::{
	AcctPathMapping, NodeClient, OutputCommitMapping, TxEstimation, TxLogEntry, WalletBackend,
	WalletInfo,
};
use crate::libwallet::Error;

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

pub struct Owner<W: ?Sized, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	/// A reference-counted mutex to an implementation of the
	/// [`WalletBackend`](../grin_wallet_libwallet/types/trait.WalletBackend.html) trait.
	pub wallet: Arc<Mutex<W>>,
	/// Flag to normalize some output during testing. Can mostly be ignored.
	pub doctest_mode: bool,
	phantom: PhantomData<K>,
	phantom_c: PhantomData<C>,
}

impl<W: ?Sized, C, K> Owner<W, C, K>
where
	W: WalletBackend<C, K>,
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
	/// [`WalletBackend`](../grin_wallet_libwallet/types/trait.WalletBackend.html) trait.
	///
	/// # Returns
	/// * An instance of the OwnerApi holding a reference to the provided wallet
	///
	/// # Example
	/// ```
	/// use grin_wallet_util::grin_keychain as keychain;
	/// use grin_wallet_util::grin_util as util;
	/// use grin_wallet_api as api;
	/// use grin_wallet_config as config;
	/// use grin_wallet_impls as impls;
	/// use grin_wallet_libwallet as libwallet;
	///
	/// use keychain::ExtKeychain;
	/// use tempfile::tempdir;
	///
	/// use std::sync::Arc;
	/// use util::Mutex;
	///
	/// use api::Owner;
	/// use config::WalletConfig;
	/// use impls::{HTTPNodeClient, LMDBBackend};
	/// use libwallet::types::WalletBackend;
	///
	/// let mut wallet_config = WalletConfig::default();
	/// # let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
	/// # let dir = dir
	/// # 	.path()
	/// # 	.to_str()
	/// # 	.ok_or("Failed to convert tmpdir path to string.".to_owned())
	/// # 	.unwrap();
	/// # wallet_config.data_file_dir = dir.to_owned();
	///
	/// // A NodeClient must first be created to handle communication between
	/// // the wallet and the node.
	///
	/// let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
	/// let mut wallet:Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> =
	///		Arc::new(Mutex::new(
	///			LMDBBackend::new(wallet_config.clone(), "", node_client).unwrap()
	///		));
	///
	/// let api_owner = Owner::new(wallet.clone());
	/// // .. perform wallet operations
	///
	/// ```

	pub fn new(wallet_in: Arc<Mutex<W>>) -> Self {
		Owner {
			wallet: wallet_in,
			doctest_mode: false,
			phantom: PhantomData,
			phantom_c: PhantomData,
		}
	}

	/// Returns a list of accounts stored in the wallet (i.e. mappings between
	/// user-specified labels and BIP32 derivation paths.
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
	/// let api_owner = Owner::new(wallet.clone());
	///
	/// let result = api_owner.accounts();
	///
	/// if let Ok(accts) = result {
	///		//...
	/// }
	/// ```

	pub fn accounts(&self) -> Result<Vec<AcctPathMapping>, Error> {
		let mut w = self.wallet.lock();
		owner::accounts(&mut *w)
	}

	/// Creates a new 'account', which is a mapping of a user-specified
	/// label to a BIP32 path
	///
	/// # Arguments
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
	/// let api_owner = Owner::new(wallet.clone());
	///
	/// let result = api_owner.create_account_path("account1");
	///
	/// if let Ok(identifier) = result {
	///		//...
	/// }
	/// ```

	pub fn create_account_path(&self, label: &str) -> Result<Identifier, Error> {
		let mut w = self.wallet.lock();
		owner::create_account_path(&mut *w, label)
	}

	/// Sets the wallet's currently active account. This sets the
	/// BIP32 parent path used for most key-derivation operations.
	///
	/// # Arguments
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
	/// let api_owner = Owner::new(wallet.clone());
	///
	/// let result = api_owner.create_account_path("account1");
	///
	/// if let Ok(identifier) = result {
	///		// set the account active
	///		let result2 = api_owner.set_active_account("account1");
	/// }
	/// ```

	pub fn set_active_account(&self, label: &str) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		owner::set_active_account(&mut *w, label)
	}

	/// Returns a list of outputs from the active account in the wallet.
	///
	/// # Arguments
	/// * `include_spent` - If `true`, outputs that have been marked as 'spent'
	/// in the wallet will be returned. If `false`, spent outputs will omitted
	/// from the results.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../grin_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain output information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
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
	/// let api_owner = Owner::new(wallet.clone());
	/// let show_spent = false;
	/// let update_from_node = true;
	/// let tx_id = None;
	///
	/// let result = api_owner.retrieve_outputs(show_spent, update_from_node, tx_id);
	///
	/// if let Ok((was_updated, output_mappings)) = result {
	///		//...
	/// }
	/// ```

	pub fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::retrieve_outputs(&mut *w, include_spent, refresh_from_node, tx_id);
		w.close()?;
		res
	}

	/// Returns a list of [Transaction Log Entries](../grin_wallet_libwallet/types/struct.TxLogEntry.html)
	/// from the active account in the wallet.
	///
	/// # Arguments
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../grin_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
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
	/// let api_owner = Owner::new(wallet.clone());
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = None;
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_txs(update_from_node, tx_id, tx_slate_id);
	///
	/// if let Ok((was_updated, tx_log_entries)) = result {
	///		//...
	/// }
	/// ```

	pub fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let mut res = owner::retrieve_txs(&mut *w, refresh_from_node, tx_id, tx_slate_id)?;
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
		w.close()?;
		Ok(res)
	}

	/// Returns summary information from the active account in the wallet.
	///
	/// # Arguments
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../grin_wallet_libwallet/types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
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
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let update_from_node = true;
	/// let minimum_confirmations=10;
	///
	/// // Return summary info for active account
	/// let result = api_owner.retrieve_summary_info(update_from_node, minimum_confirmations);
	///
	/// if let Ok((was_updated, summary_info)) = result {
	///		//...
	/// }
	/// ```

	pub fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::retrieve_summary_info(&mut *w, refresh_from_node, minimum_confirmations);
		w.close()?;
		res
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
	/// # Arguments
	/// * `src_acct_name` - The human readable account name from which to draw outputs
	/// for the transaction, overriding whatever the active account is as set via the
	/// [`set_active_account`](struct.Owner.html#method.set_active_account) method.
	/// If None, the transaction will use the active account.
	/// * `amount` - The amount to send, in nanogrins. (`1 G = 1_000_000_000nG`)
	/// * `minimum_confirmations` - The minimum number of confirmations an output
	/// should have in order to be included in the transaction.
	/// * `max_outputs` - By default, the wallet selects as many inputs as possible in a
	/// transaction, to reduce the Output set and the fees. The wallet will attempt to spend
	/// include up to `max_outputs` in a transaction, however if this is not enough to cover
	/// the whole amount, the wallet will include more outputs. This parameter should be considered
	/// a soft limit.
	/// * `num_change_outputs` - The target number of change outputs to create in the transaction.
	/// The actual number created will be `num_change_outputs` + whatever remainder is needed.
	/// * `selection_strategy_is_use_all` - If `true`, attempt to use up as many outputs as
	/// possible to create the transaction, up the 'soft limit' of `max_outputs`. This helps
	/// to reduce the size of the UTXO set and the amount of data stored in the wallet, and
	/// minimizes fees. This will generally result in many inputs and a large change output(s),
	/// usually much larger than the amount being sent. If `false`, the transaction will include
	/// as many outputs as are needed to meet the amount, (and no more) starting with the smallest
	/// value outputs.
	/// * `message` - An optional participant message to include alongside the sender's public
	/// ParticipantData within the slate. This message will include a signature created with the
	/// sender's private excess value, and will be publically verifiable. Note this message is for
	/// the convenience of the participants during the exchange; it is not included in the final
	/// transaction sent to the chain. The message will be truncated to 256 characters.
	/// Validation of this message is optional.
	/// * `target_slate_version` Optionally set the output target slate version (acceptable
	/// down to the minimum slate version compatible with the current. If `None` the slate
	/// is generated with the latest version.
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
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let amount = 2_000_000_000;
	///
	/// // Attempt to create a transaction using the 'default' account
	/// let result = api_owner.initiate_tx(
	///		None,
	///		amount,     // amount
	///		10,         // minimum confirmations
	///		500,        // max outputs
	///		1,          // num change outputs
	///		true,       // select all outputs
	///		Some("Have some Grins. Love, Yeastplume".to_owned()),
	///		None,       // Use the default slate version
	///	);
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		api_owner.tx_lock_outputs(&slate);
	/// }
	/// ```

	pub fn initiate_tx(
		&self,
		src_acct_name: Option<&str>,
		amount: u64,
		minimum_confirmations: u64,
		max_outputs: usize,
		num_change_outputs: usize,
		selection_strategy_is_use_all: bool,
		message: Option<String>,
		target_slate_version: Option<u16>,
	) -> Result<Slate, Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::initiate_tx(
			&mut *w,
			src_acct_name,
			amount,
			minimum_confirmations,
			max_outputs,
			num_change_outputs,
			selection_strategy_is_use_all,
			message,
			target_slate_version,
			self.doctest_mode,
		);
		w.close()?;
		res
	}

	/// Estimates the amount to be locked and fee for the transaction without creating one.
	///
	/// # Arguments
	/// * As found in [`initiate_tx`](struct.Owner.html#method.initiate_tx) above.
	///
	/// # Returns
	/// * a result containing a
	/// [`TxEstimation`](../grin_wallet_libwallet/types/struct.TxEstimation.html)
	///
	/// # Example
	/// Set up as in [new](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let amount = 2_000_000_000;
	///
	/// // Estimate transaction using default account
	/// let result = api_owner.estimate_initiate_tx(
	///		None,
	///		amount,     // amount
	///		10,         // minimum confirmations
	///		500,        // max outputs
	///		1,          // num change outputs
	///		true,       // select all outputs
	///	);
	///
	/// if let Ok(est) = result {
	///		// ...
	/// }
	/// ```

	pub fn estimate_initiate_tx(
		&self,
		src_acct_name: Option<&str>,
		amount: u64,
		minimum_confirmations: u64,
		max_outputs: usize,
		num_change_outputs: usize,
		selection_strategy_is_use_all: bool,
	) -> Result<TxEstimation, Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::estimate_initiate_tx(
			&mut *w,
			src_acct_name,
			amount,
			minimum_confirmations,
			max_outputs,
			num_change_outputs,
			selection_strategy_is_use_all,
		);
		w.close()?;
		res
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
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html). All
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
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let amount = 2_000_000_000;
	///
	/// // Attempt to create a transaction using the 'default' account
	/// let result = api_owner.initiate_tx(
	///		None,
	///		amount,     // amount
	///		10,         // minimum confirmations
	///		500,        // max outputs
	///		1,          // num change outputs
	///		true,       // select all outputs
	///		Some("Remember to lock when we're happy this is sent".to_owned()),
	///		None,       // Use the default slate version
	///	);
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		api_owner.tx_lock_outputs(&slate);
	/// }
	/// ```

	pub fn tx_lock_outputs(&self, slate: &Slate) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::tx_lock_outputs(&mut *w, slate);
		w.close()?;
		res
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
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let amount = 2_000_000_000;
	///
	/// // Attempt to create a transaction using the 'default' account
	/// let result = api_owner.initiate_tx(
	///		None,
	///		amount,     // amount
	///		10,         // minimum confirmations
	///		500,        // max outputs
	///		1,          // num change outputs
	///		true,       // select all outputs
	///		Some("Finalize this tx now".to_owned()),
	///		None,       // Use the default slate version
	///	);
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(&slate);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.finalize_tx(&slate);
	/// }
	/// ```

	pub fn finalize_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		let mut w = self.wallet.lock();
		let mut slate = slate.clone();
		w.open_with_credentials()?;
		slate = owner::finalize_tx(&mut *w, &slate)?;
		w.close()?;
		Ok(slate)
	}

	/// Posts a completed transaction to the listening node for validation and inclusion in a block
	/// for mining.
	///
	/// # Arguments
	/// * `tx` - A completed [`Transaction`](../grin_core/core/transaction/struct.Transaction.html),
	/// typically the `tx` field in the transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html).
	///
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
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let amount = 2_000_000_000;
	///
	/// // Attempt to create a transaction using the 'default' account
	/// let result = api_owner.initiate_tx(
	///		None,
	///		amount,     // amount
	///		10,         // minimum confirmations
	///		500,        // max outputs
	///		1,          // num change outputs
	///		true,       // select all outputs
	///		Some("Finalize this tx now".to_owned()),
	///		None,       // Use the default slate version
	///	);
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(&slate);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.finalize_tx(&slate);
	///		let res = api_owner.post_tx(&slate.tx, true);
	/// }
	/// ```

	pub fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), Error> {
		let client = {
			let mut w = self.wallet.lock();
			w.w2n_client().clone()
		};
		owner::post_tx(&client, tx, fluff)
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
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let amount = 2_000_000_000;
	///
	/// // Attempt to create a transaction using the 'default' account
	/// let result = api_owner.initiate_tx(
	///		None,
	///		amount,     // amount
	///		10,         // minimum confirmations
	///		500,        // max outputs
	///		1,          // num change outputs
	///		true,       // select all outputs
	///		Some("Cancel this tx".to_owned()),
	///		None,       // Use the default slate version
	///	);
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(&slate);
	///		//
	///		// We didn't get the slate back, or something else went wrong
	///		//
	///		let res = api_owner.cancel_tx(None, Some(slate.id.clone()));
	/// }
	/// ```

	pub fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::cancel_tx(&mut *w, tx_id, tx_slate_id);
		w.close()?;
		res
	}

	/// Retrieves the stored transaction associated with a TxLogEntry. Can be used even after the
	/// transaction has completed.
	///
	/// # Arguments
	///
	/// * `tx_log_entry` - A [`TxLogEntry`](../grin_wallet_libwallet/types/struct.TxLogEntry.html)
	///
	/// # Returns
	/// * Ok with the stored  [`Transaction`](../grin_core/core/transaction/struct.Transaction.html)
	/// if successful
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let api_owner = Owner::new(wallet.clone());
	/// let update_from_node = true;
	/// let tx_id = None;
	/// let tx_slate_id = None;
	///
	/// // Return all TxLogEntries
	/// let result = api_owner.retrieve_txs(update_from_node, tx_id, tx_slate_id);
	///
	/// if let Ok((was_updated, tx_log_entries)) = result {
	///		let stored_tx = api_owner.get_stored_tx(&tx_log_entries[0]).unwrap();
	///		//...
	/// }
	/// ```

	// TODO: Should be accepting an id, not an entire entry struct
	pub fn get_stored_tx(&self, tx_log_entry: &TxLogEntry) -> Result<Option<Transaction>, Error> {
		let w = self.wallet.lock();
		owner::get_stored_tx(&*w, tx_log_entry)
	}

	/// Verifies all messages in the slate match their public keys.
	///
	/// The optional messages themselves are part of the `participant_data` field within the slate.
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
	/// * `Ok(())` if successful and the signatures validate
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Owner.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env!(wallet, wallet_config);
	///
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let amount = 2_000_000_000;
	///
	/// // Attempt to create a transaction using the 'default' account
	/// let result = api_owner.initiate_tx(
	///		None,
	///		amount,     // amount
	///		10,         // minimum confirmations
	///		500,        // max outputs
	///		1,          // num change outputs
	///		true,       // select all outputs
	///		Some("Finalize this tx now".to_owned()),
	///		None,       // Use the default slate version
	///	);
	///
	/// if let Ok(slate) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		let res = api_owner.tx_lock_outputs(&slate);
	///		//
	///		// Retrieve slate back from recipient
	///		//
	///		let res = api_owner.verify_slate_messages(&slate);
	/// }
	/// ```
	pub fn verify_slate_messages(&self, slate: &Slate) -> Result<(), Error> {
		owner::verify_slate_messages(slate)
	}

	/// Attempt to restore contents of wallet
	/// TODO: Full docs
	pub fn restore(&self) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::restore(&mut *w);
		w.close()?;
		res
	}

	/// Attempt to check and fix the contents of the wallet
	/// TODO: Full docs
	pub fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::check_repair(&mut *w, delete_unconfirmed);
		w.close()?;
		res
	}

	/// Retrieve current height from node
	// TODO: Should return u64 as string
	pub fn node_height(&self) -> Result<(u64, bool), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = owner::node_height(&mut *w);
		w.close()?;
		res
	}
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_setup_doc_env {
	($wallet:ident, $wallet_config:ident) => {
		use grin_wallet_api as api;
		use grin_wallet_config as config;
		use grin_wallet_impls as impls;
		use grin_wallet_libwallet as libwallet;
		use grin_wallet_util::grin_keychain as keychain;
		use grin_wallet_util::grin_util as util;

		use keychain::ExtKeychain;
		use tempfile::tempdir;

		use std::sync::Arc;
		use util::Mutex;

		use api::Owner;
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
