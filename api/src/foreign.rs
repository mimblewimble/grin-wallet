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

//! Foreign API External Definition

use crate::keychain::Keychain;
use crate::libwallet::api_impl::foreign;
use crate::libwallet::{
	BlockFees, CbData, Error, NodeClient, NodeVersionInfo, Slate, VersionInfo, WalletBackend,
};
use crate::util::Mutex;
use std::marker::PhantomData;
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
	/// finalize_invoice_tx
	FinalizeInvoiceTx,
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
	/// phantom
	phantom: PhantomData<K>,
	/// phantom
	phantom_c: PhantomData<C>,
	/// foreign check middleware
	middleware: Option<ForeignCheckMiddleware>,
}

impl<'a, W: ?Sized, C, K> Foreign<W, C, K>
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
	/// (initialising a keychain with the master seed), perform its operation, then close the keychain
	/// with a call to [`close`](../grin_wallet_libwallet/types/trait.WalletBackend.html#tymethod.close)
	///
	/// # Arguments
	/// * `wallet_in` - A reference-counted mutex containing an implementation of the
	/// [`WalletBackend`](../grin_wallet_libwallet/types/trait.WalletBackend.html) trait.
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
	/// use api::Foreign;
	/// use config::WalletConfig;
	/// use impls::{HTTPNodeClient, LMDBBackend};
	/// use libwallet::WalletBackend;
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
	/// let api_foreign = Foreign::new(wallet.clone(), None);
	/// // .. perform wallet operations
	///
	/// ```

	pub fn new(wallet_in: Arc<Mutex<W>>, middleware: Option<ForeignCheckMiddleware>) -> Self {
		Foreign {
			wallet: wallet_in,
			doctest_mode: false,
			phantom: PhantomData,
			phantom_c: PhantomData,
			middleware,
		}
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
	/// let mut api_foreign = Foreign::new(wallet.clone(), None);
	///
	/// let version_info = api_foreign.check_version();
	/// // check and proceed accordingly
	/// ```

	pub fn check_version(&self) -> Result<VersionInfo, Error> {
		if let Some(m) = self.middleware.as_ref() {
			let mut w = self.wallet.lock();
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
	/// let mut api_foreign = Foreign::new(wallet.clone(), None);
	///
	/// let block_fees = BlockFees {
	///		fees: 800000,
	///		height: 234323,
	///		key_id: None,
	/// };
	/// // Build a new coinbase output
	///
	///	let res = api_foreign.build_coinbase(&block_fees);
	///
	/// if let Ok(cb_data) = res {
	///		// cb_data is populated with coinbase output info
	///		// ...
	/// }
	/// ```

	pub fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, Error> {
		let mut w = self.wallet.lock();
		if let Some(m) = self.middleware.as_ref() {
			m(
				ForeignCheckMiddlewareFn::BuildCoinbase,
				w.w2n_client().get_version_info(),
				None,
			)?;
		}
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
	/// * `Ok(())` if successful and the signatures validate
	/// * or [`libwallet::Error`](../grin_wallet_libwallet/struct.Error.html) if an error is encountered.
	///
	/// # Example
	/// Set up as in [`new`](struct.Foreign.html#method.new) method above.
	/// ```
	/// # grin_wallet_api::doctest_helper_setup_doc_env_foreign!(wallet, wallet_config);
	///
	/// let mut api_foreign = Foreign::new(wallet.clone(), None);
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
	/// 	// Slate messages are fine
	/// }
	///
	///
	/// ```

	pub fn verify_slate_messages(&self, slate: &Slate) -> Result<(), Error> {
		if let Some(m) = self.middleware.as_ref() {
			let mut w = self.wallet.lock();
			m(
				ForeignCheckMiddlewareFn::VerifySlateMessages,
				w.w2n_client().get_version_info(),
				Some(slate),
			)?;
		}
		foreign::verify_slate_messages(slate)
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
	/// * `message` - An optional participant message to include alongside the recipient's public
	/// ParticipantData within the slate. This message will include a signature created with the
	/// recipient's private excess value, and will be publically verifiable. Note this message is for
	/// the convenience of the participants during the exchange; it is not included in the final
	/// transaction sent to the chain. The message will be truncated to 256 characters.
	/// Validation of this message is optional.
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
	/// let mut api_foreign = Foreign::new(wallet.clone(), None);
	/// # let slate = Slate::blank(2);
	///
	/// // . . .
	/// // Obtain a sent slate somehow
	/// let result = api_foreign.receive_tx(&slate, None, None);
	///
	/// if let Ok(slate) = result {
	///		// Send back to recipient somehow
	///		// ...
	/// }
	/// ```

	pub fn receive_tx(
		&self,
		slate: &Slate,
		dest_acct_name: Option<&str>,
		message: Option<String>,
	) -> Result<Slate, Error> {
		let mut w = self.wallet.lock();
		if let Some(m) = self.middleware.as_ref() {
			m(
				ForeignCheckMiddlewareFn::ReceiveTx,
				w.w2n_client().get_version_info(),
				Some(slate),
			)?;
		}
		w.open_with_credentials()?;
		let res = foreign::receive_tx(&mut *w, slate, dest_acct_name, message, self.doctest_mode);
		w.close()?;
		res
	}

	/// Finalizes an invoice transaction initiated by this wallet's Owner api.
	/// This step assumes the paying party has completed round 1 and 2 of slate
	/// creation, and added their partial signatures. The invoicer will verify
	/// and add their partial sig, then create the finalized transaction,
	/// ready to post to a node.
	///
	/// Note that this function DOES NOT POST the transaction to a node
	/// for validation. This is done in separately via the
	/// [`post_tx`](struct.Owner.html#method.post_tx) function.
	///
	/// This function also stores the final transaction in the user's wallet files for retrieval
	/// via the [`get_stored_tx`](struct.Owner.html#method.get_stored_tx) function.
	///
	/// # Arguments
	/// * `slate` - The transaction [`Slate`](../grin_wallet_libwallet/slate/struct.Slate.html). The
	/// payer should have filled in round 1 and 2.
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
	/// let mut api_owner = Owner::new(wallet.clone());
	/// let mut api_foreign = Foreign::new(wallet.clone(), None);
	///
	/// // . . .
	/// // Issue the invoice tx via the owner API
	/// let args = IssueInvoiceTxArgs {
	///		amount: 10_000_000_000,
	///		..Default::default()
	/// };
	/// let result = api_owner.issue_invoice_tx(args);
	///
	///	// If result okay, send to payer, who will apply the transaction via their
	///	// owner API, then send back the slate
	///	// ...
	///	# let slate = Slate::blank(2);
	///
	/// let slate = api_foreign.finalize_invoice_tx(&slate);
	/// // if okay, then post via the owner API
	/// ```

	pub fn finalize_invoice_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		let mut w = self.wallet.lock();
		if let Some(m) = self.middleware.as_ref() {
			m(
				ForeignCheckMiddlewareFn::FinalizeInvoiceTx,
				w.w2n_client().get_version_info(),
				Some(slate),
			)?;
		}
		w.open_with_credentials()?;
		let res = foreign::finalize_invoice_tx(&mut *w, slate);
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

		use keychain::ExtKeychain;
		use tempfile::tempdir;

		use std::sync::Arc;
		use util::Mutex;

		use api::{Foreign, Owner};
		use config::WalletConfig;
		use impls::{HTTPNodeClient, LMDBBackend, WalletSeed};
		use libwallet::{BlockFees, IssueInvoiceTxArgs, Slate, WalletBackend};

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
