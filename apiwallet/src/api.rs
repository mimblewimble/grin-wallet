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
//! * The 'Owner' API is intended to expose methods that are to be
//! used by the wallet owner only. It is vital that this API is not
//! exposed to anyone other than the owner of the wallet (i.e. the
//! person with access to the seed and password.
//! * The 'Foreign' API contains methods that other wallets will
//! use to interact with the owner's wallet. This API can be exposed
//! to the outside world, with the consideration as to how that can
//! be done securely up to the implementor.
//!
//! Methods in both APIs are intended to be 'single use', that is to say each
//! method will 'open' the wallet (load the keychain with its master seed), perform
//! its operation, then 'close' the wallet (unloading references to the keychain and master
//! seed).

use crate::util::Mutex;
use std::marker::PhantomData;
use std::sync::Arc;
use uuid::Uuid;

use crate::core::core::hash::Hashed;
use crate::core::core::Transaction;
use crate::core::ser;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::internal::{keys, tx, updater};
use crate::libwallet::slate::Slate;
use crate::libwallet::types::{
	AcctPathMapping, BlockFees, CbData, NodeClient, OutputData, OutputLockFn, TxLogEntry,
	TxLogEntryType, TxWrapper, WalletBackend, WalletInfo,
};
use crate::libwallet::{Error, ErrorKind};
use crate::util;
use crate::util::secp::{pedersen, ContextFlag, Secp256k1};
use easy_jsonrpc;

const USER_MESSAGE_MAX_LEN: usize = 256;

/// Public definition used to generate jsonrpc api for APIOwner.
#[easy_jsonrpc::rpc]
pub trait OwnerApi {
	/**
	Networked version of [APIOwner::accounts](struct.APIOwner.html#method.accounts).

	# Json rpc example

	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": [],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				{
					"label": "default",
					"path": "0200000000000000000000000000000000"
				}
			]
		},
		"id": 1
	}
	# );
	```
	 */
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind>;

	/**
	Networked version of [APIOwner::create_account_path](struct.APIOwner.html#method.create_account_path).

	# Json rpc example

	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": ["account1"],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": "0200000001000000000000000000000000"
		},
		"id": 1
	}
	# );
	```
	 */
	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind>;

	/**
	Networked version of [APIOwner::set_active_account](struct.APIOwner.html#method.set_active_account).

	# Json rpc example

	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": ["default"],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		},
		"id": 1
	}
	# );
	```
	 */
	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIOwner::retrieve_outputs](struct.APIOwner.html#method.retrieve_outputs).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": [false, false, null],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<(OutputData, pedersen::Commitment)>), ErrorKind>;

	/**
	Networked version of [APIOwner::retrieve_txs](struct.APIOwner.html#method.retrieve_txs).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "retrieve_txs",
		"params": [false, null, null],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind>;

	/**
	Networked version of [APIOwner::retrieve_summary_info](struct.APIOwner.html#method.retrieve_summary_info).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": [false, 1],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind>;

	/**
	Networked version of [APIOwner::estimate_initiate_tx](struct.APIOwner.html#method.estimate_initiate_tx).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "estimate_initiate_tx",
		"params": [null, 0, 0, 10, 0, false],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn estimate_initiate_tx(
		&self,
		src_acct_name: Option<String>,
		amount: u64,
		minimum_confirmations: u64,
		max_outputs: usize,
		num_change_outputs: usize,
		selection_strategy_is_use_all: bool,
	) -> Result<(/* total */ u64, /* fee */ u64), ErrorKind>;

	/**
	Networked version of [APIOwner::finalize_tx](struct.APIOwner.html#method.finalize_tx).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"params": [{
			"version_info": {
				"version": 2,
				"orig_version": 2,
				"min_compat_version": 0
			},
			"amount": 0,
			"fee": 0,
			"height": 0,
			"id": "414bad48-3386-4fa7-8483-72384c886ba3",
			"lock_height": 0,
			"num_participants": 2,
			"participant_data": [],
			"tx": {
				"body": {
					"inputs": [],
					"kernels": [],
					"outputs": []
				},
				"offset": "0000000000000000000000000000000000000000000000000000000000000000"
			}
		}],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn finalize_tx(&self, slate: Slate) -> Result<Slate, ErrorKind>;

	/**
	Networked version of [APIOwner::cancel_tx](struct.APIOwner.html#method.cancel_tx).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": [null, null],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIOwner::get_stored_tx](struct.APIOwner.html#method.get_stored_tx).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"params": [
			{
				"amount_credited": 0,
				"amount_debited": 0,
				"confirmation_ts": null,
				"confirmed": false,
				"creation_ts": "2019-03-05T20:49:59.444095Z",
				"fee": null,
				"id": 10,
				"messages": null,
				"num_inputs": 0,
				"num_outputs": 0,
				"parent_key_id": "0000000000000000000000000000000000",
				"stored_tx": null,
				"tx_slate_id": null,
				"tx_type": "TxReceived"
			}
		],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		},
		"id": 1
	}
	# );
	```
	 */
	fn get_stored_tx(&self, entry: &TxLogEntry) -> Result<Option<Transaction>, ErrorKind>;

	/**
	Networked version of [APIOwner::post_tx](struct.APIOwner.html#method.post_tx).

	```no_run
    # // This test currently fails on travis
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "post_tx",
		"params": [
			{
				"body": {
					"inputs": [],
					"kernels": [],
					"outputs": []
				},
				"offset": "0000000000000000000000000000000000000000000000000000000000000000"
			},
			false
		],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"ClientCallback": "Posting transaction to node: Request error: Cannot make request: an error occurred trying to connect: Connection refused (os error 61)"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIOwner::verify_slate_messages](struct.APIOwner.html#method.verify_slate_messages).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"params": [{
			"version_info": {
				"version": 2,
				"orig_version": 2,
				"min_compat_version": 0
			},
			"amount": 0,
			"fee": 0,
			"height": 0,
			"id": "414bad48-3386-4fa7-8483-72384c886ba3",
			"lock_height": 0,
			"num_participants": 2,
			"participant_data": [],
			"tx": {
				"body": {
					"inputs": [],
					"kernels": [],
					"outputs": []
				},
				"offset": "0000000000000000000000000000000000000000000000000000000000000000"
			}
		}],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			 "Ok": null
		},
		"id": 1
	}
	# );
	```
	 */
	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIOwner::restore](struct.APIOwner.html#method.restore).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "restore",
		"params": [],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn restore(&self) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIOwner::check_repair](struct.APIOwner.html#method.check_repair).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "check_repair",
		"params": [false],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIOwner::node_height](struct.APIOwner.html#method.node_height).


	```
	# grin_apiwallet::doctest_helper_json_rpc_owner_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "node_height",
		"params": [],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
			"Err": {
				"CallbackImpl": "Error opening wallet"
			}
		},
		"id": 1
	}
	# );
	```
	 */
	fn node_height(&self) -> Result<(u64, bool), ErrorKind>;
}

/// Functions intended for use by the owner (e.g. master seed holder) of the wallet.
pub struct APIOwner<W: ?Sized, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	/// A reference-counted mutex to an implementation of the
	/// [`WalletBackend`](../types/trait.WalletBackend.html) trait.
	pub wallet: Arc<Mutex<W>>,
	phantom: PhantomData<K>,
	phantom_c: PhantomData<C>,
}

impl<W: ?Sized, C, K> APIOwner<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	/// Create a new API instance with the given wallet instance. All subsequent
	/// API calls will operate on this instance of the wallet.
	///
	/// Each method will call the [`WalletBackend`](../types/trait.WalletBackend.html)'s
	/// [`open_with_credentials`](../types/trait.WalletBackend.html#tymethod.open_with_credentials)
	/// (initialising a keychain with the master seed,) perform its operation, then close the keychain
	/// with a call to [`close`](../types/trait.WalletBackend.html#tymethod.close)
	///
	/// # Arguments
	/// * `wallet_in` - A reference-counted mutex containing an implementation of the
	/// [`WalletBackend`](../types/trait.WalletBackend.html) trait.
	///
	/// # Returns
	/// * An instance of the OwnerApi holding a reference to the provided wallet
	///
	/// # Example
	/// ``` ignore
	/// # extern crate grin_wallet_config as config;
	/// # extern crate grin_refwallet as wallet;
	/// # extern crate grin_keychain as keychain;
	/// # extern crate grin_util as util;
	///
	/// use std::sync::Arc;
	/// use util::Mutex;
	///
	/// use keychain::ExtKeychain;
	/// use wallet::libwallet::api::APIOwner;
	///
	/// // These contain sample implementations of each part needed for a wallet
	/// use wallet::{LMDBBackend, HTTPNodeClient, WalletBackend};
	/// use config::WalletConfig;
	///
	/// let mut wallet_config = WalletConfig::default();
	/// # wallet_config.data_file_dir = "test_output/doc/wallet1".to_owned();
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
	/// let api_owner = APIOwner::new(wallet.clone());
	/// // .. perform wallet operations
	///
	/// ```

	pub fn new(wallet_in: Arc<Mutex<W>>) -> Self {
		APIOwner {
			wallet: wallet_in,
			phantom: PhantomData,
			phantom_c: PhantomData,
		}
	}

	/// Returns a list of accounts stored in the wallet (i.e. mappings between
	/// user-specified labels and BIP32 derivation paths.
	///
	/// # Returns
	/// * Result Containing:
	/// * A Vector of [`AcctPathMapping`](../types/struct.AcctPathMapping.html) data
	/// * or [`libwallet::Error`](../struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * A wallet should always have the path with the label 'default' path defined,
	/// with path m/0/0
	/// * This method does not need to use the wallet seed or keychain.
	///
	/// # Example
	/// Set up as in [`new`](struct.APIOwner.html#method.new) method above.
	/// ``` ignore
	/// # extern crate grin_wallet_config as config;
	/// # extern crate grin_refwallet as wallet;
	/// # extern crate grin_keychain as keychain;
	/// # extern crate grin_util as util;
	/// # use std::sync::Arc;
	/// # use util::Mutex;
	/// # use keychain::ExtKeychain;
	/// # use wallet::libwallet::api::APIOwner;
	/// # use wallet::{LMDBBackend, HTTPNodeClient, WalletBackend};
	/// # use config::WalletConfig;
	/// # let mut wallet_config = WalletConfig::default();
	/// # wallet_config.data_file_dir = "test_output/doc/wallet1".to_owned();
	/// # let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
	/// # let mut wallet:Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> =
	/// # Arc::new(Mutex::new(
	/// # 	LMDBBackend::new(wallet_config.clone(), "", node_client).unwrap()
	/// # ));
	///
	/// let api_owner = APIOwner::new(wallet.clone());
	///
	/// let result = api_owner.accounts();
	///
	/// if let Ok(accts) = result {
	///		//...
	/// }
	/// ```

	pub fn accounts(&self) -> Result<Vec<AcctPathMapping>, Error> {
		let mut w = self.wallet.lock();
		keys::accounts(&mut *w)
	}

	/// Creates a new 'account', which is a mapping of a user-specified
	/// label to a BIP32 path
	///
	/// # Arguments
	/// * `label` - A human readable label to which to map the new BIP32 Path
	///
	/// # Returns
	/// * Result Containing:
	/// * A [Keychain Identifier](#) for the new path
	/// * or [`libwallet::Error`](../struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * Wallets should be initialised with the 'default' path mapped to `m/0/0`
	/// * Each call to this function will increment the first element of the path
	/// so the first call will create an account at `m/1/0` and the second at
	/// `m/2/0` etc. . .
	/// * The account path is used throughout as the parent key for most key-derivation
	/// operations. See [`set_active_account`](struct.APIOwner.html#method.set_active_account) for
	/// further details.
	///
	/// * This function does not need to use the root wallet seed or keychain.
	///
	/// # Example
	/// Set up as in [`new`](struct.APIOwner.html#method.new) method above.
	/// ``` ignore
	/// # extern crate grin_wallet as wallet;
	/// # extern crate grin_keychain as keychain;
	/// # extern crate grin_util as util;
	/// # use std::sync::Arc;
	/// # use util::Mutex;
	/// # use keychain::ExtKeychain;
	/// # use wallet::libwallet::api::APIOwner;
	/// # use wallet::{LMDBBackend, HTTPNodeClient, WalletBackend,  WalletConfig};
	/// # let mut wallet_config = WalletConfig::default();
	/// # wallet_config.data_file_dir = "test_output/doc/wallet1".to_owned();
	/// # let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
	/// # let mut wallet:Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> =
	/// # Arc::new(Mutex::new(
	/// # 	LMDBBackend::new(wallet_config.clone(), "", node_client).unwrap()
	/// # ));
	///
	/// let api_owner = APIOwner::new(wallet.clone());
	///
	/// let result = api_owner.create_account_path("account1");
	///
	/// if let Ok(identifier) = result {
	///		//...
	/// }
	/// ```

	pub fn create_account_path(&self, label: &str) -> Result<Identifier, Error> {
		let mut w = self.wallet.lock();
		keys::new_acct_path(&mut *w, label)
	}

	/// Sets the wallet's currently active account. This sets the
	/// BIP32 parent path used for most key-derivation operations.
	///
	/// # Arguments
	/// * `label` - The human readable label for the account. Accounts can be retrieved via
	/// the [`account`](struct.APIOwner.html#method.accounts) method
	///
	/// # Returns
	/// * Result Containing:
	/// * `Ok(())` if the path was correctly set
	/// * or [`libwallet::Error`](../struct.Error.html) if an error is encountered.
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
	/// Set up as in [`new`](struct.APIOwner.html#method.new) method above.
	/// ``` ignore
	/// # extern crate grin_wallet as wallet;
	/// # extern crate grin_keychain as keychain;
	/// # extern crate grin_util as util;
	/// # use std::sync::Arc;
	/// # use util::Mutex;
	/// # use keychain::ExtKeychain;
	/// # use wallet::libwallet::api::APIOwner;
	/// # use wallet::{LMDBBackend, HTTPNodeClient, WalletBackend,  WalletConfig};
	/// # let mut wallet_config = WalletConfig::default();
	/// # wallet_config.data_file_dir = "test_output/doc/wallet1".to_owned();
	/// # let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
	/// # let mut wallet:Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> =
	/// # Arc::new(Mutex::new(
	/// # 	LMDBBackend::new(wallet_config.clone(), "", node_client).unwrap()
	/// # ));
	///
	/// let api_owner = APIOwner::new(wallet.clone());
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
		w.set_parent_key_id_by_name(label)?;
		Ok(())
	}

	/// Returns a list of outputs from the active account in the wallet.
	///
	/// # Arguments
	/// * `include_spent` - If `true`, outputs that have been marked as 'spent'
	/// in the wallet will be returned. If `false`, spent outputs will omitted
	/// from the results.
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain output information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// * `tx_id` - If `Some(i)`, only return the outputs associated with
	/// the transaction log entry of id `i`.
	///
	/// # Returns
	/// * (`bool`, `Vec<OutputData, Commitment>`) - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains the result set, of which each element is
	/// a mapping between the wallet's internal [OutputData](../types/struct.OutputData.html)
	/// and the Output commitment as identified in the chain's UTXO set
	///
	/// # Example
	/// Set up as in [`new`](struct.APIOwner.html#method.new) method above.
	/// ``` ignore
	/// # extern crate grin_wallet as wallet;
	/// # extern crate grin_keychain as keychain;
	/// # extern crate grin_util as util;
	/// # use std::sync::Arc;
	/// # use util::Mutex;
	/// # use keychain::ExtKeychain;
	/// # use wallet::libwallet::api::APIOwner;
	/// # use wallet::{LMDBBackend, HTTPNodeClient, WalletBackend,  WalletConfig};
	/// # let mut wallet_config = WalletConfig::default();
	/// # wallet_config.data_file_dir = "test_output/doc/wallet1".to_owned();
	/// # let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
	/// # let mut wallet:Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> =
	/// # Arc::new(Mutex::new(
	/// # 	LMDBBackend::new(wallet_config.clone(), "", node_client).unwrap()
	/// # ));
	///
	/// let api_owner = APIOwner::new(wallet.clone());
	/// let show_spent = false;
	/// let update_from_node = true;
	/// let tx_id = None;
	///
	/// let result = api_owner.retrieve_outputs(show_spent, update_from_node, tx_id);
	///
	/// if let Ok((was_updated, output_mapping)) = result {
	///		//...
	/// }
	/// ```

	pub fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<(OutputData, pedersen::Commitment)>), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let parent_key_id = w.parent_key_id();

		let mut validated = false;
		if refresh_from_node {
			validated = self.update_outputs(&mut w, false);
		}

		let res = Ok((
			validated,
			updater::retrieve_outputs(&mut *w, include_spent, tx_id, Some(&parent_key_id))?,
		));

		w.close()?;
		res
	}

	/// Returns a list of [Transaction Log Entries](../types/struct.TxLogEntry.html)
	/// from the active account in the wallet.
	///
	/// # Arguments
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// * `tx_id` - If `Some(i)`, only return the transactions associated with
	/// the transaction log entry of id `i`.
	/// * `tx_slate_id` - If `Some(uuid)`, only return transactions associated with
	/// the given [`Slate`](../../libtx/slate/struct.Slate.html) uuid.
	///
	/// # Returns
	/// * (`bool`, `Vec<[TxLogEntry](../types/struct.TxLogEntry.html)>`) - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains the set of retrieved
	/// [TxLogEntries](../types/struct/TxLogEntry.html)
	///
	/// # Example
	/// Set up as in [`new`](struct.APIOwner.html#method.new) method above.
	/// ``` ignore
	/// # extern crate grin_wallet as wallet;
	/// # extern crate grin_keychain as keychain;
	/// # extern crate grin_util as util;
	/// # use std::sync::Arc;
	/// # use util::Mutex;
	/// # use keychain::ExtKeychain;
	/// # use wallet::libwallet::api::APIOwner;
	/// # use wallet::{LMDBBackend, HTTPNodeClient, WalletBackend,  WalletConfig};
	/// # let mut wallet_config = WalletConfig::default();
	/// # wallet_config.data_file_dir = "test_output/doc/wallet1".to_owned();
	/// # let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
	/// # let mut wallet:Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> =
	/// # Arc::new(Mutex::new(
	/// # 	LMDBBackend::new(wallet_config.clone(), "", node_client).unwrap()
	/// # ));
	///
	/// let api_owner = APIOwner::new(wallet.clone());
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
		let parent_key_id = w.parent_key_id();

		let mut validated = false;
		if refresh_from_node {
			validated = self.update_outputs(&mut w, false);
		}

		let res = Ok((
			validated,
			updater::retrieve_txs(&mut *w, tx_id, tx_slate_id, Some(&parent_key_id), false)?,
		));

		w.close()?;
		res
	}

	/// Returns summary information from the active account in the wallet.
	///
	/// # Arguments
	/// * `refresh_from_node` - If true, the wallet will attempt to contact
	/// a node (via the [`NodeClient`](../types/trait.NodeClient.html)
	/// provided during wallet instantiation). If `false`, the results will
	/// contain transaction information that may be out-of-date (from the last time
	/// the wallet's output set was refreshed against the node).
	/// * `minimum_confirmations` - The minimum number of confirmations an output
	/// should have before it's included in the 'amount_currently_spendable' total
	///
	/// # Returns
	/// * (`bool`, [`WalletInfo`](../types/struct.WalletInfo.html)) - A tuple:
	/// * The first `bool` element indicates whether the data was successfully
	/// refreshed from the node (note this may be false even if the `refresh_from_node`
	/// argument was set to `true`.
	/// * The second element contains the Summary [`WalletInfo`](../types/struct.WalletInfo.html)
	///
	/// # Example
	/// Set up as in [`new`](struct.APIOwner.html#method.new) method above.
	/// ``` ignore
	/// # extern crate grin_wallet as wallet;
	/// # extern crate grin_keychain as keychain;
	/// # extern crate grin_util as util;
	/// # use std::sync::Arc;
	/// # use util::Mutex;
	/// # use keychain::ExtKeychain;
	/// # use wallet::libwallet::api::APIOwner;
	/// # use wallet::{LMDBBackend, HTTPNodeClient, WalletBackend,  WalletConfig};
	/// # let mut wallet_config = WalletConfig::default();
	/// # wallet_config.data_file_dir = "test_output/doc/wallet1".to_owned();
	/// # let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
	/// # let mut wallet:Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> =
	/// # Arc::new(Mutex::new(
	/// # 	LMDBBackend::new(wallet_config.clone(), "", node_client).unwrap()
	/// # ));
	///
	/// let mut api_owner = APIOwner::new(wallet.clone());
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
		let parent_key_id = w.parent_key_id();

		let mut validated = false;
		if refresh_from_node {
			validated = self.update_outputs(&mut w, false);
		}

		let wallet_info = updater::retrieve_info(&mut *w, &parent_key_id, minimum_confirmations)?;
		let res = Ok((validated, wallet_info));

		w.close()?;
		res
	}

	/// Initiates a new transaction as the sender, creating a new
	/// [`Slate`](../../libtx/slate/struct.Slate.html) object containing
	/// the sender's inputs, change outputs, and public signature data. This slate can
	/// then be sent to the recipient to continue the transaction via the
	/// [Foreign API's `receive_tx`](struct.APIForeign.html#method.receive_tx) method.
	///
	/// When a transaction is created, the wallet must also lock inputs (and create unconfirmed
	/// outputs) corresponding to the transaction created in the slate, so that the wallet doesn't
	/// attempt to re-spend outputs that are already included in a transaction before the transaction
	/// is confirmed. This method also returns a function that will perform that locking, and it is
	/// up to the caller to decide the best time to call the lock function
	/// (via the [`tx_lock_outputs`](struct.APIOwner.html#method.tx_lock_outputs) method).
	/// If the exchange method is intended to be synchronous (such as via a direct http call,)
	/// then the lock call can wait until the response is confirmed. If it is asynchronous, (such
	/// as via file transfer,) the lock call should happen immediately (before the file is sent
	/// to the recipient).
	///
	/// # Arguments
	/// * `src_acct_name` - The human readable account name from which to draw outputs
	/// for the transaction, overriding whatever the active account is as set via the
	/// [`set_active_account`](struct.APIOwner.html#method.set_active_account) method.
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
	/// sender's private keys, and will be publically verifiable. Note this message is for
	/// the convenience of the participants during the exchange; it is not included in the final
	/// transaction sent to the chain. The message will be truncated to 256 characters.
	/// Validation of this message is optional.
	///
	/// # Returns
	/// * a result containing:
	/// * ([`Slate`](../../libtx/slate/struct.Slate.html), lock_function) - A tuple:
	/// * The transaction Slate, which can be forwarded to the recieving party by any means.
	/// * A lock function, which should be called when the caller deems it appropriate to lock
	/// the transaction outputs (i.e. there is relative certaintly that the slate will be
	/// transmitted to the receiving party). Must be called before calling
	/// [`finalize_tx`](struct.APIOwner.html#method.finalize_tx).
	/// * or [`libwallet::Error`](../struct.Error.html) if an error is encountered.
	///
	/// # Remarks
	///
	/// * This method requires an active connection to a node, and will fail with error if a node
	/// cannot be contacted to refresh output statuses.
	/// * This method will store a partially completed transaction in the wallet's transaction log,
	/// which will be updated on the corresponding call to [`finalize_tx`](struct.APIOwner.html#method.finalize_tx).
	///
	/// # Example
	/// Set up as in [new](struct.APIOwner.html#method.new) method above.
	/// ``` ignore
	/// # extern crate grin_wallet as wallet;
	/// # extern crate grin_keychain as keychain;
	/// # extern crate grin_util as util;
	/// # use std::sync::Arc;
	/// # use util::Mutex;
	/// # use keychain::ExtKeychain;
	/// # use wallet::libwallet::api::APIOwner;
	/// # use wallet::{LMDBBackend, HTTPNodeClient, WalletBackend,  WalletConfig};
	/// # let mut wallet_config = WalletConfig::default();
	/// # wallet_config.data_file_dir = "test_output/doc/wallet1".to_owned();
	/// # let node_client = HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
	/// # let mut wallet:Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> =
	/// # Arc::new(Mutex::new(
	/// # 	LMDBBackend::new(wallet_config.clone(), "", node_client).unwrap()
	/// # ));
	///
	/// let mut api_owner = APIOwner::new(wallet.clone());
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
	///	);
	///
	/// if let Ok((slate, lock_fn)) = result {
	///		// Send slate somehow
	///		// ...
	///		// Lock our outputs if we're happy the slate was (or is being) sent
	///		api_owner.tx_lock_outputs(&slate, lock_fn);
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
	) -> Result<(Slate, OutputLockFn<W, C, K>), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let parent_key_id = match src_acct_name {
			Some(d) => {
				let pm = w.get_acct_path(d.to_owned())?;
				match pm {
					Some(p) => p.path,
					None => w.parent_key_id(),
				}
			}
			None => w.parent_key_id(),
		};

		let message = match message {
			Some(mut m) => {
				m.truncate(USER_MESSAGE_MAX_LEN);
				Some(m)
			}
			None => None,
		};

		let mut slate = tx::new_tx_slate(&mut *w, amount, 2)?;

		let (context, lock_fn) = tx::add_inputs_to_slate(
			&mut *w,
			&mut slate,
			minimum_confirmations,
			max_outputs,
			num_change_outputs,
			selection_strategy_is_use_all,
			&parent_key_id,
			0,
			message,
		)?;

		// Save the aggsig context in our DB for when we
		// recieve the transaction back
		{
			let mut batch = w.batch()?;
			batch.save_private_context(slate.id.as_bytes(), &context)?;
			batch.commit()?;
		}

		w.close()?;
		// set target slate version
		if let Some(v) = target_slate_version {
			slate.version_info.orig_version = v;
		}
		Ok((slate, lock_fn))
	}

	/// Estimates the amount to be locked and fee for the transaction without creating one
	///
	/// # Arguments
	/// * `src_acct_name` - The human readable account name from which to draw outputs
	/// for the transaction, overriding whatever the active account is as set via the
	/// [`set_active_account`](struct.APIOwner.html#method.set_active_account) method.
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
	///
	/// # Returns
	/// * a result containing:
	/// * (total, fee) - A tuple:
	/// * Total amount to be locked.
	/// * Transaction fee
	pub fn estimate_initiate_tx(
		&self,
		src_acct_name: Option<&str>,
		amount: u64,
		minimum_confirmations: u64,
		max_outputs: usize,
		num_change_outputs: usize,
		selection_strategy_is_use_all: bool,
	) -> Result<
		(
			u64, // total
			u64, // fee
		),
		Error,
	> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let parent_key_id = match src_acct_name {
			Some(d) => {
				let pm = w.get_acct_path(d.to_owned())?;
				match pm {
					Some(p) => p.path,
					None => w.parent_key_id(),
				}
			}
			None => w.parent_key_id(),
		};
		tx::estimate_send_tx(
			&mut *w,
			amount,
			minimum_confirmations,
			max_outputs,
			num_change_outputs,
			selection_strategy_is_use_all,
			&parent_key_id,
		)
	}

	/// Lock outputs associated with a given slate/transaction
	pub fn tx_lock_outputs(
		&self,
		slate: &Slate,
		mut lock_fn: OutputLockFn<W, C, K>,
	) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		lock_fn(&mut *w, &slate.tx, PhantomData, PhantomData)?;
		Ok(())
	}

	/// Sender finalization of the transaction. Takes the file returned by the
	/// sender as well as the private file generate on the first send step.
	/// Builds the complete transaction and sends it to a grin node for
	/// propagation.
	pub fn finalize_tx(&self, slate: &mut Slate) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let context = w.get_private_context(slate.id.as_bytes())?;
		tx::complete_tx(&mut *w, slate, 0, &context)?;
		tx::update_stored_tx(&mut *w, slate)?;
		tx::update_message(&mut *w, slate)?;
		{
			let mut batch = w.batch()?;
			batch.delete_private_context(slate.id.as_bytes())?;
			batch.commit()?;
		}
		w.close()?;
		Ok(())
	}

	/// Roll back a transaction and all associated outputs with a given
	/// transaction id This means delete all change outputs, (or recipient
	/// output if you're recipient), and unlock all locked outputs associated
	/// with the transaction used when a transaction is created but never
	/// posted
	pub fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let parent_key_id = w.parent_key_id();
		if !self.update_outputs(&mut w, false) {
			return Err(ErrorKind::TransactionCancellationError(
				"Can't contact running Grin node. Not Cancelling.",
			))?;
		}
		tx::cancel_tx(&mut *w, &parent_key_id, tx_id, tx_slate_id)?;
		w.close()?;
		Ok(())
	}

	/// Retrieves a stored transaction from a TxLogEntry
	pub fn get_stored_tx(&self, entry: &TxLogEntry) -> Result<Option<Transaction>, Error> {
		let w = self.wallet.lock();
		w.get_stored_tx(entry)
	}

	/// Posts a transaction to the chain
	pub fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), Error> {
		let tx_hex = util::to_hex(ser::ser_vec(tx).unwrap());
		let client = {
			let mut w = self.wallet.lock();
			w.w2n_client().clone()
		};
		let res = client.post_tx(&TxWrapper { tx_hex: tx_hex }, fluff);
		if let Err(e) = res {
			error!("api: post_tx: failed with error: {}", e);
			Err(e)
		} else {
			debug!(
				"api: post_tx: successfully posted tx: {}, fluff? {}",
				tx.hash(),
				fluff
			);
			Ok(())
		}
	}

	/// Verifies all messages in the slate match their public keys
	pub fn verify_slate_messages(&self, slate: &Slate) -> Result<(), Error> {
		let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly);
		slate.verify_messages(&secp)?;
		Ok(())
	}

	/// Attempt to restore contents of wallet
	pub fn restore(&self) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		w.restore()?;
		w.close()?;
		Ok(())
	}

	/// Attempt to check and fix the contents of the wallet
	pub fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		self.update_outputs(&mut w, true);
		w.check_repair(delete_unconfirmed)?;
		w.close()?;
		Ok(())
	}

	/// Retrieve current height from node
	pub fn node_height(&self) -> Result<(u64, bool), Error> {
		let res = {
			let mut w = self.wallet.lock();
			w.open_with_credentials()?;
			w.w2n_client().get_chain_height()
		};
		match res {
			Ok(height) => Ok((height, true)),
			Err(_) => {
				let outputs = self.retrieve_outputs(true, false, None)?;
				let height = match outputs.1.iter().map(|(out, _)| out.height).max() {
					Some(height) => height,
					None => 0,
				};
				Ok((height, false))
			}
		}
	}

	/// Attempt to update outputs in wallet, return whether it was successful
	fn update_outputs(&self, w: &mut W, update_all: bool) -> bool {
		let parent_key_id = w.parent_key_id();
		match updater::refresh_outputs(&mut *w, &parent_key_id, update_all) {
			Ok(_) => true,
			Err(_) => false,
		}
	}
}

impl<W: ?Sized, C, K> OwnerApi for APIOwner<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind> {
		APIOwner::accounts(self).map_err(|e| e.kind())
	}

	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind> {
		APIOwner::create_account_path(self, label).map_err(|e| e.kind())
	}

	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind> {
		APIOwner::set_active_account(self, label).map_err(|e| e.kind())
	}

	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<(OutputData, pedersen::Commitment)>), ErrorKind> {
		APIOwner::retrieve_outputs(self, include_spent, refresh_from_node, tx_id)
			.map_err(|e| e.kind())
	}

	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind> {
		APIOwner::retrieve_txs(self, refresh_from_node, tx_id, tx_slate_id).map_err(|e| e.kind())
	}

	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind> {
		APIOwner::retrieve_summary_info(self, refresh_from_node, minimum_confirmations)
			.map_err(|e| e.kind())
	}

	fn estimate_initiate_tx(
		&self,
		src_acct_name: Option<String>,
		amount: u64,
		minimum_confirmations: u64,
		max_outputs: usize,
		num_change_outputs: usize,
		selection_strategy_is_use_all: bool,
	) -> Result<(/* total */ u64, /* fee */ u64), ErrorKind> {
		APIOwner::estimate_initiate_tx(
			self,
			src_acct_name.as_ref().map(String::as_str),
			amount,
			minimum_confirmations,
			max_outputs,
			num_change_outputs,
			selection_strategy_is_use_all,
		)
		.map_err(|e| e.kind())
	}

	fn finalize_tx(&self, mut slate: Slate) -> Result<Slate, ErrorKind> {
		APIOwner::finalize_tx(self, &mut slate).map_err(|e| e.kind())?;
		Ok(slate)
	}

	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind> {
		APIOwner::cancel_tx(self, tx_id, tx_slate_id).map_err(|e| e.kind())
	}

	fn get_stored_tx(&self, entry: &TxLogEntry) -> Result<Option<Transaction>, ErrorKind> {
		APIOwner::get_stored_tx(self, entry).map_err(|e| e.kind())
	}

	fn post_tx(&self, tx: &Transaction, fluff: bool) -> Result<(), ErrorKind> {
		APIOwner::post_tx(self, tx, fluff).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind> {
		APIOwner::verify_slate_messages(self, slate).map_err(|e| e.kind())
	}

	fn restore(&self) -> Result<(), ErrorKind> {
		APIOwner::restore(self).map_err(|e| e.kind())
	}

	fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), ErrorKind> {
		APIOwner::check_repair(self, delete_unconfirmed).map_err(|e| e.kind())
	}

	fn node_height(&self) -> Result<(u64, bool), ErrorKind> {
		APIOwner::node_height(self).map_err(|e| e.kind())
	}
}

/// Public definition used to generate jsonrpc api for APIForeign.
#[easy_jsonrpc::rpc]
pub trait ForeignApi {
	/**
	Networked version of [APIForeign::build_coinbase](struct.APIForeign.html#method.build_coinbase).

	# Json rpc example

	```
	# grin_apiwallet::doctest_helper_json_rpc_foreign_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "build_coinbase",
		"params": [
            {
                "fees": 0,
            	"height": 0,
                "key_id": null
            }
        ],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
            "Err": {
                "CallbackImpl": "Error opening wallet"
            }
		},
		"id": 1
	}
	# );
	```
	 */
	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind>;

	/**
	Networked version of [APIForeign::verify_slate_messages](struct.APIForeign.html#method.verify_slate_messages).

	# Json rpc example

	```
	# grin_apiwallet::doctest_helper_json_rpc_foreign_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"params": [
            {
    			"version_info": {
    				"version": 2,
    				"orig_version": 2,
    				"min_compat_version": 0
    			},
    			"amount": 0,
    			"fee": 0,
    			"height": 0,
    			"id": "414bad48-3386-4fa7-8483-72384c886ba3",
    			"lock_height": 0,
    			"num_participants": 2,
    			"participant_data": [],
    			"tx": {
    				"body": {
    					"inputs": [],
    					"kernels": [],
    					"outputs": []
    				},
    				"offset": "0000000000000000000000000000000000000000000000000000000000000000"
    			}
		    }
        ],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
            "Ok": null
		},
		"id": 1
	}
	# );
	```
	 */
	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind>;

	/**
	Networked version of [APIForeign::receive_tx](struct.APIForeign.html#method.receive_tx).

	# Json rpc example

	```ignore //TODO: No idea why this isn't expanding properly, check as we adjust the API
	# grin_apiwallet::doctest_helper_json_rpc_foreign_assert_response!(
	{
		"jsonrpc": "2.0",
		"method": "receive_tx",
		"params": [
            {
    			"version_info": {
    				"version": 2,
    				"orig_version": 2,
    				"min_compat_version": 0
    			},
    			"amount": 0,
    			"fee": 0,
    			"height": 0,
    			"id": "414bad48-3386-4fa7-8483-72384c886ba3",
    			"lock_height": 0,
    			"num_participants": 2,
    			"participant_data": [],
    			"tx": {
    				"body": {
    					"inputs": [],
    					"kernels": [],
    					"outputs": []
    				},
    				"offset": "0000000000000000000000000000000000000000000000000000000000000000"
    			}
		    },
            null,
            null
        ],
		"id": 1
	},
	{
		"jsonrpc": "2.0",
		"result": {
            "Err": {
                "CallbackImpl": "Error opening wallet"
            }
		},
		"id": 1
	}
	# );
	```
	 */
	fn receive_tx(
		&self,
		slate: Slate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<Slate, ErrorKind>;
}

/// Wrapper around external API functions, intended to communicate
/// with other parties
pub struct APIForeign<W: ?Sized, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	/// Wallet, contains its keychain (TODO: Split these up into 2 traits
	/// perhaps)
	pub wallet: Arc<Mutex<W>>,
	phantom: PhantomData<K>,
	phantom_c: PhantomData<C>,
}

impl<'a, W: ?Sized, C, K> APIForeign<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	/// Create new API instance
	pub fn new(wallet_in: Arc<Mutex<W>>) -> Box<Self> {
		Box::new(APIForeign {
			wallet: wallet_in,
			phantom: PhantomData,
			phantom_c: PhantomData,
		})
	}

	/// Build a new (potential) coinbase transaction in the wallet
	pub fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, Error> {
		let mut w = self.wallet.lock();
		w.open_with_credentials()?;
		let res = updater::build_coinbase(&mut *w, block_fees);
		w.close()?;
		res
	}

	/// Verifies all messages in the slate match their public keys
	pub fn verify_slate_messages(&self, slate: &Slate) -> Result<(), Error> {
		let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly);
		slate.verify_messages(&secp)?;
		Ok(())
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
		let parent_key_id = match dest_acct_name {
			Some(d) => {
				let pm = w.get_acct_path(d.to_owned())?;
				match pm {
					Some(p) => p.path,
					None => w.parent_key_id(),
				}
			}
			None => w.parent_key_id(),
		};
		// Don't do this multiple times
		let tx = updater::retrieve_txs(&mut *w, None, Some(slate.id), Some(&parent_key_id), false)?;
		for t in &tx {
			if t.tx_type == TxLogEntryType::TxReceived {
				return Err(ErrorKind::TransactionAlreadyReceived(slate.id.to_string()).into());
			}
		}

		let message = match message {
			Some(mut m) => {
				m.truncate(USER_MESSAGE_MAX_LEN);
				Some(m)
			}
			None => None,
		};

		let (_, mut create_fn) =
			tx::add_output_to_slate(&mut *w, slate, &parent_key_id, 1, message)?;
		create_fn(&mut *w, &slate.tx, PhantomData, PhantomData)?;
		tx::update_message(&mut *w, slate)?;
		w.close()?;
		Ok(())
	}
}

impl<W: ?Sized, C, K> ForeignApi for APIForeign<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind> {
		APIForeign::build_coinbase(self, block_fees).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind> {
		APIForeign::verify_slate_messages(self, slate).map_err(|e| e.kind())
	}

	fn receive_tx(
		&self,
		mut slate: Slate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<Slate, ErrorKind> {
		APIForeign::receive_tx(
			self,
			&mut slate,
			dest_acct_name.as_ref().map(String::as_str),
			message,
		)
		.map_err(|e| e.kind())?;
		Ok(slate)
	}
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:tt, $expected_response:tt) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		fn rpc_owner_result(
			request: serde_json::Value,
		) -> Result<Option<serde_json::Value>, String> {
			use easy_jsonrpc::Handler;
			use grin_apiwallet::api::{APIOwner, OwnerApi};
			use grin_keychain::ExtKeychain;
			use grin_refwallet::{HTTPNodeClient, LMDBBackend, WalletBackend};
			use grin_util::Mutex;
			use grin_wallet_config::WalletConfig;
			use serde_json;
			use std::sync::Arc;
			use tempfile::tempdir;

			let dir = tempdir().map_err(|e| format!("{:#?}", e))?;
				{
				let mut wallet_config = WalletConfig::default();
				wallet_config.data_file_dir = dir
					.path()
					.to_str()
					.ok_or("Failed to convert tmpdir path to string.".to_owned())?
					.to_owned();
				let node_client =
					HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
				let wallet: Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> =
					Arc::new(Mutex::new(
						LMDBBackend::new(wallet_config.clone(), "", node_client)
							.map_err(|e| format!("{:#?}", e))?,
					));
				let api_owner = APIOwner::new(wallet);
				let owner_api = &api_owner as &dyn OwnerApi;
				Ok(owner_api.handle_request(request))
				}
			}

		let response = rpc_owner_result(serde_json::json!($request))
			.unwrap()
			.unwrap();
		let expected_response = serde_json::json!($expected_response);

		if response != expected_response {
			panic!(
				"(left != right) \nleft: {}\nright: {}",
				serde_json::to_string_pretty(&response).unwrap(),
				serde_json::to_string_pretty(&expected_response).unwrap()
				);
			}
	};
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:tt, $expected_response:tt) => {
		// create temporary wallet, run jsonrpc request on api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		fn rpc_owner_result(
			request: serde_json::Value,
		) -> Result<Option<serde_json::Value>, String> {
			use easy_jsonrpc::Handler;
			use grin_apiwallet::api::{APIForeign, ForeignApi};
			use grin_keychain::ExtKeychain;
			use grin_refwallet::{HTTPNodeClient, LMDBBackend, WalletBackend};
			use grin_util::Mutex;
			use grin_wallet_config::WalletConfig;
			use serde_json;
			use std::sync::Arc;
			use tempfile::tempdir;

			let dir = tempdir().map_err(|e| format!("{:#?}", e))?;
				{
				let mut wallet_config = WalletConfig::default();
				wallet_config.data_file_dir = dir
					.path()
					.to_str()
					.ok_or("Failed to convert tmpdir path to string.".to_owned())?
					.to_owned();
				let node_client =
					HTTPNodeClient::new(&wallet_config.check_node_api_http_addr, None);
				let wallet: Arc<Mutex<WalletBackend<HTTPNodeClient, ExtKeychain>>> =
					Arc::new(Mutex::new(
						LMDBBackend::new(wallet_config.clone(), "", node_client)
							.map_err(|e| format!("{:#?}", e))?,
					));
				let api_foreign = *APIForeign::new(wallet);
				let foreign_api = &api_foreign as &dyn ForeignApi;
				Ok(foreign_api.handle_request(request))
				}
			}

		let response = rpc_owner_result(serde_json::json!($request))
			.unwrap()
			.unwrap();
		let expected_response = serde_json::json!($expected_response);

		if response != expected_response {
			panic!(
				"(left != right) \nleft: {}\nright: {}",
				serde_json::to_string_pretty(&response).unwrap(),
				serde_json::to_string_pretty(&expected_response).unwrap()
				);
			}
	};
}
