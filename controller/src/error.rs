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

//! Implementation specific error types
use crate::api;
use crate::core::core::transaction;
use crate::core::libtx;
use crate::impls;
use crate::keychain;
use crate::libwallet;

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error)]
pub enum Error {
	/// LibTX Error
	#[error("LibTx Error")]
	LibTX(#[from] libtx::Error),

	/// Impls error
	#[error("Impls Error")]
	Impls(#[from] impls::Error),

	/// LibWallet Error
	#[error("LibWallet Error: {0}")]
	LibWallet(#[from] libwallet::Error),

	/// Keychain error
	#[error("Keychain error")]
	Keychain(#[from] keychain::Error),

	/// Transaction Error
	#[error("Transaction error")]
	Transaction(#[from] transaction::Error),

	/// Secp Error
	#[error("Secp error")]
	Secp,

	/// Filewallet error
	#[error("Wallet data error: {0}")]
	FileWallet(&'static str),

	/// Error when formatting json
	#[error("IO error")]
	IO,

	/// Error when formatting json
	#[error("Serde JSON error")]
	Format,

	/// Error when contacting a node through its API
	#[error("Node API error")]
	Node(#[from] api::Error),

	/// Error originating from hyper.
	#[error("Hyper error")]
	Hyper,

	/// Error originating from hyper uri parsing.
	#[error("Uri parsing error")]
	Uri,

	/// Attempt to use duplicate transaction id in separate transactions
	#[error("Duplicate transaction ID error")]
	DuplicateTransactionId,

	/// Wallet seed already exists
	#[error("Wallet seed file exists: {0}")]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Enc/Decryption Error
	#[error("Enc/Decryption error (check password?)")]
	Encryption,

	/// BIP 39 word list
	#[error("BIP39 Mnemonic (word list) Error")]
	Mnemonic,

	/// Command line argument error
	#[error("{0}")]
	ArgumentError(String),

	/// Other
	#[error("Listener Startup Error")]
	ListenerError,

	/// Other
	#[error("Generic error: {0}")]
	GenericError(String),
}
