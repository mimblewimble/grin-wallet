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

//! Error types for libwallet

use crate::grin_core::core::{committed, transaction};
use crate::grin_core::libtx;
use crate::grin_keychain;
use crate::grin_util::secp;
use crate::util;
use grin_store;

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error, Serialize, Deserialize)]
pub enum Error {
	/// Not enough funds
	#[error("Not enough funds. Required: {needed_disp:?}, Available: {available_disp:?}")]
	NotEnoughFunds {
		/// available funds
		available: u64,
		/// Display friendly
		available_disp: String,
		/// Needed funds
		needed: u64,
		/// Display friendly
		needed_disp: String,
	},

	/// Fee error
	#[error("Fee Error: {0}")]
	Fee(String),

	/// LibTX Error
	#[error("LibTx Error")]
	LibTX(#[from] libtx::Error),

	/// Keychain error
	#[error("Keychain error")]
	Keychain(#[from] grin_keychain::Error),

	/// Transaction Error
	#[error("Transaction error")]
	Transaction(#[from] transaction::Error),

	/// API Error
	#[error("Client Callback Error: {0}")]
	ClientCallback(String),

	/// Error from underlying secp lib
	#[error("Secp Lib Error")]
	Secp(#[from] secp::Error),

	/// Onion V3 Address Error
	#[error("Onion V3 Address Error: {0}")]
	OnionV3Address(#[from] util::OnionV3AddressError),

	/// Callback implementation error conversion
	#[error("Trait Implementation error")]
	CallbackImpl(&'static str),

	/// Wallet backend error
	#[error("Wallet store error: {0}")]
	Backend(String),

	/// Callback implementation error conversion
	#[error("Restore Error")]
	Restore,

	/// An error in the format of the JSON structures exchanged by the wallet
	#[error("JSON format error: {0}")]
	Format(String),

	/// Other serialization errors
	#[error("Ser/Deserialization error")]
	Deser(crate::grin_core::ser::Error),

	/// IO Error
	#[error("I/O error {0}")]
	IO(String),

	/// Error when contacting a node through its API
	#[error("Node API error")]
	Node,

	/// Error contacting wallet API
	#[error("Wallet Communication Error: {0}")]
	WalletComms(String),

	/// Error originating from hyper.
	#[error("Hyper error")]
	Hyper,

	/// Error originating from hyper uri parsing.
	#[error("Uri parsing error")]
	Uri,

	/// Signature error
	#[error("Signature error: {0}")]
	Signature(String),

	/// OwnerAPIEncryption
	#[error("{}", _0)]
	APIEncryption(String),

	/// Attempt to use duplicate transaction id in separate transactions
	#[error("Duplicate transaction ID error")]
	DuplicateTransactionId,

	/// Wallet seed already exists
	#[error("Wallet seed exists error: {0}")]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Wallet seed doesn't exist
	#[error("Wallet seed decryption error")]
	WalletSeedDecryption,

	/// Transaction doesn't exist
	#[error("Transaction {0} doesn't exist")]
	TransactionDoesntExist(String),

	/// Transaction already rolled back
	#[error("Transaction {0} cannot be cancelled")]
	TransactionNotCancellable(String),

	/// Cancellation error
	#[error("Cancellation Error: {0}")]
	TransactionCancellationError(&'static str),

	/// Cancellation error
	#[error("Tx dump Error: {0}")]
	TransactionDumpError(&'static str),

	/// Attempt to repost a transaction that's already confirmed
	#[error("Transaction already confirmed error")]
	TransactionAlreadyConfirmed,

	/// Transaction has already been received
	#[error("Transaction {0} has already been received")]
	TransactionAlreadyReceived(String),

	/// Transaction has been cancelled
	#[error("Transaction {0} has been cancelled")]
	TransactionWasCancelled(String),

	/// Attempt to repost a transaction that's not completed and stored
	#[error("Transaction building not completed: {0}")]
	TransactionBuildingNotCompleted(u32),

	/// Invalid BIP-32 Depth
	#[error("Invalid BIP32 Depth (must be 1 or greater)")]
	InvalidBIP32Depth,

	/// Attempt to add an account that exists
	#[error("Account Label '{0}' already exists")]
	AccountLabelAlreadyExists(String),

	/// Reference unknown account label
	#[error("Unknown Account Label '{0}'")]
	UnknownAccountLabel(String),

	/// Error from summing commitments via committed trait.
	#[error("Committed Error")]
	Committed(committed::Error),

	/// Error from summing commitments
	#[error("Committed Error: {0}")]
	Commit(String),

	/// Error Deserializing commit
	#[error("Commit Deserialize Error: {0}")]
	CommitDeser(String),

	/// Error Deserializing key
	#[error("Server Key Deserialize Error: {0}")]
	ServerKeyDeser(String),

	/// Parsing integert
	#[error("Can't parse as u64: {0}")]
	U64Deser(String),

	/// Can't parse slate version
	#[error("Can't parse slate version")]
	SlateVersionParse,

	/// Can't serialize slate
	#[error("Can't Serialize slate")]
	SlateSer,

	/// Can't deserialize slate
	#[error("Can't Deserialize slate")]
	SlateDeser,

	/// Invalid slate state
	#[error("Invalid slate state")]
	SlateState,

	/// Can't serialize slate pack
	#[error("Can't Serialize slatepack")]
	SlatepackSer,

	/// Can't deserialize slate
	#[error("Can't Deserialize slatepack: {0}")]
	SlatepackDeser(String),

	/// Unknown slate version
	#[error("Unknown Slate Version: {0}")]
	SlateVersion(u16),

	/// Attempt to use slate transaction data that doesn't exists
	#[error("Slate transaction required in this context")]
	SlateTransactionRequired,

	/// Attempt to downgrade slate that can't be downgraded
	#[error("Can't downgrade slate: {0}")]
	SlateInvalidDowngrade(String),

	/// Compatibility error between incoming slate versions and what's expected
	#[error("Compatibility Error: {0}")]
	Compatibility(String),

	/// Keychain doesn't exist (wallet not openend)
	#[error("Keychain doesn't exist (has wallet been opened?)")]
	KeychainDoesntExist,

	/// Lifecycle Error
	#[error("Lifecycle Error: {0}")]
	Lifecycle(String),

	/// Invalid Keychain Mask Error
	#[error("Supplied Keychain Mask Token is incorrect")]
	InvalidKeychainMask,

	/// Tor Process error
	#[error("Tor Process Error: {0}")]
	TorProcess(String),

	/// Tor Configuration Error
	#[error("Tor Config Error: {0}")]
	TorConfig(String),

	/// Generating ED25519 Public Key
	#[error("Error generating ed25519 secret key: {0}")]
	ED25519Key(String),

	/// Generating Payment Proof
	#[error("Payment Proof generation error: {0}")]
	PaymentProof(String),

	/// Retrieving Payment Proof
	#[error("Payment Proof retrieval error: {0}")]
	PaymentProofRetrieval(String),

	/// Retrieving Payment Proof
	#[error("Payment Proof parsing error: {0}")]
	PaymentProofParsing(String),

	/// Decoding OnionV3 addresses to payment proof addresses
	#[error("Proof Address decoding: {0}")]
	AddressDecoding(String),

	/// Transaction has expired it's TTL
	#[error("Transaction Expired")]
	TransactionExpired,

	/// Kernel features args don't exist
	#[error("Kernel Features Arg {0} missing")]
	KernelFeaturesMissing(String),

	/// Unknown Kernel Feature
	#[error("Unknown Kernel Feature: {0}")]
	UnknownKernelFeatures(u8),

	/// Invalid Kernel Feature
	#[error("Invalid Kernel Feature: {0}")]
	InvalidKernelFeatures(u8),

	/// Invalid Slatepack Data
	#[error("Invalid Slatepack Data: {0}")]
	InvalidSlatepackData(String),

	/// Slatepack Encryption
	#[error("Couldn't encrypt Slatepack: {0}")]
	SlatepackEncryption(String),

	/// Slatepack Decryption
	#[error("Couldn't decrypt Slatepack: {0}")]
	SlatepackDecryption(String),

	/// age error
	#[error("Age error: {0}")]
	Age(String),

	/// Rewind Hash parsing error
	#[error("Rewind Hash error: {0}")]
	RewindHash(String),

	/// Nonce creation error
	#[error("Nonce error: {0}")]
	Nonce(String),

	/// Slatepack address parsing error
	#[error("SlatepackAddress error: {0}")]
	SlatepackAddress(String),

	/// Retrieving Stored Tx
	#[error("Stored Tx error: {0}")]
	StoredTx(String),

	/// Other
	#[error("Generic error: {0}")]
	GenericError(String),
}

impl From<grin_store::Error> for Error {
	fn from(error: grin_store::Error) -> Error {
		Error::Backend(format!("{}", error))
	}
}

impl From<age::EncryptError> for Error {
	fn from(error: age::EncryptError) -> Error {
		Error::Age(format!("{}", error))
	}
}

impl From<age::DecryptError> for Error {
	fn from(error: age::DecryptError) -> Error {
		Error::Age(format!("{}", error))
	}
}

impl From<std::io::Error> for Error {
	fn from(e: std::io::Error) -> Error {
		Error::IO(e.to_string())
	}
}

impl From<&str> for Error {
	fn from(error: &str) -> Error {
		Error::Age(format!("Bech32 Key Encoding - {}", error))
	}
}

impl From<bech32::Error> for Error {
	fn from(error: bech32::Error) -> Error {
		Error::SlatepackAddress(format!("{}", error))
	}
}
