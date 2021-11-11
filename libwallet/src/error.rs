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
use crate::grin_store;
use crate::grin_util::secp;
use crate::util;
use failure::{Backtrace, Context, Fail};
use std::env;
use std::fmt::{self, Display};
use std::io;

/// Error definition
#[derive(Debug, Fail)]
pub struct Error {
	inner: Context<ErrorKind>,
}

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, Fail, Serialize, Deserialize)]
pub enum ErrorKind {
	/// Not enough funds
	#[fail(
		display = "Not enough funds. Required: {}, Available: {}",
		needed_disp, available_disp
	)]
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
	#[fail(display = "Fee Error: {}", _0)]
	Fee(String),

	/// LibTX Error
	#[fail(display = "LibTx Error")]
	LibTX(libtx::ErrorKind),

	/// Keychain error
	#[fail(display = "Keychain error")]
	Keychain(grin_keychain::Error),

	/// Transaction Error
	#[fail(display = "Transaction error")]
	Transaction(transaction::Error),

	/// API Error
	#[fail(display = "Client Callback Error: {}", _0)]
	ClientCallback(String),

	/// Secp Error
	#[fail(display = "Secp error")]
	Secp(secp::Error),

	/// Onion V3 Address Error
	#[fail(display = "Onion V3 Address Error")]
	OnionV3Address(util::OnionV3AddressError),

	/// Callback implementation error conversion
	#[fail(display = "Trait Implementation error")]
	CallbackImpl(&'static str),

	/// Wallet backend error
	#[fail(display = "Wallet store error: {}", _0)]
	Backend(String),

	/// Callback implementation error conversion
	#[fail(display = "Restore Error")]
	Restore,

	/// An error in the format of the JSON structures exchanged by the wallet
	#[fail(display = "JSON format error: {}", _0)]
	Format(String),

	/// Other serialization errors
	#[fail(display = "Ser/Deserialization error")]
	Deser(crate::grin_core::ser::Error),

	/// IO Error
	#[fail(display = "I/O error")]
	IO,

	/// Error when contacting a node through its API
	#[fail(display = "Node API error")]
	Node,

	/// Error contacting wallet API
	#[fail(display = "Wallet Communication Error: {}", _0)]
	WalletComms(String),

	/// Error originating from hyper.
	#[fail(display = "Hyper error")]
	Hyper,

	/// Error originating from hyper uri parsing.
	#[fail(display = "Uri parsing error")]
	Uri,

	/// Signature error
	#[fail(display = "Signature error: {}", _0)]
	Signature(String),

	/// OwnerAPIEncryption
	#[fail(display = "{}", _0)]
	APIEncryption(String),

	/// Attempt to use duplicate transaction id in separate transactions
	#[fail(display = "Duplicate transaction ID error")]
	DuplicateTransactionId,

	/// Wallet seed already exists
	#[fail(display = "Wallet seed exists error: {}", _0)]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[fail(display = "Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Wallet seed doesn't exist
	#[fail(display = "Wallet seed decryption error")]
	WalletSeedDecryption,

	/// Transaction doesn't exist
	#[fail(display = "Transaction {} doesn't exist", _0)]
	TransactionDoesntExist(String),

	/// Transaction already rolled back
	#[fail(display = "Transaction {} cannot be cancelled", _0)]
	TransactionNotCancellable(String),

	/// Cancellation error
	#[fail(display = "Cancellation Error: {}", _0)]
	TransactionCancellationError(&'static str),

	/// Cancellation error
	#[fail(display = "Tx dump Error: {}", _0)]
	TransactionDumpError(&'static str),

	/// Attempt to repost a transaction that's already confirmed
	#[fail(display = "Transaction already confirmed error")]
	TransactionAlreadyConfirmed,

	/// Transaction has already been received
	#[fail(display = "Transaction {} has already been received", _0)]
	TransactionAlreadyReceived(String),

	/// Attempt to repost a transaction that's not completed and stored
	#[fail(display = "Transaction building not completed: {}", _0)]
	TransactionBuildingNotCompleted(u32),

	/// Invalid BIP-32 Depth
	#[fail(display = "Invalid BIP32 Depth (must be 1 or greater)")]
	InvalidBIP32Depth,

	/// Attempt to add an account that exists
	#[fail(display = "Account Label '{}' already exists", _0)]
	AccountLabelAlreadyExists(String),

	/// Reference unknown account label
	#[fail(display = "Unknown Account Label '{}'", _0)]
	UnknownAccountLabel(String),

	/// Error from summing commitments via committed trait.
	#[fail(display = "Committed Error")]
	Committed(committed::Error),

	/// Error from summing commitments
	#[fail(display = "Committed Error: {}", _0)]
	Commit(String),

	/// Can't parse slate version
	#[fail(display = "Can't parse slate version")]
	SlateVersionParse,

	/// Can't serialize slate
	#[fail(display = "Can't Serialize slate")]
	SlateSer,

	/// Can't deserialize slate
	#[fail(display = "Can't Deserialize slate")]
	SlateDeser,

	/// Can't serialize slate pack
	#[fail(display = "Can't Serialize slatepack")]
	SlatepackSer,

	/// Can't deserialize slate
	#[fail(display = "Can't Deserialize slatepack: {}", _0)]
	SlatepackDeser(String),

	/// Unknown slate version
	#[fail(display = "Unknown Slate Version: {}", _0)]
	SlateVersion(u16),

	/// Attempt to use slate transaction data that doesn't exists
	#[fail(display = "Slate transaction required in this context")]
	SlateTransactionRequired,

	/// Attempt to downgrade slate that can't be downgraded
	#[fail(display = "Can't downgrade slate: {}", _0)]
	SlateInvalidDowngrade(String),

	/// Compatibility error between incoming slate versions and what's expected
	#[fail(display = "Compatibility Error: {}", _0)]
	Compatibility(String),

	/// Keychain doesn't exist (wallet not openend)
	#[fail(display = "Keychain doesn't exist (has wallet been opened?)")]
	KeychainDoesntExist,

	/// Lifecycle Error
	#[fail(display = "Lifecycle Error: {}", _0)]
	Lifecycle(String),

	/// Invalid Keychain Mask Error
	#[fail(display = "Supplied Keychain Mask Token is incorrect")]
	InvalidKeychainMask,

	/// Tor Process error
	#[fail(display = "Tor Process Error: {}", _0)]
	TorProcess(String),

	/// Tor Configuration Error
	#[fail(display = "Tor Config Error: {}", _0)]
	TorConfig(String),

	/// Generating ED25519 Public Key
	#[fail(display = "Error generating ed25519 secret key: {}", _0)]
	ED25519Key(String),

	/// Generating Payment Proof
	#[fail(display = "Payment Proof generation error: {}", _0)]
	PaymentProof(String),

	/// Retrieving Payment Proof
	#[fail(display = "Payment Proof retrieval error: {}", _0)]
	PaymentProofRetrieval(String),

	/// Retrieving Payment Proof
	#[fail(display = "Payment Proof parsing error: {}", _0)]
	PaymentProofParsing(String),

	/// Decoding OnionV3 addresses to payment proof addresses
	#[fail(display = "Proof Address decoding: {}", _0)]
	AddressDecoding(String),

	/// Transaction has expired it's TTL
	#[fail(display = "Transaction Expired")]
	TransactionExpired,

	/// Kernel features args don't exist
	#[fail(display = "Kernel Features Arg {} missing", _0)]
	KernelFeaturesMissing(String),

	/// Unknown Kernel Feature
	#[fail(display = "Unknown Kernel Feature: {}", _0)]
	UnknownKernelFeatures(u8),

	/// Invalid Kernel Feature
	#[fail(display = "Invalid Kernel Feature: {}", _0)]
	InvalidKernelFeatures(u8),

	/// Invalid Slatepack Data
	#[fail(display = "Invalid Slatepack Data: {}", _0)]
	InvalidSlatepackData(String),

	/// Slatepack Encryption
	#[fail(display = "Couldn't encrypt Slatepack: {}", _0)]
	SlatepackEncryption(String),

	/// Slatepack Decryption
	#[fail(display = "Couldn't decrypt Slatepack: {}", _0)]
	SlatepackDecryption(String),

	/// age error
	#[fail(display = "Age error: {}", _0)]
	Age(String),

	/// Slatepack address parsing error
	#[fail(display = "SlatepackAddress error: {}", _0)]
	SlatepackAddress(String),

	/// Retrieving Stored Tx
	#[fail(display = "Stored Tx error: {}", _0)]
	StoredTx(String),

	/// Other
	#[fail(display = "Generic error: {}", _0)]
	GenericError(String),
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let show_bt = match env::var("RUST_BACKTRACE") {
			Ok(r) => r == "1",
			Err(_) => false,
		};
		let backtrace = match self.backtrace() {
			Some(b) => format!("{}", b),
			None => String::from("Unknown"),
		};
		let inner_output = format!("{}", self.inner,);
		let backtrace_output = format!("\n Backtrace: {}", backtrace);
		let mut output = inner_output;
		if show_bt {
			output.push_str(&backtrace_output);
		}
		Display::fmt(&output, f)
	}
}

impl Error {
	/// get kind
	pub fn kind(&self) -> ErrorKind {
		self.inner.get_context().clone()
	}
	/// get cause string
	pub fn cause_string(&self) -> String {
		match self.cause() {
			Some(k) => format!("{}", k),
			None => "Unknown".to_string(),
		}
	}
	/// get cause
	pub fn cause(&self) -> Option<&dyn Fail> {
		self.inner.cause()
	}
	/// get backtrace
	pub fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<Context<ErrorKind>> for Error {
	fn from(inner: Context<ErrorKind>) -> Error {
		Error { inner: inner }
	}
}

impl From<io::Error> for Error {
	fn from(_error: io::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::IO),
		}
	}
}

impl From<grin_keychain::Error> for Error {
	fn from(error: grin_keychain::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Keychain(error)),
		}
	}
}

impl From<libtx::Error> for Error {
	fn from(error: crate::grin_core::libtx::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::LibTX(error.kind())),
		}
	}
}

impl From<transaction::Error> for Error {
	fn from(error: transaction::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Transaction(error)),
		}
	}
}

impl From<crate::grin_core::ser::Error> for Error {
	fn from(error: crate::grin_core::ser::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Deser(error)),
		}
	}
}

impl From<secp::Error> for Error {
	fn from(error: secp::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Secp(error)),
		}
	}
}

impl From<committed::Error> for Error {
	fn from(error: committed::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Committed(error)),
		}
	}
}

impl From<grin_store::Error> for Error {
	fn from(error: grin_store::Error) -> Error {
		Error::from(ErrorKind::Backend(format!("{}", error)))
	}
}

impl From<util::OnionV3AddressError> for Error {
	fn from(error: util::OnionV3AddressError) -> Error {
		Error::from(ErrorKind::OnionV3Address(error))
	}
}

impl From<age::EncryptError> for Error {
	fn from(error: age::EncryptError) -> Error {
		Error {
			inner: Context::new(ErrorKind::Age(format!("{}", error))),
		}
	}
}

impl From<age::DecryptError> for Error {
	fn from(error: age::DecryptError) -> Error {
		Error {
			inner: Context::new(ErrorKind::Age(format!("{}", error))),
		}
	}
}

impl From<&str> for Error {
	fn from(error: &str) -> Error {
		Error {
			inner: Context::new(ErrorKind::Age(format!("Bech32 Key Encoding - {}", error))),
		}
	}
}

impl From<bech32::Error> for Error {
	fn from(error: bech32::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::SlatepackAddress(format!("{}", error))),
		}
	}
}
