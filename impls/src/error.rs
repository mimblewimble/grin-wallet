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
use crate::core::libtx;
use crate::keychain;
use crate::libwallet;
use crate::util::secp;
use grin_wallet_util::OnionV3AddressError;

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, thiserror::Error, Eq, PartialEq, Debug)]
pub enum Error {
	/// LibTX Error
	#[error("LibTx Error")]
	LibTX(#[from] libtx::Error),

	/// LibWallet Error
	#[error("LibWallet Error: {0}")]
	LibWallet(#[from] libwallet::Error),

	/// Keychain error
	#[error("Keychain error")]
	Keychain(#[from] keychain::Error),

	/// Onion V3 Address Error
	#[error("Onion V3 Address Error")]
	OnionV3Address(#[from] OnionV3AddressError),

	/// Error when obfs4proxy is not in the user path if TOR brigde is enabled
	#[error("Unable to find obfs4proxy binary in your path; {}", _0)]
	Obfs4proxyBin(String),

	/// Error the bridge input is in bad format
	#[error("Bridge line is in bad format; {}", _0)]
	BridgeLine(String),

	/// Error when formatting json
	#[error("IO error")]
	IO,

	/// Secp Error
	#[error("Secp error")]
	Secp(#[from] secp::Error),

	/// Error when formatting json
	#[error("Serde JSON error")]
	Format,

	/// Wallet seed already exists
	#[error("Wallet seed file exists: {}", _0)]
	WalletSeedExists(String),

	/// Wallet seed doesn't exist
	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	/// Wallet seed doesn't exist
	#[error("Wallet doesn't exist at {}. {}", _0, _1)]
	WalletDoesntExist(String, String),

	/// Enc/Decryption Error
	#[error("Enc/Decryption error (check password?)")]
	Encryption,

	/// BIP 39 word list
	#[error("BIP39 Mnemonic (word list) Error")]
	Mnemonic,

	/// Command line argument error
	#[error("{}", _0)]
	ArgumentError(String),

	/// Tor Bridge error
	#[error("Tor Bridge Error: {}", _0)]
	TorBridge(String),

	/// Tor Proxy error
	#[error("Tor Proxy Error: {}", _0)]
	TorProxy(String),

	/// Generating ED25519 Public Key
	#[error("Error generating ed25519 secret key: {}", _0)]
	ED25519Key(String),

	/// Checking for onion address
	#[error("Address is not an Onion v3 Address: {}", _0)]
	NotOnion(String),

	/// Other
	#[error("Generic error: {}", _0)]
	GenericError(String),
}
