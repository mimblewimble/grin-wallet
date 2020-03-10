// Copyright 2019 The Grin Developers
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

mod file;
pub mod http;
mod keybase;

pub use self::file::PathToSlate;
pub use self::http::{HttpSlateSender, SchemeNotHttp};
pub use self::keybase::{KeybaseAllChannels, KeybaseChannel};

use crate::config::{TorConfig, WalletConfig};
use crate::libwallet::{Error, ErrorKind, Slate};
use crate::tor::config::complete_tor_address;
use crate::util::ZeroingString;

/// Little SlateV4 reminder warning helper
#[deprecated(
	since = "3.0.0",
	note = "Remember to handle SlateV4 incompatibilities here"
)]
pub struct Reminder;

/// Sends transactions to a corresponding SlateReceiver
pub trait SlateSender {
	/// Send a transaction slate to another listening wallet and return result
	/// TODO: Probably need a slate wrapper type
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error>;
}

pub trait SlateReceiver {
	/// Start a listener, passing received messages to the wallet api directly
	/// Takes a wallet config for now to avoid needing all sorts of awkward
	/// type parameters on this trait
	fn listen(
		&self,
		config: WalletConfig,
		passphrase: ZeroingString,
		account: &str,
		node_api_secret: Option<String>,
	) -> Result<(), Error>;
}

/// Posts slates to be read later by a corresponding getter
pub trait SlatePutter {
	/// Send a transaction asynchronously
	fn put_tx(&self, slate: &Slate) -> Result<(), Error>;
}

/// Checks for a transaction from a corresponding SlatePutter, returns the transaction if it exists
pub trait SlateGetter {
	/// Receive a transaction async. (Actually just read it from wherever and return the slate)
	fn get_tx(&self) -> Result<Slate, Error>;
}

/// select a SlateSender based on method and dest fields from, e.g., SendArgs
pub fn create_sender(
	method: &str,
	dest: &str,
	tor_config: Option<TorConfig>,
) -> Result<Box<dyn SlateSender>, Error> {
	let invalid = || {
		ErrorKind::WalletComms(format!(
			"Invalid wallet comm type and destination. method: {}, dest: {}",
			method, dest
		))
	};

	let mut method = method;

	// will test if this is a tor address and fill out
	// the http://[].onion if missing
	let dest = match complete_tor_address(dest) {
		Ok(d) => {
			method = "tor";
			d
		}
		Err(_) => dest.into(),
	};

	Ok(match method {
		"http" => Box::new(HttpSlateSender::new(&dest).map_err(|_| invalid())?),
		"tor" => match tor_config {
			None => {
				return Err(
					ErrorKind::WalletComms("Tor Configuration required".to_string()).into(),
				);
			}
			Some(tc) => Box::new(
				HttpSlateSender::with_socks_proxy(&dest, &tc.socks_proxy_addr, &tc.send_config_dir)
					.map_err(|_| invalid())?,
			),
		},
		"keybase" => Box::new(KeybaseChannel::new(dest)?),
		"self" => {
			return Err(ErrorKind::WalletComms(
				"No sender implementation for \"self\".".to_string(),
			)
			.into());
		}
		"file" => {
			return Err(ErrorKind::WalletComms(
				"File based transactions must be performed asynchronously.".to_string(),
			)
			.into());
		}
		_ => {
			return Err(ErrorKind::WalletComms(format!(
				"Wallet comm method \"{}\" does not exist.",
				method
			))
			.into());
		}
	})
}
