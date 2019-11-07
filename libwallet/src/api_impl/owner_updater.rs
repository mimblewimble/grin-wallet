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

//! A threaded persistent Updater that can be controlled by a grin wallet
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::sync::mpsc::{Sender, Receiver};

use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::{Mutex, StopState};

use crate::api_impl::owner;
use crate::types::NodeClient;
use crate::{Error, ErrorKind};
use crate::{WalletInst, WalletLCProvider};

#[derive(Debug)]
pub enum StatusMessage {
	UpdatingOutputs(String),
	UpdatingTransactions(String),
	FullScanWarn(String),
	Scanning(String, u8),
	ScanningComplete(String),
}

/// Helper function that starts a simple log thread for updater messages
pub fn start_updater_log_thread(rx: Receiver<StatusMessage>) -> Result<(), Error> {
	let _ = thread::Builder::new()
		.name("wallet-updater-status".to_string())
		.spawn(move || {
			loop {
				while let Ok(m) = rx.try_recv() {
					match m {
						StatusMessage::UpdatingOutputs(s) => debug!("{}", s),
						StatusMessage::UpdatingTransactions(s) => debug!("{}", s),
						StatusMessage::FullScanWarn(s) => warn!("{}", s),
						StatusMessage::Scanning(s, m) => {
							debug!("{}", s);
							warn!("Scanning - {}% complete", m);
						},
						StatusMessage::ScanningComplete(s) => warn!("{}", s)
					}
				}
				thread::sleep(Duration::from_millis(500));
			}
		})?;

	Ok(())
}

pub struct Updater<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	stop_state: Arc<StopState>,
}

impl<'a, L, C, K> Updater<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// create a new updater
	pub fn new(
		wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
		stop_state: Arc<StopState>,
	) -> Self {
		Updater {
			wallet_inst,
			stop_state,
		}
	}

	/// Start the updater at the given frequency
	pub fn run(&self, 
		frequency: Duration, 
		keychain_mask: Option<SecretKey>,
		status_send_channel: &Option<Sender<StatusMessage>>,
		) -> Result<(), Error> {
		loop {
			if self.stop_state.is_paused() {
				thread::sleep(Duration::from_secs(1));
				continue;
			}
			// Business goes here
			owner::update_wallet_state(self.wallet_inst.clone(), (&keychain_mask).as_ref(), status_send_channel, false)?;
			if self.stop_state.is_stopped() {
				break;
			}
			thread::sleep(frequency);
		}
		Ok(())
	}
}
