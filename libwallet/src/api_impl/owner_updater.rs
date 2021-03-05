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

//! A threaded persistent Updater that can be controlled by a grin wallet
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::Mutex;

use crate::api_impl::owner;
use crate::types::NodeClient;
use crate::Error;
use crate::{WalletInst, WalletLCProvider};

const MESSAGE_QUEUE_MAX_LEN: usize = 10_000;

/// Update status messages which can be returned to listening clients
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StatusMessage {
	/// Wallet is performing a regular update, matching the UTXO set against
	/// current wallet outputs
	UpdatingOutputs(String),
	/// Wallet is updating transactions, potentially retrieving transactions
	/// by kernel if needed
	UpdatingTransactions(String),
	/// Warning that the wallet is about to perform a full UTXO scan
	FullScanWarn(String),
	/// Status and percentage complete messages returned during the
	/// scanning process
	Scanning(String, u8),
	/// UTXO scanning is complete
	ScanningComplete(String),
	/// Warning of issues that may have occured during an update
	UpdateWarning(String),
}

/// Helper function that starts a simple log thread for updater messages
pub fn start_updater_log_thread(
	rx: Receiver<StatusMessage>,
	queue: Arc<Mutex<Vec<StatusMessage>>>,
) -> Result<(), Error> {
	let _ = thread::Builder::new()
		.name("wallet-updater-status".to_string())
		.spawn(move || {
			while let Ok(m) = rx.recv() {
				// save to our message queue to be read by other consumers
				{
					let mut q = queue.lock();
					q.insert(0, m.clone());
					while q.len() > MESSAGE_QUEUE_MAX_LEN {
						q.pop();
					}
				}
				match m {
					StatusMessage::UpdatingOutputs(s) => debug!("{}", s),
					StatusMessage::UpdatingTransactions(s) => debug!("{}", s),
					StatusMessage::FullScanWarn(s) => warn!("{}", s),
					StatusMessage::Scanning(s, m) => {
						debug!("{}", s);
						warn!("Scanning - {}% complete", m);
					}
					StatusMessage::ScanningComplete(s) => warn!("{}", s),
					StatusMessage::UpdateWarning(s) => warn!("{}", s),
				}
			}
		})?;

	Ok(())
}

/// Handles and launches a background update thread
pub struct Updater<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	is_running: Arc<AtomicBool>,
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
		is_running: Arc<AtomicBool>,
	) -> Self {
		is_running.store(false, Ordering::Relaxed);
		Updater {
			wallet_inst,
			is_running,
		}
	}

	/// Start the updater at the given frequency
	pub fn run(
		&self,
		frequency: Duration,
		keychain_mask: Option<SecretKey>,
		status_send_channel: &Option<Sender<StatusMessage>>,
	) -> Result<(), Error> {
		self.is_running.store(true, Ordering::Relaxed);
		loop {
			let wallet_opened = {
				let mut w_lock = self.wallet_inst.lock();
				let w_provider = w_lock.lc_provider()?;
				w_provider.wallet_inst().is_ok()
			};
			// Business goes here
			if wallet_opened {
				owner::update_wallet_state(
					self.wallet_inst.clone(),
					(&keychain_mask).as_ref(),
					status_send_channel,
					false,
				)?;
			}
			if !self.is_running.load(Ordering::Relaxed) {
				break;
			}
			thread::sleep(frequency);
		}
		Ok(())
	}
}
