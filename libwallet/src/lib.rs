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

//! Higher level wallet functions which can be used by callers to operate
//! on the wallet, as well as helpers to invoke and instantiate wallets
//! and listeners

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

use grin_wallet_config as config;
use grin_wallet_util::grin_core;
use grin_wallet_util::grin_keychain;
use grin_wallet_util::grin_store;
use grin_wallet_util::grin_util;

use grin_wallet_util as util;

use blake2_rfc as blake2;

use failure;
extern crate failure_derive;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

extern crate strum;
#[macro_use]
extern crate strum_macros;

pub mod address;
pub mod api_impl;
mod error;
mod internal;
mod slate;
pub mod slate_versions;
pub mod slatepack;
mod types;

pub use crate::error::{Error, ErrorKind};
pub use crate::slate::{ParticipantData, Slate, SlateState, TxFlow};
pub use crate::slate_versions::v4::sig_is_blank;
pub use crate::slate_versions::{
	SlateVersion, VersionedBinSlate, VersionedCoinbase, VersionedSlate, CURRENT_SLATE_VERSION,
	GRIN_BLOCK_HEADER_VERSION,
};
pub use crate::slatepack::{
	Slatepack, SlatepackAddress, SlatepackArmor, SlatepackBin, Slatepacker, SlatepackerArgs,
};
pub use api_impl::owner_updater::StatusMessage;
pub use api_impl::types::{
	BlockFees, InitTxArgs, InitTxSendArgs, IssueInvoiceTxArgs, NodeHeightResult,
	OutputCommitMapping, PaymentProof, VersionInfo,
};
pub use internal::scan::scan;
pub use slate_versions::ser as dalek_ser;
pub use types::{
	AcctPathMapping, BlockIdentifier, CbData, Context, NodeClient, NodeVersionInfo, OutputData,
	OutputStatus, ScannedBlockInfo, StoredProofInfo, TxLogEntry, TxLogEntryType, TxWrapper,
	WalletBackend, WalletInfo, WalletInitStatus, WalletInst, WalletLCProvider, WalletOutputBatch,
};

/// Helper for taking a lock on the wallet instance
#[macro_export]
macro_rules! wallet_lock {
	($wallet_inst: expr, $wallet: ident) => {
		let inst = $wallet_inst.clone();
		let mut w_lock = inst.lock();
		let w_provider = w_lock.lc_provider()?;
		let $wallet = w_provider.wallet_inst()?;
	};
}
