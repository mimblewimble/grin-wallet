// Copyright 2022 The Grin Developers
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

//! Test a wallet doing contract self-spend flow
// #[macro_use]
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate log;

use grin_wallet_libwallet as libwallet;

use impls::test_framework::{self};
use libwallet::contract::my_fee_contribution;
use libwallet::contract::types::{ContractNewArgsAPI, ContractSetupArgsAPI};
use libwallet::{Slate, SlateState, TxLogEntryType};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};

/// contract self-spend flow
fn contract_self_spend_cancel_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// create a single wallet and mine 4 blocks
	let (wallets, chain, stopper, mut bh) =
		create_wallets(vec![vec![("default", 4)]], test_dir).unwrap();
	let send_wallet = wallets[0].0.clone();
	let send_mask = wallets[0].1.as_ref();

	let mut slate = Slate::blank(0, true); // this gets overriden below

	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		// Send wallet initiates a standard transaction with --send=0
		let args = &ContractNewArgsAPI {
			setup_args: ContractSetupArgsAPI {
				net_change: Some(0),
				num_participants: 1,
				..Default::default()
			},
			..Default::default()
		};
		slate = api.contract_new(m, args)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Standard1);

	// Send wallet finalizes and posts
	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		api.cancel_tx(m, None, Some(slate.id))?;
		Ok(())
	})?;

	// Assert tx log has been cancelled
	wallet::controller::owner_single_use(Some(send_wallet.clone()), send_mask, None, |api, m| {
		let query_args = libwallet::RetrieveTxQueryArgs {
			exclude_cancelled: Some(false),
			..Default::default()
		};
		let (refreshed, txs) = api.retrieve_txs(m, true, None, None, Some(query_args))?;
		assert!(refreshed);
		assert_eq!(txs.len() as u64, 5); // send wallet didn't mine 4 blocks and made 1 tx
		let tx_log = txs[4].clone(); // TODO: why -5 and not -4?
		assert_eq!(tx_log.tx_type, TxLogEntryType::TxSelfSpendCancelled);
		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn wallet_contract_self_spend_cancel() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_self_spend_cancel";
	setup(test_dir);
	contract_self_spend_cancel_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
