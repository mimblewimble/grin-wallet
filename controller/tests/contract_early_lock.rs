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

//! Test a wallet doing contract early lock when using --add-outputs
// #[macro_use]
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate log;

use grin_wallet_libwallet as libwallet;

use grin_core::consensus;
use grin_core::core::transaction::{Input, OutputFeatures};
use libwallet::contract::my_fee_contribution;
use libwallet::contract::types::{ContractNewArgsAPI, ContractSetupArgsAPI, OwnCommitmentStatus};
use libwallet::{OutputStatus, Slate, SlateState};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};
use std::path::PathBuf;

/// contract new with --add-outputs
fn contract_early_lock_tx_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// create two wallets and mine 5 blocks in each
	let (wallets, _chain, stopper, _bh) =
		create_wallets(vec![vec![("default", 5)], vec![("default", 5)]], test_dir).unwrap();
	let send_wallet = wallets[0].0.clone();
	let send_mask = wallets[0].1.as_ref();
	let recv_wallet = wallets[1].0.clone();
	let recv_mask = wallets[1].1.as_ref();

	// Confirm all our outputs are unspent
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, commits) = api.retrieve_outputs(m, true, false, None)?;
			for commit in commits.iter() {
				assert_eq!(commit.output.status, OutputStatus::Unspent);
			}
			Ok(())
		},
	)?;

	let mut slate = Slate::blank(0, false); // this gets overriden below

	// Call contract 'new' with --add-outputs
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			// Send wallet inititates a standard transaction with --send=80
			let args = &ContractNewArgsAPI {
				setup_args: ContractSetupArgsAPI {
					selection_args: common::contract_selection_args(),
					net_change: Some(-80_000_000_000),
					num_participants: 2,
					add_outputs: true,
					..Default::default()
				},
				..Default::default()
			};
			slate = api.contract_new(m, args)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard1);

	// Assert we locked 2 inputs and prepared an unconfirmed change output
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, commits) = api.retrieve_outputs(m, true, false, None)?;
			// we locked the first two coinbase outputs
			assert_eq!(commits[0].output.status, OutputStatus::Locked);
			assert_eq!(commits[1].output.status, OutputStatus::Locked);
			// we added a new unconfirmed change output
			let new_output_idx = commits.len() - 1;
			assert_eq!(
				commits[new_output_idx].output.status,
				OutputStatus::Unconfirmed
			);
			assert_eq!(
				commits[new_output_idx].output.value,
				2 * consensus::REWARD - 80_000_000_000 - my_fee_contribution(2, 1, 1, 2)?.fee()
			);
			Ok(())
		},
	)?;

	// The receiver signs without seeing the sender's locked commitments.
	wallet::controller::owner_single_use(
		recv_wallet.clone(),
		recv_mask,
		PathBuf::from(test_dir),
		|api, m| {
			slate = api.contract_sign(
				m,
				&slate,
				&ContractSetupArgsAPI {
					selection_args: common::contract_selection_args(),
					net_change: Some(80_000_000_000),
					..Default::default()
				},
			)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard2);

	// Even a commitment reserved for this contract must not be present before we add it.
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, outputs) = api.retrieve_outputs(m, false, false, None)?;
			let output = outputs
				.iter()
				.find(|output| output.output.status == OutputStatus::Locked)
				.expect("sender has a locked contract input");
			let features = if output.output.is_coinbase {
				OutputFeatures::Coinbase
			} else {
				OutputFeatures::Plain
			};
			let mut changed = slate.clone();
			changed.tx = Some(
				changed
					.tx_or_err()?
					.clone()
					.with_input(Input::new(features, output.commit)),
			);
			let view = api.contract_view(m, &changed)?;
			assert_eq!(
				view.own_commitment_status,
				OwnCommitmentStatus::UnexpectedInput
			);
			let err = api
				.contract_sign(m, &changed, &ContractSetupArgsAPI::default())
				.unwrap_err();
			match err {
				libwallet::Error::GenericError(message) => assert_eq!(
					message,
					"Contract slate contains an unexpected input commitment from this wallet"
				),
				err => panic!("unexpected error: {}", err),
			}
			Ok(())
		},
	)?;

	// The sender adds the reserved commitments and completes the contract.
	wallet::controller::owner_single_use(
		send_wallet.clone(),
		send_mask,
		PathBuf::from(test_dir),
		|api, m| {
			slate = api.contract_sign(m, &slate, &ContractSetupArgsAPI::default())?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard3);

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));

	Ok(())
}

#[test]
fn wallet_contract_early_lock_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_early_lock_tx";
	setup(test_dir);
	contract_early_lock_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
