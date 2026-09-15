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

//! Test contract revoke, including when a different account is active than the
//! one that contributed (and locked) the inputs.
// #[macro_use]
extern crate grin_wallet_api as api;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate log;

use grin_wallet_libwallet as libwallet;

use libwallet::contract::types::{ContractNewArgsAPI, ContractRevokeArgsAPI, ContractSetupArgsAPI};
use libwallet::{OutputStatus, Slate, SlateState};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallets, setup};
use std::path::{Path, PathBuf};

/// Revoke the transaction in the requested account when two accounts share a transaction id.
fn contract_revoke_other_account_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// Both accounts are funded equally, so their contract transactions get the same id.
	let (wallets, _chain, stopper, _bh) =
		create_wallets(vec![vec![("default", 4), ("account1", 4)]], test_dir).unwrap();
	let wallet1 = wallets[0].0.clone();
	let mask1 = wallets[0].1.as_ref();

	// Create an early-locked contract in the default account.
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			api.contract_new(
				m,
				&ContractNewArgsAPI {
					setup_args: ContractSetupArgsAPI {
						selection_args: common::contract_selection_args(),
						net_change: Some(-1_000_000_000),
						num_participants: 2,
						add_outputs: true,
						..Default::default()
					},
					..Default::default()
				},
			)?;
			Ok(())
		},
	)?;
	let mut default_tx_id = 0;
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
			default_tx_id = txs.last().unwrap().id;
			Ok(())
		},
	)?;

	// Create another early-locked contract in account1.
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account1")?;
	}
	let mut slate = Slate::blank(0, true);
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let args = &ContractNewArgsAPI {
				setup_args: ContractSetupArgsAPI {
					selection_args: common::contract_selection_args(),
					net_change: Some(-1_000_000_000),
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

	// Grab the tx id and confirm an input is locked under account1.
	let mut tx_id = 0;
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
			tx_id = txs.last().unwrap().id;
			let (_, outs) = api.retrieve_outputs(m, true, false, None)?;
			assert!(outs.iter().any(|o| o.output.status == OutputStatus::Locked));
			Ok(())
		},
	)?;
	assert_eq!(tx_id, default_tx_id);

	// Switch the active account to "default" — different from the inputs' account.
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("default")?;
	}

	// Revoke account1 while the default account is active.
	let mut revoked = None;
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			revoked = api.contract_revoke(
				m,
				&ContractRevokeArgsAPI {
					tx_id,
					src_acct_name: Some("account1".to_string()),
				},
			)?;
			Ok(())
		},
	)?;
	assert!(
		revoked.is_some(),
		"revoke should produce a self-spend slate"
	);

	// The default account's transaction is still locked.
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, outs) = api.retrieve_outputs(m, true, false, None)?;
			assert!(outs.iter().any(|o| {
				o.output.status == OutputStatus::Locked
					&& o.output.tx_log_entry == Some(default_tx_id)
			}));
			Ok(())
		},
	)?;

	// Back on account1: the original tx is cancelled and no input is left locked.
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account1")?;
	}
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let query = libwallet::RetrieveTxQueryArgs {
				exclude_cancelled: Some(false),
				..Default::default()
			};
			let (_, txs) = api.retrieve_txs(m, true, None, None, Some(query))?;
			let tx = txs.iter().find(|t| t.id == tx_id).unwrap();
			assert!(
				format!("{:?}", tx.tx_type).contains("Cancelled"),
				"original tx should be cancelled, was {:?}",
				tx.tx_type
			);
			Ok(())
		},
	)?;

	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_contract_revoke_other_account() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/contract_revoke_other_account";
	setup(test_dir);
	contract_revoke_other_account_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}

/// A revoke interrupted right after the cancel (inputs already unlocked, no self-spend
/// built yet) must be resumable: a second revoke detects the now-Unspent inputs that are
/// still tagged with the cancelled tx and still produces the self-spend, rather than
/// silently doing nothing.
fn contract_revoke_resume_impl(test_dir: &'static str) -> Result<(), wallet::Error> {
	let (wallets, _chain, stopper, _bh) =
		create_wallets(vec![vec![("default", 4)]], test_dir).unwrap();
	let wallet1 = wallets[0].0.clone();
	let mask1 = wallets[0].1.as_ref();
	let args = ContractNewArgsAPI {
		setup_args: ContractSetupArgsAPI {
			selection_args: common::contract_selection_args(),
			net_change: Some(-1_000_000_000),
			num_participants: 2,
			add_outputs: true,
			..Default::default()
		},
		..Default::default()
	};

	// Send (with early lock), locking an input under the contract tx.
	let mut slate = Slate::blank(0, true);
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			slate = api.contract_new(m, &args)?;
			Ok(())
		},
	)?;
	assert_eq!(slate.state, SlateState::Standard1);
	{
		wallet_inst!(wallet1, w);
		let retried =
			libwallet::contract::new(w, mask1, &args.setup_args, args.ttl_blocks, Some(slate.id))?;
		assert_eq!(retried.id, slate.id);
		assert_eq!(retried.fee_fields, slate.fee_fields);
		assert_eq!(
			retried.participant_data[0].public_nonce,
			slate.participant_data[0].public_nonce
		);
		assert_eq!(
			retried.participant_data[0].public_blind_excess,
			slate.participant_data[0].public_blind_excess
		);
	}

	let mut tx_id = 0;
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
			tx_id = txs.last().unwrap().id;
			Ok(())
		},
	)?;

	// Simulate a revoke that crashed right after cancelling: cancel the tx (inputs become
	// Unspent, still tagged with tx_id) but do NOT build the self-spend.
	wallet::controller::owner_single_use(
		wallet1.clone(),
		mask1,
		PathBuf::from(test_dir),
		|api, m| {
			api.cancel_tx(m, Some(tx_id), None)?;
			let (_, outs) = api.retrieve_outputs(m, true, false, None)?;
			assert!(
				outs.iter().any(|o| o.output.status == OutputStatus::Unspent
					&& o.output.tx_log_entry == Some(tx_id)),
				"input should be Unspent but still tagged with the cancelled tx"
			);
			Ok(())
		},
	)?;

	// Resume through the command path and write the self-spend to the requested file.
	let outfile = format!("{}/revoke.slatepack", test_dir);
	let mut owner = api::Owner::new(wallet1.clone(), None, PathBuf::from(test_dir));
	wallet::command::contract_revoke(
		&mut owner,
		mask1,
		wallet::command::ContractRevokeArgs {
			tx_id,
			outfile: Some(outfile.clone()),
		},
	)?;
	assert!(
		Path::new(&outfile).is_file(),
		"interrupted revoke should resume and produce a self-spend slate"
	);

	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn wallet_contract_revoke_resume() -> Result<(), wallet::Error> {
	let test_dir = "test_output/contract_revoke_resume";
	setup(test_dir);
	contract_revoke_resume_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
