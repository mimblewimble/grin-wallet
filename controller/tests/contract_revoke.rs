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

/// Revoke a contract while a different account is active than the one that locked
/// the inputs. The cancel + self-spend must still target the inputs' account.
fn contract_revoke_other_account_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// One wallet: empty "default" account plus a funded "account1".
	let (wallets, _chain, stopper, _bh) = create_wallets(
		vec![vec![("default", 0), ("account1", 4)]],
		test_dir,
	)
	.unwrap();
	let wallet1 = wallets[0].0.clone();
	let mask1 = wallets[0].1.as_ref();

	// Send (with early lock) from account1, locking one of its inputs.
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account1")?;
	}
	let mut slate = Slate::blank(0, true);
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let args = &ContractNewArgsAPI {
			setup_args: ContractSetupArgsAPI {
				net_change: Some(-1_000_000_000),
				num_participants: 2,
				add_outputs: true,
				..Default::default()
			},
			..Default::default()
		};
		slate = api.contract_new(m, args)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Standard1);

	// Grab the tx id and confirm an input is locked under account1.
	let mut tx_id = 0;
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (_, txs) = api.retrieve_txs(m, true, None, None, None)?;
		tx_id = txs.last().unwrap().id;
		let (_, outs) = api.retrieve_outputs(m, true, false, None)?;
		assert!(outs.iter().any(|o| o.output.status == OutputStatus::Locked));
		Ok(())
	})?;

	// Switch the active account to "default" — different from the inputs' account.
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("default")?;
	}

	// Revoke. With the active account wrong, this must still cancel + self-spend the
	// account1 transaction (it derives the account from the locked input).
	let mut revoked = None;
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		revoked = api.contract_revoke(m, &ContractRevokeArgsAPI { tx_id })?;
		Ok(())
	})?;
	assert!(revoked.is_some(), "revoke should produce a self-spend slate");

	// Back on account1: the original tx is cancelled and no input is left locked.
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("account1")?;
	}
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
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
	})?;

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
