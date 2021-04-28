// Copyright 2021 The Grin Developers
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

//! Test wallets performing an atomic swap
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;

use grin_wallet_libwallet as libwallet;
use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_keychain::{Keychain, SwitchCommitmentType};

use impls::test_framework::{self, LocalWalletClient};
use libwallet::{InitTxArgs, Slate, SlateState, TxFlow};
use std::thread;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

/// atomic swap impl
fn atomic_tx_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();

	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		true
	);
	let mask1 = (&mask1_i).as_ref();
	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		true
	);
	let mask2 = (&mask2_i).as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::REWARD;

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "mining")?;
		api.create_account_path(m, "listener")?;
		Ok(())
	})?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Sanity check wallet 1 contents
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward);
		Ok(())
	})?;

	let mut slate = Slate::blank(2, TxFlow::Atomic);

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// Wallet 1 inititates the main atomic swap transaction
		let args = InitTxArgs {
			amount: 10,
			..Default::default()
		};
		slate = api.init_atomic_swap(m, args)?;
		api.tx_lock_outputs(m, &slate)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic1);

	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
		slate = api.receive_atomic_tx(&slate, None, None)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic2);

	// Get the receiver's atomic secret created in `receive_atomic_tx`
	// This is one of the keys locking the multisig transaction on the other chain
	// Only revealed if the refund transaction is fully signed + posted
	let atomic_secret = {
		let mut w_lock = wallet2.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let atomic_id = w.get_used_atomic_id(&slate.id)?;
		w.keychain(mask2).unwrap().derive_key(
			slate.amount,
			&atomic_id,
			SwitchCommitmentType::Regular,
		)?
	};

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1.clone(), None, |api, m| {
		// wallet 1 creates the first partial signature on the atomic swap
		slate = api.countersign_atomic_swap(&slate, m)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic3);

	// wallet 2 finalizes and posts the atomic swap
	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
		slate = api.finalize_tx(&slate, false)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic4);

	let rec_atomic_secret = {
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let tx = slate.tx_or_err()?;
		libwallet::recover_atomic_secret(&mut **w, mask1, &slate, &tx)?
	};

	assert_eq!(rec_atomic_secret, atomic_secret);

	Ok(())
}

/// atomic swap refund impl
fn atomic_refund_tx_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();

	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		true
	);
	let mask1 = (&mask1_i).as_ref();
	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		true
	);
	let mask2 = (&mask2_i).as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::REWARD;

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "mining")?;
		api.create_account_path(m, "listener")?;
		Ok(())
	})?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Sanity check wallet 1 contents
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward);
		Ok(())
	})?;

	let mut slate = Slate::blank(2, TxFlow::Atomic);

	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2.clone(), None, |api, m| {
		// Wallet 2 inititates the refund atomic swap transaction
		let args = InitTxArgs {
			amount: 10,
			late_lock: Some(true),
			..Default::default()
		};
		let derive_path = 0;
		slate = api.init_atomic_swap(m, args, derive_path)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic1);

	wallet::controller::foreign_single_use(wallet1.clone(), mask1_i.clone(), |api| {
		slate = api.receive_atomic_tx(&slate, None, None)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic2);

	// Get the sender's atomic secret created in `receive_atomic_tx`
	// This is one of the keys locking the multisig transaction on the other chain
	// Only revealed if the refund transaction is fully signed + posted
	let atomic_secret = {
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let atomic_id = w.get_used_atomic_id(&slate.id)?;
		w.keychain(mask1)?
			.derive_key(slate.amount, &atomic_id, SwitchCommitmentType::Regular)?
	};

	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2.clone(), None, |api, m| {
		// wallet 1 creates the first partial signature on the atomic swap
		slate = api.countersign_atomic_swap(&slate, m)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic3);

	// wallet 2 finalizes and posts the atomic swap
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1.clone(), None, |api, m| {
		api.tx_lock_outputs(m, &slate)?;
		slate = api.finalize_atomic_swap(m, &slate)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic4);

	let rec_atomic_secret = {
		let mut w_lock = wallet2.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let tx = slate.tx_or_err()?;
		libwallet::recover_atomic_secret(&mut **w, mask2, &slate, &tx)?
	};

	assert_eq!(rec_atomic_secret, atomic_secret);

	Ok(())
}

/// atomic swap end-to-end impl
fn atomic_end_to_end_tx_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();

	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy,
		true
	);
	let mask1 = (&mask1_i).as_ref();
	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy,
		true
	);
	let mask2 = (&mask2_i).as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// few values to keep things shorter
	let reward = core::consensus::REWARD;

	// add some accounts
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		api.create_account_path(m, "mining")?;
		api.create_account_path(m, "listener")?;
		Ok(())
	})?;

	// Get some mining done
	{
		wallet_inst!(wallet1, w);
		w.set_parent_key_id_by_name("mining")?;
	}
	let bh = 10u64;
	let _ =
		test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, bh as usize, false);

	// Sanity check wallet 1 contents
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		let (wallet1_refreshed, wallet1_info) = api.retrieve_summary_info(m, true, 1)?;
		assert!(wallet1_refreshed);
		assert_eq!(wallet1_info.last_confirmed_height, bh);
		assert_eq!(wallet1_info.total, bh * reward);
		Ok(())
	})?;

	let mut slate = Slate::blank(2, TxFlow::Atomic);

	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2.clone(), None, |api, m| {
		// Wallet 2 inititates the refund atomic swap transaction
		let args = InitTxArgs {
			amount: 10,
			late_lock: Some(true),
			..Default::default()
		};
		let derive_path = 0;
		slate = api.init_atomic_swap(m, args, derive_path)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic1);

	wallet::controller::foreign_single_use(wallet1.clone(), mask1_i.clone(), |api| {
		slate = api.receive_atomic_tx(&slate, None, None)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic2);

	// Get the sender's atomic secret created in `receive_atomic_tx`
	// This is one of the keys locking the multisig transaction on the other chain
	// Only revealed if the refund transaction is fully signed + posted
	let _atomic_secret = {
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let id = w.get_used_atomic_id(&slate.id)?;
		w.keychain(mask1)?
			.derive_key(slate.amount, &id, SwitchCommitmentType::Regular)?
	};

	wallet::controller::owner_single_use(Some(wallet2.clone()), mask2.clone(), None, |api, m| {
		// wallet 1 creates the first partial signature on the atomic swap
		slate = api.countersign_atomic_swap(&slate, m)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic3);

	/* Don't finalize and lock funds, since this locks the outputs used for the main transaction
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1.clone(), None, |api, m| {
		api.tx_lock_outputs(m, &slate)?;
		slate = api.finalize_atomic_swap(m, &slate)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic4);

	let rec_atomic_secret = {
		let mut w_lock = wallet2.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let tx = slate.tx_or_err()?;
		libwallet::recover_atomic_secret(&mut **w, mask2, &slate, &tx)?
	};

	assert_eq!(rec_atomic_secret, atomic_secret);
	*/

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |api, m| {
		// Wallet 1 inititates the main atomic swap transaction
		let args = InitTxArgs {
			amount: 10,
			..Default::default()
		};
		slate = api.init_atomic_swap(m, args)?;
		api.tx_lock_outputs(m, &slate)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic1);

	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
		slate = api.receive_atomic_tx(&slate, None, None)?;
		Ok(())
	})?;

	// Create atomic secret, this is created during the refund transaction
	// This is one of the keys locking the multisig transaction on the other chain
	let atomic_secret = {
		let mut w_lock = wallet2.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let atomic_id = w.get_used_atomic_id(&slate.id)?;
		w.keychain(mask2)?
			.derive_key(slate.amount, &atomic_id, SwitchCommitmentType::Regular)?
	};

	assert_eq!(slate.state, SlateState::Atomic2);

	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1.clone(), None, |api, m| {
		// wallet 1 creates the first partial signature on the atomic swap
		slate = api.countersign_atomic_swap(&slate, m)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic3);

	// wallet 2 finalizes and posts the atomic swap
	wallet::controller::foreign_single_use(wallet2.clone(), mask2_i.clone(), |api| {
		slate = api.finalize_tx(&slate, false)?;
		Ok(())
	})?;
	assert_eq!(slate.state, SlateState::Atomic4);

	let rec_atomic_secret = {
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let tx = slate.tx_or_err()?;
		libwallet::recover_atomic_secret(&mut **w, mask1, &slate, &tx)?
	};

	assert_eq!(rec_atomic_secret, atomic_secret);

	Ok(())
}

#[test]
fn wallet_atomic_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/atomic_tx";
	setup(test_dir);
	atomic_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn wallet_atomic_refund_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/atomic_refund_tx";
	setup(test_dir);
	atomic_refund_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn wallet_atomic_end_to_end_tx() -> Result<(), libwallet::Error> {
	let test_dir = "test_output/atomic_end_to_end_tx";
	setup(test_dir);
	atomic_end_to_end_tx_impl(test_dir)?;
	clean_output_dir(test_dir);
	Ok(())
}
