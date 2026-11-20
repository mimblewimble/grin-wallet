// Copyright 2026 The Grin Developers
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

//! Tests for the opt-in stateless receive mode of the Foreign API
#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;

use grin_core as core;
use grin_keychain as keychain;
use grin_util as util;

use self::core::global;
use self::keychain::{ExtKeychain, Keychain};
use self::libwallet::{
	InitTxArgs, OutputStatus, Slate, SlateState, StatelessReceiveConfig, TxLogEntryType,
};
use impls::test_framework::{self, LocalWalletClient};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use util::ZeroingString;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

const STATELESS: Option<StatelessReceiveConfig> = Some(StatelessReceiveConfig {
	enabled: true,
	min_amount: None,
});

fn stateless_receive_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	let seed_phrase = "affair pistol cancel crush garment candy ancient flag work \
	                   market crush dry stand focus mutual weapon offer ceiling rival turn team spring \
	                   where swift";
	let seed_phrase = Some(ZeroingString::from(seed_phrase));
	let no_seed: Option<ZeroingString> = None;

	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();
	let stopper = wallet_proxy.running.clone();

	// sender
	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		no_seed,
		&mut wallet_proxy,
		false,
		api1
	);
	let mask1 = (&mask1_i).as_ref();
	// stateless recipient
	create_wallet_and_add!(
		client2,
		wallet2,
		mask2_i,
		test_dir,
		"wallet2",
		seed_phrase,
		&mut wallet_proxy,
		false,
		api2
	);
	let mask2 = (&mask2_i).as_ref();
	// same seed as the recipient, restored from the chain later on
	create_wallet_and_add!(
		client3,
		wallet3,
		mask3_i,
		test_dir,
		"wallet3",
		seed_phrase,
		&mut wallet_proxy,
		false,
		api3
	);
	let mask3 = (&mask3_i).as_ref();
	let _ = (&client1, &client2, &client3);

	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	api2.create_account_path(mask2, "named")?;
	let default_acct = ExtKeychain::derive_key_id(2, 0, 0, 0, 0);
	let named_acct = ExtKeychain::derive_key_id(2, 1, 0, 0, 0);

	let cm = global::coinbase_maturity();
	let _ = test_framework::award_blocks_to_wallet(
		&chain,
		wallet1.clone(),
		mask1,
		cm as usize + 5,
		false,
	);

	let amount = 2_000_000_000;
	let send_args = InitTxArgs {
		src_acct_name: None,
		amount,
		minimum_confirmations: 1,
		max_outputs: 500,
		num_change_outputs: 1,
		selection_strategy_is_use_all: false,
		..Default::default()
	};

	// State of the recipient as far as the database is concerned
	macro_rules! recipient_is_empty {
		() => {{
			let (_, txs) = api2.retrieve_txs(mask2, false, None, None, None)?;
			assert!(txs.is_empty(), "unexpected tx log entries: {:?}", txs);
			for acct in &["default", "named"] {
				api2.set_active_account(mask2, acct)?;
				let (_, outputs) = api2.retrieve_outputs(mask2, true, false, None)?;
				assert!(outputs.is_empty(), "unexpected outputs: {:?}", outputs);
			}
			api2.set_active_account(mask2, "default")?;
			wallet_inst!(wallet2, w);
			assert_eq!(w.current_child_index(&default_acct)?, 0);
			assert_eq!(w.current_child_index(&named_acct)?, 0);
		}};
	}

	// 1) An exchange the sender never finalizes leaves nothing behind
	{
		let slate_i = api1.init_send_tx(mask1, send_args.clone())?;
		assert_eq!(slate_i.state, SlateState::Standard1);

		let mut responses: Vec<Slate> = vec![];
		wallet::controller::foreign_single_use(
			wallet2.clone(),
			PathBuf::from(test_dir),
			mask2_i.clone(),
			|api| {
				api.set_stateless_receive(STATELESS);
				// with no state there is no duplicate check, each call builds
				// a response around a fresh output
				responses.push(api.receive_tx(&slate_i, None, None)?);
				responses.push(api.receive_tx(&slate_i, None, None)?);

				// requests below the configured minimum are refused outright
				api.set_stateless_receive(Some(StatelessReceiveConfig {
					enabled: true,
					min_amount: Some(amount + 1),
				}));
				assert_eq!(
					api.receive_tx(&slate_i, None, None).unwrap_err(),
					libwallet::Error::ReceiveAmountTooLow {
						amount,
						minimum: amount + 1
					}
				);

				// as are the requests the stateful path refuses
				api.set_stateless_receive(STATELESS);
				let mut zero_amount = slate_i.clone();
				zero_amount.amount = 0;
				assert_eq!(
					api.receive_tx(&zero_amount, None, None).unwrap_err(),
					libwallet::Error::InvalidAmount
				);
				let mut wrong_state = slate_i.clone();
				wrong_state.state = SlateState::Invoice1;
				assert_eq!(
					api.receive_tx(&wrong_state, None, None).unwrap_err(),
					libwallet::Error::SlateState
				);
				Ok(())
			},
		)?;

		assert_eq!(responses.len(), 2);
		let commits: Vec<_> = responses
			.iter()
			.map(|s| {
				assert_eq!(s.state, SlateState::Standard2);
				let tx = s.tx_or_err().unwrap();
				assert_eq!(tx.outputs().len(), 1);
				tx.outputs()[0].commitment()
			})
			.collect();
		assert_ne!(commits[0], commits[1]);

		recipient_is_empty!();

		// the sender gives up (it locked nothing, so has nothing to cancel)
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
		let (refreshed, info) = api2.retrieve_summary_info(mask2, true, 1)?;
		assert!(refreshed);
		assert_eq!(info.total, 0);
		recipient_is_empty!();
	}

	// 2) A finalized exchange shows up once it is on chain
	let commit_default = {
		let slate_i = api1.init_send_tx(mask1, send_args.clone())?;
		let mut slate = Slate::blank(2, false);
		wallet::controller::foreign_single_use(
			wallet2.clone(),
			PathBuf::from(test_dir),
			mask2_i.clone(),
			|api| {
				api.set_stateless_receive(STATELESS);
				slate = api.receive_tx(&slate_i, None, None)?;
				Ok(())
			},
		)?;
		assert_eq!(slate.state, SlateState::Standard2);
		let commit = slate.tx_or_err()?.outputs()[0].commitment();

		api1.tx_lock_outputs(mask1, &slate)?;
		let slate = api1.finalize_tx(mask1, &slate)?;
		assert_eq!(slate.state, SlateState::Standard3);

		// still nothing until the transaction is mined
		recipient_is_empty!();

		api1.post_tx(mask1, &slate, false)?;
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
		commit
	};

	// and into a named account
	let commit_named = {
		let slate_i = api1.init_send_tx(mask1, send_args.clone())?;
		let mut slate = Slate::blank(2, false);
		wallet::controller::foreign_single_use(
			wallet2.clone(),
			PathBuf::from(test_dir),
			mask2_i.clone(),
			|api| {
				api.set_stateless_receive(STATELESS);
				slate = api.receive_tx(&slate_i, Some("named"), None)?;
				Ok(())
			},
		)?;
		let commit = slate.tx_or_err()?.outputs()[0].commitment();
		api1.tx_lock_outputs(mask1, &slate)?;
		let slate = api1.finalize_tx(mask1, &slate)?;
		api1.post_tx(mask1, &slate, false)?;
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);
		commit
	};

	// What a wallet holding the recipient's seed should see, whether it took
	// part in the exchange or not
	macro_rules! check_recipient {
		($api:ident, $mask:ident, $wallet:ident) => {{
			let accounts = $api.accounts($mask)?;
			let mut paths: Vec<_> = accounts.iter().map(|a| a.path.clone()).collect();
			paths.sort();
			assert_eq!(
				paths,
				vec![default_acct.clone(), named_acct.clone()],
				"accounts: {:?}",
				accounts
			);
			for (acct, acct_path, commit) in &[
				("default", &default_acct, &commit_default),
				(
					accounts
						.iter()
						.find(|a| a.path == named_acct)
						.map(|a| a.label.as_str())
						.unwrap(),
					&named_acct,
					&commit_named,
				),
			] {
				$api.set_active_account($mask, acct)?;
				let (refreshed, info) = $api.retrieve_summary_info($mask, true, 1)?;
				assert!(refreshed);
				assert_eq!(info.total, amount);
				assert_eq!(info.amount_currently_spendable, amount);

				let (_, outputs) = $api.retrieve_outputs($mask, false, false, None)?;
				assert_eq!(outputs.len(), 1);
				let o = &outputs[0];
				assert_eq!(o.commit, **commit);
				assert_eq!(o.output.status, OutputStatus::Unspent);
				assert_eq!(o.output.value, amount);
				assert_eq!(&o.output.root_key_id, *acct_path);
				assert!(libwallet::is_stateless_receive_key_id(&o.output.key_id));
				assert_eq!(
					&libwallet::output_parent_key_id(&o.output.key_id),
					*acct_path
				);

				let (_, txs) = $api.retrieve_txs($mask, false, None, None, None)?;
				assert_eq!(txs.len(), 1);
				assert_eq!(txs[0].tx_type, TxLogEntryType::TxReceived);
				assert!(txs[0].confirmed);
				assert_eq!(txs[0].amount_credited, amount);

				// sequential derivation is left where it was
				wallet_inst!($wallet, w);
				assert_eq!(w.current_child_index(acct_path)?, 0);
			}
			$api.set_active_account($mask, "default")?;
		}};
	}

	// the regular update picks the outputs up
	check_recipient!(api2, mask2, wallet2);
	// a full scan changes nothing
	api2.scan(mask2, None, true)?;
	check_recipient!(api2, mask2, wallet2);

	// 3) A wallet restored from the same seed finds them as well, under the
	// accounts they were received into
	api3.scan(mask3, None, true)?;
	check_recipient!(api3, mask3, wallet3);

	// 4) The received output can be spent
	{
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount / 2,
			minimum_confirmations: 1,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = api2.init_send_tx(mask2, args)?;
		let slate = client2.send_tx_slate_direct("wallet1", &slate_i)?;
		api2.tx_lock_outputs(mask2, &slate)?;
		let slate = api2.finalize_tx(mask2, &slate)?;
		api2.post_tx(mask2, &slate, false)?;
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), mask1, 3, false);

		// (posting through the test framework also mines a block to the
		// poster, so look at the outputs rather than at the totals)
		let (refreshed, outputs) = api2.retrieve_outputs(mask2, true, true, None)?;
		assert!(refreshed);
		let spent = outputs
			.iter()
			.find(|o| o.commit == commit_default)
			.expect("received output");
		assert_eq!(spent.output.status, OutputStatus::Spent);
		let fee = slate.fee_fields.fee();
		let change = outputs
			.iter()
			.find(|o| !o.output.is_coinbase && o.output.status == OutputStatus::Unspent)
			.expect("change output");
		assert_eq!(change.output.value, amount - amount / 2 - fee);
		// change came from the regular sequential range
		assert_eq!(change.output.key_id.to_path().depth, 3);
		assert_eq!(change.output.n_child, 0);
	}

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn stateless_receive() {
	let test_dir = "test_output/stateless_receive";
	setup(test_dir);
	if let Err(e) = stateless_receive_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
