// Copyright 2022 The Grin Developers
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

//! Contract functions on the Slate

use crate::grin_core::libtx::build;
use crate::grin_core::libtx::proof::ProofBuilder;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::slate::{Slate, SlateState};
use crate::types::{Context, NodeClient, WalletBackend};
use crate::Error;

/// Add payment proof data to slate
pub fn add_payment_proof(slate: &mut Slate) -> Result<(), Error> {
	// TODO: Implement. Consider adding this function to the Slate itself so they can easily be versioned
	// e.g. slate.add_payment_proof_data()
	debug!("contract::slate::add_payment_proof => called (not implemented yet)");
	Ok(())
}

/// Verify payment proof signature
pub fn verify_payment_proof(slate: &Slate) -> Result<(), Error> {
	// TODO: Implement. Consider adding this function to the Slate itself so they can easily be versioned
	// e.g. slate.verify_payment_proof_sig()
	debug!("contract::slate::verify_payment_proof => called (not implemented yet)");
	Ok(())
}

/// Adds inputs and outputs to slate
pub fn add_outputs<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &mut Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	add_inputs_to_slate(w, keychain_mask, slate, context)?;
	add_outputs_to_slate(w, keychain_mask, slate, context)?;
	Ok(())
}

/// Contribute inputs to slate
fn add_inputs_to_slate<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &mut Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("contract::slate::add_inputs_to_slate => adding inputs to slate");
	let keychain = w.keychain(keychain_mask)?;
	let batch = w.batch(keychain_mask)?;
	for (key_id, mmr_index, _) in context.get_inputs() {
		// We have no information if the input is a coinbase or not, so we fetch the data from DB
		let coin = batch.get(&key_id, &mmr_index).unwrap();
		if coin.is_coinbase {
			slate.add_transaction_elements(
				&keychain,
				&ProofBuilder::new(&keychain),
				vec![build::coinbase_input(coin.value, coin.key_id.clone())],
			)?;
			debug!(
				"contract::slate::add_inputs_to_slate => added coinbase input id: {}, value: {}",
				coin.key_id.clone(),
				coin.value
			);
		} else {
			slate.add_transaction_elements(
				&keychain,
				&ProofBuilder::new(&keychain),
				vec![build::input(coin.value, coin.key_id.clone())],
			)?;
			debug!(
				"contract::slate::add_inputs_to_slate => added regular input id: {}, value: {}",
				coin.key_id.clone(),
				coin.value
			);
		}
	}

	Ok(())
}

/// Contribute outputs to slate
fn add_outputs_to_slate<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &mut Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("contract::slate::add_outputs_to_slate => start");
	let keychain = w.keychain(keychain_mask)?;
	// Iterate over outputs in the Context and add the same output to the slate
	for (key_id, _, amount) in context.get_outputs() {
		slate.add_transaction_elements(
			&keychain,
			&ProofBuilder::new(&keychain),
			vec![build::output(amount, key_id.clone())],
		)?;
		debug!(
			"contract::slate::add_outputs_to_slate => added output to slate. Output id: {}, amount: {}",
			key_id.clone(),
			amount
		);
	}

	Ok(())
}

/// Transition the slate state to the next one
pub fn transition_state(slate: &mut Slate) -> Result<(), Error> {
	// We don't really use these states right now apart from leaving it to derive expected net_change.
	// This suggests these can't be used for manipulation. It doesn't hurt to think a bit more if that's the case.
	let new_state = match slate.state {
		SlateState::Invoice1 => SlateState::Invoice2,
		SlateState::Invoice2 => SlateState::Invoice3,
		SlateState::Standard1 => SlateState::Standard2,
		SlateState::Standard2 => SlateState::Standard3,
		_ => {
			debug!("Slate.state: {}", slate.state);
			SlateState::Standard3
		}
	};
	slate.state = new_state;
	// NOTE: It's possible to never reach the step3. A self-spend has only 2 steps: new -> sign.
	Ok(())
}

/// Add partial signature to the slate.
// TODO: Should be a sign & forget pubkey+nonce implementation.
pub fn sign<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("contract::slate::sign => called");
	let keychain = w.keychain(keychain_mask)?;
	slate.fill_round_2(&keychain, &context.sec_key, &context.sec_nonce)?;
	debug!("contract::slate::sign => done");

	Ok(())
}

/// We can finalize if all partial sigs are present
pub fn can_finalize(slate: &Slate) -> bool {
	let res = slate
		.participant_data
		.clone()
		.into_iter()
		.filter(|v| !v.is_complete())
		.count();

	// We can finalize if the number of partial sigs is the same as the number of participants
	res == 0 && slate.participant_data.len() == slate.num_participants as usize
}

/// Finalize slate
pub fn finalize<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("contract::slate::finalize => called");
	// Final transaction can be built by anyone at this stage
	trace!("Slate to finalize is: {}", slate);
	// At this point, everyone adjusted their offset, so we update the offset on the tx
	slate.tx_or_err_mut()?.offset = slate.offset.clone();
	slate.finalize(&w.keychain(keychain_mask)?)?;

	Ok(())
}

/// Perform 'setup' step for a contract. This adds our public key and nonce to the slate
/// The operation should be idempotent.
pub fn add_keys<K>(slate: &mut Slate, keychain: &K, context: &mut Context) -> Result<(), Error>
where
	K: Keychain,
{
	debug!("contract::slate::add_keys => called");
	// TODO: Is this safe from manipulation?
	slate.add_participant_info(keychain, context, None)
}
