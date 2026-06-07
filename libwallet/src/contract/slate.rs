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
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::slate::{Slate, SlateState};
use crate::types::{Context, NodeClient, WalletBackend};
use crate::Error;

use super::types::ProofArgs;
use crate::contract::proofs::InvoiceProof;
use ed25519_dalek::PublicKey as DalekPublicKey;

/// Add payment proof data to slate, noop for sender
pub fn add_payment_proof<'a, T: ?Sized, C, K>(
	w: &mut T,
	slate: &mut Slate,
	keychain_mask: Option<&SecretKey>,
	context: &Context,
	net_change: &Option<i64>,
	proof_args: &ProofArgs,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// TODO: Implement. Consider adding this function to the Slate itself so they can easily be versioned
	// e.g. slate.add_payment_proof_data()
	debug!("contract::slate::add_payment_proof => called");
	// If we're a recipient, generate proof unless explicity told not to
	if let Some(ref c) = net_change {
		if *c > 0 && !proof_args.suppress_proof && slate.payment_proof.is_none() {
			super::proofs::add_payment_proof(w, keychain_mask, slate, &context, proof_args)?;
		}
	}

	Ok(())
}

/// Verify payment proof signature
pub fn verify_payment_proof(
	slate: &Slate,
	net_change: i64,
	recipient_address: &DalekPublicKey,
) -> Result<(), Error> {
	// TODO: Implement. Consider adding this function to the Slate itself so they can easily be versioned
	// e.g. slate.verify_payment_proof_sig()
	debug!("contract::slate::verify_payment_proof => called");
	if net_change > 0 && slate.payment_proof.is_some() {
		let invoice_proof = InvoiceProof::from_slate(&slate, 1, None)?;
		invoice_proof.verify_promise_signature(&recipient_address)?;
	}
	Ok(())
}

/// Adds inputs and outputs to slate
pub fn add_outputs<'a, T: ?Sized, C, K>(
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
	add_inputs_to_slate(w, keychain_mask, slate, context)?;
	add_outputs_to_slate(w, keychain_mask, slate, context)?;
	// Adjust the offset for the added input and outputs
	let keychain = &w.keychain(keychain_mask)?;
	slate.adjust_offset(keychain, &context)?;

	Ok(())
}

/// Contribute inputs to slate
fn add_inputs_to_slate<'a, T: ?Sized, C, K>(
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
	context: &Context,
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
// Nonce reuse is prevented by forgetting the signing context after a signed step:
// save_step deletes the private context (which holds sec_key/sec_nonce) once is_signed
// (except the deliberately-retained step2 context used for safe cancel). The context is
// keyed by slate.id, so a given nonce is only ever used for one message.
pub fn sign<'a, T: ?Sized, C, K>(
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
	debug!("contract::slate::sign => called");
	let keychain = w.keychain(keychain_mask)?;
	slate.fill_round_2(&keychain, &context.sec_key, &context.sec_nonce)?;
	debug!(
		"contract::sign => signed for slate fees: {}",
		slate.fee_fields
	);
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
	// Guard against a tampered slate that already carries the full participant set.
	// Re-adding our own info is idempotent, so only block when we are not already in it.
	let our_pub_key = PublicKey::from_secret_key(keychain.secp(), &context.sec_key)?;
	let already_ours = slate
		.participant_data
		.iter()
		.any(|p| p.public_blind_excess == our_pub_key);
	if !already_ours && slate.participant_data.len() >= slate.num_participants as usize {
		return Err(Error::GenericError(format!(
			"Slate already has the expected {} participant(s)",
			slate.num_participants
		)));
	}
	slate.add_participant_info(keychain, context, None)
}
