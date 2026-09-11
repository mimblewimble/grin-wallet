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

use crate::backend::WalletBackend;
use crate::grin_core::core::transaction::{Inputs, OutputFeatures, OutputIdentifier};
use crate::grin_core::libtx::build;
use crate::grin_core::libtx::proof::ProofBuilder;
use crate::grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::grin_util::from_hex;
use crate::grin_util::secp::constants::PEDERSEN_COMMITMENT_SIZE;
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::Commitment;
use crate::slate::{Slate, SlateState};
use crate::types::{Context, NodeClient, OutputData};
use crate::util::OnionV3Address;
use crate::Error;
use std::collections::BTreeSet;

use super::types::{OwnCommitmentStatus, ProofArgs};

/// Add payment proof data to slate, noop for sender
pub fn add_payment_proof<C, K>(
	w: &mut WalletBackend<C, K>,
	slate: &mut Slate,
	keychain_mask: Option<&SecretKey>,
	context: &Context,
	net_change: &Option<i64>,
	proof_args: &ProofArgs,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	debug!("contract::slate::add_payment_proof => called");
	if !proof_args.suppress_proof {
		crate::payment_proof::check_proof_type(&proof_args.proof_type)?;
	}
	// If we're a recipient, generate proof unless explicity told not to
	if let Some(ref c) = net_change {
		if *c > 0 && !proof_args.suppress_proof && slate.payment_proof.is_none() {
			super::proofs::add_payment_proof(w, keychain_mask, slate, &context, proof_args)?;
		}
	}

	Ok(())
}

/// Verify the receiver's early payment promise before paying
pub fn verify_payment_promise<K>(
	slate: &Slate,
	keychain: &K,
	context: &Context,
) -> Result<(), Error>
where
	K: Keychain,
{
	debug!("contract::slate::verify_payment_promise => called");
	if context.get_net_change()? >= 0 {
		return Ok(());
	}
	if slate.payment_proof.is_none() {
		return Ok(());
	}
	if slate.participant_data.len() != 2 {
		return Err(Error::GenericError(format!(
			"Expected 2 participants for a payment promise, found {}",
			slate.participant_data.len()
		)));
	}

	let payer_index = slate.find_index_matching_context(keychain, context)?;
	let receiver_index = slate
		.participant_data
		.iter()
		.enumerate()
		.find_map(|(index, _)| (index != payer_index).then_some(index))
		.ok_or_else(|| Error::GenericError("Payment promise has no receiver".to_string()))?;
	let derivation_index = context.payment_proof_derivation_index.unwrap_or(0);
	let sender_key = crate::address::address_from_derivation_path(
		keychain,
		&context.parent_key_id,
		derivation_index,
	)?;
	let sender_address = OnionV3Address::from_private(&sender_key.0)?.to_ed25519()?;
	slate.verify_payment_proof_sig(receiver_index, Some(sender_address))
}

/// Adds inputs and outputs to slate
pub fn add_outputs<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	add_inputs_to_slate(w, keychain_mask, slate, context)?;
	add_outputs_to_slate(w, keychain_mask, slate, context)?;
	// Adjust the offset for the added input and outputs
	let keychain = &w.keychain(keychain_mask)?;
	slate.adjust_offset(keychain, &context)?;

	Ok(())
}

fn derive_commitment<K>(keychain: &K, id: &Identifier, amount: u64) -> Result<Commitment, Error>
where
	K: Keychain,
{
	keychain
		.commit(amount, id, SwitchCommitmentType::Regular)
		.map_err(Error::from)
}

fn cached_commitment(commit: &str) -> Option<Commitment> {
	from_hex(commit)
		.ok()
		.filter(|bytes| bytes.len() == PEDERSEN_COMMITMENT_SIZE)
		.map(Commitment::from_vec)
}

fn stored_commitment<K>(keychain: &K, output: &OutputData) -> Result<Commitment, Error>
where
	K: Keychain,
{
	// Commitments written by the wallet are used directly. Rebuild malformed cache entries.
	if let Some(commit) = output.commit.as_deref().and_then(cached_commitment) {
		return Ok(commit);
	}
	derive_commitment(keychain, &output.key_id, output.value)
}

fn derive_identifier<K>(
	keychain: &K,
	id: &Identifier,
	amount: u64,
	features: OutputFeatures,
) -> Result<OutputIdentifier, Error>
where
	K: Keychain,
{
	Ok(OutputIdentifier::new(
		features,
		&derive_commitment(keychain, id, amount)?,
	))
}

fn check_identifiers(
	actual: &[OutputIdentifier],
	expected: &[OutputIdentifier],
	kind: &str,
) -> Result<(), Error> {
	for expected in expected {
		let mut matches = actual
			.iter()
			.filter(|actual| actual.commitment() == expected.commitment());
		match matches.next() {
			None => {
				return Err(Error::GenericError(format!(
					"Contract slate is missing one of our {} commitments",
					kind
				)))
			}
			Some(actual) if actual != expected || matches.next().is_some() => {
				return Err(Error::GenericError(format!(
					"Contract slate changed or duplicated one of our {} commitments",
					kind
				)))
			}
			Some(_) => {}
		}
	}
	Ok(())
}

fn expected_identifiers<C, K>(
	w: &WalletBackend<C, K>,
	keychain: &K,
	context: &Context,
) -> Result<(Vec<OutputIdentifier>, Vec<OutputIdentifier>), Error>
where
	C: NodeClient,
	K: Keychain,
{
	let expected_inputs = context
		.input_ids
		.iter()
		.map(|(id, mmr_index, amount)| {
			let output = w.get(id, mmr_index)?;
			derive_identifier(
				keychain,
				id,
				*amount,
				if output.is_coinbase {
					OutputFeatures::Coinbase
				} else {
					OutputFeatures::Plain
				},
			)
		})
		.collect::<Result<Vec<_>, Error>>()?;
	let expected_outputs = context
		.output_ids
		.iter()
		.map(|(id, _, amount)| derive_identifier(keychain, id, *amount, OutputFeatures::Plain))
		.collect::<Result<Vec<_>, Error>>()?;
	Ok((expected_inputs, expected_outputs))
}

const MISSING_INPUT_FEATURES: &str = "Contract slate input features are missing";

/// Compare a slate with commitments owned by this wallet. A signed context
/// identifies commitments that this wallet has already added.
pub(super) fn own_commitment_status<C, K>(
	w: &WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	signed_context: Option<&Context>,
) -> Result<OwnCommitmentStatus, Error>
where
	C: NodeClient,
	K: Keychain,
{
	let keychain = w.keychain(keychain_mask)?;
	let tx = slate.tx_or_err()?;
	let inputs = match tx.inputs() {
		// Unknown only means missing input features here. View also uses Unknown when
		// the private context has already been removed.
		Inputs::CommitOnly(_) => return Ok(OwnCommitmentStatus::Unknown),
		Inputs::FeaturesAndCommit(inputs) => inputs,
	};
	let (expected_inputs, expected_outputs) = match signed_context {
		Some(context) => {
			let (inputs, outputs) = expected_identifiers(w, &keychain, context)?;
			(
				inputs
					.into_iter()
					.map(|input| input.commitment())
					.collect::<BTreeSet<_>>(),
				outputs
					.into_iter()
					.map(|output| output.commitment())
					.collect::<BTreeSet<_>>(),
			)
		}
		None => (BTreeSet::new(), BTreeSet::new()),
	};
	let incoming_inputs = inputs
		.into_iter()
		.map(|input| input.commitment())
		.filter(|commit| !expected_inputs.contains(commit))
		.collect::<BTreeSet<_>>();
	let incoming_outputs = tx
		.outputs()
		.iter()
		.map(|output| output.commitment())
		.filter(|commit| !expected_outputs.contains(commit))
		.collect::<BTreeSet<_>>();
	if incoming_inputs.is_empty() && incoming_outputs.is_empty() {
		return Ok(OwnCommitmentStatus::Clean);
	}

	let mut unexpected_input = false;
	let mut unexpected_output = false;
	for output in w.iter()? {
		let commit = stored_commitment(&keychain, &output)?;
		unexpected_input |= incoming_inputs.contains(&commit);
		unexpected_output |= incoming_outputs.contains(&commit);
		if (unexpected_input || incoming_inputs.is_empty())
			&& (unexpected_output || incoming_outputs.is_empty())
		{
			break;
		}
	}
	Ok(match (unexpected_input, unexpected_output) {
		(true, true) => OwnCommitmentStatus::UnexpectedInputAndOutput,
		(true, false) => OwnCommitmentStatus::UnexpectedInput,
		(false, true) => OwnCommitmentStatus::UnexpectedOutput,
		(false, false) => OwnCommitmentStatus::Clean,
	})
}

/// Reject commitments from this wallet before contract setup reserves any keys.
pub(super) fn verify_incoming_own_commitments<C, K>(
	w: &WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	let found = match own_commitment_status(w, keychain_mask, slate, None)? {
		OwnCommitmentStatus::UnexpectedInput => "an unexpected input commitment",
		OwnCommitmentStatus::UnexpectedOutput => "an unexpected output commitment",
		OwnCommitmentStatus::UnexpectedInputAndOutput => "unexpected input and output commitments",
		OwnCommitmentStatus::Unknown => {
			return Err(Error::GenericError(MISSING_INPUT_FEATURES.to_string()))
		}
		OwnCommitmentStatus::Clean => return Ok(()),
	};
	Err(Error::GenericError(format!(
		"Contract slate contains {} from this wallet",
		found
	)))
}

/// Check that the slate still contains the commitments selected for this contract.
pub(super) fn verify_own_commitments<C, K>(
	w: &WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	context: &Context,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	let keychain = w.keychain(keychain_mask)?;
	let (expected_inputs, expected_outputs) = expected_identifiers(w, &keychain, context)?;
	let tx = slate.tx_or_err()?;
	match tx.inputs() {
		Inputs::CommitOnly(_) => {
			return Err(Error::GenericError(MISSING_INPUT_FEATURES.to_string()))
		}
		Inputs::FeaturesAndCommit(inputs) => {
			let inputs = inputs
				.iter()
				.map(OutputIdentifier::from)
				.collect::<Vec<_>>();
			check_identifiers(&inputs, &expected_inputs, "input")?;
		}
	}
	let actual_outputs = tx
		.outputs()
		.iter()
		.map(|output| output.identifier())
		.collect::<Vec<_>>();

	check_identifiers(&actual_outputs, &expected_outputs, "output")
}

/// Contribute inputs to slate
fn add_inputs_to_slate<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	debug!("contract::slate::add_inputs_to_slate => adding inputs to slate");
	let keychain = w.keychain(keychain_mask)?;
	let batch = w.batch(keychain_mask)?;
	for (key_id, mmr_index, _) in context.get_inputs() {
		// We have no information if the input is a coinbase or not, so we fetch the data from DB
		let coin = batch.get(&key_id, &mmr_index)?;
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
fn add_outputs_to_slate<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
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

/// Return the next contract slate state
pub(super) fn next_state(state: &SlateState) -> Result<SlateState, Error> {
	let next = match state {
		SlateState::Invoice1 => SlateState::Invoice2,
		SlateState::Invoice2 => SlateState::Invoice3,
		SlateState::Standard1 => SlateState::Standard2,
		SlateState::Standard2 => SlateState::Standard3,
		// Unknown and final states cannot be advanced.
		s => {
			return Err(Error::GenericError(format!(
				"Cannot advance a contract slate in state {}",
				s
			)))
		}
	};
	Ok(next)
}

/// Transition the slate state to the next one
pub(super) fn transition_state(slate: &mut Slate) -> Result<(), Error> {
	slate.state = next_state(&slate.state)?;
	// NOTE: It's possible to never reach the step3. A self-spend has only 2 steps: new -> sign.
	Ok(())
}

/// Add partial signature to the slate.
// Nonce reuse is prevented by forgetting the signing context after a signed step:
// save_step deletes sec_key/sec_nonce after signing, except for step2 contract view
// Contexts are keyed by slate.id so a nonce is only used for one message
pub fn sign<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &mut Context,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	debug!("contract::slate::sign => called");
	// The counterparty controls the participant list, so require it to hold exactly the
	// participants the slate declares before we sign over it. Setup has already added our
	// own entry by this point.
	if slate.participant_data.len() != slate.num_participants as usize {
		return Err(Error::GenericError(format!(
			"Expected {} participant(s) before signing, found {}",
			slate.num_participants,
			slate.participant_data.len()
		)));
	}
	let keychain = w.keychain(keychain_mask)?;
	// Do not let fill_round_2 skip a missing participant
	slate.find_index_matching_context(&keychain, context)?;
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
	// We can finalize if the number of partial sigs is the same as the number of participants
	slate.participant_data.iter().all(|v| v.is_complete())
		&& slate.participant_data.len() == slate.num_participants as usize
}

/// Finalize slate
pub fn finalize<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
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
	let our_pub_key = PublicKey::from_secret_key(keychain.secp(), &context.sec_key)?;
	let our_pub_nonce = PublicKey::from_secret_key(keychain.secp(), &context.sec_nonce)?;
	// An entry is ours only when both keys match, which is what add_participant_info and
	// fill_round_2 use. Our excess paired with a nonce that is not ours cannot have come
	// from us, so reject it rather than treating the entry as ours: we would otherwise
	// append a further participant and sign nothing.
	if slate
		.participant_data
		.iter()
		.any(|p| p.public_blind_excess == our_pub_key && p.public_nonce != our_pub_nonce)
	{
		return Err(Error::GenericError(
			"Slate carries our public excess with a different nonce".to_string(),
		));
	}
	// Guard against a tampered slate that already carries the full participant set.
	// Re-adding our own info is idempotent, so only block when we are not already in it.
	let already_ours = slate
		.participant_data
		.iter()
		.any(|p| p.public_blind_excess == our_pub_key && p.public_nonce == our_pub_nonce);
	if !already_ours && slate.participant_data.len() >= slate.num_participants as usize {
		return Err(Error::GenericError(format!(
			"Slate already has the expected {} participant(s)",
			slate.num_participants
		)));
	}
	slate.add_participant_info(keychain, context, None)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::grin_keychain::{ExtKeychain, SwitchCommitmentType};
	use crate::slate::ParticipantData;

	fn keychain_and_context() -> (ExtKeychain, Context) {
		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let parent_key_id = ExtKeychain::derive_key_id(1, 0, 0, 0, 0);
		let context = Context::new(keychain.secp(), &parent_key_id, true, true);
		(keychain, context)
	}

	#[test]
	fn add_keys_rejects_our_excess_with_a_foreign_nonce() {
		let (keychain, mut context) = keychain_and_context();
		let our_excess = PublicKey::from_secret_key(keychain.secp(), &context.sec_key).unwrap();
		let other_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let other_key = keychain
			.derive_key(0, &other_id, SwitchCommitmentType::Regular)
			.unwrap();
		let other = PublicKey::from_secret_key(keychain.secp(), &other_key).unwrap();

		let mut slate = Slate::blank(2, false);
		slate.participant_data.push(ParticipantData {
			public_blind_excess: our_excess,
			public_nonce: other,
			part_sig: None,
		});
		assert!(add_keys(&mut slate, &keychain, &mut context).is_err());
	}

	#[test]
	fn transition_state_rejects_states_it_cannot_advance() {
		for state in [
			SlateState::Unknown,
			SlateState::Standard3,
			SlateState::Invoice3,
		] {
			let mut slate = Slate::blank(2, false);
			slate.state = state.clone();
			assert!(
				transition_state(&mut slate).is_err(),
				"expected {} to be rejected",
				state
			);
		}

		// The transitions the contract flows actually use are still accepted
		for (from, to) in [
			(SlateState::Standard1, SlateState::Standard2),
			(SlateState::Standard2, SlateState::Standard3),
			(SlateState::Invoice1, SlateState::Invoice2),
			(SlateState::Invoice2, SlateState::Invoice3),
		] {
			let mut slate = Slate::blank(2, false);
			slate.state = from;
			transition_state(&mut slate).unwrap();
			assert_eq!(slate.state, to);
		}
	}

	#[test]
	fn checks_own_commitments() {
		let identifier =
			|value, features| OutputIdentifier::new(features, &Commitment::from_vec(vec![value]));
		let own_input = identifier(1, OutputFeatures::Plain);
		let own_output = identifier(2, OutputFeatures::Plain);

		check_identifiers(&[own_input], &[own_input], "input").unwrap();
		assert!(check_identifiers(&[], &[own_input], "input").is_err());
		assert!(check_identifiers(&[own_input], &[own_output], "output").is_err());
		assert!(check_identifiers(&[own_input, own_input], &[own_input], "input").is_err());
		assert!(cached_commitment("01").is_none());
		assert!(cached_commitment("not hex").is_none());
		assert!(cached_commitment(&"00".repeat(PEDERSEN_COMMITMENT_SIZE)).is_some());
	}

	#[test]
	fn coinbase_features() {
		let commit = Commitment::from_vec(vec![1]);
		let plain = OutputIdentifier::new(OutputFeatures::Plain, &commit);
		let coinbase = OutputIdentifier::new(OutputFeatures::Coinbase, &commit);

		for (actual, expected) in [(plain, coinbase), (coinbase, plain)] {
			let err = check_identifiers(&[actual], &[expected], "input").unwrap_err();
			assert!(matches!(
				err,
				Error::GenericError(ref message)
					if message == "Contract slate changed or duplicated one of our input commitments"
			));
		}
	}
}
