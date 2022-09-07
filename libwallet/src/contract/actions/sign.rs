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

//! Implementation of contract sign

use crate::contract;
use crate::contract::actions::setup;
use crate::contract::types::ContractSetupArgsAPI;
use crate::contract::utils as contract_utils;
use crate::error::Error;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::slate::Slate;
use crate::types::{Context, NodeClient, WalletBackend};

/// Sign a contract
pub fn sign<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	setup_args: &ContractSetupArgsAPI,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Compute if we will add outputs at this step
	let will_add_outputs = match w.get_private_context(keychain_mask, slate.id.as_bytes()) {
		Ok(ctx) => ctx.get_inputs().len() + ctx.get_outputs().len() == 0,
		Err(_) => true,
	};
	// Compute state for 'sign'
	let (sl, mut context) = compute(w, keychain_mask, slate, setup_args)?;

	// Atomically commit state
	contract_utils::save_step(w, keychain_mask, &sl, &mut context, will_add_outputs, true)?;

	Ok(sl)
}

/// Compute logic for sign
pub fn compute<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	setup_args: &ContractSetupArgsAPI,
) -> Result<(Slate, Context), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut sl = slate.clone();
	if contract_utils::check_already_signed(w, sl.id) {
		panic!("This slate has already been signed.");
	}

	// Ensure net_change has been provided
	let expected_net_change =
		contract_utils::get_net_change(w, keychain_mask, &sl, setup_args.net_change)?;
	debug!(
		"contract::sign => expected_net_change: {}",
		expected_net_change
	);

	// Define the values that must be provided in the setup phase at the sign step
	let mut setup_args = setup_args.clone();
	setup_args.net_change = Some(expected_net_change);
	setup_args.num_participants = sl.num_participants;
	setup_args.add_outputs = true;

	// Ensure Setup phase is done and that inputs/outputs have been contributed
	let (mut sl, mut context) = setup::compute(w, keychain_mask, &mut sl, &setup_args)?;
	// At this point we have already selected our inputs and outputs so we add them to slate
	contract::slate::add_outputs(w, keychain_mask, &mut sl, &mut context)?;
	// Verify the payment proof signature (noop for the receiver)
	contract::slate::verify_payment_proof_sig(&sl)?;
	debug!("contract::sign => will sign slate fees: {}", sl.fee_fields);

	// The slate might not have a tx if one has not been initiated already. In this case, we
	// create an empty transaction.
	if !sl.tx.is_some() {
		debug!("contract::sign => slate had no slate.tx, creating empty tx");
		sl.tx = Some(Slate::empty_transaction());
	}
	// Add our offset contribution before we sign the partial sig
	// // TODO: Make sure the statement below works for both flows
	// context.initial_sec_key = context.sec_key.clone();
	let keychain = &w.keychain(keychain_mask)?;
	sl.adjust_offset(keychain, &context)?;
	debug!(
		"contract::sign => is offset zero after adjusting offset: {}",
		sl.offset.is_zero()
	);
	contract::slate::add_partial_signature(w, keychain_mask, &mut sl, &context)?;
	// We have now contributed all the transaction elements so we can transition the slate to the next step
	contract::slate::transition_state(&mut sl)?;

	// If we have all the partial signatures, finalize the tx
	if contract::slate::can_finalize(&sl) {
		debug!("contract::sign => finalizing tx");
		contract::slate::finalize_slate(w, keychain_mask, &mut sl)?;
	}

	Ok((sl, context))
}
