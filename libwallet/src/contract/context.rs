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

//! Contract functions on the Context

use crate::contract::selection::prepare_outputs;
use crate::contract::types::ContractSetupArgsAPI;
use crate::contract::utils as contract_utils;
use crate::grin_keychain::{Identifier, Keychain};
use crate::grin_util::secp::key::SecretKey;
use crate::internal::{keys, updater};
use crate::slate::Slate;
use crate::types::{Context, NodeClient, WalletBackend};
use crate::{Error, OutputData};
use grin_core::core::FeeFields;

/// Get or create transaction Context for the given slate
pub fn get_or_create<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	setup_args: &ContractSetupArgsAPI,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("contract::context::get_or_create => called");
	let maybe_context = w.get_private_context(keychain_mask, slate.id.as_bytes());

	let context = match maybe_context {
		Err(_) => {
			// Get data required for creating a context
			let height = w.w2n_client().get_chain_tip()?.0;
			let parent_key_id =
				contract_utils::parent_key_for(w, setup_args.src_acct_name.as_ref());
			self::create(
				w,
				keychain_mask,
				slate,
				height,
				// &args,
				setup_args,
				&parent_key_id,
				false,
			)?
		}
		Ok(ctx) => ctx,
	};
	Ok(context)
}

/// Creates a context for a contract
fn create<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	// TODO: compare with &InitTxArgs to see if any information is missing
	setup_args: &ContractSetupArgsAPI,
	parent_key_id: &Identifier,
	use_test_rng: bool,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("Creating a new contract context");
	// sender should always refresh outputs
	updater::refresh_outputs(w, keychain_mask, parent_key_id, false)?;

	// Fee contribution estimation
	let net_change = setup_args.net_change.unwrap();
	// select inputs to estimate fee cost
	let (inputs, _, my_fee) =
		prepare_outputs(w, &parent_key_id, current_height, &setup_args, None)?;
	// The number of outputs we expect is the number of custom outputs plus one change output
	debug!(
		"My fee contribution estimation: {} for n_inputs: {}, n_outputs: {}, n_kernels: {}, num_participants: {}",
		my_fee.fee(), inputs.len(), setup_args.selection_args.num_custom_outputs() + 1, 1, setup_args.num_participants
	);
	// Make sure `my_fee < net_change` holds for the receiver. This can't be true for a self-spend, because nobody
	// has a net_change > 0 which makes a self-spend ok to be a net negative when fees are included.
	if net_change > 0 && my_fee.fee() > net_change.abs() as u64 {
		panic!(
			"My contribution as a receiver would be net negative. my_fee: {}, net_change: {}",
			my_fee.fee(),
			net_change
		);
	}
	// Add my share of fee contribution to the slate fees
	slate.fee_fields = FeeFields::new(0, slate.fee_fields.fee() + my_fee.fee())?;
	debug!("Slate.fee: {}", slate.fee_fields.fee());

	// Create a Context for this slate
	let keychain = w.keychain(keychain_mask)?;
	// TODO: it seems 'is_initiator: true' is only used in test_rng. Do we care about this?
	let mut context = Context::new(keychain.secp(), &parent_key_id, use_test_rng, true);
	// Context.fee will hold _our_ fee contribution and not the total slate fee
	context.fee = my_fee.as_opt();
	// Context.amount is not used in contracts, but we set it anyway.
	context.amount = slate.amount;
	// TODO: looking at what uses Context.late_lock_args, it seems only the args in SelectionArgs are used except
	// for args.ttl_blocks. Is this needed? Can we refactor this?
	context.setup_args = Some(setup_args.clone());
	debug!(
		"Setting Context.net_change as: {}",
		context.get_net_change()
	);

	Ok(context)
}

/// Add outputs to a contract context (including spent outputs which get locked)
pub fn add_outputs<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	context: &mut Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	debug!("contract::utils::add_outputs => called");
	// Do nothing if we have already contributed our outputs. The assumption is that if this was done,
	// our output contribution is complete.
	if context.output_ids.len() > 0 || context.input_ids.len() > 0 {
		debug!("contract::utils::add_outputs => outputs have already been added, returning.");
		return Ok(());
	}
	let setup_args = context.setup_args.as_ref().unwrap();
	debug!("contract::utils::add_outputs => adding outputs");
	let current_height = w.w2n_client().get_chain_tip()?.0;
	let parent_key_id = &context.parent_key_id;

	// Select inputs for which `Σmy_inputs >= Σmy_outputs + my_fee_cost` holds. Uses committed fee if present.
	let (inputs, my_output_amounts, my_fee) = prepare_outputs(
		&mut *w,
		parent_key_id,
		current_height,
		&setup_args,
		context.fee,
	)?;
	assert_eq!(my_fee.fee(), context.fee.unwrap().fee(), "my_fee!=ctx.fee");
	// Add selected/created inputs/outputs to the context
	add_inputs_to_ctx(context, &inputs)?;
	add_outputs_to_ctx(w, keychain_mask, context, my_output_amounts)?;

	Ok(())
}

/// Add inputs to Context
fn add_inputs_to_ctx(context: &mut Context, inputs: &Vec<OutputData>) -> Result<(), Error> {
	debug!("contract::utils::add_inputs_to_ctx => adding inputs to context");
	for input in inputs {
		context.add_input(&input.key_id, &input.mmr_index, input.value);
		debug!(
			"contract::utils::add_inputs_to_ctx => input id: {}, value:{}",
			&input.key_id, input.value
		);
	}

	Ok(())
}

/// Add outputs to Context
fn add_outputs_to_ctx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	context: &mut Context,
	amounts: Vec<u64>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	for amount in amounts {
		// TODO: it seems like next_available_key does not respect the parent_key_id. Check if it does, it probably should?
		//  A late-lock might have a different account set to active than the one that was set to the Context
		let key_id = keys::next_available_key(w, keychain_mask).unwrap();
		context.add_output(&key_id, &None, amount);
		debug!(
			"contract::utils::add_output_to_ctx => added output to context. Output id: {}, amount: {}",
			key_id.clone(),
			amount
		);
	}
	Ok(())
}
