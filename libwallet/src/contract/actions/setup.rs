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

//! Implementation of contract setup

use crate::api_impl::owner::check_ttl_at_height;
use crate::backend::WalletBackend;
use crate::contract;
use crate::contract::types::ContractSetupArgsAPI;
use crate::error::Error;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::slate::Slate;
use crate::types::{Context, NodeClient};
use grin_core::core::FeeFields;

// Contract deadlines use the node tip because the active account may not own the context
fn check_contract_ttl<C, K>(w: &mut WalletBackend<C, K>, slate: &Slate) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	if slate.ttl_cutoff_height == 0 {
		return Ok(());
	}
	check_ttl_at_height(slate, w.w2n_client().get_chain_tip()?.0)
}

/// Perform a contract setup
pub fn setup<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	setup_args: &ContractSetupArgsAPI,
) -> Result<Slate, Error>
where
	C: NodeClient,
	K: Keychain,
{
	contract::utils::verify_num_participants(slate.num_participants)?;
	contract::utils::verify_fee_rate(setup_args.fee_rate)?;
	if slate.num_participants != setup_args.num_participants {
		return Err(Error::GenericError(format!(
			"Inconsistent num_participants. Slate num_participants:{}, Setup num_participants: {}",
			slate.num_participants, setup_args.num_participants
		)));
	}
	contract::utils::verify_not_signed(w, slate.id)?;
	// Compute state for 'setup'
	let (slate, context) = compute(w, keychain_mask, slate, setup_args, None)?;

	// Atomically commit state
	contract::utils::save_step(w, keychain_mask, &slate, context, setup_args.add_outputs)?;

	Ok(slate)
}

/// Compute logic for setup
pub fn compute<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	setup_args: &ContractSetupArgsAPI,
	existing_context: Option<Context>,
) -> Result<(Slate, Context), Error>
where
	C: NodeClient,
	K: Keychain,
{
	let mut sl = slate.clone();
	check_contract_ttl(w, &sl)?;

	// Get or create the Context and check the setup arguments
	let mut context = match existing_context {
		Some(context) => context,
		None => contract::context::get_or_create(w, keychain_mask, &mut sl, setup_args)?,
	};
	let mut setup_args = setup_args.clone();
	setup_args.net_change = Some(contract::utils::get_net_change(
		Some(&context),
		setup_args.net_change,
	)?);
	contract::utils::verify_ttl(context.contract_ttl_cutoff_height, &sl)?;
	let context_args = context
		.setup_args
		.as_ref()
		.ok_or_else(|| Error::GenericError("Context carries no contract setup args".to_string()))?;
	contract::utils::verify_setup_args_consistency(context_args, &setup_args)?;

	// Add keys and payment proof to slate (both are idempotent operations)
	let keychain = w.keychain(keychain_mask)?;
	// Restore our fee when a stored context is applied to a slate without our keys
	if context.log_id.is_some() {
		let has_our_keys = match sl.find_index_matching_context(&keychain, &context) {
			Ok(_) => true,
			Err(Error::ContextToIndex) => false,
			Err(e) => return Err(e),
		};
		if !has_our_keys {
			if let Some(fee) = context.fee {
				sl.fee_fields = FeeFields::new(0, sl.fee_fields.fee() + fee.fee())?;
			}
		}
	}
	contract::proofs::commit_sender_nonce(&sl, &mut context, keychain.secp())?;
	contract::slate::add_keys(&mut sl, &keychain, &mut context)?;
	contract::slate::add_payment_proof(
		w,
		&mut sl,
		keychain_mask,
		&mut context,
		&setup_args.net_change,
		&setup_args.proof_args,
	)?; // noop for the sender

	// Add inputs/outputs to the Context if needed. No locking is done here. This happens at save_step.
	if setup_args.add_outputs {
		contract::context::add_outputs(&mut *w, keychain_mask, &mut context)?;
	}

	Ok((sl, context))
}
