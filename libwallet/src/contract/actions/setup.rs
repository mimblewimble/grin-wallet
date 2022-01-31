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

//! Functions for doing contract setup

use crate::api_impl::owner::check_ttl;
use crate::contract::types::ContractSetupArgsAPI;
use crate::contract::utils as contract_utils;
use crate::error::Error;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::slate::Slate;
use crate::types::{Context, NodeClient, WalletBackend};

/// Perform a contract setup
pub fn setup<'a, T: ?Sized, C, K>(
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
	// Compute state for 'setup'
	let (slate, mut context) = compute(w, keychain_mask, slate, setup_args)?;

	// Atomically commit state
	contract_utils::save_step(
		w,
		keychain_mask,
		&slate,
		&mut context,
		setup_args.add_outputs,
		false,
	)?;

	Ok(slate)
}

/// Compute logic for setup - adds keys, payment proof data and potentially inputs/outputs (doesn't lock them)
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
	// We expect net_change to have been defined once we call setup
	let expected_net_change = setup_args.net_change.unwrap();
	let mut sl = slate.clone();
	check_ttl(w, &sl)?;

	// 1. Obtain transaction Context
	let height = w.w2n_client().get_chain_tip()?.0;
	debug!(
		"contract::setup => expected_net_change: {} num_participants: {}",
		expected_net_change, setup_args.num_participants
	);
	// Check if a context for the slate already exists
	let maybe_context = w.get_private_context(keychain_mask, sl.id.as_bytes());

	let mut context = match maybe_context {
		Err(_) => {
			// Read the parent_key id which is required for creating a context
			let parent_key_id =
				contract_utils::parent_key_for(w, setup_args.src_acct_name.as_ref());
			contract_utils::create_contract_ctx(
				w,
				keychain_mask,
				&mut sl,
				height,
				// &args,
				setup_args,
				&parent_key_id,
				false,
			)?
		}
		Ok(ctx) => {
			// Means we are at step3 and we need to compare there are no conflicts in the setup args with
			// the ones we provided at step1. This includes output selection arguments.
			// TODO: verify that the parent_key_id is consistent, perhaps even with the active_account set?
			contract_utils::verify_setup_consistency(
				&ctx.setup_args.as_ref().unwrap(),
				&setup_args,
			)?;
			ctx
		}
	};
	// 2. Handle key setup, payment proofs and input/output contribution (all idempotent operations)
	// Setup keys in case the slate doesn't have them
	sl.add_key_setup(&w.keychain(keychain_mask)?, &mut context)?;
	debug!("contract::setup => performed key setup");

	// Add payment proof data
	contract_utils::add_payment_proof_data(&mut sl)?;
	debug!("contract::setup => added payment proof data (not implemented yet)");

	// Add inputs/outputs to the Context (includes input selection)
	if setup_args.add_outputs {
		debug!("contract:setup => adding outputs to context");
		contract_utils::add_outputs(&mut *w, keychain_mask, &mut context)?;
	}

	Ok((sl, context))
}
