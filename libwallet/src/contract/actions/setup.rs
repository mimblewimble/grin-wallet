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

use crate::api_impl::owner::check_ttl;
use crate::contract;
use crate::contract::types::ContractSetupArgsAPI;
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
	contract::utils::save_step(
		w,
		keychain_mask,
		&slate,
		&mut context,
		setup_args.add_outputs,
		false,
	)?;

	Ok(slate)
}

/// Compute logic for setup
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
	check_ttl(w, &sl)?;

	// Get or create a transaction Context and verify consistency of setup arguments
	let mut context = contract::context::get_or_create(w, keychain_mask, &mut sl, setup_args)?;
	contract::utils::verify_setup_args_consistency(
		&context.setup_args.as_ref().unwrap(),
		&setup_args,
	)?;

	// Add keys and payment proof to slate (both are idempotent operations)
	contract::slate::add_keys(&mut sl, &w.keychain(keychain_mask)?, &mut context)?;
	contract::slate::add_payment_proof(&mut sl)?; // noop for the sender

	// Add inputs/outputs to the Context if needed. No locking is done here. This happens at save_step.
	if setup_args.add_outputs {
		contract::context::add_outputs(&mut *w, keychain_mask, &mut context)?;
	}

	Ok((sl, context))
}
