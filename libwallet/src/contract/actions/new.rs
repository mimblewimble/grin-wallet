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

//! Implementation of contract new

use crate::contract::actions::setup;
use crate::contract::types::ContractSetupArgsAPI;
use crate::contract::utils as contract_utils;
use crate::error::Error;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::slate::Slate;
use crate::types::{Context, NodeClient, WalletBackend};

/// Create a new contract with initial setup done by the initiator
pub fn new<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	setup_args: &ContractSetupArgsAPI,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Compute state for 'new'
	let (slate, mut context) = compute(w, keychain_mask, setup_args)?;

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

/// Compute logic for new
pub fn compute<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	setup_args: &ContractSetupArgsAPI,
) -> Result<(Slate, Context), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let net_change = setup_args.net_change.unwrap();
	debug!("contract::new => net_change passed: {}", net_change);

	// Initialize a new contract (if net_change is positive, I'm the receiver meaning this is invoice flow)
	let num_participants = setup_args.num_participants;
	let mut slate = Slate::blank(num_participants, net_change > 0);
	// We set slate.amount to contain the _positive_ net_change for the other party so they can derive expectations.
	slate.amount = net_change.abs() as u64;
	debug!("contract::new => slate amount: {}", slate.amount);

	// Perform setup for the slate
	setup::compute(w, keychain_mask, &mut slate, setup_args)
}
