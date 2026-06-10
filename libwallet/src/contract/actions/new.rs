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

use crate::contract;
use crate::contract::actions::setup;
use crate::contract::types::ContractSetupArgsAPI;
use crate::error::Error;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::slate::Slate;
use crate::types::{Context, NodeClient};
use crate::backend::WalletBackend;
use uuid::Uuid;

/// Create a new contract with initial setup done by the initiator. `slate_id`, when
/// provided, fixes the slate id (rather than a random one) so the caller can make a
/// retried creation idempotent: get_or_create reuses the existing context for that id.
pub fn new<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	setup_args: &ContractSetupArgsAPI,
	slate_id: Option<Uuid>,
) -> Result<Slate, Error>
where
	C: NodeClient,
	K: Keychain,
{
	// Compute state for 'new'
	let (slate, mut context) = compute(w, keychain_mask, setup_args, slate_id)?;

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

/// Compute logic for new
pub fn compute<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	setup_args: &ContractSetupArgsAPI,
	slate_id: Option<Uuid>,
) -> Result<(Slate, Context), Error>
where
	C: NodeClient,
	K: Keychain,
{
	let net_change = setup_args.net_change.ok_or_else(|| {
		Error::GenericError("Contract requires a net change (--send or --receive)".to_string())
	})?;
	debug!("contract::new => net_change passed: {}", net_change);

	// Initialize a new contract (if net_change is positive, I'm the receiver meaning this is invoice flow)
	let num_participants = setup_args.num_participants;
	let mut slate = Slate::blank(num_participants, net_change > 0);
	// Use a caller-supplied id when given, so a retried creation reuses the same context.
	if let Some(id) = slate_id {
		slate.id = id;
	}
	// We set slate.amount to contain the _positive_ net_change for the other party so they can derive expectations.
	// unsigned_abs avoids the i64::MIN overflow panic of abs().
	slate.amount = net_change.unsigned_abs();
	debug!("contract::new => slate amount: {}", slate.amount);

	// Perform setup for the slate
	setup::compute(w, keychain_mask, &mut slate, setup_args)
}
