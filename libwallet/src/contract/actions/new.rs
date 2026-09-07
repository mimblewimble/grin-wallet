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

use crate::backend::WalletBackend;
use crate::contract;
use crate::contract::actions::setup;
use crate::contract::types::ContractSetupArgsAPI;
use crate::error::Error;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::slate::Slate;
use crate::types::{Context, NodeClient};
use uuid::Uuid;

/// Create a new contract with initial setup done by the initiator. `slate_id`, when
/// provided, fixes the slate id (rather than a random one) so the caller can make a
/// retried creation idempotent: get_or_create reuses the existing context for that id.
pub fn new<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	setup_args: &ContractSetupArgsAPI,
	ttl_blocks: Option<u64>,
	slate_id: Option<Uuid>,
) -> Result<Slate, Error>
where
	C: NodeClient,
	K: Keychain,
{
	contract::utils::verify_num_participants(setup_args.num_participants)?;
	contract::utils::verify_fee_rate(setup_args.fee_rate)?;
	// Compute state for 'new'
	let (slate, context) = compute(w, keychain_mask, setup_args, ttl_blocks, slate_id)?;

	// Atomically commit state
	contract::utils::save_step(w, keychain_mask, &slate, context, setup_args.add_outputs)?;

	Ok(slate)
}

/// Compute logic for new
pub fn compute<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	setup_args: &ContractSetupArgsAPI,
	ttl_blocks: Option<u64>,
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
	// Contracts start with V4 and move to V5 when their proof data requires it
	slate.version_info.version = 4;
	// Use a caller-supplied id when given, so a retried creation reuses the same context.
	let mut reused_context = false;
	if let Some(id) = slate_id {
		slate.id = id;
		match w.get_private_context(keychain_mask, slate.id.as_bytes()) {
			Ok(context) => {
				slate.ttl_cutoff_height = context.contract_ttl_cutoff_height.unwrap_or(0);
				reused_context = true;
			}
			Err(Error::NotFoundErr(_)) => {}
			Err(e) => return Err(e),
		}
	}
	if !reused_context {
		if let Some(blocks) = ttl_blocks {
			if blocks == 0 {
				return Err(Error::GenericError(
					"Contract TTL must be at least 1 block".to_string(),
				));
			}
			let height = w.w2n_client().get_chain_tip()?.0;
			slate.ttl_cutoff_height = height.checked_add(blocks).ok_or_else(|| {
				Error::GenericError("Contract TTL exceeds the maximum block height".to_string())
			})?;
		}
	}
	// We set slate.amount to contain the _positive_ net_change for the other party so they can derive expectations.
	// unsigned_abs avoids the i64::MIN overflow panic of abs().
	slate.amount = net_change.unsigned_abs();
	debug!("contract::new => slate amount: {}", slate.amount);

	// Perform setup for the slate
	setup::compute(w, keychain_mask, &mut slate, setup_args)
}
