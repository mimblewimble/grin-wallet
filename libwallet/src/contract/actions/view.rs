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

//! Implementation of contract view

use crate::contract::types::ContractView;
use crate::error::Error;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::slate::{Slate, SlateState};
use crate::types::{NodeClient};
use crate::backend::WalletBackend;

/// View contract
pub fn view<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	_encrypted_for: &str,
) -> Result<ContractView, Error>
where
	C: NodeClient,
	K: Keychain,
{
	// NOTE: This should only be run on slates that we received and were signed for us.
	// Otherwise, you can't really predict who the party doing the next step should be.

	// Reject a slate we can't interpret. Standard2/3 and Invoice2/3 are valid mid/late
	// flow states (they fall through to suggested_net_change = None below), so only the
	// Unknown state is rejected here.
	if slate.state == SlateState::Unknown {
		return Err(Error::GenericError(
			"Cannot view a slate with an Unknown state".to_string(),
		));
	}
	// Mirror the contract setup bound so a tampered slate can't surface a bogus count.
	if slate.num_participants < 1 || slate.num_participants > 2 {
		return Err(Error::GenericError(format!(
			"Unsupported num_participants: {} (expected 1 or 2)",
			slate.num_participants
		)));
	}
	// Checked conversion so an out-of-range amount can't wrap into a bogus net change.
	let suggested_net_change: Option<i64> = match slate.state {
		SlateState::Invoice1 => Some(i64::try_from(slate.amount).map_err(|_| {
			Error::GenericError(format!("Slate amount {} exceeds i64", slate.amount))
		})?),
		SlateState::Standard1 => Some(-i64::try_from(slate.amount).map_err(|_| {
			Error::GenericError(format!("Slate amount {} exceeds i64", slate.amount))
		})?),
		_ => None,
	};
	let is_executed = false;
	// Count signatures present (a participant is "complete" once it has a partial sig).
	let num_sigs = slate
		.participant_data
		.clone()
		.into_iter()
		.filter(|v| v.is_complete())
		.count();

	// If we have a local context for this slate we've agreed on a net change; surface it.
	let agreed_net_change = match w.get_private_context(keychain_mask, slate.id.as_bytes()) {
		Ok(ctx) => Some(ctx.get_net_change()),
		Err(Error::NotFoundErr(_)) => None,
		Err(e) => return Err(e),
	};

	// TODO: Maybe we can know if the slate was meant for us if it was encrypted for us.
	// A possible issue is that one can encrypt the same slate for 10 people.
	let ct_view = ContractView {
		num_participants: slate.num_participants,
		suggested_net_change: suggested_net_change,
		agreed_net_change,
		num_sigs: num_sigs as u8,
		is_executed: is_executed,
		..Default::default()
	};
	Ok(ct_view)
}
