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
use crate::types::{NodeClient, WalletBackend};

/// View contract
pub fn view<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	encrypted_for: &str,
) -> Result<ContractView, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// NOTE: This should only be run on slates that we received and were signed for us.
	// Otherwise, you can't really predict who the party doing the next step should be.

	// TODO: Do we need to do any slate verification here?
	let suggested_net_change: Option<i64> = match slate.state {
		// TODO: Check bounds against overflow/underflow
		SlateState::Invoice1 => Some(slate.amount as i64),
		SlateState::Standard1 => Some(-(slate.amount as i64)),
		_ => None,
	};
	let is_executed = false;
	let num_sigs = slate
		.participant_data
		.clone()
		.into_iter()
		.filter(|v| !v.is_complete())
		.count();

	// TODO: Maybe we can know if the slate was meant for us if it was encrypted for us.
	// A possible issue is that one can encrypt the same slate for 10 people.
	let ct_view = ContractView {
		num_participants: slate.num_participants,
		suggested_net_change: suggested_net_change,
		agreed_net_change: None, // TODO
		num_sigs: num_sigs as u8,
		is_executed: is_executed,
		..Default::default()
	};
	Ok(ct_view)
}
