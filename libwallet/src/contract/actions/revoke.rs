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

//! Implementation of contract revoke
use crate::contract::types::{ContractRevokeArgsAPI, ContractSetupArgsAPI, OutputSelectionArgs};
use crate::contract::{new, sign};
use crate::error::Error;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::internal::tx;
use crate::slate::Slate;
use crate::types::{NodeClient, OutputData, OutputStatus, WalletBackend};

/// Contract revocation is done by double-spending the input
pub fn revoke<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	args: &ContractRevokeArgsAPI,
) -> Result<Option<Slate>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// TODO: check the correctness of this. This is essentially old cancel + self-spend.
	// FUTURE: we may want to boost fees in case we notice something in the mempool. There
	// are also race conditions possible. We may not want to label txlogenry as Canceled
	// until the new tx gets on the chain.
	// NOTE: We should not care about deleting the context because as soon as we sign
	// a contract, the context is deleted.

	// If we contributed inputs, we must have locked them at which point we also set the
	// OutputData.tx_log_entry which is the tx_id.
	let tx_id = args.tx_id;

	// Find my outputs that have been Locked and refer to the given tx_id
	let my_contributed_inputs = w
		.batch(keychain_mask)?
		.iter()
		.filter(|out| {
			// Find an output that is Locked and is in the tx_input_commit
			out.status == OutputStatus::Locked
				&& (out.tx_log_entry.is_some() && out.tx_log_entry.as_ref().unwrap() == &tx_id)
		})
		.collect::<Vec<OutputData>>();

	// 1. Unlock the input by calling cancel_tx
	let parent_key_id = w.parent_key_id();
	tx::cancel_tx(&mut *w, keychain_mask, &parent_key_id, Some(tx_id), None)?;

	if my_contributed_inputs.len() == 0 {
		return Ok(None);
	}
	let input_commit = my_contributed_inputs[0].commit.as_ref().unwrap();
	// 2. Create a 1-1 self-spend transaction using this input
	let ct_slate = new(
		w,
		keychain_mask,
		&ContractSetupArgsAPI {
			// TODO: Check the src_acct_name below. This would use the currently active account
			src_acct_name: None,
			net_change: Some(0), // self-spend
			num_participants: 1,
			add_outputs: false,
			delete_context_on_final_sign: true,
			selection_args: OutputSelectionArgs {
				use_inputs: Some(String::from(input_commit)),
				..Default::default()
			},
			proof_args: Default::default(),
		},
	)?;
	let finished_slate = sign(
		w,
		keychain_mask,
		&ct_slate,
		&ContractSetupArgsAPI {
			// TODO: Check the src_acct_name below. This would use the currently active account
			src_acct_name: None,
			net_change: None, // we already have it in the context as 0 now
			num_participants: 1,
			add_outputs: false,
			delete_context_on_final_sign: true,
			selection_args: OutputSelectionArgs {
				use_inputs: Some(String::from(input_commit)),
				..Default::default()
			},
			proof_args: Default::default(),
		},
	)?;
	// TODO: Think about what to do with transaction context of the cancelled slate. It should probably get deleted.

	Ok(Some(finished_slate))
}
