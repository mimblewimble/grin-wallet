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
use crate::types::{NodeClient, OutputData, OutputStatus, TxLogEntryType};
use crate::backend::WalletBackend;

/// Contract revocation is done by double-spending the input
pub fn revoke<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	args: &ContractRevokeArgsAPI,
) -> Result<Option<Slate>, Error>
where
	C: NodeClient,
	K: Keychain,
{
	// Revoke double-spends an input we contributed to tx_id. cancel_tx, the self-spend
	// new() and sign() each commit separately, so these steps are NOT one atomic unit.
	// revoke() is therefore written to be safely re-invocable: a crash between cancelling
	// and finishing the self-spend leaves our inputs Unspent but still tagged with tx_id,
	// and a second call resumes from there. cancel_tx must run first because a Locked
	// output is ineligible for selection (OutputData::eligible_to_spend), so the self-spend
	// cannot be built until the input is unlocked.
	// FUTURE: we may want to boost fees if we notice the original tx in the mempool.
	let tx_id = args.tx_id;

	// Inputs we contributed to tx_id that are still recoverable. Locked => the original tx
	// is still active; Unspent => a previous revoke cancelled it but the self-spend did not
	// finish. Once the self-spend completes these reference the self-spend's tx id instead
	// and are no longer matched here, which makes a repeat revoke a no-op.
	let my_contributed_inputs = w
		.batch(keychain_mask)?
		.iter()?
		.filter(|out| {
			out.tx_log_entry == Some(tx_id)
				&& (out.status == OutputStatus::Locked || out.status == OutputStatus::Unspent)
		})
		.collect::<Vec<OutputData>>();

	// Determine the account that owns the inputs so the cancel and the self-spend target it
	// rather than whatever account happens to be active.
	let parent_key_id = match my_contributed_inputs.first() {
		Some(out) => out.root_key_id.clone(),
		None => w.parent_key_id(),
	};

	// Cancel the original tx only if it is still in a cancellable state. On a resumed revoke
	// it is already a *Cancelled type (and the inputs are Unspent), so we skip straight to
	// re-spending them.
	let revoked = w.get_tx_log_entry(parent_key_id.clone(), tx_id)?;
	let needs_cancel = match revoked.as_ref() {
		Some(e) => matches!(
			e.tx_type,
			TxLogEntryType::TxSent
				| TxLogEntryType::TxReceived
				| TxLogEntryType::TxReverted
				| TxLogEntryType::TxSelfSpend
		),
		None => false,
	};
	if needs_cancel {
		// 1. Unlock the inputs by cancelling the original tx.
		tx::cancel_tx(&mut *w, keychain_mask, &parent_key_id, Some(tx_id), None)?;
		// Drop the canceled slate's private context if one still exists (signing already
		// deletes it).
		if let Some(slate_id) = revoked.and_then(|e| e.tx_slate_id) {
			if w
				.get_private_context(keychain_mask, slate_id.as_bytes())
				.is_ok()
			{
				let mut batch = w.batch(keychain_mask)?;
				batch.delete_private_context(slate_id.as_bytes())?;
				batch.commit()?;
			}
		}
	}

	// Nothing of ours to double-spend: we contributed no inputs, or a prior revoke already
	// re-spent them.
	if my_contributed_inputs.is_empty() {
		return Ok(None);
	}
	let input_commit = my_contributed_inputs[0].commit.as_ref().ok_or_else(|| {
		Error::GenericError("Locked input has no cached commitment".to_string())
	})?;
	// Account label for the self-spend, so recovered funds return to the inputs' account.
	let src_acct_name = w
		.acct_path_iter()?
		.find(|m| m.path == parent_key_id)
		.map(|m| m.label);
	// 2. Create a 1-1 self-spend transaction using this input
	let ct_slate = new(
		w,
		keychain_mask,
		&ContractSetupArgsAPI {
			src_acct_name: src_acct_name.clone(),
			net_change: Some(0), // self-spend
			num_participants: 1,
			add_outputs: false,
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
			src_acct_name,
			net_change: None, // we already have it in the context as 0 now
			num_participants: 1,
			add_outputs: false,
			selection_args: OutputSelectionArgs {
				use_inputs: Some(String::from(input_commit)),
				..Default::default()
			},
			proof_args: Default::default(),
		},
	)?;

	Ok(Some(finished_slate))
}
