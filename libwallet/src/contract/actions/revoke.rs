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
use crate::backend::WalletBackend;
use crate::blake2::blake2b::blake2b;
use crate::contract::types::{ContractRevokeArgsAPI, ContractSetupArgsAPI, OutputSelectionArgs};
use crate::contract::{new, sign, utils};
use crate::error::Error;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::internal::tx;
use crate::slate::Slate;
use crate::types::{NodeClient, OutputData, OutputStatus, TxLogEntryType};
use uuid::Uuid;

/// Deterministic slate id for the self-spend that revokes a given contract slate.
/// Derived from the revoked slate id so a revoke interrupted between creating and
/// signing the self-spend resumes by reusing the same context, rather
/// than orphaning a fresh self-spend on each retry.
fn self_spend_slate_id(revoked_slate_id: Uuid) -> Uuid {
	let hash = blake2b(16, b"grin-contract-revoke", revoked_slate_id.as_bytes());
	let mut bytes = [0u8; 16];
	bytes.copy_from_slice(hash.as_bytes());
	Uuid::from_bytes(bytes)
}

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
	let parent_key_id = utils::parent_key_for(w, args.src_acct_name.as_ref())?;

	// Inputs we contributed to tx_id that are still recoverable. Locked => the original tx
	// is still active; Unspent => a previous revoke cancelled it but the self-spend did not
	// finish. Once the self-spend completes these reference the self-spend's tx id instead
	// and are no longer matched here, which makes a repeat revoke a no-op.
	let my_contributed_inputs = w
		.batch(keychain_mask)?
		.iter()?
		.filter(|out| {
			out.tx_log_entry == Some(tx_id)
				&& out.root_key_id == parent_key_id
				&& (out.status == OutputStatus::Locked || out.status == OutputStatus::Unspent)
		})
		.collect::<Vec<OutputData>>();

	// Cancel the original tx only if it is still in a cancellable state. On a resumed revoke
	// it is already a *Cancelled type (and the inputs are Unspent), so we skip straight to
	// re-spending them.
	let revoked = w
		.get_tx_log_entry_by_id(parent_key_id.clone(), tx_id)?
		.ok_or_else(|| Error::NotFoundErr(format!("Transaction {}", tx_id)))?;
	let revoked_slate_id = revoked.tx_slate_id;
	let needs_cancel = matches!(
		revoked.tx_type,
		TxLogEntryType::TxSent
			| TxLogEntryType::TxReceived
			| TxLogEntryType::TxReverted
			| TxLogEntryType::TxSelfSpend
	);
	if needs_cancel {
		// 1. Unlock the inputs by cancelling the original tx.
		tx::cancel_tx(&mut *w, keychain_mask, &parent_key_id, Some(tx_id), None)?;
		// Drop the canceled slate's private context if one still exists (signing already
		// deletes it).
		if let Some(slate_id) = revoked_slate_id {
			match w.get_private_context(keychain_mask, slate_id.as_bytes()) {
				Ok(_) => {
					let mut batch = w.batch(keychain_mask)?;
					batch.delete_private_context(slate_id.as_bytes())?;
					batch.commit()?;
				}
				Err(Error::NotFoundErr(_)) => {}
				Err(e) => return Err(e),
			}
		}
	}

	// Nothing of ours to double-spend: we contributed no inputs, or a prior revoke already
	// re-spent them.
	if my_contributed_inputs.is_empty() {
		return Ok(None);
	}
	let input_commit = my_contributed_inputs[0]
		.commit
		.as_ref()
		.ok_or_else(|| Error::GenericError("Locked input has no cached commitment".to_string()))?;
	// Account label for the self-spend, so recovered funds return to the inputs' account.
	let src_acct_name = w
		.acct_path_iter()?
		.find(|m| m.path == parent_key_id)
		.map(|m| m.label);
	// Deterministic self-spend slate id (when we know the revoked slate) so a crash
	// between new() and sign() is resumed by reusing the same context rather than
	// orphaning a fresh self-spend on the retry.
	let self_spend_id = revoked_slate_id.map(self_spend_slate_id);
	// 2. Create a 1-1 self-spend transaction using this input
	let ct_slate = new(
		w,
		keychain_mask,
		&ContractSetupArgsAPI {
			src_acct_name: src_acct_name.clone(),
			net_change: Some(0), // self-spend
			num_participants: 1,
			fee_rate: None,
			add_outputs: false,
			selection_args: OutputSelectionArgs {
				// Keep revoke at one confirmation
				minimum_confirmations: Some(1),
				use_inputs: Some(String::from(input_commit)),
				..Default::default()
			},
			proof_args: Default::default(),
		},
		None,
		self_spend_id,
	)?;
	let finished_slate = sign(
		w,
		keychain_mask,
		&ct_slate,
		&ContractSetupArgsAPI {
			src_acct_name,
			net_change: None, // we already have it in the context as 0 now
			num_participants: 1,
			fee_rate: None,
			add_outputs: false,
			selection_args: OutputSelectionArgs {
				minimum_confirmations: Some(1),
				use_inputs: Some(String::from(input_commit)),
				..Default::default()
			},
			proof_args: Default::default(),
		},
	)?;

	Ok(Some(finished_slate))
}

#[cfg(test)]
mod tests {
	use super::self_spend_slate_id;
	use uuid::Uuid;

	#[test]
	fn self_spend_id_is_deterministic_and_distinct() {
		let revoked = Uuid::parse_str("936da01f-9abd-4d9d-80c7-02af85c822a8").unwrap();
		// Same revoked slate -> same self-spend id, so a retried revoke reuses the context.
		assert_eq!(self_spend_slate_id(revoked), self_spend_slate_id(revoked));
		// Distinct from the revoked id (the self-spend is a different tx).
		assert_ne!(self_spend_slate_id(revoked), revoked);
		// Different revoked slates -> different self-spend ids.
		let other = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
		assert_ne!(self_spend_slate_id(revoked), self_spend_slate_id(other));
	}
}
