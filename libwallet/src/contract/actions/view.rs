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

use super::initial_net_change;
use crate::backend::WalletBackend;
use crate::contract;
use crate::contract::types::{ContractView, OwnCommitmentStatus};
use crate::error::Error;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::SecretKey;
use crate::internal::updater;
use crate::slate::{Slate, SlateState};
use crate::types::{NodeClient, TxLogEntry};

fn balance_change(net_change: Option<i64>, fee: Option<u64>) -> Result<Option<i64>, Error> {
	match (net_change, fee) {
		(Some(change), Some(fee)) => {
			let fee = i64::try_from(fee)
				.map_err(|_| Error::GenericError(format!("Contract fee {} exceeds i64", fee)))?;
			change
				.checked_sub(fee)
				.map(Some)
				.ok_or_else(|| Error::GenericError("Contract balance change overflow".to_string()))
		}
		_ => Ok(None),
	}
}

fn tx_net_change(tx: &TxLogEntry) -> Result<i64, Error> {
	let credited = i64::try_from(tx.amount_credited).map_err(|_| {
		Error::GenericError(format!(
			"Contract credit {} exceeds i64",
			tx.amount_credited
		))
	})?;
	let debited = i64::try_from(tx.amount_debited).map_err(|_| {
		Error::GenericError(format!("Contract debit {} exceeds i64", tx.amount_debited))
	})?;
	credited
		.checked_sub(debited)
		.ok_or_else(|| Error::GenericError("Contract net change overflow".to_string()))
}

/// View contract
pub fn view<C, K>(
	w: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
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
	contract::utils::verify_num_participants(slate.num_participants)?;
	let context = match w.get_private_context(keychain_mask, slate.id.as_bytes()) {
		Ok(context) => Some(context),
		Err(Error::NotFoundErr(_)) => None,
		Err(e) => return Err(e),
	};
	let suggested_net_change = initial_net_change(&slate.state, slate.amount)?;
	// A contract is executed once the transaction it produced has confirmed. That is
	// recorded on our own tx log entry for this slate, so no chain lookup is needed; a
	// slate we have never signed simply has no entry and is not executed.
	let txs = updater::retrieve_txs(w, None, Some(slate.id), None, None, false)?;
	let is_executed = txs.iter().any(|tx| tx.confirmed);
	let signed_tx = txs
		.iter()
		.find(|tx| contract::utils::is_signed_tx(tx, slate.id));
	let has_signed = signed_tx.is_some();
	let tx = signed_tx.or_else(|| txs.first());
	let stored_ttl = context
		.as_ref()
		.map(|context| context.contract_ttl_cutoff_height)
		.or_else(|| tx.map(|tx| tx.ttl_cutoff_height));
	if let Some(expected) = stored_ttl {
		contract::utils::verify_ttl(expected, slate)?;
	}
	// Once we have signed, the context identifies the commitments we added. If it has
	// already been removed, the slate no longer carries enough information to do that.
	let own_commitment_status = if slate.tx.is_none() || (context.is_none() && !txs.is_empty()) {
		OwnCommitmentStatus::Unknown
	} else {
		contract::slate::own_commitment_status(
			w,
			keychain_mask,
			slate,
			if has_signed { context.as_ref() } else { None },
		)?
	};
	// Count signatures present (a participant is "complete" once it has a partial sig).
	let num_sigs = slate
		.participant_data
		.iter()
		.filter(|v| v.is_complete())
		.count();

	// Read the agreed change from the context, or from the transaction log once it is gone.
	let agreed_net_change = context
		.as_ref()
		.and_then(|context| context.setup_args.as_ref())
		.and_then(|args| args.net_change)
		.map(Ok)
		.or_else(|| tx.map(tx_net_change))
		.transpose()?;
	let own_fee = context
		.as_ref()
		.and_then(|context| context.fee)
		.or_else(|| tx.and_then(|tx| tx.fee))
		.map(|fee| fee.fee());
	let balance_change = balance_change(agreed_net_change, own_fee)?;

	let ct_view = ContractView {
		num_participants: slate.num_participants,
		suggested_net_change: suggested_net_change,
		agreed_net_change,
		own_fee,
		balance_change,
		num_sigs: num_sigs as u8,
		is_executed: is_executed,
		own_commitment_status,
		..Default::default()
	};
	Ok(ct_view)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn suggested_change_direction() {
		assert_eq!(
			initial_net_change(&SlateState::Standard1, 10).unwrap(),
			Some(10)
		);
		assert_eq!(
			initial_net_change(&SlateState::Invoice1, 10).unwrap(),
			Some(-10)
		);
		assert_eq!(
			initial_net_change(&SlateState::Standard2, 10).unwrap(),
			None
		);
	}

	#[test]
	fn balance_change_includes_fee() {
		assert_eq!(balance_change(Some(10), Some(2)).unwrap(), Some(8));
		assert_eq!(balance_change(Some(-10), Some(2)).unwrap(), Some(-12));
		assert_eq!(balance_change(Some(10), None).unwrap(), None);
		assert!(balance_change(Some(i64::MIN), Some(1)).is_err());
	}

	#[test]
	fn reads_change_from_tx_log() {
		let mut tx = TxLogEntry::new(
			crate::grin_keychain::Identifier::zero(),
			crate::types::TxLogEntryType::TxReceived,
			0,
		);
		tx.amount_credited = 10;
		assert_eq!(tx_net_change(&tx).unwrap(), 10);
		tx.amount_credited = 0;
		tx.amount_debited = 10;
		assert_eq!(tx_net_change(&tx).unwrap(), -10);
	}
}
