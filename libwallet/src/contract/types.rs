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

//! Types related to a contract

use crate::error::Error;
use crate::grin_core::libtx::secp_ser;
pub use crate::slate::{PaymentMemo, PaymentProofType as ProofType};
use crate::slate_versions::ser as dalek_ser;
use ed25519_dalek::VerifyingKey as DalekPublicKey;

/// Default confirmations for contract inputs
/// Keep in sync with contract new in grin-wallet.yml
pub const DEFAULT_MINIMUM_CONFIRMATIONS: u64 = 10;

/// Output selection args
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OutputSelectionArgs {
	/// Required confirmations, or None to use the stored value or default
	pub minimum_confirmations: Option<u64>,
	/// Which inputs we want to use - default to payjoin if available with Some("any")
	pub use_inputs: Option<String>,
	/// Change output specification: explicit output amounts in nanogrin, not including
	/// fee subtraction. e.g. [3, 1, 4, 0, 0] describes 5 outputs, two of which hold 0 value.
	pub make_outputs: Option<Vec<u64>>,
}

impl OutputSelectionArgs {
	/// Number of confirmations required when selecting inputs
	pub fn effective_minimum_confirmations(&self) -> u64 {
		self.minimum_confirmations
			.unwrap_or(DEFAULT_MINIMUM_CONFIRMATIONS)
	}

	/// We try to make a payjoin if use_inputs has a value (either commitments or Some("any"))
	pub fn is_payjoin(&self) -> bool {
		self.use_inputs.is_some()
	}
	/// Return a list of commitments we must use
	pub fn required_inputs(&self) -> Option<Vec<&str>> {
		if self.use_inputs.is_some() {
			Some(
				self.use_inputs.as_ref().unwrap()[..]
					.split(",")
					.filter(|x| *x != "any")
					.collect(),
			)
		} else {
			None
		}
	}
	/// Returns the output amounts (nanogrin) we have to create. Amounts arrive already
	/// parsed by the caller (e.g. the CLI), so this is just an accessor.
	pub fn output_amounts(&self) -> Result<Vec<u64>, Error> {
		Ok(self.make_outputs.clone().unwrap_or_default())
	}
	/// Returns the sum of our output amounts
	pub fn sum_output_amounts(&self) -> Result<u64, Error> {
		self.output_amounts()?
			.iter()
			.try_fold(0u64, |acc, v| acc.checked_add(*v))
			.ok_or_else(|| Error::GenericError("output amounts sum overflow".to_string()))
	}
	/// Returns the number of custom outputs
	pub fn num_custom_outputs(&self) -> usize {
		self.make_outputs.as_ref().map(|v| v.len()).unwrap_or(0)
	}
}

impl Default for OutputSelectionArgs {
	fn default() -> OutputSelectionArgs {
		OutputSelectionArgs {
			minimum_confirmations: None,
			use_inputs: Some(String::from("any")),
			make_outputs: None,
		}
	}
}

/// Proof generation parameters that can be provided during new or sign phases
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProofArgs {
	/// If net change is positive during this step, whether to suppress the creation of payment proof
	pub suppress_proof: bool,
	/// Requested early payment proof type
	pub proof_type: ProofType,
	/// Memo used when this step creates the payment proof
	pub memo: Option<PaymentMemo>,
	/// Sender address (required at some stage, may not necessarily be in slate so can be provided explicitly)
	#[serde(with = "dalek_ser::option_dalek_pubkey_serde")]
	pub sender_address: Option<DalekPublicKey>,
}

impl Default for ProofArgs {
	fn default() -> ProofArgs {
		ProofArgs {
			// Proofs are opt-in (#729): a `false` default made the receiver build an
			// invoice promise with no sender address, failing with NoSenderAddressProvided.
			suppress_proof: true,
			proof_type: ProofType::Invoice,
			memo: None,
			sender_address: None,
		}
	}
}

/// Contract Setup - defines how we pick inputs/outputs and what we expect from a contract. Both
/// 'new' and 'sign' actions perform a setup phase which is why their endpoints take these parameters.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ContractSetupArgsAPI {
	/// The human readable account name from which to draw outputs
	/// for the transaction, overriding whatever the active account is as set via the
	/// [`set_active_account`](../grin_wallet_api/owner/struct.Owner.html#method.set_active_account) method.
	/// Only used when creating the local contract context
	pub src_acct_name: Option<String>,
	/// The net change we will agree on. The amount is in nanogrins (`1 G = 1_000_000_000nG`).
	/// The value is positive when we are on the receiving end and negative when we are the sender.
	/// It is optional because we could have agreed on it before we reach the sign e.g. when we create new contract
	pub net_change: Option<i64>,
	/// The number of participants in a contract. Used for computing our kernel fee contribution
	pub num_participants: u8,
	/// Fee rate in nanogrin per unit of transaction weight
	/// `None` uses the wallet default. The rate is fixed when the local context is created
	/// and may be omitted in later steps
	pub fee_rate: Option<u32>,
	/// Should we perform an early lock of outputs
	pub add_outputs: bool,
	/// Output selection arguments
	pub selection_args: OutputSelectionArgs,
	/// Proof arguments
	pub proof_args: ProofArgs,
}

impl Default for ContractSetupArgsAPI {
	fn default() -> ContractSetupArgsAPI {
		ContractSetupArgsAPI {
			src_acct_name: None,
			net_change: None,
			num_participants: 2,
			fee_rate: None,
			add_outputs: false,
			selection_args: OutputSelectionArgs {
				..Default::default()
			},
			proof_args: ProofArgs::default(),
		}
	}
}

/// Contract New
#[derive(Clone, Serialize, Deserialize)]
pub struct ContractNewArgsAPI {
	/// Setup args - contract new also initiates the setup by default
	pub setup_args: ContractSetupArgsAPI,
	/// Blocks until wallets should stop signing the contract
	/// Only used when creating a new contract context
	#[serde(with = "secp_ser::opt_string_or_u64", default)]
	pub ttl_blocks: Option<u64>,
}

impl Default for ContractNewArgsAPI {
	fn default() -> ContractNewArgsAPI {
		ContractNewArgsAPI {
			ttl_blocks: None,
			setup_args: ContractSetupArgsAPI {
				src_acct_name: None,
				net_change: None,
				num_participants: 2,
				fee_rate: None,
				add_outputs: false,
				selection_args: OutputSelectionArgs {
					..Default::default()
				},
				proof_args: ProofArgs::default(),
			},
		}
	}
}

/// ContractView
#[derive(Clone, Serialize, Deserialize)]
pub struct ContractView {
	/// Every slatepack has a number of participants
	pub num_participants: u8,
	/// Suggested value for the party at step2 (only provided if slatepack is at step1)
	pub suggested_net_change: Option<i64>,
	/// Agreed net_change, when known from the context or transaction log
	pub agreed_net_change: Option<i64>,
	/// This wallet's fee contribution, when known from the context or transaction log
	pub own_fee: Option<u64>,
	/// Agreed balance change after this wallet's fee, or None while the fee is unknown
	pub balance_change: Option<i64>,
	/// Number of singatures on the contract
	pub num_sigs: u8,
	/// Has the contract been executed on chain
	pub is_executed: bool,
	/// Whether the slate contains an unexpected commitment from this wallet.
	/// This is unknown when the private context is no longer available, input
	/// features are missing, or the slate contains no transaction.
	#[serde(default)]
	pub own_commitment_status: OwnCommitmentStatus,
}

/// Result of comparing a contract slate with commitments owned by this wallet
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnCommitmentStatus {
	/// No unexpected wallet commitment was found
	Clean,
	/// The slate contains an unexpected input from this wallet
	UnexpectedInput,
	/// The slate contains an unexpected output from this wallet
	UnexpectedOutput,
	/// The slate contains an unexpected input and output from this wallet
	UnexpectedInputAndOutput,
	/// The comparison could not be made
	#[default]
	#[serde(other)]
	Unknown,
}

impl Default for ContractView {
	fn default() -> ContractView {
		ContractView {
			num_participants: 2,
			suggested_net_change: None,
			agreed_net_change: None,
			own_fee: None,
			balance_change: None,
			num_sigs: 0,
			is_executed: false,
			own_commitment_status: OwnCommitmentStatus::Unknown,
		}
	}
}

/// Arguments for contract revoke function
#[derive(Clone, Serialize, Deserialize)]
pub struct ContractRevokeArgsAPI {
	/// Tx id to cancel
	pub tx_id: u32,
	/// Account containing the transaction, or the active account when omitted
	pub src_acct_name: Option<String>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn selection_args_json() {
		let explicit: OutputSelectionArgs = serde_json::from_value(serde_json::json!({
			"minimum_confirmations": 3,
			"use_inputs": "any",
			"make_outputs": null
		}))
		.unwrap();
		assert_eq!(explicit.minimum_confirmations, Some(3));

		let omitted: OutputSelectionArgs = serde_json::from_value(serde_json::json!({
			"use_inputs": "any",
			"make_outputs": null
		}))
		.unwrap();
		assert_eq!(omitted.minimum_confirmations, None);
		assert_eq!(
			omitted.effective_minimum_confirmations(),
			DEFAULT_MINIMUM_CONFIRMATIONS
		);
	}

	#[test]
	fn contract_ttl_json() {
		let mut args = ContractNewArgsAPI::default();
		args.ttl_blocks = Some(20);
		let mut json = serde_json::to_value(&args).unwrap();
		assert_eq!(json["ttl_blocks"], "20");

		json["ttl_blocks"] = serde_json::json!(20);
		assert_eq!(
			serde_json::from_value::<ContractNewArgsAPI>(json.clone())
				.unwrap()
				.ttl_blocks,
			Some(20)
		);

		json.as_object_mut().unwrap().remove("ttl_blocks");
		assert_eq!(
			serde_json::from_value::<ContractNewArgsAPI>(json)
				.unwrap()
				.ttl_blocks,
			None
		);
	}

	#[test]
	fn fee_rate_json() {
		let mut json = serde_json::to_value(ContractSetupArgsAPI::default()).unwrap();
		json["fee_rate"] = serde_json::json!(2);
		assert_eq!(
			serde_json::from_value::<ContractSetupArgsAPI>(json.clone())
				.unwrap()
				.fee_rate,
			Some(2)
		);
		json.as_object_mut().unwrap().remove("fee_rate");
		assert_eq!(
			serde_json::from_value::<ContractSetupArgsAPI>(json)
				.unwrap()
				.fee_rate,
			None
		);
	}

	#[test]
	fn own_commitment_status_json() {
		for (status, value) in [
			(OwnCommitmentStatus::Clean, "clean"),
			(OwnCommitmentStatus::UnexpectedInput, "unexpected_input"),
			(OwnCommitmentStatus::UnexpectedOutput, "unexpected_output"),
			(
				OwnCommitmentStatus::UnexpectedInputAndOutput,
				"unexpected_input_and_output",
			),
			(OwnCommitmentStatus::Unknown, "unknown"),
		] {
			let json = format!("\"{}\"", value);
			assert_eq!(serde_json::to_string(&status).unwrap(), json);
			assert_eq!(
				serde_json::from_str::<OwnCommitmentStatus>(&json).unwrap(),
				status
			);
		}
		assert_eq!(
			serde_json::from_str::<OwnCommitmentStatus>("\"future_status\"").unwrap(),
			OwnCommitmentStatus::Unknown
		);

		let view: ContractView = serde_json::from_value(serde_json::json!({
			"num_participants": 2,
			"suggested_net_change": null,
			"agreed_net_change": null,
			"num_sigs": 0,
			"is_executed": false
		}))
		.unwrap();
		assert_eq!(view.own_commitment_status, OwnCommitmentStatus::Unknown);
	}
}
