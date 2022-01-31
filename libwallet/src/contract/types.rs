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
use crate::grin_core::consensus;

/// Output selection args
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OutputSelectionArgs {
	/// Constraint on how many confirmations used inputs must have
	pub min_input_confirmation: u64,
	/// Which inputs we want to use - default to payjoin if available with Some("any")
	pub use_inputs: Option<String>,
	/// Change output specification (comma separated amounts which don't include fee subtraction)
	/// e.g. "3,1,4,0,0" describes 5 outputs two of which hold 0 value
	pub make_outputs: Option<String>,
}

impl OutputSelectionArgs {
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
	/// Returns the outputs we have to create
	pub fn output_amounts(&self) -> Vec<u64> {
		if self.make_outputs.is_some() {
			let output_amounts: Vec<u64> = self.make_outputs.as_ref().unwrap()[..]
				.split(",")
				// TODO: move consensus code outside of here. Consider turning make_outputs to Vec<u64>
				.map(|amt| (amt.parse::<f64>().unwrap() * consensus::GRIN_BASE as f64) as u64)
				.collect();
			output_amounts
		} else {
			vec![]
		}
	}
	/// Returns the sum of our output amounts
	pub fn sum_output_amounts(&self) -> u64 {
		self.output_amounts().iter().sum()
	}
	/// Returns the number of custom outputs
	pub fn num_custom_outputs(&self) -> usize {
		self.output_amounts().len()
	}

	// TODO: make sure to validate this: if custom outputs are specified, it has to be a payjoin.
}

impl Default for OutputSelectionArgs {
	fn default() -> OutputSelectionArgs {
		OutputSelectionArgs {
			min_input_confirmation: 10,
			use_inputs: Some(String::from("any")),
			make_outputs: None,
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
	pub src_acct_name: Option<String>,
	/// The net change we will agree on. The amount is in nanogrins (`1 G = 1_000_000_000nG`).
	/// The value is positive when we are on the receiving end and negative when we are the sender.
	/// It is optional because we could have agreed on it before we reach the sign e.g. when we create new contract
	pub net_change: Option<i64>,
	/// The number of participants in a contract. Used for computing our kernel fee contribution
	pub num_participants: u8,
	/// Should we perform an early lock of outputs
	pub add_outputs: bool,
	/// Output selection arguments
	pub selection_args: OutputSelectionArgs,
}

impl Default for ContractSetupArgsAPI {
	fn default() -> ContractSetupArgsAPI {
		ContractSetupArgsAPI {
			src_acct_name: None,
			net_change: None,
			num_participants: 2,
			add_outputs: false,
			selection_args: OutputSelectionArgs {
				..Default::default()
			},
		}
	}
}

/// Contract New
#[derive(Clone, Serialize, Deserialize)]
pub struct ContractNewArgsAPI {
	/// TODO: do we need the target_slate_version?
	/// Optionally set the output target slate version (acceptable
	/// down to the minimum slate version compatible with the current. If `None` the slate
	/// is generated with the latest version.
	pub target_slate_version: Option<u16>,
	/// Setup args - contract new also initiates the setup by default
	pub setup_args: ContractSetupArgsAPI,
}

impl Default for ContractNewArgsAPI {
	fn default() -> ContractNewArgsAPI {
		ContractNewArgsAPI {
			target_slate_version: None,
			setup_args: ContractSetupArgsAPI {
				src_acct_name: None,
				net_change: None,
				num_participants: 2,
				add_outputs: false,
				selection_args: OutputSelectionArgs {
					..Default::default()
				},
			},
		}
	}
}

/// ContractView
#[derive(Clone, Serialize, Deserialize)]
pub struct ContractView {
	/// TODO: do we need the target_slate_version?
	pub target_slate_version: Option<u16>,
	/// Every slatepack has a number of participants
	pub num_participants: u8,
	/// Suggested value for the party at step2 (only provided if slatepack is at step1)
	pub suggested_net_change: Option<i64>,
	/// Agreed net_change if we've agreed on it (the context must exist for this)
	// NOTE: we drop the Context once we've signed. Perhaps we should think about dropping
	// only the private keys associated with it to prevent double-signing with the same
	// (pubkey, nonce) pair. This way, we'd retain the history on that wallet instance.
	// There might also be value in forgetting the whole context.
	pub agreed_net_change: Option<i64>,
	/// Number of singatures on the contract
	pub num_sigs: u8,
	/// Has the contract been executed on chain
	pub is_executed: bool,
}

impl Default for ContractView {
	fn default() -> ContractView {
		ContractView {
			target_slate_version: None,
			num_participants: 2,
			suggested_net_change: None,
			agreed_net_change: None,
			num_sigs: 0,
			is_executed: false,
		}
	}
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ContractRevokeArgsAPI {
	/// Tx id to cancel
	pub tx_id: u32,
}
