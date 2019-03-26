// Copyright 2018 The Grin Developers
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

//! Contains V1 of the slate (grin 1.0.1, 1.0.2)
//! Changes from V0:
//! * Addition of a version field to Slate struct

use crate::grin_core::core::transaction::{KernelFeatures, OutputFeatures};
use crate::grin_core::map_vec;
use crate::grin_keychain::BlindingFactor;
use crate::grin_util::secp;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use uuid::Uuid;

use crate::slate_versions::v0::{
	InputV0, OutputV0, ParticipantDataV0, SlateV0, TransactionBodyV0, TransactionV0, TxKernelV0,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlateV1 {
	/// The number of participants intended to take part in this transaction
	pub num_participants: usize,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// The core transaction data:
	/// inputs, outputs, kernels, kernel offset
	pub tx: TransactionV1,
	/// base amount (excluding fee)
	pub amount: u64,
	/// fee amount
	pub fee: u64,
	/// Block height for the transaction
	pub height: u64,
	/// Lock height
	pub lock_height: u64,
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub participant_data: Vec<ParticipantDataV1>,
	/// Version
	pub version: u64,
	#[serde(skip)]
	pub orig_version: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantDataV1 {
	/// Id of participant in the transaction. (For now, 0=sender, 1=rec)
	pub id: u64,
	/// Public key corresponding to private blinding factor
	pub public_blind_excess: PublicKey,
	/// Public key corresponding to private nonce
	pub public_nonce: PublicKey,
	/// Public partial signature
	pub part_sig: Option<Signature>,
	/// A message for other participants
	pub message: Option<String>,
	/// Signature, created with private key corresponding to 'public_blind_excess'
	pub message_sig: Option<Signature>,
}

/// A transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionV1 {
	/// The kernel "offset" k2
	/// excess is k1G after splitting the key k = k1 + k2
	pub offset: BlindingFactor,
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBodyV1,
}

/// TransactionBody is a common abstraction for transaction and block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionBodyV1 {
	/// List of inputs spent by the transaction.
	pub inputs: Vec<InputV1>,
	/// List of outputs the transaction produces.
	pub outputs: Vec<OutputV1>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kernels: Vec<TxKernelV1>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputV1 {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	pub features: OutputFeatures,
	/// The commit referencing the output being spent.
	pub commit: Commitment,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct OutputV1 {
	/// Options for an output's structure or use
	pub features: OutputFeatures,
	/// The homomorphic commitment representing the output amount
	pub commit: Commitment,
	/// A proof that the commitment is in the right range
	pub proof: RangeProof,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxKernelV1 {
	/// Options for a kernel's structure or use
	pub features: KernelFeatures,
	/// Fee originally included in the transaction this proof is for.
	pub fee: u64,
	/// This kernel is not valid earlier than lock_height blocks
	/// The max lock_height of all *inputs* to this transaction
	pub lock_height: u64,
	/// Remainder of the sum of all transaction commitments. If the transaction
	/// is well formed, amounts components should sum to zero and the excess
	/// is hence a valid public key.
	pub excess: Commitment,
	/// The signature proving the excess is a valid public key, which signs
	/// the transaction fee.
	pub excess_sig: secp::Signature,
}

// V1 to V0 Downgrade Conversion ////////////////////////////////////

impl From<SlateV1> for SlateV0 {
	fn from(slate: SlateV1) -> SlateV0 {
		let SlateV1 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			participant_data,
			version: _,
			orig_version: _,
		} = slate;
		let tx = TransactionV0::from(tx);
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV0::from(data));
		SlateV0 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			participant_data,
		}
	}
}

impl From<&ParticipantDataV1> for ParticipantDataV0 {
	fn from(data: &ParticipantDataV1) -> ParticipantDataV0 {
		let ParticipantDataV1 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		} = data;
		let id = *id;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		let message: Option<String> = message.as_ref().map(|t| String::from(&**t));
		let message_sig = *message_sig;
		ParticipantDataV0 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		}
	}
}

impl From<TransactionV1> for TransactionV0 {
	fn from(tx: TransactionV1) -> TransactionV0 {
		let TransactionV1 { offset, body } = tx;
		let body = TransactionBodyV0::from(&body);
		TransactionV0 { offset, body }
	}
}

impl From<&TransactionBodyV1> for TransactionBodyV0 {
	fn from(body: &TransactionBodyV1) -> Self {
		let TransactionBodyV1 {
			inputs,
			outputs,
			kernels,
		} = body;

		let inputs = map_vec!(inputs, |inp| InputV0::from(inp));
		let outputs = map_vec!(outputs, |out| OutputV0::from(out));
		let kernels = map_vec!(kernels, |kern| TxKernelV0::from(kern));
		TransactionBodyV0 {
			inputs,
			outputs,
			kernels,
		}
	}
}

impl From<&InputV1> for InputV0 {
	fn from(input: &InputV1) -> InputV0 {
		let InputV1 { features, commit } = *input;
		InputV0 { features, commit }
	}
}

impl From<&OutputV1> for OutputV0 {
	fn from(output: &OutputV1) -> OutputV0 {
		let OutputV1 {
			features,
			commit,
			proof,
		} = *output;
		OutputV0 {
			features,
			commit,
			proof,
		}
	}
}

impl From<&TxKernelV1> for TxKernelV0 {
	fn from(kernel: &TxKernelV1) -> TxKernelV0 {
		let TxKernelV1 {
			features,
			fee,
			lock_height,
			excess,
			excess_sig,
		} = *kernel;
		TxKernelV0 {
			features,
			fee,
			lock_height,
			excess,
			excess_sig,
		}
	}
}

// V0 to V1 Upgrade Conversion ////////////////////////////////////

impl From<SlateV0> for SlateV1 {
	fn from(slate: SlateV0) -> SlateV1 {
		let SlateV0 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			participant_data,
		} = slate;
		let tx = TransactionV1::from(tx);
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV1::from(data));
		SlateV1 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			participant_data,
			version: 1,
			orig_version: 0,
		}
	}
}

impl From<&ParticipantDataV0> for ParticipantDataV1 {
	fn from(data: &ParticipantDataV0) -> ParticipantDataV1 {
		let ParticipantDataV0 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		} = data;
		let id = *id;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		let message: Option<String> = message.as_ref().map(|t| String::from(&**t));
		let message_sig = *message_sig;
		ParticipantDataV1 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		}
	}
}

impl From<TransactionV0> for TransactionV1 {
	fn from(tx: TransactionV0) -> TransactionV1 {
		let TransactionV0 { offset, body } = tx;
		let body = TransactionBodyV1::from(&body);
		TransactionV1 { offset, body }
	}
}

impl From<&TransactionBodyV0> for TransactionBodyV1 {
	fn from(body: &TransactionBodyV0) -> Self {
		let TransactionBodyV0 {
			inputs,
			outputs,
			kernels,
		} = body;

		let inputs = map_vec!(inputs, |inp| InputV1::from(inp));
		let outputs = map_vec!(outputs, |out| OutputV1::from(out));
		let kernels = map_vec!(kernels, |kern| TxKernelV1::from(kern));
		TransactionBodyV1 {
			inputs,
			outputs,
			kernels,
		}
	}
}

impl From<&InputV0> for InputV1 {
	fn from(input: &InputV0) -> InputV1 {
		let InputV0 { features, commit } = *input;
		InputV1 { features, commit }
	}
}

impl From<&OutputV0> for OutputV1 {
	fn from(output: &OutputV0) -> OutputV1 {
		let OutputV0 {
			features,
			commit,
			proof,
		} = *output;
		OutputV1 {
			features,
			commit,
			proof,
		}
	}
}

impl From<&TxKernelV0> for TxKernelV1 {
	fn from(kernel: &TxKernelV0) -> TxKernelV1 {
		let TxKernelV0 {
			features,
			fee,
			lock_height,
			excess,
			excess_sig,
		} = *kernel;
		TxKernelV1 {
			features,
			fee,
			lock_height,
			excess,
			excess_sig,
		}
	}
}
