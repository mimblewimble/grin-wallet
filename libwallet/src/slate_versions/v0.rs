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

//! Contains V0 of the slate (grin 1.0.0)
//! And methods to downgrade v1 to v0
use crate::grin_core::core::transaction::{KernelFeatures, OutputFeatures};
use crate::grin_keychain::BlindingFactor;
use crate::grin_util::secp;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlateV0 {
	/// The number of participants intended to take part in this transaction
	pub num_participants: usize,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// The core transaction data:
	/// inputs, outputs, kernels, kernel offset
	pub tx: TransactionV0,
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
	pub participant_data: Vec<ParticipantDataV0>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantDataV0 {
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
pub struct TransactionV0 {
	/// The kernel "offset" k2
	/// excess is k1G after splitting the key k = k1 + k2
	pub offset: BlindingFactor,
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBodyV0,
}

/// TransactionBody is a common abstraction for transaction and block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionBodyV0 {
	/// List of inputs spent by the transaction.
	pub inputs: Vec<InputV0>,
	/// List of outputs the transaction produces.
	pub outputs: Vec<OutputV0>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kernels: Vec<TxKernelV0>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputV0 {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	pub features: OutputFeatures,
	/// The commit referencing the output being spent.
	pub commit: Commitment,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct OutputV0 {
	/// Options for an output's structure or use
	pub features: OutputFeatures,
	/// The homomorphic commitment representing the output amount
	pub commit: Commitment,
	/// A proof that the commitment is in the right range
	pub proof: RangeProof,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxKernelV0 {
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
