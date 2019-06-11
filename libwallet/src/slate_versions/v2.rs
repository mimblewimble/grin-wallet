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

//! Contains V2 of the slate (grin-wallet 1.1.0)
//! Changes from V1:
//! * ParticipantData struct fields serialized as hex strings instead of arrays:
//!    * public_blind_excess
//!    * public_nonce
//!    * part_sig
//!    * message_sig
//! * Transaction fields serialized as hex strings instead of arrays:
//!    * offset
//! * Input field serialized as hex strings instead of arrays:
//!    commit
//! * Output fields serialized as hex strings instead of arrays:
//!    commit
//!    proof
//! * TxKernel fields serialized as hex strings instead of arrays:
//!    commit
//!    signature
//! * version field removed
//! * VersionCompatInfo struct created with fields and added to beginning of struct
//!    version: u16
//!    orig_version: u16,
//!    block_header_version: u16,

use crate::grin_core::core::transaction::{KernelFeatures, OutputFeatures};
use crate::grin_core::libtx::secp_ser;
use crate::grin_keychain::BlindingFactor;
use crate::grin_util::secp;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlateV2 {
	/// Versioning info
	pub version_info: VersionCompatInfoV2,
	/// The number of participants intended to take part in this transaction
	pub num_participants: usize,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// The core transaction data:
	/// inputs, outputs, kernels, kernel offset
	pub tx: TransactionV2,
	/// base amount (excluding fee)
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount: u64,
	/// fee amount
	#[serde(with = "secp_ser::string_or_u64")]
	pub fee: u64,
	/// Block height for the transaction
	#[serde(with = "secp_ser::string_or_u64")]
	pub height: u64,
	/// Lock height
	#[serde(with = "secp_ser::string_or_u64")]
	pub lock_height: u64,
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub participant_data: Vec<ParticipantDataV2>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionCompatInfoV2 {
	/// The current version of the slate format
	pub version: u16,
	/// Original version this slate was converted from
	pub orig_version: u16,
	/// Version of grin block header this slate is compatible with
	pub block_header_version: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantDataV2 {
	/// Id of participant in the transaction. (For now, 0=sender, 1=rec)
	#[serde(with = "secp_ser::string_or_u64")]
	pub id: u64,
	/// Public key corresponding to private blinding factor
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_blind_excess: PublicKey,
	/// Public key corresponding to private nonce
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_nonce: PublicKey,
	/// Public partial signature
	#[serde(with = "secp_ser::option_sig_serde")]
	pub part_sig: Option<Signature>,
	/// A message for other participants
	pub message: Option<String>,
	/// Signature, created with private key corresponding to 'public_blind_excess'
	#[serde(with = "secp_ser::option_sig_serde")]
	pub message_sig: Option<Signature>,
}

/// A transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionV2 {
	/// The kernel "offset" k2
	/// excess is k1G after splitting the key k = k1 + k2
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	pub offset: BlindingFactor,
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBodyV2,
}

/// TransactionBody is a common abstraction for transaction and block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionBodyV2 {
	/// List of inputs spent by the transaction.
	pub inputs: Vec<InputV2>,
	/// List of outputs the transaction produces.
	pub outputs: Vec<OutputV2>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kernels: Vec<TxKernelV2>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputV2 {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	pub features: OutputFeatures,
	/// The commit referencing the output being spent.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct OutputV2 {
	/// Options for an output's structure or use
	pub features: OutputFeatures,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
	/// A proof that the commitment is in the right range
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::rangeproof_from_hex"
	)]
	pub proof: RangeProof,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxKernelV2 {
	/// Options for a kernel's structure or use
	pub features: KernelFeatures,
	/// Fee originally included in the transaction this proof is for.
	#[serde(with = "secp_ser::string_or_u64")]
	pub fee: u64,
	/// This kernel is not valid earlier than lock_height blocks
	/// The max lock_height of all *inputs* to this transaction
	#[serde(with = "secp_ser::string_or_u64")]
	pub lock_height: u64,
	/// Remainder of the sum of all transaction commitments. If the transaction
	/// is well formed, amounts components should sum to zero and the excess
	/// is hence a valid public key.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub excess: Commitment,
	/// The signature proving the excess is a valid public key, which signs
	/// the transaction fee.
	#[serde(with = "secp_ser::sig_serde")]
	pub excess_sig: secp::Signature,
}
