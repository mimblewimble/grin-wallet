// Copyright 2019 The Grin Developers
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

//! Contains V3 of the slate (grin-wallet 3.0.0)
//! Changes from V2:
//! * Addition of payment_proof (PaymentInfo struct)
//! * Addition of a u64 ttl_cutoff_height field

use crate::grin_core::core::transaction::OutputFeatures;
use crate::grin_core::libtx::secp_ser;
use crate::grin_keychain::{BlindingFactor, Identifier};
use crate::grin_util::secp;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use crate::slate::CompatKernelFeatures;
use crate::slate_versions::ser as dalek_ser;
use ed25519_dalek::PublicKey as DalekPublicKey;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlateV3 {
	/// Versioning info
	pub version_info: VersionCompatInfoV3,
	/// The number of participants intended to take part in this transaction
	pub num_participants: usize,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// The core transaction data:
	/// inputs, outputs, kernels, kernel offset
	pub tx: TransactionV3,
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
	/// TTL, the block height at which wallets
	/// should refuse to process the transaction and unlock all
	/// associated outputs
	#[serde(with = "secp_ser::string_or_u64")]
	pub ttl_cutoff_height: u64,
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub participant_data: Vec<ParticipantDataV3>,
	/// Payment Proof
	#[serde(default = "default_payment_none")]
	pub payment_proof: Option<PaymentInfoV3>,
}

fn default_payment_none() -> Option<PaymentInfoV3> {
	None
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionCompatInfoV3 {
	/// The current version of the slate format
	pub version: u16,
	/// Original version this slate was converted from
	pub orig_version: u16,
	/// Version of grin block header this slate is compatible with
	pub block_header_version: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantDataV3 {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PaymentInfoV3 {
	#[serde(with = "dalek_ser::dalek_pubkey_serde")]
	pub sender_address: DalekPublicKey,
	#[serde(with = "dalek_ser::option_dalek_pubkey_serde")]
	pub receiver_address: Option<DalekPublicKey>,
	#[serde(with = "secp_ser::option_sig_serde")]
	pub receiver_signature: Option<Signature>,
}

/// A transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionV3 {
	/// The kernel "offset" k2
	/// excess is k1G after splitting the key k = k1 + k2
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	pub offset: BlindingFactor,
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBodyV3,
}

/// TransactionBody is a common abstraction for transaction and block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionBodyV3 {
	/// List of inputs spent by the transaction.
	pub inputs: Vec<InputV3>,
	/// List of outputs the transaction produces.
	pub outputs: Vec<OutputV3>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kernels: Vec<TxKernelV3>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputV3 {
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
pub struct OutputV3 {
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
pub struct TxKernelV3 {
	/// Options for a kernel's structure or use
	pub features: CompatKernelFeatures,
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

/// A mining node requests new coinbase via the foreign api every time a new candidate block is built.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CoinbaseV3 {
	/// Output
	pub output: OutputV3,
	/// Kernel
	pub kernel: TxKernelV3,
	/// Key Id
	pub key_id: Option<Identifier>,
}
