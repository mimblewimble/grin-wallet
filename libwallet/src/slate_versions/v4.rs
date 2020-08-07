// Copyright 2020 The Grin Developers
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

//! Contains V4 of the slate (grin-wallet 4.0.0)
//! Changes from V3:
//! /#### Top-Level Slate Struct

//! * The `version_info` struct is removed, and is replaced with `ver`, which has the format "[version]:[block header version]"
//! * `sta` is added, with possible values S1|S2|S3|I1|I2|I3|NA
//! * `num_participants` is renamed to `num_parts`
//! * `num_parts` may be omitted from the slate. If omitted its value is assumed to be 2.
//! * `amount` is renamed to `amt`
//! * `amt` may be removed from the slate on the S2 phase of a transaction.
//! * `fee` may be removed from the slate on the S2 phase of a transaction. It may also be ommited when intiating an I1 transaction, and added during the I2 phase.
//! * `lock_height` is removed
//! * `feat` is added to the slate denoting the Kernel feature set. May be omitted from the slate if kernel is plain (0)
//! * `ttl_cutoff_height` is renamed to `ttl`
//! * `ttl` may be omitted from the slate. If omitted its value is assumed to be 0 (no TTL).
//! *  The `participant_data` struct is renamed to `sigs`
//! * `tx` is removed
//! *  The `coms` (commitments) array is added, from which the final transaction object can be reconstructed
//! *  The `payment_proof` struct is renamed to `proof`
//! * The feat_args struct is added, which may be populated for non-Plain kernels
//! * `proof` may be omitted from the slate if it is None (null),
//! * `off` (offset) is added, and will be modified by every participant in the transaction with a random
//! value - the value of their inputs' blinding factors
//!
//! #### Participant Data (`sigs`)
//!
//! * `public_blind_excess` is renamed to `xs`
//! * `public_nonce` is renamed to `nonce`
//! * `part_sig` is renamed to `part`
//! * `part` may be omitted if it has not yet been filled out
//! * `message` is removed
//! * `message_sig` is removed
//! * `id` is removed. Parties can identify themselves via the keys stored in their transaction context
//!
//! #### Payment Proof Data (`proof`)
//!
//! *  The `sender_address` field is renamed to `saddr`
//! *  The `receiver_address` field is renamed to `raddr`
//! *  The `receiver_signature` field is renamed to `rsig`
//! * `rsig` may be omitted if it has not yet been filled out

use crate::grin_core::libtx::secp_ser;
use crate::grin_keychain::{BlindingFactor, Identifier};
use crate::grin_util::secp;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use crate::slate::{CompatKernelFeatures, CompatOutputFeatures};
use crate::slate_versions::ser;
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlateV4 {
	// Required Fields
	/// Versioning info
	#[serde(with = "ser::version_info_v4")]
	pub ver: VersionCompatInfoV4,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// Slate state
	#[serde(with = "ser::slate_state_v4")]
	pub sta: SlateStateV4,
	/// Offset, modified by each participant inserting inputs
	/// as the transaction progresses
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	#[serde(default = "default_offset_zero")]
	#[serde(skip_serializing_if = "offset_is_zero")]
	pub off: BlindingFactor,
	// Optional fields depending on state
	/// The number of participants intended to take part in this transaction
	#[serde(default = "default_num_participants_2")]
	#[serde(skip_serializing_if = "num_parts_is_2")]
	pub num_parts: u8,
	/// base amount (excluding fee)
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	#[serde(default = "default_u64_0")]
	pub amt: u64,
	/// fee amount
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(default = "default_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	pub fee: u64,
	/// kernel features, if any
	#[serde(skip_serializing_if = "u8_is_blank")]
	#[serde(default = "default_u8_0")]
	pub feat: u8,
	/// TTL, the block height at which wallets
	/// should refuse to process the transaction and unlock all
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	#[serde(default = "default_u64_0")]
	pub ttl: u64,
	// Structs always required
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub sigs: Vec<ParticipantDataV4>,
	// Situational, but required at some point in the tx
	/// Inputs/Output commits added to slate
	#[serde(default = "default_coms_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub coms: Option<Vec<CommitsV4>>,
	// Optional Structs
	/// Payment Proof
	#[serde(default = "default_payment_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub proof: Option<PaymentInfoV4>,
	/// Kernel features arguments
	#[serde(default = "default_kernel_features_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub feat_args: Option<KernelFeaturesArgsV4>,
}

fn default_payment_none() -> Option<PaymentInfoV4> {
	None
}

fn default_offset_zero() -> BlindingFactor {
	BlindingFactor::zero()
}

fn offset_is_zero(o: &BlindingFactor) -> bool {
	*o == BlindingFactor::zero()
}

fn default_coms_none() -> Option<Vec<CommitsV4>> {
	None
}

fn default_u64_0() -> u64 {
	0
}

fn num_parts_is_2(n: &u8) -> bool {
	*n == 2
}

fn default_num_participants_2() -> u8 {
	2
}

fn default_kernel_features_none() -> Option<KernelFeaturesArgsV4> {
	None
}

/// Slate state definition
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SlateStateV4 {
	/// Unknown, coming from earlier versions of the slate
	Unknown,
	/// Standard flow, freshly init
	Standard1,
	/// Standard flow, return journey
	Standard2,
	/// Standard flow, ready for transaction posting
	Standard3,
	/// Invoice flow, freshly init
	Invoice1,
	///Invoice flow, return journey
	Invoice2,
	/// Invoice flow, ready for tranasction posting
	Invoice3,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Kernel features arguments definition
pub struct KernelFeaturesArgsV4 {
	/// Lock height, for HeightLocked
	pub lock_hgt: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VersionCompatInfoV4 {
	/// The current version of the slate format
	pub version: u16,
	/// Version of grin block header this slate is compatible with
	pub block_header_version: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ParticipantDataV4 {
	/// Public key corresponding to private blinding factor
	#[serde(with = "secp_ser::pubkey_serde")]
	pub xs: PublicKey,
	/// Public key corresponding to private nonce
	#[serde(with = "secp_ser::pubkey_serde")]
	pub nonce: PublicKey,
	/// Public partial signature
	#[serde(default = "default_part_sig_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "secp_ser::option_sig_serde")]
	pub part: Option<Signature>,
}

fn default_part_sig_none() -> Option<Signature> {
	None
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct PaymentInfoV4 {
	#[serde(with = "ser::dalek_pubkey_serde")]
	pub saddr: DalekPublicKey,
	#[serde(with = "ser::dalek_pubkey_serde")]
	pub raddr: DalekPublicKey,
	#[serde(default = "default_receiver_signature_none")]
	#[serde(with = "ser::option_dalek_sig_serde")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub rsig: Option<DalekSignature>,
}

fn default_receiver_signature_none() -> Option<DalekSignature> {
	None
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CommitsV4 {
	/// Options for an output's structure or use
	#[serde(default = "default_output_feature_v4")]
	#[serde(skip_serializing_if = "output_feature_is_plain_v4")]
	pub f: OutputFeaturesV4,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub c: Commitment,
	/// A proof that the commitment is in the right range
	/// Only applies for transaction outputs
	#[serde(with = "ser::option_rangeproof_hex")]
	#[serde(default = "default_range_proof")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p: Option<RangeProof>,
}

#[derive(Serialize, Deserialize, Copy, Debug, Clone, PartialEq, Eq)]
pub struct OutputFeaturesV4(pub u8);

fn default_output_feature_v4() -> OutputFeaturesV4 {
	OutputFeaturesV4(0)
}

fn output_feature_is_plain_v4(o: &OutputFeaturesV4) -> bool {
	o.0 == 0
}

/// A transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionV4 {
	/// The kernel "offset" k2
	/// excess is k1G after splitting the key k = k1 + k2
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	#[serde(default = "default_blinding_factor")]
	#[serde(skip_serializing_if = "blinding_factor_is_zero")]
	pub offset: BlindingFactor,
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBodyV4,
}

fn default_blinding_factor() -> BlindingFactor {
	BlindingFactor::zero()
}

fn blinding_factor_is_zero(bf: &BlindingFactor) -> bool {
	*bf == BlindingFactor::zero()
}

/// TransactionBody is a common abstraction for transaction and block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionBodyV4 {
	/// List of inputs spent by the transaction.
	#[serde(default = "default_inputs")]
	#[serde(skip_serializing_if = "inputs_are_empty")]
	pub ins: Vec<InputV4>,
	/// List of outputs the transaction produces.
	#[serde(default = "default_outputs")]
	#[serde(skip_serializing_if = "outputs_are_empty")]
	pub outs: Vec<OutputV4>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kers: Vec<TxKernelV4>,
}

fn inputs_are_empty(v: &[InputV4]) -> bool {
	v.len() == 0
}

fn default_inputs() -> Vec<InputV4> {
	vec![]
}

fn outputs_are_empty(v: &[OutputV4]) -> bool {
	v.len() == 0
}

fn default_outputs() -> Vec<OutputV4> {
	vec![]
}

fn default_range_proof() -> Option<RangeProof> {
	None
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputV4 {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub features: CompatOutputFeatures,
	/// The commit referencing the output being spent.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct OutputV4 {
	/// Options for an output's structure or use
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub features: CompatOutputFeatures,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub com: Commitment,
	/// A proof that the commitment is in the right range
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::rangeproof_from_hex"
	)]
	pub prf: RangeProof,
}

fn default_output_feature() -> CompatOutputFeatures {
	CompatOutputFeatures::Plain
}

fn output_feature_is_plain(o: &CompatOutputFeatures) -> bool {
	match o {
		CompatOutputFeatures::Plain => true,
		_ => false,
	}
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxKernelV4 {
	/// Options for a kernel's structure or use
	#[serde(default = "default_kernel_feature")]
	#[serde(skip_serializing_if = "kernel_feature_is_plain")]
	pub features: CompatKernelFeatures,
	/// Fee originally included in the transaction this proof is for.
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(default = "default_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	pub fee: u64,
	/// This kernel is not valid earlier than lock_height blocks
	/// The max lock_height of all *inputs* to this transaction
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(default = "default_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	pub lock_height: u64,
	/// Remainder of the sum of all transaction commitments. If the transaction
	/// is well formed, amounts components should sum to zero and the excess
	/// is hence a valid public key.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	#[serde(default = "default_commitment")]
	#[serde(skip_serializing_if = "commitment_is_blank")]
	pub excess: Commitment,
	/// The signature proving the excess is a valid public key, which signs
	/// the transaction fee.
	#[serde(with = "secp_ser::sig_serde")]
	#[serde(default = "default_sig")]
	#[serde(skip_serializing_if = "sig_is_blank")]
	pub excess_sig: secp::Signature,
}

fn default_kernel_feature() -> CompatKernelFeatures {
	CompatKernelFeatures::Plain
}

fn kernel_feature_is_plain(k: &CompatKernelFeatures) -> bool {
	match k {
		CompatKernelFeatures::Plain => true,
		_ => false,
	}
}

fn default_commitment() -> Commitment {
	Commitment::from_vec([0u8; 1].to_vec())
}

fn commitment_is_blank(c: &Commitment) -> bool {
	for b in c.0.iter() {
		if *b != 0 {
			return false;
		}
	}
	true
}

fn default_sig() -> secp::Signature {
	Signature::from_raw_data(&[0; 64]).unwrap()
}

pub fn sig_is_blank(s: &secp::Signature) -> bool {
	for b in s.to_raw_data().iter() {
		if *b != 0 {
			return false;
		}
	}
	true
}

fn default_u64() -> u64 {
	0
}

fn u64_is_blank(u: &u64) -> bool {
	*u == 0
}

fn default_u8_0() -> u8 {
	0
}

fn u8_is_blank(u: &u8) -> bool {
	*u == 0
}
/// A mining node requests new coinbase via the foreign api every time a new candidate block is built.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CoinbaseV4 {
	/// Output
	pub output: OutputV4,
	/// Kernel
	pub kernel: TxKernelV4,
	/// Key Id
	pub key_id: Option<Identifier>,
}
