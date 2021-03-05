// Copyright 2021 The Grin Developers
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

use crate::grin_core::core::FeeFields;
use crate::grin_core::core::{Input, Output, TxKernel};
use crate::grin_core::libtx::secp_ser;
use crate::grin_keychain::{BlindingFactor, Identifier};
use crate::grin_util::secp;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use crate::{slate_versions::ser, CbData};
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
	/// fee
	#[serde(skip_serializing_if = "fee_is_zero")]
	#[serde(default = "default_fee")]
	pub fee: FeeFields,
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
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
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

impl From<&Output> for CommitsV4 {
	fn from(out: &Output) -> CommitsV4 {
		CommitsV4 {
			f: out.features().into(),
			c: out.commitment(),
			p: Some(out.proof()),
		}
	}
}

// This will need to be reworked once we no longer support input features with "commit only" inputs.
impl From<&Input> for CommitsV4 {
	fn from(input: &Input) -> CommitsV4 {
		CommitsV4 {
			f: input.features.into(),
			c: input.commitment(),
			p: None,
		}
	}
}

fn default_output_feature() -> OutputFeaturesV4 {
	OutputFeaturesV4(0)
}

fn output_feature_is_plain(o: &OutputFeaturesV4) -> bool {
	o.0 == 0
}

#[derive(Serialize, Deserialize, Copy, Debug, Clone, PartialEq, Eq)]
pub struct OutputFeaturesV4(pub u8);

pub fn sig_is_blank(s: &secp::Signature) -> bool {
	for b in s.to_raw_data().iter() {
		if *b != 0 {
			return false;
		}
	}
	true
}

fn default_range_proof() -> Option<RangeProof> {
	None
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

fn fee_is_zero(f: &FeeFields) -> bool {
	f.is_zero()
}

fn default_fee() -> FeeFields {
	FeeFields::zero()
}

/// A mining node requests new coinbase via the foreign api every time a new candidate block is built.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CoinbaseV4 {
	/// Output
	output: CbOutputV4,
	/// Kernel
	kernel: CbKernelV4,
	/// Key Id
	key_id: Option<Identifier>,
}

impl From<CbData> for CoinbaseV4 {
	fn from(cb: CbData) -> CoinbaseV4 {
		CoinbaseV4 {
			output: CbOutputV4::from(&cb.output),
			kernel: CbKernelV4::from(&cb.kernel),
			key_id: cb.key_id,
		}
	}
}

impl From<&Output> for CbOutputV4 {
	fn from(output: &Output) -> CbOutputV4 {
		CbOutputV4 {
			features: CbOutputFeatures::Coinbase,
			commit: output.commitment(),
			proof: output.proof(),
		}
	}
}

impl From<&TxKernel> for CbKernelV4 {
	fn from(kernel: &TxKernel) -> CbKernelV4 {
		CbKernelV4 {
			features: CbKernelFeatures::Coinbase,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		}
	}
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
enum CbOutputFeatures {
	Coinbase,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
enum CbKernelFeatures {
	Coinbase,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
struct CbOutputV4 {
	features: CbOutputFeatures,
	#[serde(serialize_with = "secp_ser::as_hex")]
	commit: Commitment,
	#[serde(serialize_with = "secp_ser::as_hex")]
	proof: RangeProof,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CbKernelV4 {
	features: CbKernelFeatures,
	#[serde(serialize_with = "secp_ser::as_hex")]
	excess: Commitment,
	#[serde(with = "secp_ser::sig_serde")]
	excess_sig: secp::Signature,
}
