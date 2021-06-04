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

//! Contains V5 of the slate (grin-wallet 5.1.0)
//! Changes from V4:
//! /#### ParticipantData Struct
//!
//! * `tau_x` is added for creating multisig output range proofs
//! * `tau_one` is added for creating multisig output range proofs
//! * `tau_two` is added for creating multisig output range proofs

use crate::grin_core::core::FeeFields;
use crate::grin_core::core::{Input, Output, TxKernel};
use crate::grin_core::libtx::secp_ser;
use crate::grin_keychain::{BlindingFactor, Identifier};
use crate::grin_util::secp;
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use crate::{slate_versions::ser, CbData};
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlateV5 {
	// Required Fields
	/// Versioning info
	#[serde(with = "ser::version_info_v5")]
	pub ver: VersionCompatInfoV5,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// Slate state
	#[serde(with = "ser::slate_state_v5")]
	pub sta: SlateStateV5,
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
	pub sigs: Vec<ParticipantDataV5>,
	// Situational, but required at some point in the tx
	/// Inputs/Output commits added to slate
	#[serde(default = "default_coms_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub coms: Option<Vec<CommitsV5>>,
	// Optional Structs
	/// Payment Proof
	#[serde(default = "default_payment_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub proof: Option<PaymentInfoV5>,
	/// Kernel features arguments
	#[serde(default = "default_kernel_features_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub feat_args: Option<KernelFeaturesArgsV5>,
}

fn default_payment_none() -> Option<PaymentInfoV5> {
	None
}

fn default_offset_zero() -> BlindingFactor {
	BlindingFactor::zero()
}

fn offset_is_zero(o: &BlindingFactor) -> bool {
	*o == BlindingFactor::zero()
}

fn default_coms_none() -> Option<Vec<CommitsV5>> {
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

fn default_kernel_features_none() -> Option<KernelFeaturesArgsV5> {
	None
}

/// Slate state definition
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SlateStateV5 {
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
	/// Multisig flow, freshly init
	Multisig1,
	///Multisig flow, step 1 proof build
	Multisig2,
	/// Multisig flow, step 2 proof build
	Multisig3,
	/// Multisig flow, final proof step
	Multisig4,
	/// Atomic flow, freshly init
	Atomic1,
	///Atomic flow, return journey
	Atomic2,
	/// Atomic flow, partial signature from initiator
	Atomic3,
	/// Atomic flow, ready for tranasction posting
	Atomic4,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Kernel features arguments definition
pub struct KernelFeaturesArgsV5 {
	/// Lock height, for HeightLocked
	pub lock_hgt: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VersionCompatInfoV5 {
	/// The current version of the slate format
	pub version: u16,
	/// Version of grin block header this slate is compatible with
	pub block_header_version: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ParticipantDataV5 {
	/// Public key corresponding to private blinding factor
	#[serde(with = "secp_ser::pubkey_serde")]
	pub xs: PublicKey,
	/// Public key corresponding to private nonce
	#[serde(with = "secp_ser::pubkey_serde")]
	pub nonce: PublicKey,
	/// Public key corresponding to atomic secret
	#[serde(default = "default_atomic_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "secp_ser::option_pubkey_serde")]
	pub atomic: Option<PublicKey>,
	/// Public partial signature
	#[serde(default = "default_part_sig_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "secp_ser::option_sig_serde")]
	pub part: Option<Signature>,
	/// Public partial commitment to multisig output value
	#[serde(default = "default_part_com_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "secp_ser::option_commitment_serde")]
	pub part_commit: Option<Commitment>,
	/// Tau X key for shared outputs
	#[serde(default = "default_tau_x_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "secp_ser::option_seckey_serde")]
	pub tau_x: Option<SecretKey>,
	/// Tau part one key for shared outputs
	#[serde(default = "default_tau_part_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "secp_ser::option_pubkey_serde")]
	pub tau_one: Option<PublicKey>,
	/// Tau part two key for shared outputs
	#[serde(default = "default_tau_part_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "secp_ser::option_pubkey_serde")]
	pub tau_two: Option<PublicKey>,
}

fn default_atomic_none() -> Option<PublicKey> {
	None
}

fn default_part_sig_none() -> Option<Signature> {
	None
}

fn default_part_com_none() -> Option<Commitment> {
	None
}

fn default_tau_x_none() -> Option<SecretKey> {
	None
}

fn default_tau_part_none() -> Option<PublicKey> {
	None
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct PaymentInfoV5 {
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
pub struct CommitsV5 {
	/// Options for an output's structure or use
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub f: OutputFeaturesV5,
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

impl From<&Output> for CommitsV5 {
	fn from(out: &Output) -> CommitsV5 {
		CommitsV5 {
			f: out.features().into(),
			c: out.commitment(),
			p: Some(out.proof()),
		}
	}
}

// This will need to be reworked once we no longer support input features with "commit only" inputs.
impl From<&Input> for CommitsV5 {
	fn from(input: &Input) -> CommitsV5 {
		CommitsV5 {
			f: input.features.into(),
			c: input.commitment(),
			p: None,
		}
	}
}

fn default_output_feature() -> OutputFeaturesV5 {
	OutputFeaturesV5(0)
}

fn output_feature_is_plain(o: &OutputFeaturesV5) -> bool {
	o.0 == 0
}

#[derive(Serialize, Deserialize, Copy, Debug, Clone, PartialEq, Eq)]
pub struct OutputFeaturesV5(pub u8);

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
pub struct CoinbaseV5 {
	/// Output
	output: CbOutputV5,
	/// Kernel
	kernel: CbKernelV5,
	/// Key Id
	key_id: Option<Identifier>,
}

impl From<CbData> for CoinbaseV5 {
	fn from(cb: CbData) -> CoinbaseV5 {
		CoinbaseV5 {
			output: CbOutputV5::from(&cb.output),
			kernel: CbKernelV5::from(&cb.kernel),
			key_id: cb.key_id,
		}
	}
}

impl From<&Output> for CbOutputV5 {
	fn from(output: &Output) -> CbOutputV5 {
		CbOutputV5 {
			features: CbOutputFeatures::Coinbase,
			commit: output.commitment(),
			proof: output.proof(),
		}
	}
}

impl From<&TxKernel> for CbKernelV5 {
	fn from(kernel: &TxKernel) -> CbKernelV5 {
		CbKernelV5 {
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
struct CbOutputV5 {
	features: CbOutputFeatures,
	#[serde(serialize_with = "secp_ser::as_hex")]
	commit: Commitment,
	#[serde(serialize_with = "secp_ser::as_hex")]
	proof: RangeProof,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CbKernelV5 {
	features: CbKernelFeatures,
	#[serde(serialize_with = "secp_ser::as_hex")]
	excess: Commitment,
	#[serde(with = "secp_ser::sig_serde")]
	excess_sig: secp::Signature,
}
