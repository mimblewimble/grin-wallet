// Copyright 2023 The Grin Developers
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

//! Contains V5 of the slate (version as yet undetermined)
//!
//! V5 is experimental and should remain so until the relevant RFCs are accepted.
//!
//! Changes from V4:
//! #### Top-Level Slate Struct
//! *
//! #### PaymentInfoV5
//! * `saddr`, i.e. `sender_address` in main Slate becomes optional
//! * `rsig` is renamed to `psig`, corresponding to rename of `receiver_signature` to `promise_signature` in main Slate
//!
//! * `ptype` identifies the payment proof type
//! * `ts` adds an optional timestamp, serialized as seconds since the epoch
//! * `memo` adds optional payment details

use crate::grin_core::core::FeeFields;
use crate::grin_core::libtx::secp_ser;
use crate::grin_keychain::BlindingFactor;
use crate::slate::{PaymentMemo, PaymentProofType};
use crate::slate_versions::ser;
use chrono::prelude::{DateTime, Utc};
use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::VerifyingKey as DalekPublicKey;
use serde_with::TimestampSeconds;
use uuid::Uuid;

// These fields have the same representation in V4 and V5
pub use crate::slate_versions::common::{
	sig_is_blank, Coinbase as CoinbaseV5, Commits as CommitsV5,
	KernelFeaturesArgs as KernelFeaturesArgsV5, OutputFeatures as OutputFeaturesV5,
	ParticipantData as ParticipantDataV5, SlateState as SlateStateV5,
};

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VersionCompatInfoV5 {
	/// The current version of the slate format
	pub version: u16,
	/// Version of grin block header this slate is compatible with
	pub block_header_version: u16,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct PaymentInfoV5 {
	pub ptype: PaymentProofType,
	#[serde(default)]
	#[serde(with = "ser::option_dalek_pubkey_serde")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub saddr: Option<DalekPublicKey>,
	#[serde(with = "ser::dalek_pubkey_serde")]
	pub raddr: DalekPublicKey,
	#[serde_as(as = "Option<TimestampSeconds<i64>>")]
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ts: Option<DateTime<Utc>>,
	#[serde(default = "default_promise_signature_none")]
	#[serde(with = "ser::option_dalek_sig_serde")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub psig: Option<DalekSignature>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub memo: Option<PaymentMemo>,
}

fn default_promise_signature_none() -> Option<DalekSignature> {
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
