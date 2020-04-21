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
//! * `tx` field becomes an Option
//! * `tx` field is omitted from the slate if it is None (null)
//! * `tx` field and enclosed inputs/outputs do not need to be included in the first
//!   leg of a transaction exchange. (All inputs/outputs naturally need to be present at time
//!   of posting).
//! * `num_participants` becomes a u8
//! * `num_participants` may be omitted from the slate if it is the default 2
//!    if `num_participants` is omitted, it's value is assumed to be 2
//! * `lock_height` becomes an Option
//! * `lock_height` may be omitted from the slate if it is None (null),
//!    if `lock_height` is omitted, it's value is assumed to be 2
//! * `ttl_cutoff_height` may be omitted from the slate if it is None (null),
//! * `payment_proof` may be omitted from the slate if it is None (null),
//! * `message` is removed from `participant_info` entries
//! * `message_sig` is removed from `participant_info` entries
//! * `id` is removed from `participant_info` entries. Parties can identify themselves via
//!    private keys stored in the transaction context
//! * `part_sig` may be omitted from a `participant_info` entry if it has not yet been filled out
//! * `receiver_signature` may be omitted from `payment_proof` if it has not yet been filled out

use crate::grin_core::core::transaction::{KernelFeatures, OutputFeatures};
use crate::grin_core::libtx::secp_ser;
use crate::grin_core::map_vec;
use crate::grin_keychain::{BlindingFactor, Identifier};
use crate::grin_util::secp;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use crate::slate::CompatKernelFeatures;
use crate::slate_versions::ser;
use crate::{Error, ErrorKind};
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use std::convert::TryFrom;
use uuid::Uuid;

use crate::slate_versions::v3::{
	InputV3, OutputV3, ParticipantDataV3, PaymentInfoV3, SlateV3, TransactionBodyV3, TransactionV3,
	TxKernelV3, VersionCompatInfoV3,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlateV4 {
	// Required Fields
	/// Versioning info
	#[serde(with = "ser::version_info_v4")]
	pub ver: VersionCompatInfoV4,
	/// Unique transaction ID, selected by sender
	#[serde(with = "ser::uuid_base64")]
	pub id: Uuid,
	/// Slate state
	#[serde(with = "ser::slate_state_v4")]
	pub sta: SlateStateV4,
	// Optional fields depending on state
	/// The number of participants intended to take part in this transaction
	#[serde(default = "default_num_participants_2")]
	#[serde(skip_serializing_if = "num_parts_is_2")]
	pub num_parts: u8,
	/// base amount (excluding fee)
	#[serde(with = "secp_ser::string_or_u64")]
	pub amt: u64,
	/// fee amount
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(default = "default_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	pub fee: u64,
	/// Lock height
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	#[serde(default = "default_u64_0")]
	pub lock_hgt: u64,
	/// TTL, the block height at which wallets
	/// should refuse to process the transaction and unlock all
	/// associated outputs
	#[serde(with = "secp_ser::string_or_u64")]
	#[serde(skip_serializing_if = "u64_is_blank")]
	#[serde(default = "default_u64_0")]
	pub ttl: u64,
	// Structs always required
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub sigs: Vec<ParticipantDataV4>,
	// Situational, but required at somepoint tx
	/// Inputs/Output commits added to slate
	#[serde(default = "default_coms_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub coms: Option<Vec<CommitsV4>>,
	// Optional Structs
	/// Payment Proof
	#[serde(default = "default_payment_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub payment_proof: Option<PaymentInfoV4>,
}

fn default_payment_none() -> Option<PaymentInfoV4> {
	None
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionCompatInfoV4 {
	/// The current version of the slate format
	pub version: u16,
	/// Version of grin block header this slate is compatible with
	pub block_header_version: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParticipantDataV4 {
	/// Public key corresponding to private blinding factor
	#[serde(with = "ser::pubkey_base64")]
	pub xs: PublicKey,
	/// Public key corresponding to private nonce
	#[serde(with = "ser::pubkey_base64")]
	pub nonce: PublicKey,
	/// Public partial signature
	#[serde(default = "default_part_sig_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "ser::option_sig_base64")]
	pub part: Option<Signature>,
}

fn default_part_sig_none() -> Option<Signature> {
	None
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PaymentInfoV4 {
	#[serde(with = "ser::dalek_pubkey_serde")]
	pub sender_address: DalekPublicKey,
	#[serde(with = "ser::dalek_pubkey_serde")]
	pub receiver_address: DalekPublicKey,
	#[serde(default = "default_receiver_signature_none")]
	#[serde(with = "ser::option_dalek_sig_serde")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub receiver_signature: Option<DalekSignature>,
}

fn default_receiver_signature_none() -> Option<DalekSignature> {
	None
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CommitsV4 {
	/// Options for an output's structure or use
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub f: OutputFeatures,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "ser::as_base64",
		deserialize_with = "ser::commitment_from_base64"
	)]
	pub c: Commitment,
	/// A proof that the commitment is in the right range
	/// Only applies for transaction outputs
	#[serde(with = "ser::option_rangeproof_base64")]
	pub p: Option<RangeProof>,
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

fn inputs_are_empty(v: &Vec<InputV4>) -> bool {
	v.len() == 0
}

fn default_inputs() -> Vec<InputV4> {
	vec![]
}

fn outputs_are_empty(v: &Vec<OutputV4>) -> bool {
	v.len() == 0
}

fn default_outputs() -> Vec<OutputV4> {
	vec![]
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputV4 {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub features: OutputFeatures,
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
	pub features: OutputFeatures,
	/// The homomorphic commitment representing the output amount
	#[serde(
		serialize_with = "ser::as_base64",
		deserialize_with = "ser::commitment_from_base64"
	)]
	pub com: Commitment,
	/// A proof that the commitment is in the right range
	#[serde(
		serialize_with = "ser::as_base64",
		deserialize_with = "ser::rangeproof_from_base64"
	)]
	pub prf: RangeProof,
}

fn default_output_feature() -> OutputFeatures {
	OutputFeatures::Plain
}

fn output_feature_is_plain(o: &OutputFeatures) -> bool {
	*o == OutputFeatures::Plain
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

fn sig_is_blank(s: &secp::Signature) -> bool {
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

// V3 to V4 For Slate
impl From<SlateV3> for SlateV4 {
	fn from(slate: SlateV3) -> SlateV4 {
		let SlateV3 {
			version_info,
			num_participants,
			id,
			tx: _,
			amount,
			fee,
			height: _,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			payment_proof,
		} = slate.clone();
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV4::from(data));
		let ver = VersionCompatInfoV4::from(&version_info);

		let payment_proof = match payment_proof {
			Some(p) => Some(PaymentInfoV4::from(&p)),
			None => None,
		};
		let ttl_cutoff_height = match ttl_cutoff_height {
			None => 0,
			Some(n) => n,
		};
		SlateV4 {
			ver,
			num_parts: num_participants as u8,
			id,
			sta: SlateStateV4::Unknown,
			coms: (&slate).into(),
			amt: amount,
			fee,
			lock_hgt: lock_height,
			ttl: ttl_cutoff_height,
			sigs: participant_data,
			payment_proof,
		}
	}
}

impl From<&SlateV3> for Option<Vec<CommitsV4>> {
	fn from(slate: &SlateV3) -> Option<Vec<CommitsV4>> {
		let mut ret_vec = vec![];
		for i in slate.tx.body.inputs.iter() {
			ret_vec.push(CommitsV4 {
				f: i.features,
				c: i.commit,
				p: None,
			});
		}
		for o in slate.tx.body.outputs.iter() {
			ret_vec.push(CommitsV4 {
				f: o.features,
				c: o.commit,
				p: Some(o.proof),
			});
		}
		Some(ret_vec)
	}
}

impl From<&ParticipantDataV3> for ParticipantDataV4 {
	fn from(data: &ParticipantDataV3) -> ParticipantDataV4 {
		let ParticipantDataV3 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		} = data;
		let _id = *id;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		let _message: Option<String> = message.as_ref().map(|t| String::from(&**t));
		let _message_sig = *message_sig;
		ParticipantDataV4 {
			xs: public_blind_excess,
			nonce: public_nonce,
			part: part_sig,
		}
	}
}

impl From<&VersionCompatInfoV3> for VersionCompatInfoV4 {
	fn from(data: &VersionCompatInfoV3) -> VersionCompatInfoV4 {
		let VersionCompatInfoV3 {
			version,
			orig_version,
			block_header_version,
		} = data;
		let version = *version;
		let _orig_version = *orig_version;
		let block_header_version = *block_header_version;
		VersionCompatInfoV4 {
			version,
			block_header_version,
		}
	}
}

impl From<TransactionV3> for TransactionV4 {
	fn from(tx: TransactionV3) -> TransactionV4 {
		let TransactionV3 { offset, body } = tx;
		let body = TransactionBodyV4::from(&body);
		TransactionV4 { offset, body }
	}
}

impl From<&TransactionBodyV3> for TransactionBodyV4 {
	fn from(body: &TransactionBodyV3) -> TransactionBodyV4 {
		let TransactionBodyV3 {
			inputs,
			outputs,
			kernels,
		} = body;

		let inputs = map_vec!(inputs, |inp| InputV4::from(inp));
		let outputs = map_vec!(outputs, |out| OutputV4::from(out));
		let kernels = map_vec!(kernels, |kern| TxKernelV4::from(kern));
		TransactionBodyV4 {
			ins: inputs,
			outs: outputs,
			kers: kernels,
		}
	}
}

impl From<&InputV3> for InputV4 {
	fn from(input: &InputV3) -> InputV4 {
		let InputV3 { features, commit } = *input;
		InputV4 { features, commit }
	}
}

impl From<&OutputV3> for OutputV4 {
	fn from(output: &OutputV3) -> OutputV4 {
		let OutputV3 {
			features,
			commit,
			proof,
		} = *output;
		OutputV4 {
			features,
			com: commit,
			prf: proof,
		}
	}
}

impl From<&TxKernelV3> for TxKernelV4 {
	fn from(kernel: &TxKernelV3) -> TxKernelV4 {
		let (fee, lock_height) = (kernel.fee, kernel.lock_height);
		TxKernelV4 {
			features: kernel.features,
			fee,
			lock_height,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		}
	}
}

impl From<&PaymentInfoV3> for PaymentInfoV4 {
	fn from(input: &PaymentInfoV3) -> PaymentInfoV4 {
		let PaymentInfoV3 {
			sender_address,
			receiver_address,
			receiver_signature,
		} = *input;
		PaymentInfoV4 {
			sender_address,
			receiver_address,
			receiver_signature,
		}
	}
}

// V4 to V3
#[allow(unused_variables)]
impl TryFrom<&SlateV4> for SlateV3 {
	type Error = Error;
	fn try_from(slate: &SlateV4) -> Result<SlateV3, Error> {
		let SlateV4 {
			num_parts: num_participants,
			id,
			sta: _,
			coms,
			amt: amount,
			fee,
			lock_hgt: lock_height,
			ttl: ttl_cutoff_height,
			sigs: participant_data,
			ver,
			payment_proof,
		} = slate;
		let num_participants = match *num_participants {
			0 => 2,
			n => n,
		};
		let id = *id;
		let amount = *amount;
		let fee = *fee;
		let lock_height = *lock_height;
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV3::from(data));
		let version_info = VersionCompatInfoV3::from(ver);
		let payment_proof = match payment_proof {
			Some(p) => Some(PaymentInfoV3::from(p)),
			None => None,
		};
		let tx: Option<TransactionV3> = slate.into();
		let tx = match tx {
			Some(t) => TransactionV3::from(t),
			None => {
				return Err(ErrorKind::SlateInvalidDowngrade(
					"Full transaction info required".to_owned(),
				)
				.into())
			}
		};

		let ttl_cutoff_height = match *ttl_cutoff_height {
			0 => None,
			n => Some(n),
		};

		Ok(SlateV3 {
			num_participants: num_participants as usize,
			id,
			tx,
			amount,
			fee,
			height: 0,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			version_info,
			payment_proof,
		})
	}
}

// Node's Transaction object and lock height to SlateV4 `coms`
impl From<&SlateV4> for Option<TransactionV3> {
	fn from(slate: &SlateV4) -> Option<TransactionV3> {
		let res = crate::slate::tx_from_slate_v4(slate);
		let tx = match res {
			Some(tx) => tx,
			None => return None,
		};
		let mut out_fee = 0;
		let mut out_lock_height = 0;
		let txv4 = TransactionV3 {
			offset: tx.offset,
			body: TransactionBodyV3 {
				inputs: tx
					.body
					.inputs
					.iter()
					.map(|i| InputV3 {
						features: i.features,
						commit: i.commit,
					})
					.collect(),
				outputs: tx
					.body
					.outputs
					.iter()
					.map(|o| OutputV3 {
						features: o.features,
						commit: o.commit,
						proof: o.proof,
					})
					.collect(),
				kernels: tx
					.body
					.kernels
					.iter()
					.map(|k| TxKernelV3 {
						features: match k.features {
							KernelFeatures::Plain { fee } => {
								out_fee = fee;
								CompatKernelFeatures::Plain
							}
							KernelFeatures::Coinbase => CompatKernelFeatures::Coinbase,
							KernelFeatures::HeightLocked { fee, lock_height } => {
								out_fee = fee;
								out_lock_height = lock_height;
								CompatKernelFeatures::HeightLocked
							}
						},
						fee: out_fee,
						lock_height: out_lock_height,
						excess: k.excess,
						excess_sig: k.excess_sig,
					})
					.collect(),
			},
		};
		Some(txv4)
	}
}

impl From<&ParticipantDataV4> for ParticipantDataV3 {
	fn from(data: &ParticipantDataV4) -> ParticipantDataV3 {
		let ParticipantDataV4 {
			xs: public_blind_excess,
			nonce: public_nonce,
			part: part_sig,
		} = data;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		ParticipantDataV3 {
			id: 0,
			public_blind_excess,
			public_nonce,
			part_sig,
			message: None,
			message_sig: None,
		}
	}
}

impl From<&VersionCompatInfoV4> for VersionCompatInfoV3 {
	fn from(data: &VersionCompatInfoV4) -> VersionCompatInfoV3 {
		let VersionCompatInfoV4 {
			version,
			block_header_version,
		} = data;
		let version = *version;
		let orig_version = version;
		let block_header_version = *block_header_version;
		VersionCompatInfoV3 {
			version,
			orig_version,
			block_header_version,
		}
	}
}

impl From<TransactionV4> for TransactionV3 {
	fn from(tx: TransactionV4) -> TransactionV3 {
		let TransactionV4 { offset, body } = tx;
		let body = TransactionBodyV3::from(&body);
		TransactionV3 { offset, body }
	}
}

impl From<&TransactionV4> for TransactionV3 {
	fn from(tx: &TransactionV4) -> TransactionV3 {
		let TransactionV4 { offset, body } = tx;
		let offset = offset.clone();
		let body = TransactionBodyV3::from(body);
		TransactionV3 { offset, body }
	}
}

impl From<&TransactionBodyV4> for TransactionBodyV3 {
	fn from(body: &TransactionBodyV4) -> TransactionBodyV3 {
		let TransactionBodyV4 { ins, outs, kers } = body;

		let inputs = map_vec!(ins, |inp| InputV3::from(inp));
		let outputs = map_vec!(outs, |out| OutputV3::from(out));
		let kernels = map_vec!(kers, |kern| TxKernelV3::from(kern));
		TransactionBodyV3 {
			inputs,
			outputs,
			kernels,
		}
	}
}

impl From<&InputV4> for InputV3 {
	fn from(input: &InputV4) -> InputV3 {
		let InputV4 { features, commit } = *input;
		InputV3 { features, commit }
	}
}

impl From<&OutputV4> for OutputV3 {
	fn from(output: &OutputV4) -> OutputV3 {
		let OutputV4 {
			features,
			com: commit,
			prf: proof,
		} = *output;
		OutputV3 {
			features,
			commit,
			proof,
		}
	}
}

impl From<&TxKernelV4> for TxKernelV3 {
	fn from(kernel: &TxKernelV4) -> TxKernelV3 {
		TxKernelV3 {
			features: kernel.features,
			fee: kernel.fee,
			lock_height: kernel.lock_height,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		}
	}
}

impl From<&PaymentInfoV4> for PaymentInfoV3 {
	fn from(input: &PaymentInfoV4) -> PaymentInfoV3 {
		let PaymentInfoV4 {
			sender_address,
			receiver_address,
			receiver_signature,
		} = *input;
		PaymentInfoV3 {
			sender_address,
			receiver_address,
			receiver_signature,
		}
	}
}
