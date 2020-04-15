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
//! * `num_participants` becomes an Option
//! * `num_participants` may be omitted from the slate if it is None (null),
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

use crate::grin_core::core::transaction::OutputFeatures;
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
	/// Versioning info
	#[serde(with = "ser::version_info_v4")]
	pub ver: VersionCompatInfoV4,
	/// The number of participants intended to take part in this transaction
	#[serde(default = "default_num_participants_2")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub num_participants: Option<usize>,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// The core transaction data:
	/// inputs, outputs, kernels, kernel offset
	/// Optional as of V4 to allow for a compact
	/// transaction initiation
	#[serde(default = "default_tx_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tx: Option<TransactionV4>,
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
	#[serde(with = "secp_ser::opt_string_or_u64")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(default = "default_lock_height_0")]
	pub lock_height: Option<u64>,
	/// TTL, the block height at which wallets
	/// should refuse to process the transaction and unlock all
	/// associated outputs
	#[serde(with = "secp_ser::opt_string_or_u64")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(default = "default_ttl_none")]
	pub ttl_cutoff_height: Option<u64>,
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub participant_data: Vec<ParticipantDataV4>,
	/// Payment Proof
	#[serde(default = "default_payment_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub payment_proof: Option<PaymentInfoV4>,
}

fn default_payment_none() -> Option<PaymentInfoV4> {
	None
}

fn default_tx_none() -> Option<TransactionV4> {
	None
}

fn default_ttl_none() -> Option<u64> {
	None
}

fn default_num_participants_2() -> Option<usize> {
	None
}

fn default_lock_height_0() -> Option<u64> {
	None
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
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_blind_excess: PublicKey,
	/// Public key corresponding to private nonce
	#[serde(with = "secp_ser::pubkey_serde")]
	pub public_nonce: PublicKey,
	/// Public partial signature
	#[serde(default = "default_part_sig_none")]
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "secp_ser::option_sig_serde")]
	pub part_sig: Option<Signature>,
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

/// A transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionV4 {
	/// The kernel "offset" k2
	/// excess is k1G after splitting the key k = k1 + k2
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	pub offset: BlindingFactor,
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBodyV4,
}

/// TransactionBody is a common abstraction for transaction and block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionBodyV4 {
	/// List of inputs spent by the transaction.
	pub inputs: Vec<InputV4>,
	/// List of outputs the transaction produces.
	pub outputs: Vec<OutputV4>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kernels: Vec<TxKernelV4>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputV4 {
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
pub struct OutputV4 {
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
pub struct TxKernelV4 {
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
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			payment_proof,
		} = slate;
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV4::from(data));
		let ver = VersionCompatInfoV4::from(&version_info);

		let payment_proof = match payment_proof {
			Some(p) => Some(PaymentInfoV4::from(&p)),
			None => None,
		};
		let tx = TransactionV4::from(tx);
		SlateV4 {
			ver,
			num_participants: Some(num_participants),
			id,
			tx: Some(tx),
			amount,
			fee,
			height,
			lock_height: Some(lock_height),
			ttl_cutoff_height,
			participant_data,
			payment_proof,
		}
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
			public_blind_excess,
			public_nonce,
			part_sig,
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
			inputs,
			outputs,
			kernels,
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
			commit,
			proof,
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
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			ver,
			payment_proof,
		} = slate;
		let num_participants = match *num_participants {
			Some(p) => p,
			None => 2,
		};
		let id = *id;
		let amount = *amount;
		let fee = *fee;
		let height = *height;
		let lock_height = match *lock_height {
			Some(l) => l,
			None => 0,
		};
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV3::from(data));
		let version_info = VersionCompatInfoV3::from(ver);
		let payment_proof = match payment_proof {
			Some(p) => Some(PaymentInfoV3::from(p)),
			None => None,
		};
		let tx = match tx {
			Some(t) => TransactionV3::from(t),
			None => {
				return Err(ErrorKind::SlateInvalidDowngrade(
					"Full transaction info required".to_owned(),
				)
				.into())
			}
		};

		let ttl_cutoff_height = *ttl_cutoff_height;
		Ok(SlateV3 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height,
			participant_data,
			version_info,
			payment_proof,
		})
	}
}

impl From<&ParticipantDataV4> for ParticipantDataV3 {
	fn from(data: &ParticipantDataV4) -> ParticipantDataV3 {
		let ParticipantDataV4 {
			public_blind_excess,
			public_nonce,
			part_sig,
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
		let TransactionBodyV4 {
			inputs,
			outputs,
			kernels,
		} = body;

		let inputs = map_vec!(inputs, |inp| InputV3::from(inp));
		let outputs = map_vec!(outputs, |out| OutputV3::from(out));
		let kernels = map_vec!(kernels, |kern| TxKernelV3::from(kern));
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
			commit,
			proof,
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
