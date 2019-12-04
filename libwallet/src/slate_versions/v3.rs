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
use crate::grin_core::map_vec;
use crate::grin_keychain::{BlindingFactor, Identifier};
use crate::grin_util::secp;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use crate::slate::CompatKernelFeatures;
use crate::slate_versions::ser as dalek_ser;
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use uuid::Uuid;

use crate::slate_versions::v2::{
	InputV2, OutputV2, ParticipantDataV2, SlateV2, TransactionBodyV2, TransactionV2, TxKernelV2,
	VersionCompatInfoV2,
};

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
	#[serde(with = "secp_ser::opt_string_or_u64")]
	pub ttl_cutoff_height: Option<u64>,
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
	#[serde(with = "dalek_ser::dalek_pubkey_serde")]
	pub receiver_address: DalekPublicKey,
	#[serde(with = "dalek_ser::option_dalek_sig_serde")]
	pub receiver_signature: Option<DalekSignature>,
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

// V2 to V3 For Slate
impl From<SlateV2> for SlateV3 {
	fn from(slate: SlateV2) -> SlateV3 {
		let SlateV2 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			participant_data,
			version_info,
		} = slate;
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV3::from(data));
		let version_info = VersionCompatInfoV3::from(&version_info);
		let tx = TransactionV3::from(tx);
		SlateV3 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			ttl_cutoff_height: None,
			participant_data,
			version_info,
			payment_proof: None,
		}
	}
}

impl From<&ParticipantDataV2> for ParticipantDataV3 {
	fn from(data: &ParticipantDataV2) -> ParticipantDataV3 {
		let ParticipantDataV2 {
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
		ParticipantDataV3 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		}
	}
}

impl From<&VersionCompatInfoV2> for VersionCompatInfoV3 {
	fn from(data: &VersionCompatInfoV2) -> VersionCompatInfoV3 {
		let VersionCompatInfoV2 {
			version,
			orig_version,
			block_header_version,
		} = data;
		let version = *version;
		let orig_version = *orig_version;
		let block_header_version = *block_header_version;
		VersionCompatInfoV3 {
			version,
			orig_version,
			block_header_version,
		}
	}
}

impl From<TransactionV2> for TransactionV3 {
	fn from(tx: TransactionV2) -> TransactionV3 {
		let TransactionV2 { offset, body } = tx;
		let body = TransactionBodyV3::from(&body);
		TransactionV3 { offset, body }
	}
}

impl From<&TransactionBodyV2> for TransactionBodyV3 {
	fn from(body: &TransactionBodyV2) -> TransactionBodyV3 {
		let TransactionBodyV2 {
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

impl From<&InputV2> for InputV3 {
	fn from(input: &InputV2) -> InputV3 {
		let InputV2 { features, commit } = *input;
		InputV3 { features, commit }
	}
}

impl From<&OutputV2> for OutputV3 {
	fn from(output: &OutputV2) -> OutputV3 {
		let OutputV2 {
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

impl From<&TxKernelV2> for TxKernelV3 {
	fn from(kernel: &TxKernelV2) -> TxKernelV3 {
		let (fee, lock_height) = (kernel.fee, kernel.lock_height);
		TxKernelV3 {
			features: kernel.features,
			fee,
			lock_height,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		}
	}
}

// V3 to V2
#[allow(unused_variables)]
impl From<&SlateV3> for SlateV2 {
	fn from(slate: &SlateV3) -> SlateV2 {
		let SlateV3 {
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
		} = slate;
		let num_participants = *num_participants;
		let id = *id;
		let tx = TransactionV2::from(tx);
		let amount = *amount;
		let fee = *fee;
		let height = *height;
		let lock_height = *lock_height;
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV2::from(data));
		let version_info = VersionCompatInfoV2::from(version_info);
		SlateV2 {
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			participant_data,
			version_info,
		}
	}
}

impl From<&ParticipantDataV3> for ParticipantDataV2 {
	fn from(data: &ParticipantDataV3) -> ParticipantDataV2 {
		let ParticipantDataV3 {
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
		ParticipantDataV2 {
			id,
			public_blind_excess,
			public_nonce,
			part_sig,
			message,
			message_sig,
		}
	}
}

impl From<&VersionCompatInfoV3> for VersionCompatInfoV2 {
	fn from(data: &VersionCompatInfoV3) -> VersionCompatInfoV2 {
		let VersionCompatInfoV3 {
			version,
			orig_version,
			block_header_version,
		} = data;
		let version = *version;
		let orig_version = *orig_version;
		let block_header_version = *block_header_version;
		VersionCompatInfoV2 {
			version,
			orig_version,
			block_header_version,
		}
	}
}

impl From<TransactionV3> for TransactionV2 {
	fn from(tx: TransactionV3) -> TransactionV2 {
		let TransactionV3 { offset, body } = tx;
		let body = TransactionBodyV2::from(&body);
		TransactionV2 { offset, body }
	}
}

impl From<&TransactionV3> for TransactionV2 {
	fn from(tx: &TransactionV3) -> TransactionV2 {
		let TransactionV3 { offset, body } = tx;
		let offset = offset.clone();
		let body = TransactionBodyV2::from(body);
		TransactionV2 { offset, body }
	}
}

impl From<&TransactionBodyV3> for TransactionBodyV2 {
	fn from(body: &TransactionBodyV3) -> TransactionBodyV2 {
		let TransactionBodyV3 {
			inputs,
			outputs,
			kernels,
		} = body;

		let inputs = map_vec!(inputs, |inp| InputV2::from(inp));
		let outputs = map_vec!(outputs, |out| OutputV2::from(out));
		let kernels = map_vec!(kernels, |kern| TxKernelV2::from(kern));
		TransactionBodyV2 {
			inputs,
			outputs,
			kernels,
		}
	}
}

impl From<&InputV3> for InputV2 {
	fn from(input: &InputV3) -> InputV2 {
		let InputV3 { features, commit } = *input;
		InputV2 { features, commit }
	}
}

impl From<&OutputV3> for OutputV2 {
	fn from(output: &OutputV3) -> OutputV2 {
		let OutputV3 {
			features,
			commit,
			proof,
		} = *output;
		OutputV2 {
			features,
			commit,
			proof,
		}
	}
}

impl From<&TxKernelV3> for TxKernelV2 {
	fn from(kernel: &TxKernelV3) -> TxKernelV2 {
		TxKernelV2 {
			features: kernel.features,
			fee: kernel.fee,
			lock_height: kernel.lock_height,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		}
	}
}
