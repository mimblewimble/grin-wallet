// Copyright 2026 The Grin Developers
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

//! Wire types shared by V4 and V5 slates

use crate::grin_core::core::{Input, Output, TxKernel};
use crate::grin_core::libtx::secp_ser;
use crate::grin_keychain::Identifier;
use crate::grin_util::secp;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use crate::{slate_versions::ser, CbData};

/// Slate state definition
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SlateState {
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
	/// Invoice flow, return journey
	Invoice2,
	/// Invoice flow, ready for tranasction posting
	Invoice3,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Kernel features arguments definition
pub struct KernelFeaturesArgs {
	/// Lock height, for HeightLocked
	pub lock_hgt: u64,
}

/// Participant keys and optional partial signature
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ParticipantData {
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

/// Input commitment or output with its range proof
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Commits {
	/// Options for an output's structure or use
	#[serde(default = "default_output_feature")]
	#[serde(skip_serializing_if = "output_feature_is_plain")]
	pub f: OutputFeatures,
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

impl From<&Output> for Commits {
	fn from(out: &Output) -> Commits {
		Commits {
			f: out.features().into(),
			c: out.commitment(),
			p: Some(out.proof()),
		}
	}
}

// This will need to be reworked once we no longer support input features with "commit only" inputs.
impl From<&Input> for Commits {
	fn from(input: &Input) -> Commits {
		Commits {
			f: input.features.into(),
			c: input.commitment(),
			p: None,
		}
	}
}

fn default_output_feature() -> OutputFeatures {
	OutputFeatures(0)
}

fn output_feature_is_plain(o: &OutputFeatures) -> bool {
	o.0 == 0
}

/// Output feature byte
#[derive(Serialize, Deserialize, Copy, Debug, Clone, PartialEq, Eq)]
pub struct OutputFeatures(pub u8);

/// Whether all signature bytes are zero
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

/// A mining node requests new coinbase via the foreign api every time a new candidate block is built.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Coinbase {
	/// Output
	output: CbOutput,
	/// Kernel
	kernel: CbKernel,
	/// Key Id
	key_id: Option<Identifier>,
}

impl From<CbData> for Coinbase {
	fn from(cb: CbData) -> Coinbase {
		Coinbase {
			output: CbOutput::from(&cb.output),
			kernel: CbKernel::from(&cb.kernel),
			key_id: cb.key_id,
		}
	}
}

impl From<&Output> for CbOutput {
	fn from(output: &Output) -> CbOutput {
		CbOutput {
			features: CbOutputFeatures::Coinbase,
			commit: output.commitment(),
			proof: output.proof(),
		}
	}
}

impl From<&TxKernel> for CbKernel {
	fn from(kernel: &TxKernel) -> CbKernel {
		CbKernel {
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
struct CbOutput {
	features: CbOutputFeatures,
	#[serde(serialize_with = "secp_ser::as_hex")]
	commit: Commitment,
	#[serde(serialize_with = "secp_ser::as_hex")]
	proof: RangeProof,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CbKernel {
	features: CbKernelFeatures,
	#[serde(serialize_with = "secp_ser::as_hex")]
	excess: Commitment,
	#[serde(with = "secp_ser::sig_serde")]
	excess_sig: secp::Signature,
}
