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

//! This module contains old slate versions and conversions to the newest slate version
//! Used for serialization and deserialization of slates in a backwards compatible way.
//! Versions earlier than V3 are removed for the 4.0.0 release, but versioning code
//! remains for future needs

use crate::slate::Slate;
use crate::slate_versions::v4::{CoinbaseV4, SlateV4};
use crate::slate_versions::v4_bin::SlateV4Bin;
use crate::slate_versions::v5::{CoinbaseV5, SlateV5};
use crate::slate_versions::v5_bin::SlateV5Bin;
use crate::types::CbData;
use crate::Error;
use std::convert::TryFrom;

pub mod ser;

#[allow(missing_docs)]
pub mod v4;
#[allow(missing_docs)]
pub mod v4_bin;
#[allow(missing_docs)]
pub mod v5;
#[allow(missing_docs)]
pub mod v5_bin;

/// The most recent version of the slate
pub const CURRENT_SLATE_VERSION: u16 = 5;

/// The grin block header this slate is intended to be compatible with
pub const GRIN_BLOCK_HEADER_VERSION: u16 = 3;

/// Existing versions of the slate
#[derive(EnumIter, Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum SlateVersion {
	/// V5 (Most Current)
	V5,
	/// V4
	V4,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
/// Versions are ordered newest to oldest so serde attempts to
/// deserialize newer versions first, then falls back to older versions.
pub enum VersionedSlate {
	/// Current (5.0.0 Onwards?)
	V5(SlateV5),
	/// Current (4.0.0)
	V4(SlateV4),
}

impl VersionedSlate {
	/// Return slate version
	pub fn version(&self) -> SlateVersion {
		match *self {
			VersionedSlate::V5(_) => SlateVersion::V4,
			VersionedSlate::V4(_) => SlateVersion::V4,
		}
	}

	/// convert this slate type to a specified older version
	pub fn into_version(slate: Slate, version: SlateVersion) -> Result<VersionedSlate, Error> {
		match version {
			SlateVersion::V5 => Ok(VersionedSlate::V5(slate.into())),
			SlateVersion::V4 => Ok(VersionedSlate::V4(slate.into())),
		}
	}
}

impl From<VersionedSlate> for Slate {
	fn from(slate: VersionedSlate) -> Slate {
		match slate {
			VersionedSlate::V5(s) => Slate::from(s),
			VersionedSlate::V4(s) => Slate::from(s),
		}
	}
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
/// Binary versions, can only be parsed 1:1 into the appropriate
/// version, and VersionedSlate can up/downgrade from there
pub enum VersionedBinSlate {
	/// Version 4, binary
	V4(SlateV4Bin),
	/// Version 5, binary
	V5(SlateV5Bin),
}

impl TryFrom<VersionedSlate> for VersionedBinSlate {
	type Error = Error;
	fn try_from(slate: VersionedSlate) -> Result<VersionedBinSlate, Error> {
		match slate {
			VersionedSlate::V5(s) => Ok(VersionedBinSlate::V5(SlateV5Bin(s))),
			VersionedSlate::V4(s) => Ok(VersionedBinSlate::V4(SlateV4Bin(s))),
		}
	}
}

impl From<VersionedBinSlate> for VersionedSlate {
	fn from(slate: VersionedBinSlate) -> VersionedSlate {
		match slate {
			VersionedBinSlate::V5(s) => VersionedSlate::V5(s.0),
			VersionedBinSlate::V4(s) => VersionedSlate::V4(s.0),
		}
	}
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
/// Versions are ordered newest to oldest so serde attempts to
/// deserialize newer versions first, then falls back to older versions.
pub enum VersionedCoinbase {
	/// Current supported coinbase version.
	V5(CoinbaseV5),
	/// Previous version (no difference)
	V4(CoinbaseV4),
}

impl VersionedCoinbase {
	/// convert this coinbase data to a specific versioned representation for the json api.
	pub fn into_version(cb: CbData, version: SlateVersion) -> VersionedCoinbase {
		match version {
			SlateVersion::V5 => VersionedCoinbase::V5(cb.into()),
			SlateVersion::V4 => VersionedCoinbase::V4(cb.into()),
		}
	}
}
#[cfg(test)]
mod tests {
	use crate::grin_core::core::transaction::{FeeFields, OutputFeatures};
	use crate::grin_util::from_hex;
	use crate::grin_util::secp::key::PublicKey;
	use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
	use crate::grin_util::secp::Signature;
	use crate::slate::{KernelFeaturesArgs, ParticipantData, PaymentInfo, PaymentMemo};
	use crate::slate_versions::v5::{CommitsV5, SlateV5};
	use crate::{slate, Error, Slate, VersionedBinSlate, VersionedSlate};
	use chrono::{DateTime, NaiveDateTime, Utc};
	use ed25519_dalek::PublicKey as DalekPublicKey;
	use ed25519_dalek::Signature as DalekSignature;
	use grin_core::global::{set_local_chain_type, ChainTypes};
	use grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
	use grin_wallet_util::byte_ser::from_bytes;
	use std::convert::TryInto;

	// Populate a test internal slate with all fields to test conversions
	fn populate_test_slate() -> Result<Slate, Error> {
		let keychain = ExtKeychain::from_random_seed(true).unwrap();
		let switch = SwitchCommitmentType::Regular;

		let mut slate_internal = Slate::blank(2, false);
		let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let id2 = ExtKeychain::derive_key_id(1, 1, 1, 0, 0);
		let skey1 = keychain.derive_key(0, &id1, switch).unwrap();
		let skey2 = keychain.derive_key(0, &id2, switch).unwrap();
		let xs = PublicKey::from_secret_key(keychain.secp(), &skey1).unwrap();
		let nonce = PublicKey::from_secret_key(keychain.secp(), &skey2).unwrap();

		let part = ParticipantData {
			public_blind_excess: xs,
			public_nonce: nonce,
			part_sig: None,
		};
		let part2 = ParticipantData {
			public_blind_excess: xs,
			public_nonce: nonce,
			part_sig: Some(Signature::from_raw_data(&[11; 64]).unwrap()),
		};
		slate_internal.participant_data.push(part.clone());
		slate_internal.participant_data.push(part2);
		slate_internal.participant_data.push(part);

		// Another temp slate to convert commit data into internal 'transaction' like data
		// add some random commit data
		let slate_tmp = Slate::blank(1, false);
		let mut v5 = SlateV5::from(slate_tmp);

		let com1 = CommitsV5 {
			f: OutputFeatures::Plain.into(),
			c: Commitment::from_vec([3u8; 1].to_vec()),
			p: None,
		};
		let com2 = CommitsV5 {
			f: OutputFeatures::Plain.into(),
			c: Commitment::from_vec([4u8; 1].to_vec()),
			p: Some(RangeProof::zero()),
		};

		let mut coms = vec![];
		coms.push(com1.clone());
		coms.push(com1.clone());
		coms.push(com1.clone());
		coms.push(com2);

		v5.coms = Some(coms);

		slate_internal.tx = slate::tx_from_slate_v5(&v5);

		// basic fields
		slate_internal.amount = 23820323;
		slate_internal.kernel_features = 1;
		slate_internal.num_participants = 2;
		slate_internal.kernel_features_args = Some(KernelFeaturesArgs {
			lock_height: 2323223,
		});

		// current style payment proof
		let raw_pubkey_str = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb";
		let b = from_hex(raw_pubkey_str).unwrap();
		let d_pkey = DalekPublicKey::from_bytes(&b).unwrap();
		// Need to remove milliseconds component for comparison. Won't be serialized
		let ts = NaiveDateTime::from_timestamp(Utc::now().timestamp(), 0);
		let ts = DateTime::<Utc>::from_utc(ts, Utc);
		let pm = PaymentMemo {
			memo_type: 0,
			memo: [9; 32],
		};

		let psig = DalekSignature::from_bytes(&[0u8; 64]).unwrap();
		slate_internal.payment_proof = Some(PaymentInfo {
			sender_address: Some(d_pkey.clone()),
			receiver_address: d_pkey.clone(),
			timestamp: ts.clone(),
			promise_signature: Some(psig),
			memo: Some(pm),
		});

		Ok(slate_internal)
	}

	#[test]
	fn slatepack_version_v4_v5() -> Result<(), Error> {
		set_local_chain_type(ChainTypes::Mainnet);

		// Convert V5 slate into V4 slate, check result
		let slate_internal = populate_test_slate()?;
		let v5 = VersionedSlate::V5(slate_internal.clone().into());
		let v4 = VersionedSlate::V4(slate_internal.into());

		let v5_converted: Slate = v5.into();
		let v4_converted: Slate = v4.into();

		assert!(v5_converted.payment_proof.as_ref().unwrap().memo.is_some());

		// Converted from v4 will not have memos and ts will be zeroed out
		assert!(v4_converted.payment_proof.as_ref().unwrap().memo.is_none());
		assert_eq!(
			v4_converted
				.payment_proof
				.as_ref()
				.unwrap()
				.timestamp
				.timestamp(),
			0
		);

		Ok(())
	}

	#[test]
	fn slatepack_version_v4_v5_bin() -> Result<(), Error> {
		set_local_chain_type(ChainTypes::Mainnet);

		// Convert V5 slate into V4 slate, check result
		let slate_internal = populate_test_slate()?;
		let v5 = VersionedSlate::V5(slate_internal.clone().into());
		let v5_bin: VersionedBinSlate = v5.try_into().unwrap();

		let v4 = VersionedSlate::V4(slate_internal.into());
		let v4_bin: VersionedBinSlate = v4.try_into().unwrap();

		let v5_versioned: VersionedSlate = v5_bin.into();
		let v4_versioned: VersionedSlate = v4_bin.into();

		let v5_converted: Slate = v5_versioned.into();
		let v4_converted: Slate = v4_versioned.into();

		assert!(v5_converted.payment_proof.as_ref().unwrap().memo.is_some());
		// Converted from v4 will not have memos and ts will be zeroed out
		assert!(v4_converted.payment_proof.as_ref().unwrap().memo.is_none());
		assert_eq!(
			v4_converted
				.payment_proof
				.as_ref()
				.unwrap()
				.timestamp
				.timestamp(),
			0
		);

		Ok(())
	}
}
