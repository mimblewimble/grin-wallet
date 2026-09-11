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

const HEIGHT_LOCKED_FEATURE: u8 = 2;
const NRD_FEATURE: u8 = 3;

fn kernel_has_height_arg(feature: u8) -> bool {
	matches!(feature, HEIGHT_LOCKED_FEATURE | NRD_FEATURE)
}

/// Existing versions of the slate
#[derive(EnumIter, Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum SlateVersion {
	/// V5 (Most Current)
	V5,
	/// V4
	V4,
}

impl TryFrom<u16> for SlateVersion {
	type Error = Error;

	fn try_from(version: u16) -> Result<Self, Self::Error> {
		match version {
			4 => Ok(Self::V4),
			5 => Ok(Self::V5),
			version => Err(Error::SlateVersion(version)),
		}
	}
}

impl SlateVersion {
	/// Use V5 only when the slate has fields that V4 cannot store
	/// V4 does not support the proof type, timestamp or memo
	pub fn lowest_for(slate: &Slate) -> SlateVersion {
		match &slate.payment_proof {
			Some(p) if p.requires_v5() => SlateVersion::V5,
			_ => SlateVersion::V4,
		}
	}

	/// The requested output version, raised when the slate needs a newer version
	pub fn output_for(slate: &Slate) -> Result<SlateVersion, Error> {
		let requested = SlateVersion::try_from(slate.version_info.version)?;
		Ok(match SlateVersion::lowest_for(slate) {
			SlateVersion::V5 => SlateVersion::V5,
			SlateVersion::V4 => requested,
		})
	}
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
			VersionedSlate::V5(_) => SlateVersion::V5,
			VersionedSlate::V4(_) => SlateVersion::V4,
		}
	}

	/// convert this slate type to a specified older version
	pub fn into_version(slate: Slate, version: SlateVersion) -> Result<VersionedSlate, Error> {
		match version {
			SlateVersion::V5 => Ok(VersionedSlate::V5(slate.into())),
			SlateVersion::V4 => Ok(VersionedSlate::V4(SlateV4::try_from(slate)?)),
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
/// NB (IMPORTANT): Ensure the slates are listed in reverse chronological
/// order (latest first)
pub enum VersionedBinSlate {
	/// Version 5, binary
	V5(SlateV5Bin),
	/// Version 4, binary
	V4(SlateV4Bin),
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
/// Shared slate fixtures, used by the version conversion tests
#[cfg(test)]
pub mod tests {
	use super::HEIGHT_LOCKED_FEATURE;
	use crate::grin_core::core::transaction::{KernelFeatures, NRDRelativeHeight, OutputFeatures};
	use crate::grin_core::core::FeeFields;
	use crate::grin_util::from_hex;
	use crate::grin_util::secp::key::PublicKey;
	use crate::grin_util::secp::pedersen::Commitment;
	use crate::grin_util::secp::Signature;
	use crate::slate::{
		KernelFeaturesArgs, ParticipantData, PaymentInfo, PaymentMemo, PaymentProofType,
	};
	use crate::slate_versions::v4::SlateV4;
	use crate::slate_versions::v5::{CommitsV5, SlateV5};
	use crate::{
		slate, Error, Slate, SlateVersion, Slatepacker, SlatepackerArgs, VersionedBinSlate,
		VersionedSlate,
	};
	use chrono::{DateTime, Utc};
	use ed25519_dalek::Signature as DalekSignature;
	use ed25519_dalek::VerifyingKey as DalekPublicKey;
	use grin_core::global::{set_local_chain_type, ChainTypes};
	use grin_keychain::{BlindingFactor, ExtKeychain, Keychain, SwitchCommitmentType};
	use grin_wallet_util::byte_ser;
	use std::convert::TryInto;

	/// Populate a test internal slate with all fields to test conversions
	pub fn populate_test_slate() -> Result<Slate, Error> {
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
			p: Some(keychain.secp().bullet_proof(
				42,
				skey1.clone(),
				skey1.clone(),
				skey2,
				None,
				None,
			)),
		};

		let mut coms = vec![];
		coms.push(CommitsV5 {
			f: OutputFeatures::Coinbase.into(),
			c: Commitment::from_vec([5u8; 1].to_vec()),
			p: None,
		});
		coms.push(com1.clone());
		coms.push(com1.clone());
		coms.push(com2);

		v5.coms = Some(coms);

		slate_internal.tx = slate::tx_from_slate_v5(&v5);

		// basic fields
		slate_internal.amount = 23820323;
		slate_internal.kernel_features = HEIGHT_LOCKED_FEATURE;
		slate_internal.num_participants = 3;
		slate_internal.fee_fields = FeeFields::new(0, 42)?;
		slate_internal.ttl_cutoff_height = 100;
		slate_internal.offset = BlindingFactor::from_secret_key(skey1);
		slate_internal.kernel_features_args = Some(KernelFeaturesArgs {
			lock_height: 2323223,
		});

		// current style payment proof
		let raw_pubkey_str = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb";
		let b = from_hex(raw_pubkey_str).unwrap();
		let b = <&[u8; 32]>::try_from(b.as_slice()).unwrap();
		let d_pkey = DalekPublicKey::from_bytes(b).unwrap();
		// Need to remove milliseconds component for comparison. Won't be serialized
		let ts = DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap();
		let pm = PaymentMemo::new("payment details".to_string()).unwrap();

		let psig = DalekSignature::from_bytes(&[11u8; 64]);
		slate_internal.payment_proof = Some(PaymentInfo {
			proof_type: PaymentProofType::Invoice,
			sender_address: Some(d_pkey.clone()),
			receiver_address: d_pkey.clone(),
			timestamp: Some(ts.clone()),
			promise_signature: Some(psig),
			memo: Some(pm),
		});

		Ok(slate_internal)
	}

	fn use_legacy_proof(slate: &mut Slate) {
		if let Some(proof) = slate.payment_proof.as_mut() {
			proof.proof_type = PaymentProofType::Legacy;
			proof.timestamp = None;
			proof.memo = None;
		}
	}

	#[test]
	fn v5_proof_json() -> Result<(), Error> {
		let mut v5 = SlateV5::from(populate_test_slate()?);
		let timestamp = 1_234_567_890;
		v5.proof.as_mut().unwrap().ts = DateTime::from_timestamp(timestamp, 0);
		let mut value = serde_json::to_value(v5).unwrap();
		assert_eq!(value["proof"]["ptype"].as_u64(), Some(1));
		assert_eq!(value["proof"]["ts"].as_i64(), Some(timestamp));
		let decoded: SlateV5 = serde_json::from_value(value.clone()).unwrap();
		assert_eq!(decoded.proof.unwrap().ts.unwrap().timestamp(), timestamp);
		value["proof"].as_object_mut().unwrap().remove("ptype");
		assert!(serde_json::from_value::<SlateV5>(value.clone()).is_err());

		value["proof"]["ptype"] = serde_json::json!(3);
		assert!(serde_json::from_value::<SlateV5>(value).is_err());
		Ok(())
	}

	#[test]
	fn ser_deser_current_slate() -> Result<(), Error> {
		let slate_internal = populate_test_slate()?;
		// Serialize slate into slatepack
		let slatepacker_args = SlatepackerArgs {
			sender: None,
			recipients: vec![],
			dec_key: None,
		};

		let slate_packer = Slatepacker::new(slatepacker_args);
		let slate_packed = slate_packer.create_slatepack(&slate_internal).unwrap();

		let slate_unpacked = slate_packer.get_slate(&slate_packed).unwrap();

		assert_eq!(slate_internal.payment_proof, slate_unpacked.payment_proof);
		let version = SlateVersion::output_for(&slate_internal)?;
		let expected = VersionedSlate::into_version(slate_internal, version.clone())?;
		let recovered = VersionedSlate::into_version(slate_unpacked, version)?;
		assert_eq!(
			serde_json::to_value(recovered).unwrap(),
			serde_json::to_value(expected).unwrap()
		);
		Ok(())
	}

	#[test]
	fn create_slatepack_uses_output_version() -> Result<(), Error> {
		set_local_chain_type(ChainTypes::Mainnet);
		let packer = Slatepacker::new(SlatepackerArgs {
			sender: None,
			recipients: vec![],
			dec_key: None,
		});

		// A slate carrying a payment proof needs V5 (the proof carries memo/timestamp
		// that V4 can't represent), and the V5 fields survive the round trip.
		let slate_with_proof = populate_test_slate()?;
		assert!(slate_with_proof.payment_proof.is_some());
		let recovered_v5 = packer.get_slate(&packer.create_slatepack(&slate_with_proof)?)?;
		assert_eq!(recovered_v5.version_info.version, 5);
		assert!(recovered_v5.payment_proof.unwrap().memo.is_some());

		// A plain slate keeps its requested version.
		let mut slate_no_proof = populate_test_slate()?;
		slate_no_proof.payment_proof = None;
		let recovered_v5 = packer.get_slate(&packer.create_slatepack(&slate_no_proof)?)?;
		assert_eq!(recovered_v5.version_info.version, 5);

		slate_no_proof.version_info.version = 4;
		let recovered_v4 = packer.get_slate(&packer.create_slatepack(&slate_no_proof)?)?;
		assert_eq!(recovered_v4.version_info.version, 4);

		// A legacy send proof also fits in V4 and survives the round trip intact.
		let mut slate_legacy_proof = populate_test_slate()?;
		use_legacy_proof(&mut slate_legacy_proof);
		slate_legacy_proof.version_info.version = 4;
		let proof = slate_legacy_proof.payment_proof.clone().unwrap();
		let recovered_legacy = packer.get_slate(&packer.create_slatepack(&slate_legacy_proof)?)?;
		assert_eq!(recovered_legacy.version_info.version, 4);
		let recovered_proof = recovered_legacy.payment_proof.unwrap();
		assert_eq!(recovered_proof.sender_address, proof.sender_address);
		assert_eq!(recovered_proof.receiver_address, proof.receiver_address);
		assert_eq!(recovered_proof.promise_signature, proof.promise_signature);

		let mut partial_proof = populate_test_slate()?;
		let proof = partial_proof.payment_proof.as_mut().unwrap();
		proof.sender_address = None;
		proof.timestamp = None;
		proof.memo = None;
		proof.promise_signature = None;
		partial_proof.version_info.version = 4;
		let recovered = packer.get_slate(&packer.create_slatepack(&partial_proof)?)?;
		assert_eq!(recovered.version_info.version, 5);
		let proof = recovered.payment_proof.unwrap();
		assert!(proof.sender_address.is_none());
		assert!(proof.timestamp.is_none());

		assert!(SlateV4::try_from(populate_test_slate()?).is_err());

		Ok(())
	}

	#[test]
	fn slatepack_version_v4_v5() -> Result<(), Error> {
		set_local_chain_type(ChainTypes::Mainnet);

		// Convert V5 slate into V4 slate, check result
		let slate_internal = populate_test_slate()?;
		let v5 = VersionedSlate::V5(slate_internal.clone().into());
		let mut legacy_slate = slate_internal;
		use_legacy_proof(&mut legacy_slate);
		let v4 = VersionedSlate::V4(SlateV4::try_from(legacy_slate)?);

		let v5_converted: Slate = v5.into();
		let v4_converted: Slate = v4.into();

		assert!(v5_converted.payment_proof.as_ref().unwrap().memo.is_some());

		// V4 has no memo or timestamp
		assert!(v4_converted.payment_proof.as_ref().unwrap().memo.is_none());
		assert!(v4_converted
			.payment_proof
			.as_ref()
			.unwrap()
			.timestamp
			.is_none());

		Ok(())
	}

	// A slate must deserialize back into the version it declares. VersionedSlate is
	// untagged and tries V5 first, so without a version check in each deserializer a
	// V4 slate is silently parsed (and reported) as V5.
	#[test]
	fn versioned_slate_json_round_trip() -> Result<(), Error> {
		set_local_chain_type(ChainTypes::Mainnet);
		let slate_internal = populate_test_slate()?;

		// A slate without a payment proof is the case that matters: the V4 and V5 proof
		// shapes differ, so a proof makes the variants distinguishable by accident.
		for with_proof in [true, false] {
			for version in [SlateVersion::V4, SlateVersion::V5] {
				let mut slate = slate_internal.clone();
				if !with_proof {
					slate.payment_proof = None;
				} else if version == SlateVersion::V4 {
					use_legacy_proof(&mut slate);
				}
				slate.version_info.version = match version {
					SlateVersion::V4 => 4,
					SlateVersion::V5 => 5,
				};
				let versioned = VersionedSlate::into_version(slate, version.clone())?;
				let json = serde_json::to_string(&versioned).unwrap();
				let recovered: VersionedSlate = serde_json::from_str(&json).unwrap();
				assert_eq!(recovered.version(), version, "json round trip: {}", json);
				assert_eq!(
					serde_json::to_value(&recovered).unwrap(),
					serde_json::to_value(&versioned).unwrap()
				);
			}
		}

		Ok(())
	}

	#[test]
	fn versioned_bin_slate_round_trip() -> Result<(), Error> {
		set_local_chain_type(ChainTypes::Mainnet);
		let slate_internal = populate_test_slate()?;

		for with_proof in [true, false] {
			for version in [SlateVersion::V4, SlateVersion::V5] {
				let mut slate = slate_internal.clone();
				if !with_proof {
					slate.payment_proof = None;
				} else if version == SlateVersion::V4 {
					use_legacy_proof(&mut slate);
				}
				slate.version_info.version = match version {
					SlateVersion::V4 => 4,
					SlateVersion::V5 => 5,
				};
				let versioned = VersionedSlate::into_version(slate, version.clone())?;
				let expected = serde_json::to_value(&versioned).unwrap();
				let bin: VersionedBinSlate = versioned.try_into().unwrap();
				let bytes = byte_ser::to_bytes(&bin).unwrap();
				let recovered: VersionedSlate = byte_ser::from_bytes::<VersionedBinSlate>(&bytes)
					.unwrap()
					.into();
				assert_eq!(recovered.version(), version);
				assert_eq!(serde_json::to_value(&recovered).unwrap(), expected);
			}
		}

		Ok(())
	}

	#[test]
	fn kernel_features_round_trip() -> Result<(), Error> {
		set_local_chain_type(ChainTypes::Mainnet);
		let fee = FeeFields::new(0, 42).unwrap();

		for version in [SlateVersion::V4, SlateVersion::V5] {
			let features = [
				KernelFeatures::Plain { fee },
				KernelFeatures::HeightLocked {
					fee,
					lock_height: 500_000,
				},
				KernelFeatures::NoRecentDuplicate {
					fee,
					relative_height: NRDRelativeHeight::new(10).unwrap(),
				},
			];

			for expected in features {
				let mut slate = Slate::blank_with_kernel_features(2, false, expected)?;
				assert_eq!(slate.tx.as_ref().unwrap().kernels()[0].features, expected);
				slate.payment_proof = None;
				slate.tx = populate_test_slate()?.tx;

				let versioned = VersionedSlate::into_version(slate.clone(), version.clone())?;
				let json = serde_json::to_string(&versioned).unwrap();
				let recovered: Slate = serde_json::from_str::<VersionedSlate>(&json)
					.unwrap()
					.into();
				assert_eq!(recovered.tx.unwrap().kernels()[0].features, expected);

				let bin: VersionedBinSlate = versioned.try_into()?;
				let bytes = byte_ser::to_bytes(&bin).unwrap();
				let recovered: Slate = VersionedSlate::from(
					byte_ser::from_bytes::<VersionedBinSlate>(&bytes).unwrap(),
				)
				.into();

				assert_eq!(recovered.tx.unwrap().kernels()[0].features, expected);
			}
		}

		assert!(Slate::blank_with_kernel_features(2, false, KernelFeatures::Coinbase).is_err());

		Ok(())
	}

	#[test]
	fn slatepack_version_v4_v5_bin() -> Result<(), Error> {
		set_local_chain_type(ChainTypes::Mainnet);

		// Convert V5 slate into V4 slate, check result
		let slate_internal = populate_test_slate()?;
		let v5 = VersionedSlate::V5(slate_internal.clone().into());
		let v5_bin: VersionedBinSlate = v5.try_into().unwrap();

		let mut legacy_slate = slate_internal;
		use_legacy_proof(&mut legacy_slate);
		let v4 = VersionedSlate::V4(SlateV4::try_from(legacy_slate)?);
		let v4_bin: VersionedBinSlate = v4.try_into().unwrap();

		let v5_versioned: VersionedSlate = v5_bin.into();
		let v4_versioned: VersionedSlate = v4_bin.into();

		let v5_converted: Slate = v5_versioned.into();
		let v4_converted: Slate = v4_versioned.into();

		assert!(v5_converted.payment_proof.as_ref().unwrap().memo.is_some());
		// V4 has no memo or timestamp
		assert!(v4_converted.payment_proof.as_ref().unwrap().memo.is_none());
		assert!(v4_converted
			.payment_proof
			.as_ref()
			.unwrap()
			.timestamp
			.is_none());

		Ok(())
	}

	#[test]
	fn slate_version_numbers() {
		for (number, version) in [(4, SlateVersion::V4), (5, SlateVersion::V5)] {
			assert_eq!(SlateVersion::try_from(number).unwrap(), version);
		}
		assert!(matches!(
			SlateVersion::try_from(6),
			Err(Error::SlateVersion(6))
		));
	}
}
