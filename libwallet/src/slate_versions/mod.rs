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

//! This module contains old slate versions and conversions to the newest slate version
//! Used for serialization and deserialization of slates in a backwards compatible way.
//! Versions earlier than V2 are removed for the 2.0.0 release, but versioning code
//! remains for future needs

use crate::error::{Error, ErrorKind};
use crate::slate::Slate;
use crate::slate_versions::v2::SlateV2;

use crate::grin_util::secp;
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};
use std::io::{Cursor, Read};
use std::str;
use crate::enum_primitive::FromPrimitive;

#[allow(missing_docs)]
pub mod v2;

/// The most recent version of the slate
pub const CURRENT_SLATE_VERSION: u16 = 2;

/// The grin block header this slate is intended to be compatible with
pub const GRIN_BLOCK_HEADER_VERSION: u16 = 2;

/// Existing versions of the slate
#[derive(EnumIter, Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum SlateVersion {
	/// V2 (most current)
	V2,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
/// Versions are ordered newest to oldest so serde attempts to
/// deserialize newer versions first, then falls back to older versions.
pub enum VersionedSlate {
	/// Current (Grin 1.1.0 - 2.x (current))
	V2(SlateV2),
}

impl VersionedSlate {
	/// Return slate version
	pub fn version(&self) -> SlateVersion {
		match *self {
			VersionedSlate::V2(_) => SlateVersion::V2,
		}
	}

	/// convert this slate type to a specified older version
	pub fn into_version(slate: Slate, version: SlateVersion) -> VersionedSlate {
		match version {
			SlateVersion::V2 => VersionedSlate::V2(slate.into()),
			// Left here as a reminder of what needs to be inserted on
			// the release of a new slate
			/*SlateVersion::V0 => {
				let s = SlateV2::from(slate);
				let s = SlateV1::from(s);
				let s = SlateV0::from(s);
				VersionedSlate::V0(s)
			}*/
		}
	}

	/// Encodes a slate into a vec of bytes by serializing the fields in order
	/// and prepending variable length fields with their length
	pub fn encode(&self) -> Result<Vec<u8>, Error> {
		let slate: &SlateV2 = match self {
			VersionedSlate::V2(s) => s,
			VersionedSlate::V1(_) => {
				return Err(ErrorKind::SlateSer)?;
			}
			VersionedSlate::V0(_) => {
				return Err(ErrorKind::SlateSer)?;
			}
		};
		let mut buf: Vec<u8> = Vec::new();

		// Save 3 bytes by casting u16 to u8 (should be fine up to slate v255)
		buf.push(slate.version_info.version as u8);
		buf.push(slate.version_info.orig_version as u8);
		buf.push(slate.version_info.min_compat_version as u8);

		buf.write_u16::<BigEndian>(slate.num_participants as u16)?;

		let txid = slate.id.to_hyphenated().to_string().into_bytes();
		buf.push(txid.len() as u8); // max 255 bytes long txid
		buf.extend(txid);

		buf.extend(slate.tx.offset.as_ref());
		buf.write_u16::<BigEndian>(slate.tx.body.inputs.len() as u16)?;

		for input in slate.tx.body.inputs.iter() {
			buf.push(input.features as u8);
			buf.extend(input.commit.0.iter())
		}

		buf.write_u16::<BigEndian>(slate.tx.body.outputs.len() as u16)?;

		for output in slate.tx.body.outputs.iter() {
			buf.push(output.features as u8);

			buf.extend(output.commit.0.iter());

			buf.write_u16::<BigEndian>(output.proof.len() as u16)?;
			buf.extend(output.proof.bytes().iter())
		}

		buf.write_u16::<BigEndian>(slate.tx.body.kernels.len() as u16)?;

		for kernel in slate.tx.body.kernels.iter() {
			buf.push(kernel.features as u8);

			buf.write_u64::<BigEndian>(kernel.fee)?;

			buf.write_u64::<BigEndian>(kernel.lock_height)?;
			buf.extend(kernel.excess.0.iter());
			buf.extend(kernel.excess_sig.as_ref());
		}

		buf.write_u64::<BigEndian>(slate.amount)?;
		buf.write_u64::<BigEndian>(slate.fee)?;
		buf.write_u64::<BigEndian>(slate.height)?;
		buf.write_u64::<BigEndian>(slate.lock_height)?;

		buf.write_u16::<BigEndian>(slate.participant_data.len() as u16)?;

		let s = secp::Secp256k1::new();

		for pd in slate.participant_data.iter() {
			// Save 7 bytes by casting u64 to u8, we only use 1 bit anyway
			buf.push(pd.id as u8);
			buf.extend(pd.public_blind_excess.serialize_vec(&s, true));
			buf.extend(pd.public_nonce.serialize_vec(&s, true));

			match pd.part_sig {
				None => buf.push(0),
				Some(n) => {
					buf.push(n.as_ref().len() as u8);
					buf.extend(n.as_ref().iter());
				}
			};

			match &pd.message {
				None => buf.push(0),
				Some(n) => {
					let msg = n.clone().into_bytes();
					buf.push(msg.len() as u8); // maximum message size 255 bytes
					buf.extend(msg);
				}
			}
			match pd.message_sig {
				None => buf.push(0),
				Some(n) => {
					buf.push(n.as_ref().len() as u8);
					buf.extend(n.as_ref().iter());
				}
			}
		}
		Ok(buf)
	}

	/// Deserialize raw bytes to a v2 VersionedSlate
	pub fn from_bytes(data: Vec<u8>) -> Result<Self, Error> {
		let mut rdr = Cursor::new(data);

		let version_info = v2::VersionCompatInfoV2{
			version: rdr.read_u8()? as u16, 
			orig_version: rdr.read_u8()? as u16, 
			min_compat_version: rdr.read_u8()? as u16
		};

		let num_participants = rdr.read_u16::<BigEndian>()? as usize;
		let txid_len = rdr.read_u8()? as usize;
		let mut id = [0u8; 255];
		rdr.read_exact(&mut id[..txid_len])?;
		let id = str::from_utf8(&id[..txid_len]).map_err(|_| ErrorKind::SlateDeser)?;
		let id = v2::Uuid::parse_str(id).map_err(|_| ErrorKind::SlateDeser)?;

		let mut offset = [0u8; 32];
		rdr.read_exact(&mut offset)?;
		let offset = v2::BlindingFactor::from_slice(&offset);

		let n_inputs = rdr.read_u16::<BigEndian>()? as usize;
		let mut inputs: Vec<v2::InputV2> = Vec::with_capacity(n_inputs);

		for _ in 0..n_inputs {
			let features = v2::OutputFeatures::from_u8(rdr.read_u8()?).ok_or_else(|| ErrorKind::SlateDeser)?;
			let mut commit = [0u8; secp::constants::PEDERSEN_COMMITMENT_SIZE];
			rdr.read_exact(&mut commit)?;
			let commit = v2::Commitment(commit);
			inputs.push(v2::InputV2{features, commit});
		}

		let n_outputs = rdr.read_u16::<BigEndian>()? as usize;
		let mut outputs: Vec<v2::OutputV2> = Vec::with_capacity(n_outputs);

		for _ in 0..n_outputs {
			let features = v2::OutputFeatures::from_u8(rdr.read_u8()?).ok_or_else(|| ErrorKind::SlateDeser)?;
			let mut commit = [0u8; secp::constants::PEDERSEN_COMMITMENT_SIZE];
			rdr.read_exact(&mut commit)?;
			let commit = v2::Commitment(commit);
			let mut proof = [0u8; secp::constants::MAX_PROOF_SIZE];
			let plen = rdr.read_u16::<BigEndian>()? as usize;
			rdr.read_exact(&mut proof[..plen])?;

			let output = v2::OutputV2{
				features,
				commit,
				proof: v2::RangeProof {
					proof,
					plen
				}
			};
			outputs.push(output);
		}

		let n_kernels = rdr.read_u16::<BigEndian>()? as usize;
		let mut kernels: Vec<v2::TxKernelV2> = Vec::with_capacity(n_kernels);

		for _ in 0..n_kernels {
			let features = v2::KernelFeatures::from_u8(rdr.read_u8()?).ok_or_else(|| ErrorKind::SlateDeser)?;
			let fee = rdr.read_u64::<BigEndian>()?;
			let lock_height = rdr.read_u64::<BigEndian>()?;
			
			let mut excess = [0u8; secp::constants::PEDERSEN_COMMITMENT_SIZE];
			rdr.read_exact(&mut excess)?;
			let excess = v2::Commitment(excess);

			let mut excess_sig = [0u8; secp::constants::COMPACT_SIGNATURE_SIZE];
			rdr.read_exact(&mut excess_sig)?;
			let excess_sig = v2::Signature::from_raw_data(&excess_sig)?;

			kernels.push(v2::TxKernelV2{features, fee, lock_height, excess, excess_sig});
		}

		let tx = v2::TransactionV2{
			offset,
			body: v2::TransactionBodyV2{
				inputs,
				outputs,
				kernels
			}
		};

		let amount = rdr.read_u64::<BigEndian>()?;
		let fee = rdr.read_u64::<BigEndian>()?;
		let height = rdr.read_u64::<BigEndian>()?;
		let lock_height = rdr.read_u64::<BigEndian>()?;

		let pdata_len = rdr.read_u16::<BigEndian>()? as usize;
		let mut participant_data: Vec<v2::ParticipantDataV2> = Vec::with_capacity(pdata_len);



		let s = secp::Secp256k1::new();

		for _ in 0..pdata_len {
			let id = rdr.read_u8()? as u64;

			let mut public_blind_excess = [0u8; secp::constants::COMPRESSED_PUBLIC_KEY_SIZE];
			rdr.read_exact(&mut public_blind_excess)?;
			let public_blind_excess = v2::PublicKey::from_slice(&s, &public_blind_excess)?;

			let mut public_nonce = [0u8; secp::constants::COMPRESSED_PUBLIC_KEY_SIZE];
			rdr.read_exact(&mut public_nonce)?;
			let public_nonce = v2::PublicKey::from_slice(&s, &public_nonce)?;

			let part_sig: Option<v2::Signature> = match rdr.read_u8()? {
				0 => None,
				_ => {
					let mut sig = [0u8; 64];
					rdr.read_exact(&mut sig)?;
					Some(v2::Signature::from_raw_data(&sig)?)
				}
			};

			let message: Option<String> = match rdr.read_u8()? {
				0 => None,
				n => {
					let n = n as usize;
					let mut msg = [0u8; 255];
					rdr.read_exact(&mut msg[..n])?;
					let string = String::from_utf8(msg[..n].to_vec()).map_err(|_| ErrorKind::SlateDeser)?;
					Some(string)
				}
			};

			let message_sig: Option<v2::Signature> = match rdr.read_u8()? {
				0 => None,
				_ => {
					let mut sig = [0u8; 64];
					rdr.read_exact(&mut sig)?;
					Some(v2::Signature::from_raw_data(&sig)?)
				}
			};

			participant_data.push(v2::ParticipantDataV2{
				id,
				public_blind_excess,
				public_nonce,
				part_sig,
				message,
				message_sig
			});
		}

		let slate = v2::SlateV2{
			version_info,
			num_participants,
			id,
			tx,
			amount,
			fee,
			height,
			lock_height,
			participant_data
		};

		Ok(VersionedSlate::V2(slate))
	}
}

impl From<VersionedSlate> for Slate {
	fn from(slate: VersionedSlate) -> Slate {
		match slate {
			VersionedSlate::V2(s) => {
				let s = SlateV2::from(s);
				Slate::from(s)
			} // Again, left in as a reminder
			  /*VersionedSlate::V0(s) => {
				  let s = SlateV0::from(s);
				  let s = SlateV1::from(s);
				  let s = SlateV2::from(s);
				  Slate::from(s)
			  }*/
		}
	}
}
