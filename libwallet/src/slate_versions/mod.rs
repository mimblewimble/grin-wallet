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
use byteorder::{BigEndian, WriteBytesExt};

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
