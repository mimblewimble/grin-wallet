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

//! Wraps a V4 Slate into a V4 Binary slate

use crate::grin_core::core::transaction::OutputFeatures;
use crate::grin_core::ser as grin_ser;
use crate::grin_core::ser::{Readable, Reader, Writeable, Writer};
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use uuid::Uuid;

use crate::slate_versions::v4::{
	CommitsV4, ParticipantDataV4, SlateStateV4, SlateV4, VersionCompatInfoV4,
};

#[derive(Debug, Clone)]
pub struct SlateV4Bin(pub SlateV4);

impl Writeable for SlateV4Bin {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		let v4 = &self.0;
		writer.write_u16(v4.ver.version)?;
		writer.write_u16(v4.ver.block_header_version)?;
		(UuidWrap(v4.id)).write(writer)?;
		let state = match v4.sta {
			SlateStateV4::Unknown => 0,
			SlateStateV4::Standard1 => 1,
			SlateStateV4::Standard2 => 2,
			SlateStateV4::Standard3 => 3,
			SlateStateV4::Invoice1 => 4,
			SlateStateV4::Invoice2 => 5,
			SlateStateV4::Invoice3 => 6,
		};
		writer.write_u8(state)?;
		writer.write_u64(v4.amt)?;
		writer.write_u64(v4.fee)?;

		// commit data
		let coms_len = match &v4.coms {
			Some(c) => c.len() as u16,
			None => 0,
		};
		writer.write_u16(coms_len)?;
		if let Some(c) = &v4.coms {
			for o in c.iter() {
				//0 means input
				//1 means output with proof
				if o.p.is_some() {
					writer.write_u8(1)?;
				} else {
					writer.write_u8(0)?;
				}
				OutputFeatures::from(o.f).write(writer)?;
				o.c.write(writer)?;
				if let Some(p) = o.p.clone() {
					p.write(writer)?;
				}
			}
		}

		// Signature data
		writer.write_u8(v4.sigs.len() as u8)?;
		for s in v4.sigs.iter() {
			//0 means part sig is not yet included
			//1 means part sig included
			if s.part.is_some() {
				writer.write_u8(1)?;
			} else {
				writer.write_u8(0)?;
			}
			s.xs.write(writer)?;
			s.nonce.write(writer)?;
			if let Some(s) = s.part.clone() {
				s.write(writer)?;
			}
		}
		Ok(())
	}
}

struct UuidWrap(Uuid);

impl Writeable for UuidWrap {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		writer.write_fixed_bytes(&self.0.as_bytes())
	}
}

impl Readable for SlateV4Bin {
	fn read(reader: &mut dyn Reader) -> Result<SlateV4Bin, grin_ser::Error> {
		let ver = VersionCompatInfoV4 {
			version: reader.read_u16()?,
			block_header_version: reader.read_u16()?,
		};
		let id = UuidWrap::read(reader)?.0;
		let b = reader.read_u8()?;
		let sta = match b {
			0 => SlateStateV4::Unknown,
			1 => SlateStateV4::Standard1,
			2 => SlateStateV4::Standard2,
			3 => SlateStateV4::Standard3,
			4 => SlateStateV4::Invoice1,
			5 => SlateStateV4::Invoice2,
			6 => SlateStateV4::Invoice3,
			_ => SlateStateV4::Unknown,
		};
		let amt = reader.read_u64()?;
		let fee = reader.read_u64()?;

		let coms_len = reader.read_u16()?;
		let coms = match coms_len {
			0 => None,
			n => {
				let mut ret = vec![];
				for _ in 0..n {
					let is_output = reader.read_u8()?;
					let c = CommitsV4 {
						f: OutputFeatures::read(reader)?.into(),
						c: Commitment::read(reader)?,
						p: match is_output {
							1 => Some(RangeProof::read(reader)?),
							0 | _ => None,
						},
					};
					ret.push(c);
				}
				Some(ret)
			}
		};
		let sigs_len = reader.read_u8()?;
		let sigs = {
			let mut ret = vec![];
			for _ in 0..sigs_len as usize {
				let has_partial = reader.read_u8()?;
				let c = ParticipantDataV4 {
					xs: PublicKey::read(reader)?,
					nonce: PublicKey::read(reader)?,
					part: match has_partial {
						1 => Some(Signature::read(reader)?),
						0 | _ => None,
					},
				};
				ret.push(c);
			}
			ret
		};
		Ok(SlateV4Bin(SlateV4 {
			ver,
			num_parts: 2, //TODO
			id,
			sta,
			coms,
			amt,
			fee,
			lock_hgt: 0, //TODO
			ttl: 0,      //TODO
			sigs,
			proof: None, //TODO
		}))
	}
}

impl Readable for UuidWrap {
	fn read(reader: &mut dyn Reader) -> Result<UuidWrap, grin_ser::Error> {
		let bytes = reader.read_fixed_bytes(16)?;
		let mut b = [0u8; 16];
		b.copy_from_slice(&bytes[0..16]);
		Ok(UuidWrap(Uuid::from_bytes(b)))
	}
}

#[test]
fn slate_v4_serialize_deserialize() {
	use crate::grin_util::secp::key::PublicKey;
	use crate::Slate;
	use grin_wallet_util::grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
	let slate = Slate::blank(1, false);
	let mut v4 = SlateV4::from(slate);

	let keychain = ExtKeychain::from_random_seed(true).unwrap();
	let switch = SwitchCommitmentType::Regular;
	// add some sig data
	let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let id2 = ExtKeychain::derive_key_id(1, 1, 1, 0, 0);
	let skey1 = keychain.derive_key(0, &id1, switch).unwrap();
	let skey2 = keychain.derive_key(0, &id2, switch).unwrap();
	let xs = PublicKey::from_secret_key(keychain.secp(), &skey1).unwrap();
	let nonce = PublicKey::from_secret_key(keychain.secp(), &skey2).unwrap();
	let part = ParticipantDataV4 {
		xs,
		nonce,
		part: None,
	};
	let part2 = ParticipantDataV4 {
		xs,
		nonce,
		part: Some(Signature::from_raw_data(&[11; 64]).unwrap()),
	};
	v4.sigs.push(part.clone());
	v4.sigs.push(part2);
	v4.sigs.push(part);

	// add some random commit data
	let com1 = CommitsV4 {
		f: OutputFeatures::Plain.into(),
		c: Commitment::from_vec([3u8; 1].to_vec()),
		p: None,
	};
	let com2 = CommitsV4 {
		f: OutputFeatures::Plain.into(),
		c: Commitment::from_vec([4u8; 1].to_vec()),
		p: Some(RangeProof::zero()),
	};
	let mut coms = vec![];
	coms.push(com1.clone());
	coms.push(com1.clone());
	coms.push(com1.clone());
	coms.push(com2);

	v4.coms = Some(coms);

	let v4_1 = v4.clone();
	let v4_bin = SlateV4Bin(v4);
	let mut vec = Vec::new();
	let _ = grin_ser::serialize_default(&mut vec, &v4_bin).expect("serialization failed");
	let b4_bin_2: SlateV4Bin = grin_ser::deserialize_default(&mut &vec[..]).unwrap();
	let v4_2 = b4_bin_2.0.clone();
	assert_eq!(v4_1.ver, v4_2.ver);
	assert_eq!(v4_1.id, v4_2.id);
	assert_eq!(v4_1.amt, v4_2.amt);
	assert_eq!(v4_1.fee, v4_2.fee);
	let v4_2_coms = v4_2.coms.as_ref().unwrap().clone();
	for (i, c) in v4_1.coms.unwrap().iter().enumerate() {
		assert_eq!(c.f, v4_2_coms[i].f);
		assert_eq!(c.c, v4_2_coms[i].c);
		assert_eq!(c.p, v4_2_coms[i].p);
	}
	assert_eq!(v4_1.sigs, v4_2.sigs);
}
