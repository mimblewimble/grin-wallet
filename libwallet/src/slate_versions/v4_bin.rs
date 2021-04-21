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

//! Wraps a V4 Slate into a V4 Binary slate

use crate::grin_core::core::transaction::{FeeFields, OutputFeatures};
use crate::grin_core::ser as grin_ser;
use crate::grin_core::ser::{Readable, Reader, Writeable, Writer};
use crate::grin_keychain::BlindingFactor;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use std::convert::TryFrom;
use uuid::Uuid;

use crate::slate_versions::v4::{
	CommitsV4, KernelFeaturesArgsV4, ParticipantDataV4, PaymentInfoV4, SlateStateV4, SlateV4,
	VersionCompatInfoV4,
};

impl Writeable for SlateStateV4 {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		let b = match self {
			SlateStateV4::Unknown => 0,
			SlateStateV4::Standard1 => 1,
			SlateStateV4::Standard2 => 2,
			SlateStateV4::Standard3 => 3,
			SlateStateV4::Invoice1 => 4,
			SlateStateV4::Invoice2 => 5,
			SlateStateV4::Invoice3 => 6,
		};
		writer.write_u8(b)
	}
}

impl Readable for SlateStateV4 {
	fn read<R: Reader>(reader: &mut R) -> Result<SlateStateV4, grin_ser::Error> {
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
		Ok(sta)
	}
}

/// Allow serializing of Uuids not defined in crate
struct UuidWrap(Uuid);

impl Writeable for UuidWrap {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		writer.write_fixed_bytes(&self.0.as_bytes())
	}
}

impl Readable for UuidWrap {
	fn read<R: Reader>(reader: &mut R) -> Result<UuidWrap, grin_ser::Error> {
		let bytes = reader.read_fixed_bytes(16)?;
		let mut b = [0u8; 16];
		b.copy_from_slice(&bytes[0..16]);
		Ok(UuidWrap(Uuid::from_bytes(b)))
	}
}

/// Helper struct to serialize optional fields efficiently
struct SlateOptFields {
	/// num parts, default 2
	pub num_parts: u8,
	/// amt, default 0
	pub amt: u64,
	/// fee_fields, default FeeFields::zero()
	pub fee: FeeFields,
	/// kernel features, default 0
	pub feat: u8,
	/// ttl, default 0
	pub ttl: u64,
}

impl Writeable for SlateOptFields {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		// Status byte, bits determing which optional fields are serialized
		// 0 0 0 1  1 1 1 1
		//       t  f f a n
		let mut status = 0u8;
		if self.num_parts != 2 {
			status |= 0x01;
		}
		if self.amt > 0 {
			status |= 0x02;
		}
		if self.fee.fee() > 0 {
			// apply fee mask past HF4
			status |= 0x04;
		}
		if self.feat > 0 {
			status |= 0x08;
		}
		if self.ttl > 0 {
			status |= 0x10;
		}
		writer.write_u8(status)?;
		if status & 0x01 > 0 {
			writer.write_u8(self.num_parts)?;
		}
		if status & 0x02 > 0 {
			writer.write_u64(self.amt)?;
		}
		if status & 0x04 > 0 {
			self.fee.write(writer)?;
		}
		if status & 0x08 > 0 {
			writer.write_u8(self.feat)?;
		}
		if status & 0x10 > 0 {
			writer.write_u64(self.ttl)?;
		}
		Ok(())
	}
}

impl Readable for SlateOptFields {
	fn read<R: Reader>(reader: &mut R) -> Result<SlateOptFields, grin_ser::Error> {
		let status = reader.read_u8()?;
		let num_parts = if status & 0x01 > 0 {
			reader.read_u8()?
		} else {
			2
		};
		let amt = if status & 0x02 > 0 {
			reader.read_u64()?
		} else {
			0
		};
		let fee = if status & 0x04 > 0 {
			FeeFields::read(reader)?
		} else {
			FeeFields::zero()
		};
		let feat = if status & 0x08 > 0 {
			reader.read_u8()?
		} else {
			0
		};
		let ttl = if status & 0x10 > 0 {
			reader.read_u64()?
		} else {
			0
		};
		Ok(SlateOptFields {
			num_parts,
			amt,
			fee,
			feat,
			ttl,
		})
	}
}

struct SigsWrap(Vec<ParticipantDataV4>);
struct SigsWrapRef<'a>(&'a Vec<ParticipantDataV4>);

impl<'a> Writeable for SigsWrapRef<'a> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		writer.write_u8(self.0.len() as u8)?;
		for s in self.0.iter() {
			//0 means part sig is not yet included
			//1 means part sig included
			if s.part.is_some() {
				writer.write_u8(1)?;
			} else {
				writer.write_u8(0)?;
			}
			s.xs.write(writer)?;
			s.nonce.write(writer)?;
			if let Some(s) = s.part {
				s.write(writer)?;
			}
		}
		Ok(())
	}
}

impl Readable for SigsWrap {
	fn read<R: Reader>(reader: &mut R) -> Result<SigsWrap, grin_ser::Error> {
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
		Ok(SigsWrap(sigs))
	}
}

/// Serialization of optional structs
struct SlateOptStructsRef<'a> {
	/// coms, default none
	pub coms: &'a Option<Vec<CommitsV4>>,
	///// proof, default none
	pub proof: &'a Option<PaymentInfoV4>,
}

/// Serialization of optional structs
struct SlateOptStructs {
	/// coms, default none
	pub coms: Option<Vec<CommitsV4>>,
	/// proof, default none
	pub proof: Option<PaymentInfoV4>,
}

impl<'a> Writeable for SlateOptStructsRef<'a> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		// Status byte, bits determing which optional structs are serialized
		// 0 0 0 0  0 0 1 1
		//              p c
		let mut status = 0u8;
		if self.coms.is_some() {
			status |= 0x01
		};
		if self.proof.is_some() {
			status |= 0x02
		};
		writer.write_u8(status)?;
		if let Some(c) = self.coms {
			ComsWrapRef(&c).write(writer)?;
		}
		if let Some(p) = self.proof {
			ProofWrapRef(&p).write(writer)?;
		}
		Ok(())
	}
}

impl Readable for SlateOptStructs {
	fn read<R: Reader>(reader: &mut R) -> Result<SlateOptStructs, grin_ser::Error> {
		let status = reader.read_u8()?;
		let coms = if status & 0x01 > 0 {
			Some(ComsWrap::read(reader)?.0)
		} else {
			None
		};
		let proof = if status & 0x02 > 0 {
			Some(ProofWrap::read(reader)?.0)
		} else {
			None
		};
		Ok(SlateOptStructs { coms, proof })
	}
}

struct ComsWrap(Vec<CommitsV4>);
struct ComsWrapRef<'a>(&'a Vec<CommitsV4>);

impl<'a> Writeable for ComsWrapRef<'a> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		writer.write_u16(self.0.len() as u16)?;
		for o in self.0.iter() {
			//0 means input
			//1 means output with proof
			if o.p.is_some() {
				writer.write_u8(1)?;
			} else {
				writer.write_u8(0)?;
			}
			OutputFeatures::from(o.f).write(writer)?;
			o.c.write(writer)?;
			if let Some(p) = o.p {
				p.write(writer)?;
			}
		}
		Ok(())
	}
}

impl Readable for ComsWrap {
	fn read<R: Reader>(reader: &mut R) -> Result<ComsWrap, grin_ser::Error> {
		let coms_len = reader.read_u16()?;
		let coms = {
			let mut ret = vec![];
			for _ in 0..coms_len as usize {
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
			ret
		};
		Ok(ComsWrap(coms))
	}
}

struct ProofWrap(PaymentInfoV4);
struct ProofWrapRef<'a>(&'a PaymentInfoV4);

impl<'a> Writeable for ProofWrapRef<'a> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		writer.write_fixed_bytes(self.0.saddr.to_bytes())?;
		writer.write_fixed_bytes(self.0.raddr.to_bytes())?;
		match self.0.rsig {
			Some(s) => {
				writer.write_u8(1)?;
				writer.write_fixed_bytes(&s.to_bytes().to_vec())?;
			}
			None => writer.write_u8(0)?,
		}
		Ok(())
	}
}

impl Readable for ProofWrap {
	fn read<R: Reader>(reader: &mut R) -> Result<ProofWrap, grin_ser::Error> {
		let saddr = DalekPublicKey::from_bytes(&reader.read_fixed_bytes(32)?).unwrap();
		let raddr = DalekPublicKey::from_bytes(&reader.read_fixed_bytes(32)?).unwrap();
		let rsig = match reader.read_u8()? {
			0 => None,
			1 | _ => Some(DalekSignature::try_from(&reader.read_fixed_bytes(64)?[..]).unwrap()),
		};
		Ok(ProofWrap(PaymentInfoV4 { saddr, raddr, rsig }))
	}
}

#[derive(Debug, Clone)]
pub struct SlateV4Bin(pub SlateV4);

impl From<SlateV4> for SlateV4Bin {
	fn from(slate: SlateV4) -> SlateV4Bin {
		SlateV4Bin(slate)
	}
}

impl From<SlateV4Bin> for SlateV4 {
	fn from(slate: SlateV4Bin) -> SlateV4 {
		slate.0
	}
}

impl serde::Serialize for SlateV4Bin {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		let mut vec = vec![];
		grin_ser::serialize(&mut vec, grin_ser::ProtocolVersion(4), self)
			.map_err(|err| serde::ser::Error::custom(err.to_string()))?;
		serializer.serialize_bytes(&vec)
	}
}

impl<'de> serde::Deserialize<'de> for SlateV4Bin {
	fn deserialize<D>(deserializer: D) -> Result<SlateV4Bin, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		struct SlateV4BinVisitor;

		impl<'de> serde::de::Visitor<'de> for SlateV4BinVisitor {
			type Value = SlateV4Bin;

			fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
				write!(formatter, "a serialised binary V4 slate")
			}

			fn visit_bytes<E>(self, value: &[u8]) -> Result<SlateV4Bin, E>
			where
				E: serde::de::Error,
			{
				let mut reader = std::io::Cursor::new(value.to_vec());
				let s = grin_ser::deserialize(&mut reader, grin_ser::ProtocolVersion(4))
					.map_err(|err| serde::de::Error::custom(err.to_string()))?;
				Ok(s)
			}
		}
		deserializer.deserialize_bytes(SlateV4BinVisitor)
	}
}

impl Writeable for SlateV4Bin {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		let v4 = &self.0;
		writer.write_u16(v4.ver.version)?;
		writer.write_u16(v4.ver.block_header_version)?;
		(UuidWrap(v4.id)).write(writer)?;
		v4.sta.write(writer)?;
		v4.off.write(writer)?;
		SlateOptFields {
			num_parts: v4.num_parts,
			amt: v4.amt,
			fee: v4.fee,
			feat: v4.feat,
			ttl: v4.ttl,
		}
		.write(writer)?;
		(SigsWrapRef(&v4.sigs)).write(writer)?;
		SlateOptStructsRef {
			coms: &v4.coms,
			proof: &v4.proof,
		}
		.write(writer)?;
		// Write lock height for height locked kernels
		if v4.feat == 2 {
			let lock_hgt = match &v4.feat_args {
				Some(l) => l.lock_hgt,
				None => 0,
			};
			writer.write_u64(lock_hgt)?;
		}
		Ok(())
	}
}

impl Readable for SlateV4Bin {
	fn read<R: Reader>(reader: &mut R) -> Result<SlateV4Bin, grin_ser::Error> {
		let ver = VersionCompatInfoV4 {
			version: reader.read_u16()?,
			block_header_version: reader.read_u16()?,
		};
		let id = UuidWrap::read(reader)?.0;
		let sta = SlateStateV4::read(reader)?;
		let off = BlindingFactor::read(reader)?;

		let opts = SlateOptFields::read(reader)?;
		let sigs = SigsWrap::read(reader)?.0;
		let opt_structs = SlateOptStructs::read(reader)?;

		let feat_args = if opts.feat == 2 {
			Some(KernelFeaturesArgsV4 {
				lock_hgt: reader.read_u64()?,
			})
		} else {
			None
		};

		Ok(SlateV4Bin(SlateV4 {
			ver,
			id,
			sta,
			off,
			num_parts: opts.num_parts,
			amt: opts.amt,
			fee: opts.fee,
			feat: opts.feat,
			ttl: opts.ttl,
			sigs,
			coms: opt_structs.coms,
			proof: opt_structs.proof,
			feat_args,
		}))
	}
}

#[test]
fn slate_v4_serialize_deserialize() {
	use crate::grin_util::from_hex;
	use crate::grin_util::secp::key::PublicKey;
	use crate::{Slate, TxFlow};
	use grin_wallet_util::grin_core::global::{set_local_chain_type, ChainTypes};
	use grin_wallet_util::grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
	set_local_chain_type(ChainTypes::Mainnet);
	let slate = Slate::blank(1, TxFlow::Standard);
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
	v4.amt = 234324899824;
	v4.feat = 1;
	v4.num_parts = 2;
	v4.feat_args = Some(KernelFeaturesArgsV4 { lock_hgt: 23092039 });
	let v4_1 = v4.clone();
	let v4_1_copy = v4.clone();

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
	assert_eq!(v4_1.proof, v4_2.proof);

	// Include Payment proof, remove coms to mix it up a bit
	let mut v4 = v4_1_copy;
	let raw_pubkey_str = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb";
	let b = from_hex(raw_pubkey_str).unwrap();
	let d_pkey = DalekPublicKey::from_bytes(&b).unwrap();
	v4.proof = Some(PaymentInfoV4 {
		raddr: d_pkey.clone(),
		saddr: d_pkey.clone(),
		rsig: None,
	});
	v4.coms = None;
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
	assert!(v4_1.coms.is_none());
	assert_eq!(v4_1.sigs, v4_2.sigs);
	assert_eq!(v4_1.proof, v4_2.proof);
}
