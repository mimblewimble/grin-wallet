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

//! Wraps a V5 Slate into a V5 Binary slate

use crate::grin_core::core::transaction::{FeeFields, OutputFeatures};
use crate::grin_core::ser as grin_ser;
use crate::grin_core::ser::{Readable, Reader, Writeable, Writer};
use crate::grin_keychain::{BlindingFactor, Identifier, IDENTIFIER_SIZE};
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use crate::grin_util::static_secp_instance;
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use std::convert::TryFrom;
use uuid::Uuid;

use crate::slate_versions::v5::{
	CommitsV5, KernelFeaturesArgsV5, ParticipantDataV5, PaymentInfoV5, SlateStateV5, SlateV5,
	VersionCompatInfoV5,
};

impl Writeable for SlateStateV5 {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		let b = match self {
			SlateStateV5::Unknown => 0,
			SlateStateV5::Standard1 => 1,
			SlateStateV5::Standard2 => 2,
			SlateStateV5::Standard3 => 3,
			SlateStateV5::Invoice1 => 4,
			SlateStateV5::Invoice2 => 5,
			SlateStateV5::Invoice3 => 6,
			SlateStateV5::Multisig1 => 7,
			SlateStateV5::Multisig2 => 8,
			SlateStateV5::Multisig3 => 9,
			SlateStateV5::Multisig4 => 10,
			SlateStateV5::Atomic1 => 11,
			SlateStateV5::Atomic2 => 12,
			SlateStateV5::Atomic3 => 13,
			SlateStateV5::Atomic4 => 14,
		};
		writer.write_u8(b)
	}
}

impl Readable for SlateStateV5 {
	fn read<R: Reader>(reader: &mut R) -> Result<SlateStateV5, grin_ser::Error> {
		let b = reader.read_u8()?;
		let sta = match b {
			0 => SlateStateV5::Unknown,
			1 => SlateStateV5::Standard1,
			2 => SlateStateV5::Standard2,
			3 => SlateStateV5::Standard3,
			4 => SlateStateV5::Invoice1,
			5 => SlateStateV5::Invoice2,
			6 => SlateStateV5::Invoice3,
			7 => SlateStateV5::Multisig1,
			8 => SlateStateV5::Multisig2,
			9 => SlateStateV5::Multisig3,
			10 => SlateStateV5::Multisig4,
			11 => SlateStateV5::Atomic1,
			12 => SlateStateV5::Atomic2,
			13 => SlateStateV5::Atomic3,
			14 => SlateStateV5::Atomic4,
			_ => SlateStateV5::Unknown,
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

struct SigsWrap(Vec<ParticipantDataV5>);
struct SigsWrapRef<'a>(&'a Vec<ParticipantDataV5>);

impl<'a> Writeable for SigsWrapRef<'a> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		writer.write_u8(self.0.len() as u8)?;
		for s in self.0.iter() {
			//0 means part sig is not yet included
			//1 bit set means part sig included
			//2 bit set means atomic included
			//4 bit set means part commit included
			//8 bit set means tau_x included
			//16 bit set means tau_one included
			//32 bit set means tau_two included
			let mut optional = s.part.is_some() as u8;
			if s.atomic.is_some() {
				optional |= 2;
			}
			if s.part_commit.is_some() {
				optional |= 4;
			}
			if s.tau_x.is_some() {
				optional |= 8;
			}
			if s.tau_one.is_some() {
				optional |= 16;
			}
			if s.tau_two.is_some() {
				optional |= 32;
			}
			writer.write_u8(optional)?;
			s.xs.write(writer)?;
			s.nonce.write(writer)?;
			if let Some(a) = s.atomic {
				a.write(writer)?;
			}
			if let Some(s) = s.part {
				s.write(writer)?;
			}
			if let Some(c) = s.part_commit {
				c.write(writer)?;
			}
			if let Some(tx) = s.tau_x.as_ref() {
				writer.write_fixed_bytes(tx.0)?;
			}
			if let Some(to) = s.tau_one.as_ref() {
				to.write(writer)?;
			}
			if let Some(tt) = s.tau_two.as_ref() {
				tt.write(writer)?;
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
				let has_optional = reader.read_u8()?;
				let has_atomic = has_optional & 2 != 0;
				let has_partial = has_optional & 1 != 0;
				let has_part_com = has_optional & 4 != 0;
				let has_tau_x = has_optional & 8 != 0;
				let has_tau_one = has_optional & 16 != 0;
				let has_tau_two = has_optional & 32 != 0;
				let c = ParticipantDataV5 {
					xs: PublicKey::read(reader)?,
					nonce: PublicKey::read(reader)?,
					atomic: match has_atomic {
						true => Some(PublicKey::read(reader)?),
						false => None,
					},
					part: match has_partial {
						true => Some(Signature::read(reader)?),
						false => None,
					},
					part_commit: match has_part_com {
						true => Some(Commitment::read(reader)?),
						false => None,
					},
					tau_x: match has_tau_x {
						true => {
							let secp = static_secp_instance();
							let secp = secp.lock();
							let key_bytes = reader.read_fixed_bytes(32)?;
							Some(
								SecretKey::from_slice(&secp, &key_bytes)
									.map_err(|_| grin_ser::Error::CorruptedData)?,
							)
						}
						false => None,
					},
					tau_one: match has_tau_one {
						true => Some(PublicKey::read(reader)?),
						false => None,
					},
					tau_two: match has_tau_two {
						true => Some(PublicKey::read(reader)?),
						false => None,
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
	pub coms: &'a Option<Vec<CommitsV5>>,
	///// proof, default none
	pub proof: &'a Option<PaymentInfoV5>,
}

/// Serialization of optional structs
struct SlateOptStructs {
	/// coms, default none
	pub coms: Option<Vec<CommitsV5>>,
	/// proof, default none
	pub proof: Option<PaymentInfoV5>,
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

struct ComsWrap(Vec<CommitsV5>);
struct ComsWrapRef<'a>(&'a Vec<CommitsV5>);

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
				let c = CommitsV5 {
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

struct ProofWrap(PaymentInfoV5);
struct ProofWrapRef<'a>(&'a PaymentInfoV5);

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
		Ok(ProofWrap(PaymentInfoV5 { saddr, raddr, rsig }))
	}
}

#[derive(Debug, Clone)]
pub struct SlateV5Bin(pub SlateV5);

impl From<SlateV5> for SlateV5Bin {
	fn from(slate: SlateV5) -> SlateV5Bin {
		SlateV5Bin(slate)
	}
}

impl From<SlateV5Bin> for SlateV5 {
	fn from(slate: SlateV5Bin) -> SlateV5 {
		slate.0
	}
}

impl serde::Serialize for SlateV5Bin {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		let mut vec = vec![];
		grin_ser::serialize(&mut vec, grin_ser::ProtocolVersion(5), self)
			.map_err(|err| serde::ser::Error::custom(err.to_string()))?;
		serializer.serialize_bytes(&vec)
	}
}

impl<'de> serde::Deserialize<'de> for SlateV5Bin {
	fn deserialize<D>(deserializer: D) -> Result<SlateV5Bin, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		struct SlateV5BinVisitor;

		impl<'de> serde::de::Visitor<'de> for SlateV5BinVisitor {
			type Value = SlateV5Bin;

			fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
				write!(formatter, "a serialised binary V5 slate")
			}

			fn visit_bytes<E>(self, value: &[u8]) -> Result<SlateV5Bin, E>
			where
				E: serde::de::Error,
			{
				let mut reader = std::io::Cursor::new(value.to_vec());
				let s = grin_ser::deserialize(&mut reader, grin_ser::ProtocolVersion(4))
					.map_err(|err| serde::de::Error::custom(err.to_string()))?;
				Ok(s)
			}
		}
		deserializer.deserialize_bytes(SlateV5BinVisitor)
	}
}

impl Writeable for SlateV5Bin {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		let v5 = &self.0;
		writer.write_u16(v5.ver.version)?;
		writer.write_u16(v5.ver.block_header_version)?;
		(UuidWrap(v5.id)).write(writer)?;
		v5.sta.write(writer)?;
		v5.off.write(writer)?;
		SlateOptFields {
			num_parts: v5.num_parts,
			amt: v5.amt,
			fee: v5.fee,
			feat: v5.feat,
			ttl: v5.ttl,
		}
		.write(writer)?;
		(SigsWrapRef(&v5.sigs)).write(writer)?;
		SlateOptStructsRef {
			coms: &v5.coms,
			proof: &v5.proof,
		}
		.write(writer)?;
		// Write lock height for height locked kernels
		if v5.feat == 2 {
			let lock_hgt = match &v5.feat_args {
				Some(l) => l.lock_hgt,
				None => 0,
			};
			writer.write_u64(lock_hgt)?;
		}
		if let Some(mid) = v5.multisig_key_id.as_ref() {
			writer.write_u8(1)?;
			writer.write_fixed_bytes(mid.to_bytes())?;
		} else {
			writer.write_u8(0)?;
		}
		Ok(())
	}
}

impl Readable for SlateV5Bin {
	fn read<R: Reader>(reader: &mut R) -> Result<SlateV5Bin, grin_ser::Error> {
		let ver = VersionCompatInfoV5 {
			version: reader.read_u16()?,
			block_header_version: reader.read_u16()?,
		};
		let id = UuidWrap::read(reader)?.0;
		let sta = SlateStateV5::read(reader)?;
		let off = BlindingFactor::read(reader)?;

		let opts = SlateOptFields::read(reader)?;
		let sigs = SigsWrap::read(reader)?.0;
		let opt_structs = SlateOptStructs::read(reader)?;

		let feat_args = if opts.feat == 2 {
			Some(KernelFeaturesArgsV5 {
				lock_hgt: reader.read_u64()?,
			})
		} else {
			None
		};

		let multisig_key_id = if reader.read_u8()? != 0 {
			let id_bytes = reader.read_fixed_bytes(IDENTIFIER_SIZE)?;
			Some(Identifier::from_bytes(id_bytes.as_ref()))
		} else {
			None
		};

		Ok(SlateV5Bin(SlateV5 {
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
			multisig_key_id,
		}))
	}
}

#[test]
fn slate_v5_serialize_deserialize() {
	use crate::grin_util::from_hex;
	use crate::grin_util::secp::key::PublicKey;
	use crate::{Slate, TxFlow};
	use grin_wallet_util::grin_core::global::{set_local_chain_type, ChainTypes};
	use grin_wallet_util::grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
	set_local_chain_type(ChainTypes::Mainnet);
	let slate = Slate::blank(1, TxFlow::Standard);
	let mut v5 = SlateV5::from(slate);

	let keychain = ExtKeychain::from_random_seed(true).unwrap();
	let switch = SwitchCommitmentType::Regular;
	// add some sig data
	let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
	let id2 = ExtKeychain::derive_key_id(1, 1, 1, 0, 0);
	let skey1 = keychain.derive_key(0, &id1, switch).unwrap();
	let skey2 = keychain.derive_key(0, &id2, switch).unwrap();
	let xs = PublicKey::from_secret_key(keychain.secp(), &skey1).unwrap();
	let nonce = PublicKey::from_secret_key(keychain.secp(), &skey2).unwrap();
	let part = ParticipantDataV5 {
		xs,
		nonce,
		atomic: None,
		part: None,
		part_commit: None,
		tau_x: None,
		tau_one: None,
		tau_two: None,
	};
	let part2 = ParticipantDataV5 {
		xs,
		nonce,
		atomic: None,
		part: Some(Signature::from_raw_data(&[11; 64]).unwrap()),
		part_commit: None,
		tau_x: None,
		tau_one: None,
		tau_two: None,
	};
	v5.sigs.push(part.clone());
	v5.sigs.push(part2);
	v5.sigs.push(part);

	// add some random commit data
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
	v5.amt = 234324899824;
	v5.feat = 1;
	v5.num_parts = 2;
	v5.feat_args = Some(KernelFeaturesArgsV5 { lock_hgt: 23092039 });
	let v5_1 = v5.clone();
	let v5_1_copy = v5.clone();

	let v5_bin = SlateV5Bin(v5);
	let mut vec = Vec::new();
	let _ = grin_ser::serialize_default(&mut vec, &v5_bin).expect("serialization failed");
	let b4_bin_2: SlateV5Bin = grin_ser::deserialize_default(&mut &vec[..]).unwrap();
	let v5_2 = b4_bin_2.0.clone();
	assert_eq!(v5_1.ver, v5_2.ver);
	assert_eq!(v5_1.id, v5_2.id);
	assert_eq!(v5_1.amt, v5_2.amt);
	assert_eq!(v5_1.fee, v5_2.fee);
	let v5_2_coms = v5_2.coms.as_ref().unwrap().clone();
	for (i, c) in v5_1.coms.unwrap().iter().enumerate() {
		assert_eq!(c.f, v5_2_coms[i].f);
		assert_eq!(c.c, v5_2_coms[i].c);
		assert_eq!(c.p, v5_2_coms[i].p);
	}
	assert_eq!(v5_1.sigs, v5_2.sigs);
	assert_eq!(v5_1.proof, v5_2.proof);

	// Include Payment proof, remove coms to mix it up a bit
	let mut v5 = v5_1_copy;
	let raw_pubkey_str = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb";
	let b = from_hex(raw_pubkey_str).unwrap();
	let d_pkey = DalekPublicKey::from_bytes(&b).unwrap();
	v5.proof = Some(PaymentInfoV5 {
		raddr: d_pkey.clone(),
		saddr: d_pkey.clone(),
		rsig: None,
	});
	v5.coms = None;
	let v5_1 = v5.clone();
	let v5_bin = SlateV5Bin(v5);
	let mut vec = Vec::new();
	let _ = grin_ser::serialize_default(&mut vec, &v5_bin).expect("serialization failed");
	let b4_bin_2: SlateV5Bin = grin_ser::deserialize_default(&mut &vec[..]).unwrap();
	let v5_2 = b4_bin_2.0.clone();
	assert_eq!(v5_1.ver, v5_2.ver);
	assert_eq!(v5_1.id, v5_2.id);
	assert_eq!(v5_1.amt, v5_2.amt);
	assert_eq!(v5_1.fee, v5_2.fee);
	assert!(v5_1.coms.is_none());
	assert_eq!(v5_1.sigs, v5_2.sigs);
	assert_eq!(v5_1.proof, v5_2.proof);
}
