// Copyright 2023 The Grin Developers
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

//! Experimental early payment proof functionality, currently only used
//! with contracts. Can move outside of this module if early proofs are adopted
//! by legacy transactions

use crate::contract::types::ProofArgs;
use crate::grin_core::libtx::aggsig;
use crate::grin_core::libtx::secp_ser;
use crate::grin_core::ser as grin_ser;
use crate::grin_core::ser::{Readable, Reader, Writeable, Writer};
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::Commitment;
use crate::grin_util::secp::Signature;
use crate::grin_util::static_secp_instance;
use crate::slate::{PaymentInfo, PaymentMemo, Slate};
use crate::slate_versions::ser as dalek_ser;
use crate::types::{Context, NodeClient, WalletBackend};
use crate::{address, Error};
use byteorder::{BigEndian, ByteOrder};
use chrono::{DateTime, NaiveDateTime, Utc};
use ed25519_dalek::Keypair as DalekKeypair;
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::{Signer, Verifier};
use grin_util::secp::Message;
use std::convert::TryInto;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProofWitness {
	/// Kernel index, supplied so verifiers can look up kernel
	/// without an expensive lookup operation
	#[serde(with = "secp_ser::string_or_u64")]
	pub kernel_index: u64,
	/// Kernel commitment, supplied so prover can recompute index
	/// if required after a reorg
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub kernel_commitment: Commitment,
	/// sender partial signature, used to recover receiver partial signature
	#[serde(with = "secp_ser::sig_serde")]
	pub sender_partial_sig: Signature,
}

// Payment proof, to be extracted from slates for
// signing (when wrapped as PaymentProofBin) or json export from stored tx data
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct InvoiceProof {
	/// Proof type, 0x00 legacy (though this will use StoredProofInfo above, 1 invoice, 2 Sender nonce)
	pub proof_type: u8,
	/// amount
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount: u64,
	/// receiver's public nonce from signing
	#[serde(with = "secp_ser::pubkey_serde")]
	pub receiver_public_nonce: PublicKey,
	/// receiver's public excess from signing
	#[serde(with = "secp_ser::pubkey_serde")]
	pub receiver_public_excess: PublicKey,
	/// Sender's address
	#[serde(with = "dalek_ser::dalek_pubkey_serde")]
	pub sender_address: DalekPublicKey,
	/// Timestamp provided by recipient when signing
	pub timestamp: i64,
	/// Optional payment memo
	#[serde(skip_serializing_if = "Option::is_none")]
	pub memo: Option<PaymentMemo>,
	/// Not serialized in binary format
	#[serde(with = "dalek_ser::option_dalek_sig_serde")]
	pub promise_signature: Option<DalekSignature>,
	/// Not serialized in binary format, just a convenient place to insert
	/// the witness kernel commitment index
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_data: Option<ProofWitness>,
	/// Also convenient place to return sender part sig when retrieving from DB
	/// TODO: check if needed
	#[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with = "secp_ser::option_sig_serde")]
	pub sender_partial_sig: Option<Signature>,
}

struct InvoiceProofBin(InvoiceProof);

impl Writeable for InvoiceProofBin {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		writer.write_u8(1)?;

		// Amount field is 7 bytes, throw error if value is greater
		let mut amount_bytes = [0; 8];
		BigEndian::write_u64(&mut amount_bytes, self.0.amount);

		if amount_bytes[0] > 0 {
			return Err(grin_ser::Error::UnexpectedData {
				expected: [0u8].to_vec(),
				received: [amount_bytes[0]].to_vec(),
			});
		}
		writer.write_fixed_bytes(amount_bytes[1..].to_vec())?;
		{
			let static_secp = static_secp_instance();
			let static_secp = static_secp.lock();
			writer.write_fixed_bytes(
				self.0
					.receiver_public_nonce
					.serialize_vec(&static_secp, true),
			)?;
			writer.write_fixed_bytes(
				self.0
					.receiver_public_excess
					.serialize_vec(&static_secp, true),
			)?;
		}
		writer.write_fixed_bytes(self.0.sender_address.as_bytes())?;
		writer.write_i64(self.0.timestamp)?;
		match &self.0.memo {
			Some(s) => {
				writer.write_u8(s.memo_type)?;
				writer.write_fixed_bytes(&s.memo.to_vec())?;
			}
			None => {
				writer.write_u8(0)?;
				writer.write_fixed_bytes([0u8; 32].to_vec())?;
			}
		}
		Ok(())
	}
}

/// Not strictly necessary, but useful for tests
impl Readable for InvoiceProofBin {
	fn read<R: Reader>(reader: &mut R) -> Result<InvoiceProofBin, grin_ser::Error> {
		// first 8 bytes are proof type + 7 bytes worth of amount
		let mut amount = reader.read_u64()?;
		let proof_type: u8 = ((amount & 0xFF00_0000_0000_0000) >> 56).try_into().unwrap();
		amount &= 0x00FF_FFFF_FFFF_FFFF;

		let receiver_public_nonce;
		let receiver_public_excess;
		{
			let static_secp = static_secp_instance();
			let static_secp = static_secp.lock();
			receiver_public_nonce =
				PublicKey::from_slice(&static_secp, &reader.read_fixed_bytes(33)?).unwrap();
			receiver_public_excess =
				PublicKey::from_slice(&static_secp, &reader.read_fixed_bytes(33)?).unwrap();
		}

		let sender_address_vec = reader.read_fixed_bytes(32)?;
		let sender_address = DalekPublicKey::from_bytes(&sender_address_vec).unwrap();

		let timestamp = reader.read_i64()?;

		let memo_type = reader.read_u8()?;
		let memo = reader.read_fixed_bytes(32)?;
		let mut memo_bytes: [u8; 32] = [0u8; 32];
		memo_bytes.copy_from_slice(&memo);

		let res = InvoiceProof {
			proof_type,
			amount,
			receiver_public_nonce,
			receiver_public_excess,
			sender_address,
			timestamp,
			memo: match memo_type {
				0 => None,
				_ => Some(PaymentMemo {
					memo_type,
					memo: memo_bytes,
				}),
			},
			promise_signature: None,
			witness_data: None,
			sender_partial_sig: None,
		};

		Ok(InvoiceProofBin(res))
	}
}

impl InvoiceProof {
	/// Extracts as much data as possible from the slate to create an invoice proof
	pub fn from_slate(
		slate: &Slate,
		participant_index: usize,
		sender_address: Option<DalekPublicKey>,
	) -> Result<Self, Error> {
		// Sender address is either provided or in slate (or error)
		let sender_address = match sender_address {
			Some(a) => a,
			None => {
				if let Some(ref p) = slate.payment_proof {
					if let Some(a) = p.sender_address {
						a
					} else {
						return Err(Error::NoSenderAddressProvided);
					}
				} else {
					return Err(Error::NoSenderAddressProvided);
				}
			}
		};

		let timestamp = match slate.payment_proof.as_ref() {
			Some(p) => NaiveDateTime::from_timestamp(p.timestamp.timestamp(), 0).timestamp(),
			None => 0,
		};

		let memo = match slate.payment_proof.as_ref() {
			Some(p) => p.memo.clone(),
			None => None,
		};

		let promise_signature = match slate.payment_proof.as_ref() {
			Some(p) => p.promise_signature.clone(),
			None => None,
		};

		Ok(Self {
			proof_type: 1u8,
			amount: slate.amount,
			receiver_public_nonce: slate.participant_data[participant_index].public_nonce,
			receiver_public_excess: slate.participant_data[participant_index].public_blind_excess,
			sender_address,
			timestamp,
			memo,
			promise_signature,
			witness_data: None,
			sender_partial_sig: None,
		})
	}

	pub fn sign(&self, sec_key: &SecretKey) -> Result<(DalekSignature, DalekPublicKey), Error> {
		let d_skey = match DalekSecretKey::from_bytes(&sec_key.0) {
			Ok(k) => k,
			Err(e) => {
				return Err(Error::ED25519Key(format!("{}", e)));
			}
		};
		let pub_key: DalekPublicKey = (&d_skey).into();
		let keypair = DalekKeypair {
			public: pub_key,
			secret: d_skey,
		};
		let mut sig_data_bin = Vec::new();
		let _ = grin_ser::serialize_default(&mut sig_data_bin, &InvoiceProofBin(self.clone()))
			.expect("serialization failed");

		Ok((keypair.sign(&sig_data_bin), pub_key))
	}

	pub fn verify_promise_signature(
		&self,
		recipient_address: &DalekPublicKey,
	) -> Result<(), Error> {
		if self.promise_signature.is_none() {
			return Err(Error::PaymentProofValidation(
				"Missing promise signature".into(),
			));
		}

		// Rebuild message
		let mut sig_data_bin = Vec::new();
		let _ = grin_ser::serialize_default(&mut sig_data_bin, &InvoiceProofBin(self.clone()))
			.expect("serialization failed");

		if recipient_address
			.verify(&sig_data_bin, self.promise_signature.as_ref().unwrap())
			.is_err()
		{
			return Err(Error::PaymentProof(
				"Invalid recipient signature".to_owned(),
			));
		};
		Ok(())
	}

	pub fn verify_witness(
		&self,
		recipient_address: Option<&DalekPublicKey>,
		excess_sig: &Signature,
		msg: &Message,
	) -> Result<(), Error> {
		if self.witness_data.is_none() {
			return Err(Error::PaymentProofValidation("Missing witness data".into()));
		}

		if let Some(a) = recipient_address {
			self.verify_promise_signature(a)?;
		};

		let wd = self.witness_data.as_ref().unwrap().clone();
		{
			let static_secp = static_secp_instance();
			let static_secp = static_secp.lock();

			let receiver_part_sig =
				aggsig::subtract_signature(&static_secp, &excess_sig, &wd.sender_partial_sig)?;

			// Retrieve the public nonce sum from the kernel excess signature
			let mut pub_nonce_sum_bytes = [3u8; 33];
			pub_nonce_sum_bytes[1..33].copy_from_slice(&excess_sig[0..32]);
			let pub_nonce_sum = PublicKey::from_slice(&static_secp, &pub_nonce_sum_bytes)?;

			// Retrieve the public key sum from the kernel excess
			let pub_blind_sum = wd.kernel_commitment.to_pubkey(&static_secp)?;

			if let Err(_) = aggsig::verify_partial_sig(
				&static_secp,
				&receiver_part_sig.0,
				&pub_nonce_sum,
				&self.receiver_public_excess,
				Some(&pub_blind_sum),
				&msg,
			) {
				// Try other possibility
				if let Some(s) = receiver_part_sig.1 {
					aggsig::verify_partial_sig(
						&static_secp,
						&s,
						&pub_nonce_sum,
						&self.receiver_public_excess,
						Some(&pub_blind_sum),
						&msg,
					)?;
				} else {
					return Err(Error::PaymentProofValidation(
						"Signature subtraction failed".into(),
					));
				}
			}
		}

		Ok(())
	}
}

impl serde::Serialize for InvoiceProofBin {
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

/// Adds all info needed for a payment proof to a slate, complete with signed recipient data
pub fn add_payment_proof<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
	proof_args: &ProofArgs,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// TODO: Just generating invoice (type 1) for now
	let (invoice_proof, promise_signature, receiver_address) =
		generate_invoice_signature(wallet, keychain_mask, slate, context, proof_args)?;
	let timestamp = NaiveDateTime::from_timestamp(Utc::now().timestamp(), 0);
	let timestamp = DateTime::<Utc>::from_utc(timestamp, Utc);

	let proof = PaymentInfo {
		sender_address: proof_args.sender_address.clone(),
		receiver_address,
		timestamp,
		promise_signature: Some(promise_signature),
		memo: invoice_proof.memo,
	};
	slate.payment_proof = Some(proof);
	Ok(())
}

/// Generates a signature for proof type 'Invoice'
fn generate_invoice_signature<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
	proof_args: &ProofArgs,
) -> Result<(InvoiceProof, DalekSignature, DalekPublicKey), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = wallet.keychain(keychain_mask)?;
	let index = slate.find_index_matching_context(&keychain, context)?;
	let mut invoice_proof = InvoiceProof::from_slate(&slate, index, proof_args.sender_address)?;
	let derivation_index = match context.payment_proof_derivation_index {
		Some(i) => i,
		None => 0,
	};
	let parent_key_id = wallet.parent_key_id();
	let recp_key =
		address::address_from_derivation_path(&keychain, &parent_key_id, derivation_index)?;

	invoice_proof.timestamp = NaiveDateTime::from_timestamp(Utc::now().timestamp(), 0).timestamp();
	let (sig, addr) = invoice_proof.sign(&recp_key)?;
	Ok((invoice_proof, sig, addr))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::slate_versions::tests::populate_test_slate;

	#[test]
	fn ser_invoice_proof_bin() -> Result<(), Error> {
		let mut slate = populate_test_slate()?;
		slate.amount |= 0xFF00_0000_0000_0000;
		// Bin serialization doesn't include promise sig as it's used to create signature data
		slate.payment_proof.as_mut().unwrap().promise_signature = None;

		// Should fail, amount too big
		let invoice_proof = InvoiceProof::from_slate(&slate, 1, None)?;
		let mut vec = Vec::new();
		assert!(grin_ser::serialize_default(&mut vec, &InvoiceProofBin(invoice_proof)).is_err());

		// Should be okay now
		slate.amount = 1234;
		let invoice_proof = InvoiceProof::from_slate(&slate, 1, None)?;
		let mut vec = Vec::new();
		grin_ser::serialize_default(&mut vec, &InvoiceProofBin(invoice_proof.clone()))
			.expect("Serialization Failed");

		let proof_deser: InvoiceProofBin = grin_ser::deserialize_default(&mut &vec[..]).unwrap();
		assert_eq!(invoice_proof, proof_deser.0);
		Ok(())
	}
}
