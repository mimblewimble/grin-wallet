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

use crate::backend::WalletBackend;
use crate::blake2::blake2b::blake2b;
use crate::contract::types::{ProofArgs, ProofType};
use crate::grin_core::libtx::aggsig;
use crate::grin_core::libtx::secp_ser;
use crate::grin_core::ser as grin_ser;
use crate::grin_core::ser::{Writeable, Writer};
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::Commitment;
use crate::grin_util::secp::Secp256k1;
use crate::grin_util::secp::Signature;
use crate::grin_util::static_secp_instance;
use crate::slate::{PaymentInfo, PaymentMemo, PaymentProofType, Slate, SlateState};
use crate::slate_versions::ser as dalek_ser;
use crate::types::{Context, NodeClient};
use crate::{address, Error};
use chrono::{DateTime, Utc};
use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::SigningKey as DalekSecretKey;
use ed25519_dalek::VerifyingKey as DalekPublicKey;
use ed25519_dalek::{Signer, Verifier};
use grin_util::secp::Message;

pub(super) fn check_proof_type(proof_type: &ProofType) -> Result<(), Error> {
	match proof_type {
		ProofType::Invoice | ProofType::SenderNonce => Ok(()),
		_ => Err(Error::GenericError(
			"Unsupported contract proof type".to_string(),
		)),
	}
}

fn write_amount<W: Writer>(writer: &mut W, amount: u64) -> Result<(), grin_ser::Error> {
	let amount_bytes = amount.to_be_bytes();
	if amount_bytes[0] != 0 {
		return Err(grin_ser::Error::UnexpectedData {
			expected: vec![0],
			received: vec![amount_bytes[0]],
		});
	}
	writer.write_fixed_bytes(&amount_bytes[1..])
}

fn verify_receiver_sig(
	secp: &Secp256k1,
	sig: &Signature,
	receiver_nonce: &PublicKey,
	pub_nonce_sum: &PublicKey,
	receiver_excess: &PublicKey,
	pub_blind_sum: &PublicKey,
	msg: &Message,
) -> Result<(), Error> {
	let receiver_nonce = receiver_nonce.serialize_vec(secp, true);
	if sig[0..32] != receiver_nonce[1..33] {
		return Err(Error::PaymentProofValidation(
			"Receiver nonce does not match the promise".into(),
		));
	}
	aggsig::verify_partial_sig(
		secp,
		sig,
		pub_nonce_sum,
		receiver_excess,
		Some(pub_blind_sum),
		msg,
	)?;
	Ok(())
}

fn recover_receiver_sig(
	secp: &Secp256k1,
	excess_sig: &Signature,
	sender_sig: &Signature,
	receiver_nonce: &PublicKey,
) -> Result<Signature, Error> {
	let mut scalar = SecretKey::from_slice(secp, &excess_sig[32..])?;
	let mut sender_scalar = SecretKey::from_slice(secp, &sender_sig[32..])?;
	sender_scalar.neg_assign(secp)?;
	scalar.add_assign(secp, &sender_scalar)?;

	let nonce = receiver_nonce.serialize_vec(secp, true);
	let mut signature = [0; 64];
	signature[..32].copy_from_slice(&nonce[1..]);
	signature[32..].copy_from_slice(&scalar.0);
	Signature::from_raw_data(&signature).map_err(Error::from)
}

/// All elements required to validate a proof within a single struct
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
	/// Untweaked sender nonce used by sender-nonce proofs
	#[serde(
		default,
		with = "dalek_ser::option_pubkey_serde",
		skip_serializing_if = "Option::is_none"
	)]
	pub sender_public_nonce: Option<PublicKey>,
}

/// Early payment proof extracted from a slate and stored transaction data
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EarlyPaymentProof {
	/// Proof type
	#[serde(with = "crate::slate::payment_proof_type_serde")]
	pub proof_type: PaymentProofType,
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
}

struct PromiseBin<'a>(&'a EarlyPaymentProof);

impl Writeable for PromiseBin<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		writer.write_u8(self.0.proof_type.as_u8())?;
		match self.0.proof_type {
			PaymentProofType::Invoice => write_amount(writer, self.0.amount)?,
			PaymentProofType::SenderNonce => writer.write_fixed_bytes(&[0; 7])?,
			PaymentProofType::Legacy => {
				return Err(grin_ser::Error::CorruptedData);
			}
		}
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
		if self.0.proof_type == PaymentProofType::Invoice {
			writer.write_i64(self.0.timestamp)?;
			let memo = self.0.memo.as_ref().map(PaymentMemo::as_str).unwrap_or("");
			writer.write_fixed_bytes(blake2b(32, &[], memo.as_bytes()).as_bytes())?;
		}
		Ok(())
	}
}

struct SenderNonceMessage<'a>(&'a EarlyPaymentProof);

impl Writeable for SenderNonceMessage<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		writer.write_u8(PaymentProofType::SenderNonce.as_u8())?;
		write_amount(writer, self.0.amount)?;
		writer.write_i64(self.0.timestamp)?;
		let memo = self.0.memo.as_ref().map(PaymentMemo::as_str).unwrap_or("");
		writer.write_fixed_bytes(blake2b(32, &[], memo.as_bytes()).as_bytes())
	}
}

impl EarlyPaymentProof {
	/// Extract as much proof data as possible from a slate
	pub fn from_slate(
		slate: &Slate,
		participant_index: usize,
		sender_address: Option<DalekPublicKey>,
	) -> Result<Self, Error> {
		// Bounds-check the participant index before indexing participant_data, so a
		// malformed slate returns an error rather than panicking.
		if participant_index >= slate.participant_data.len() {
			return Err(Error::GenericError(format!(
				"Participant index {} out of range for slate with {} participant(s)",
				participant_index,
				slate.participant_data.len()
			)));
		}
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

		let (proof_type, timestamp) = match slate.payment_proof.as_ref() {
			Some(p) => (
				p.proof_type,
				p.timestamp
					.ok_or_else(|| Error::PaymentProof("Missing proof timestamp".to_string()))?
					.timestamp(),
			),
			None => (PaymentProofType::Invoice, 0),
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
			proof_type,
			amount: slate.amount,
			receiver_public_nonce: slate.participant_data[participant_index].public_nonce,
			receiver_public_excess: slate.participant_data[participant_index].public_blind_excess,
			sender_address,
			timestamp,
			memo,
			promise_signature,
			witness_data: None,
		})
	}

	/// Sign the payment promise
	pub fn sign(&self, sec_key: &SecretKey) -> Result<(DalekSignature, DalekPublicKey), Error> {
		let d_skey = DalekSecretKey::from_bytes(&sec_key.0);
		let pub_key = d_skey.verifying_key();
		let mut sig_data_bin = Vec::new();
		grin_ser::serialize_default(&mut sig_data_bin, &PromiseBin(self)).map_err(|e| {
			Error::GenericError(format!("Payment proof serialization failed: {}", e))
		})?;

		Ok((d_skey.sign(&sig_data_bin), pub_key))
	}

	/// Verify the receiver's promise signature
	/// Sender-nonce payment details are only checked by `verify_witness`
	pub fn verify_promise_signature(
		&self,
		recipient_address: &DalekPublicKey,
	) -> Result<(), Error> {
		check_proof_type(&self.proof_type)?;
		if self.promise_signature.is_none() {
			return Err(Error::PaymentProofValidation(
				"Missing promise signature".into(),
			));
		}

		// Rebuild message
		let mut sig_data_bin = Vec::new();
		grin_ser::serialize_default(&mut sig_data_bin, &PromiseBin(self)).map_err(|e| {
			Error::GenericError(format!("Payment proof serialization failed: {}", e))
		})?;

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

	/// Verify signature and proof against a given kernel message (kernel lookup is beyond the scope
	/// of this module)
	pub fn verify_witness(
		&self,
		recipient_address: &DalekPublicKey,
		excess_sig: &Signature,
		msg: &Message,
	) -> Result<(), Error> {
		if self.witness_data.is_none() {
			return Err(Error::PaymentProofValidation("Missing witness data".into()));
		}

		self.verify_promise_signature(recipient_address)?;

		let wd = self.witness_data.as_ref().unwrap().clone();
		{
			let static_secp = static_secp_instance();
			let static_secp = static_secp.lock();

			// Retrieve the public nonce sum from the kernel excess signature
			let mut pub_nonce_sum_bytes = [3u8; 33];
			pub_nonce_sum_bytes[1..33].copy_from_slice(&excess_sig[0..32]);
			let pub_nonce_sum = PublicKey::from_slice(&static_secp, &pub_nonce_sum_bytes)?;
			let receiver_part_sigs = if self.proof_type == PaymentProofType::SenderNonce {
				let sender_nonce = wd.sender_public_nonce.as_ref().ok_or_else(|| {
					Error::PaymentProofValidation("Missing sender nonce witness".into())
				})?;
				let mut expected_sender_nonce = sender_nonce.clone();
				expected_sender_nonce.add_exp_assign(
					&static_secp,
					&sender_nonce_tweak(&static_secp, sender_nonce, self)?,
				)?;
				let expected_sum = PublicKey::from_combination(
					&static_secp,
					vec![&expected_sender_nonce, &self.receiver_public_nonce],
				)?;
				if expected_sum.serialize_vec(&static_secp, true)[1..] != excess_sig[0..32] {
					return Err(Error::PaymentProofValidation(
						"Sender nonce does not commit to the payment details".into(),
					));
				}
				let sender_nonce = expected_sender_nonce.serialize_vec(&static_secp, true);
				if wd.sender_partial_sig[0..32] != sender_nonce[1..] {
					return Err(Error::PaymentProofValidation(
						"Sender partial signature nonce does not match the proof".into(),
					));
				}
				vec![recover_receiver_sig(
					&static_secp,
					excess_sig,
					&wd.sender_partial_sig,
					&self.receiver_public_nonce,
				)?]
			} else {
				let (signature, alternative) =
					aggsig::subtract_signature(&static_secp, excess_sig, &wd.sender_partial_sig)?;
				alternative.into_iter().chain(Some(signature)).collect()
			};

			// Retrieve the public key sum from the kernel excess
			let pub_blind_sum = wd.kernel_commitment.to_pubkey(&static_secp)?;
			if !receiver_part_sigs.iter().any(|signature| {
				verify_receiver_sig(
					&static_secp,
					signature,
					&self.receiver_public_nonce,
					&pub_nonce_sum,
					&self.receiver_public_excess,
					&pub_blind_sum,
					&msg,
				)
				.is_ok()
			}) {
				return Err(Error::PaymentProofValidation(
					"Receiver signature does not match the promise".into(),
				));
			}
		}
		Ok(())
	}
}

fn sender_nonce_tweak(
	secp: &Secp256k1,
	sender_nonce: &PublicKey,
	proof: &EarlyPaymentProof,
) -> Result<SecretKey, Error> {
	let mut message = Vec::new();
	grin_ser::serialize_default(&mut message, &SenderNonceMessage(proof)).map_err(|e| {
		Error::GenericError(format!("Sender nonce message serialization failed: {}", e))
	})?;
	let nonce = sender_nonce.serialize_vec(secp, true);
	let mut data = Vec::with_capacity(nonce.len() + message.len());
	data.extend_from_slice(&nonce);
	data.extend_from_slice(&message);
	let hash = blake2b(32, &[], &data);
	SecretKey::from_slice(secp, hash.as_bytes()).map_err(Error::from)
}

/// Commit the payer nonce to the sender-nonce proof fields
pub(super) fn commit_sender_nonce(
	slate: &Slate,
	context: &mut Context,
	secp: &Secp256k1,
) -> Result<(), Error> {
	if context.get_net_change()? >= 0 {
		return Ok(());
	}
	let payment_proof = match slate.payment_proof.as_ref() {
		Some(proof) if proof.proof_type == PaymentProofType::SenderNonce => proof,
		_ => return Ok(()),
	};
	if slate.state != SlateState::Invoice1 || slate.participant_data.len() != 1 {
		return Err(Error::PaymentProofValidation(
			"Sender nonce proofs require the first RSR signing round".into(),
		));
	}
	let sender_address = payment_proof
		.sender_address
		.ok_or(Error::NoSenderAddressProvided)?;
	let proof = EarlyPaymentProof::from_slate(slate, 0, Some(sender_address))?;
	if let Some(base_public) = context.sender_public_nonce.as_ref() {
		let mut expected = base_public.clone();
		expected.add_exp_assign(secp, &sender_nonce_tweak(secp, base_public, &proof)?)?;
		if PublicKey::from_secret_key(secp, &context.sec_nonce)? != expected {
			return Err(Error::PaymentProofValidation(
				"Sender nonce proof details changed".into(),
			));
		}
	} else {
		let base_public = PublicKey::from_secret_key(secp, &context.sec_nonce)?;
		context
			.sec_nonce
			.add_assign(secp, &sender_nonce_tweak(secp, &base_public, &proof)?)?;
		context.sender_public_nonce = Some(base_public);
	}
	Ok(())
}

/// Adds all info needed for a payment proof to a slate, complete with signed recipient data
pub(super) fn add_payment_proof<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
	proof_args: &ProofArgs,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	if proof_args.proof_type == PaymentProofType::SenderNonce && slate.state != SlateState::Invoice1
	{
		return Err(Error::PaymentProofValidation(
			"Sender nonce proofs are only supported for RSR contracts".into(),
		));
	}
	let (early_proof, promise_signature, receiver_address) =
		generate_promise_signature(wallet, keychain_mask, slate, context, proof_args)?;
	// Carry over the timestamp the promise signature was made over rather than reading
	// the clock a second time. The signature binds it, so a tick between the two reads
	// would leave a proof that cannot verify.
	let timestamp = DateTime::from_timestamp(early_proof.timestamp, 0).ok_or_else(|| {
		Error::GenericError(format!(
			"Invalid proof timestamp: {}",
			early_proof.timestamp
		))
	})?;

	let proof = PaymentInfo {
		proof_type: early_proof.proof_type,
		sender_address: proof_args.sender_address.clone(),
		receiver_address,
		timestamp: Some(timestamp),
		promise_signature: Some(promise_signature),
		memo: early_proof.memo,
	};
	slate.payment_proof = Some(proof);
	Ok(())
}

fn generate_promise_signature<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
	proof_args: &ProofArgs,
) -> Result<(EarlyPaymentProof, DalekSignature, DalekPublicKey), Error>
where
	C: NodeClient,
	K: Keychain,
{
	let keychain = wallet.keychain(keychain_mask)?;
	let index = slate.find_index_matching_context(&keychain, context)?;
	let mut early_proof = EarlyPaymentProof::from_slate(&slate, index, proof_args.sender_address)?;
	early_proof.proof_type = proof_args.proof_type;
	let derivation_index = match context.payment_proof_derivation_index {
		Some(i) => i,
		None => 0,
	};
	// Derive the proof address under the contract's account, not the active one.
	let parent_key_id = context.parent_key_id.clone();
	let recp_key =
		address::address_from_derivation_path(&keychain, &parent_key_id, derivation_index)?;

	early_proof.timestamp = Utc::now().timestamp();
	let (sig, addr) = early_proof.sign(&recp_key)?;
	Ok((early_proof, sig, addr))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::slate_versions::tests::populate_test_slate;

	#[test]
	fn rejects_unsupported_proofs() {
		assert!(check_proof_type(&ProofType::Invoice).is_ok());
		assert!(check_proof_type(&ProofType::Legacy).is_err());
		assert!(check_proof_type(&ProofType::SenderNonce).is_ok());
	}

	#[test]
	fn checks_receiver_nonce() {
		let secp = Secp256k1::new();
		let sender_key = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let receiver_key = SecretKey::from_slice(&secp, &[2; 32]).unwrap();
		let sender_nonce = SecretKey::from_slice(&secp, &[3; 32]).unwrap();
		let receiver_nonce = SecretKey::from_slice(&secp, &[4; 32]).unwrap();
		let sender_pub_nonce = PublicKey::from_secret_key(&secp, &sender_nonce).unwrap();
		let receiver_pub_nonce = PublicKey::from_secret_key(&secp, &receiver_nonce).unwrap();
		let sender_excess = PublicKey::from_secret_key(&secp, &sender_key).unwrap();
		let receiver_excess = PublicKey::from_secret_key(&secp, &receiver_key).unwrap();
		let pub_nonce_sum =
			PublicKey::from_combination(&secp, vec![&sender_pub_nonce, &receiver_pub_nonce])
				.unwrap();
		let pub_blind_sum =
			PublicKey::from_combination(&secp, vec![&sender_excess, &receiver_excess]).unwrap();
		let msg = Message::from_slice(&[5; 32]).unwrap();
		let sig = aggsig::calculate_partial_sig(
			&secp,
			&receiver_key,
			&receiver_nonce,
			&pub_nonce_sum,
			Some(&pub_blind_sum),
			&msg,
		)
		.unwrap();

		assert!(verify_receiver_sig(
			&secp,
			&sig,
			&receiver_pub_nonce,
			&pub_nonce_sum,
			&receiver_excess,
			&pub_blind_sum,
			&msg,
		)
		.is_ok());
		assert!(verify_receiver_sig(
			&secp,
			&sig,
			&sender_pub_nonce,
			&pub_nonce_sum,
			&receiver_excess,
			&pub_blind_sum,
			&msg,
		)
		.is_err());
	}

	#[test]
	fn proof_promise() -> Result<(), Error> {
		use crate::grin_util::ToHex;

		let mut slate = populate_test_slate()?;
		slate.amount |= 0xFF00_0000_0000_0000;
		// Bin serialization doesn't include promise sig as it's used to create signature data
		slate.payment_proof.as_mut().unwrap().promise_signature = None;

		// Should fail, amount too big
		let proof = EarlyPaymentProof::from_slate(&slate, 1, None)?;
		let mut vec = Vec::new();
		assert!(grin_ser::serialize_default(&mut vec, &PromiseBin(&proof)).is_err());

		// Should be okay now
		slate.amount = 1234;
		slate.payment_proof.as_mut().unwrap().timestamp = DateTime::from_timestamp(123456789, 0);
		let mut proof = EarlyPaymentProof::from_slate(&slate, 1, None)?;
		let secp = Secp256k1::new();
		proof.receiver_public_nonce =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secp, &[1; 32])?)?;
		proof.receiver_public_excess =
			PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secp, &[2; 32])?)?;
		let mut vec = Vec::new();
		grin_ser::serialize_default(&mut vec, &PromiseBin(&proof)).expect("Serialization Failed");
		assert_eq!(
			vec.to_hex(),
			"01000000000004d2031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb00000000075bcd15c60e4f851ed93b6641571e6810f608fe42ee566f7e199915061ea13b3b04e772"
		);
		let proof_key = SecretKey::from_slice(&Secp256k1::new(), &[7; 32])?;
		let (signature, recipient) = proof.sign(&proof_key)?;
		proof.promise_signature = Some(signature);
		proof.verify_promise_signature(&recipient)?;
		proof.memo = Some(PaymentMemo::new("changed details".to_string())?);
		assert!(proof.verify_promise_signature(&recipient).is_err());

		let mut sender_nonce = proof.clone();
		sender_nonce.memo = slate.payment_proof.as_ref().unwrap().memo.clone();
		sender_nonce.proof_type = PaymentProofType::SenderNonce;
		let mut promise = Vec::new();
		grin_ser::serialize_default(&mut promise, &PromiseBin(&sender_nonce))
			.expect("Serialization Failed");
		assert_eq!(
			promise.to_hex(),
			"0200000000000000031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb"
		);
		let mut sender_message = Vec::new();
		grin_ser::serialize_default(&mut sender_message, &SenderNonceMessage(&sender_nonce))
			.expect("Serialization Failed");
		assert_eq!(
			sender_message.to_hex(),
			"02000000000004d200000000075bcd15c60e4f851ed93b6641571e6810f608fe42ee566f7e199915061ea13b3b04e772"
		);
		let base = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secp, &[9; 32])?)?;
		assert_eq!(
			sender_nonce_tweak(&secp, &base, &sender_nonce)?.0.to_hex(),
			"6bd7c4e86bd61999c26fdd4cc1af90cdcb0a79e39644f4d8045e2a6599bd4db0"
		);
		let (signature, recipient) = sender_nonce.sign(&proof_key)?;
		sender_nonce.promise_signature = Some(signature);
		sender_nonce.amount += 1;
		sender_nonce.timestamp += 1;
		sender_nonce.verify_promise_signature(&recipient)?;

		let mut wrong_type = proof;
		wrong_type.proof_type = PaymentProofType::Legacy;
		assert!(wrong_type
			.verify_promise_signature(&slate.payment_proof.unwrap().receiver_address)
			.is_err());
		Ok(())
	}

	#[test]
	fn memo_limit() {
		assert!(PaymentMemo::new("a".repeat(PaymentMemo::MAX_LEN)).is_ok());
		assert!(PaymentMemo::new("a".repeat(PaymentMemo::MAX_LEN + 1)).is_err());
		assert!(PaymentMemo::new("ä".repeat(PaymentMemo::MAX_LEN / 2)).is_ok());
		assert!(PaymentMemo::new("ä".repeat(PaymentMemo::MAX_LEN / 2 + 1)).is_err());
	}
}
