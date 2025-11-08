//! Cryptographic helpers used by libwallet.

pub mod frost {
	//! Utilities bridging FROST (threshold Schnorr) primitives and Grin's
	//! underlying secp256k1 implementation.

	use crate::types::{Context, FrostParticipantShare, FrostSession};
	use frost_secp256k1::{
		self as frost,
		keys::{self, IdentifierList, KeyPackage, PublicKeyPackage},
		rand_core::OsRng,
		round1, round2, Field, Group, Identifier, Secp256K1Group, Secp256K1ScalarField,
		Signature as FrostSignature, SigningKey as FrostSigningKey, SigningPackage,
		VerifyingKey as FrostVerifyingKey,
	};
	use grin_util::secp::{
		self as grin_secp, key::SecretKey as GrinSecretKey, PublicKey as GrinPublicKey, Secp256k1,
		Signature as GrinSignature,
	};
	use std::collections::{BTreeMap, HashMap};
	use std::convert::TryFrom;
	use thiserror::Error;

	/// Errors that can occur when converting between FROST and Grin types.
	#[derive(Debug, Error)]
	pub enum FrostConversionError {
		/// Error reported by the underlying FROST library.
		#[error("frost error: {0}")]
		Frost(#[from] frost::Error),
		/// Error reported by the secp256k1 library used by Grin.
		#[error("secp256k1 error: {0}")]
		Secp(#[from] grin_secp::Error),
		/// Unexpected serialization encountered while converting between formats.
		#[error("signature serialization error: {0}")]
		Serialization(String),
		/// Invalid parameters supplied when preparing a session.
		#[error("invalid FROST parameters: {0}")]
		InvalidParameters(String),
	}

	/// Convert a Grin `SecretKey` into a FROST signing key.
	pub fn signing_key_from_secret(
		secret: &GrinSecretKey,
	) -> Result<FrostSigningKey, FrostConversionError> {
		FrostSigningKey::deserialize(&secret.0).map_err(FrostConversionError::from)
	}

	/// Convert a FROST (R, z) signature into the `(Rx, s)` encoding used by Grin's
	/// Schnorr implementation. Returns the converted signature, the aggregated
	/// public key, and the aggregated nonce commitment.
	pub fn signature_to_grin(
		signature: &FrostSignature,
		verifying_key: &FrostVerifyingKey,
	) -> Result<(GrinSignature, GrinPublicKey, GrinPublicKey), FrostConversionError> {
		let secp = Secp256k1::new();

		let r_bytes = Secp256K1Group::serialize(signature.R())
			.map_err(|e| FrostConversionError::Serialization(e.to_string()))?;
		let aggregated_nonce = GrinPublicKey::from_slice(&secp, &r_bytes)?;

		let verifying_bytes = Secp256K1Group::serialize(&(*verifying_key).to_element())
			.map_err(|e| FrostConversionError::Serialization(e.to_string()))?;
		let aggregated_pubkey = GrinPublicKey::from_slice(&secp, &verifying_bytes)?;

		let s_serialized = Secp256K1ScalarField::serialize(signature.z());
		let mut s_scalar = GrinSecretKey::from_slice(&secp, &s_serialized)?;
		if matches!(r_bytes.first(), Some(0x03)) {
			// In BIP-340 encoding the y-coordinate of R must be even. If the
			// compressed point indicates an odd y, negate the scalar mod n.
			s_scalar.neg_assign(&secp)?;
		}

		let mut grin_bytes = [0u8; 64];
		grin_bytes[..32].copy_from_slice(&r_bytes[1..]);
		grin_bytes[32..].copy_from_slice(&s_scalar.0);

		Ok((
			GrinSignature::from_raw_data(&grin_bytes)?,
			aggregated_pubkey,
			aggregated_nonce,
		))
	}

	/// Serialize a FROST identifier.
	pub fn identifier_to_bytes(identifier: &Identifier) -> Result<Vec<u8>, FrostConversionError> {
		Ok(identifier.serialize())
	}

	/// Deserialize a FROST identifier.
	pub fn identifier_from_bytes(bytes: &[u8]) -> Result<Identifier, FrostConversionError> {
		Identifier::deserialize(bytes)
			.map_err(|e| FrostConversionError::Serialization(e.to_string()))
	}

	/// Serialize a [`KeyPackage`].
	pub fn serialize_key_package(pkg: &KeyPackage) -> Result<Vec<u8>, FrostConversionError> {
		pkg.serialize()
			.map_err(|e| FrostConversionError::Serialization(e.to_string()))
	}

	/// Deserialize a [`KeyPackage`].
	pub fn deserialize_key_package(bytes: &[u8]) -> Result<KeyPackage, FrostConversionError> {
		KeyPackage::deserialize(bytes)
			.map_err(|e| FrostConversionError::Serialization(e.to_string()))
	}

	/// Serialize a verifying key to bytes.
	pub fn verify_key_to_bytes(
		verifying_key: &FrostVerifyingKey,
	) -> Result<Vec<u8>, FrostConversionError> {
		verifying_key
			.serialize()
			.map_err(|e| FrostConversionError::Serialization(e.to_string()))
	}

	/// Deserialize a verifying key from bytes.
	pub fn verify_key_from_bytes(bytes: &[u8]) -> Result<FrostVerifyingKey, FrostConversionError> {
		FrostVerifyingKey::deserialize(bytes)
			.map_err(|e| FrostConversionError::Serialization(e.to_string()))
	}

	/// Convert a verifying key into a Grin public key.
	pub fn verifying_key_to_grin(
		verifying_key: &FrostVerifyingKey,
	) -> Result<GrinPublicKey, FrostConversionError> {
		let secp = Secp256k1::new();
		let bytes = verify_key_to_bytes(verifying_key)?;
		Ok(GrinPublicKey::from_slice(&secp, &bytes)?)
	}

	/// Serialize signing commitments.
	pub fn serialize_round1_commitments(
		commitments: &round1::SigningCommitments,
	) -> Result<Vec<u8>, FrostConversionError> {
		Ok(commitments
			.serialize()
			.map_err(|e| FrostConversionError::Serialization(e.to_string()))?)
	}

	/// Deserialize signing commitments.
	pub fn deserialize_round1_commitments(
		bytes: &[u8],
	) -> Result<round1::SigningCommitments, FrostConversionError> {
		round1::SigningCommitments::deserialize(bytes)
			.map_err(|e| FrostConversionError::Serialization(e.to_string()))
	}

	/// Serialize a signature share.
	pub fn serialize_round2_signature(
		signature: &round2::SignatureShare,
	) -> Result<Vec<u8>, FrostConversionError> {
		Ok(signature.serialize())
	}

	/// Deserialize a signature share.
	pub fn deserialize_round2_signature(
		bytes: &[u8],
	) -> Result<round2::SignatureShare, FrostConversionError> {
		round2::SignatureShare::deserialize(bytes)
			.map_err(|e| FrostConversionError::Serialization(e.to_string()))
	}

	/// Split a secret into shares for the given participant labels using the dealer
	/// method and return serialized session data.
	pub fn split_secret_with_labels(
		secret: &GrinSecretKey,
		threshold: u16,
		labels: &[String],
	) -> Result<FrostSession, FrostConversionError> {
		let max_signers = labels.len();
		if max_signers == 0 {
			return Err(FrostConversionError::InvalidParameters(
				"participant list cannot be empty".to_owned(),
			));
		}
		if threshold < 2 {
			return Err(FrostConversionError::InvalidParameters(
				"threshold must be at least 2".to_owned(),
			));
		}
		if threshold as usize > max_signers {
			return Err(FrostConversionError::InvalidParameters(format!(
				"invalid threshold {threshold} for {max_signers} participants",
			)));
		}

		let signing_key = signing_key_from_secret(secret)?;
		let mut identifiers = Vec::with_capacity(max_signers);
		for label in labels {
			let identifier =
				Identifier::derive(label.as_bytes()).map_err(FrostConversionError::from)?;
			identifiers.push(identifier);
		}

		let mut rng = OsRng;
		let (secret_shares, public_package) = keys::split(
			&signing_key,
			max_signers as u16,
			threshold,
			IdentifierList::Custom(&identifiers),
			&mut rng,
		)?;

		let mut participants = Vec::with_capacity(max_signers);
		for (label, identifier) in labels.iter().zip(identifiers.iter()) {
			let secret_share = secret_shares.get(identifier).ok_or_else(|| {
				FrostConversionError::InvalidParameters(format!(
					"missing share for participant {label}"
				))
			})?;
			let key_package = KeyPackage::try_from(secret_share.clone())?;
			let key_package_bytes = serialize_key_package(&key_package)?;
			let identifier_bytes = identifier_to_bytes(identifier)?;
			participants.push(FrostParticipantShare {
				label: label.clone(),
				identifier: identifier_bytes,
				key_package: key_package_bytes,
			});
		}

		let verifying_key = verify_key_to_bytes(public_package.verifying_key())?;

		Ok(FrostSession {
			threshold,
			max_signers: max_signers as u16,
			participants,
			verifying_key,
		})
	}

	/// Generate and attach a FROST session to the provided context.
	pub fn initialize_context_frost_session(
		context: &mut Context,
		threshold: u16,
		labels: &[String],
	) -> Result<(), FrostConversionError> {
		let secret = context.sec_key.clone();
		let session = split_secret_with_labels(&secret, threshold, labels)?;
		context.frost = Some(session);
		Ok(())
	}

	/// Remove any stored FROST session from the context.
	pub fn clear_context_frost_session(context: &mut Context) {
		context.frost = None;
	}

	/// Record a participant's round-1 commitment on the context.
	pub fn record_round1_commitment(
		context: &mut Context,
		label: String,
		commitment: &round1::SigningCommitments,
	) -> Result<(), FrostConversionError> {
		let bytes = serialize_round1_commitments(commitment)?;
		context
			.frost_signing_state_mut()
			.upsert_commitment(label, bytes);
		Ok(())
	}

	/// Record a participant's signature share on the context.
	pub fn record_round2_signature(
		context: &mut Context,
		label: String,
		signature: &round2::SignatureShare,
	) -> Result<(), FrostConversionError> {
		let bytes = serialize_round2_signature(signature)?;
		context
			.frost_signing_state_mut()
			.upsert_signature(label, bytes);
		Ok(())
	}

	/// Result of aggregating recorded FROST signature shares into a Grin-compatible
	/// signature and associated points.
	#[derive(Debug, Clone, PartialEq, Eq)]
	pub struct AggregatedSignatureResult {
		/// Final Grin Schnorr signature derived from the aggregated FROST signature.
		pub signature: GrinSignature,
		/// Aggregated public key corresponding to the signature.
		pub aggregated_pubkey: GrinPublicKey,
		/// Aggregated nonce commitment corresponding to the signature.
		pub aggregated_nonce: GrinPublicKey,
	}

	/// Aggregate stored FROST commitments and signature shares into a single
	/// Grin-compatible Schnorr signature.
	pub fn aggregate_signature(
		context: &Context,
		message: &[u8; 32],
	) -> Result<AggregatedSignatureResult, FrostConversionError> {
		let session = context.frost_session().ok_or_else(|| {
			FrostConversionError::InvalidParameters("no stored FROST session on context".to_owned())
		})?;
		let signing_state = context.frost_signing_state().ok_or_else(|| {
			FrostConversionError::InvalidParameters("no recorded FROST signing state".to_owned())
		})?;
		if signing_state.partial_signatures.is_empty() {
			return Err(FrostConversionError::InvalidParameters(
				"no signature shares recorded".to_owned(),
			));
		}

		let verifying_key = verify_key_from_bytes(&session.verifying_key)?;

		let participants_by_label: HashMap<_, _> = session
			.participants
			.iter()
			.map(|participant| (participant.label.as_str(), participant))
			.collect();
		let commitments_by_label: HashMap<_, _> = signing_state
			.commitments
			.iter()
			.map(|commitment| (commitment.label.as_str(), commitment))
			.collect();

		let mut commitment_map = BTreeMap::new();
		let mut signature_map = BTreeMap::new();
		let mut verifying_shares = BTreeMap::new();

		for share in &signing_state.partial_signatures {
			let participant = participants_by_label
				.get(share.label.as_str())
				.ok_or_else(|| {
					FrostConversionError::InvalidParameters(format!(
						"unknown participant label '{}' in recorded signature share",
						share.label
					))
				})?;
			let identifier = identifier_from_bytes(&participant.identifier)?;
			let commitment_entry =
				commitments_by_label
					.get(share.label.as_str())
					.ok_or_else(|| {
						FrostConversionError::InvalidParameters(format!(
							"missing round-1 commitment for participant '{}'",
							share.label
						))
					})?;
			let commitment = deserialize_round1_commitments(&commitment_entry.commitment)?;
			let signature_share = deserialize_round2_signature(&share.signature)?;
			let key_package = deserialize_key_package(&participant.key_package)?;

			commitment_map.insert(identifier, commitment);
			signature_map.insert(identifier, signature_share);
			verifying_shares.insert(identifier, *key_package.verifying_share());
		}

		if signature_map.len() < session.threshold as usize {
			return Err(FrostConversionError::InvalidParameters(format!(
				"only {} signature shares recorded (threshold is {})",
				signature_map.len(),
				session.threshold
			)));
		}

		let signing_package = SigningPackage::new(commitment_map, message);
		let public_key_package = PublicKeyPackage::new(verifying_shares, verifying_key.clone());

		let aggregated_signature =
			frost_secp256k1::aggregate(&signing_package, &signature_map, &public_key_package)?;

		public_key_package
			.verifying_key()
			.verify(message, &aggregated_signature)?;

		let (grin_signature, aggregated_pubkey, aggregated_nonce) =
			signature_to_grin(&aggregated_signature, public_key_package.verifying_key())?;

		Ok(AggregatedSignatureResult {
			signature: grin_signature,
			aggregated_pubkey,
			aggregated_nonce,
		})
	}

	#[cfg(test)]
	mod tests {
		use super::*;
		use frost_secp256k1::{rand_core::RngCore, round1, round2, SigningPackage};
		use grin_keychain::Identifier as KeychainIdentifier;
		use grin_util::secp::Secp256k1;
		use std::collections::BTreeMap;

		#[test]
		#[ignore]
		fn frost_signature_roundtrip_to_grin() {
			let secp = Secp256k1::new();
			let mut rng = OsRng;

			let base_secret = loop {
				let mut candidate = [0u8; 32];
				rng.fill_bytes(&mut candidate);
				if let Ok(sk) = GrinSecretKey::from_slice(&secp, &candidate) {
					break sk;
				}
			};

			let labels = vec!["alice".to_string(), "bob".to_string(), "carol".to_string()];
			let session = split_secret_with_labels(&base_secret, 2, &labels).expect("session");

			assert_eq!(session.threshold, 2);
			assert_eq!(session.max_signers as usize, labels.len());
			assert_eq!(session.participants.len(), labels.len());

			let verifying_key = verify_key_from_bytes(&session.verifying_key).expect("vk");
			let grin_pubkey_expected = verifying_key_to_grin(&verifying_key).expect("grin");
			let verifying_bytes = verify_key_to_bytes(&verifying_key).expect("vk bytes");

			let mut key_packages = BTreeMap::new();
			let mut verifying_shares = BTreeMap::new();
			for share in &session.participants {
				let identifier = identifier_from_bytes(&share.identifier).expect("identifier");
				let package = deserialize_key_package(&share.key_package).expect("key package");
				assert_eq!(*package.min_signers(), session.threshold);
				assert_eq!(identifier_to_bytes(&identifier).unwrap(), share.identifier);
				verifying_shares.insert(identifier, *package.verifying_share());
				key_packages.insert(identifier, package);
			}

			let public_key_package = keys::PublicKeyPackage::new(verifying_shares, verifying_key);

			let participants: Vec<_> = key_packages.keys().cloned().collect();
			let selected = &participants[..session.threshold as usize];
			let mut rng = OsRng;
			let mut nonces = BTreeMap::new();
			let mut commitments = BTreeMap::new();
			for identifier in selected {
				let package = key_packages.get(identifier).unwrap();
				let (nonce, commitment) = round1::commit(package.signing_share(), &mut rng);
				nonces.insert(*identifier, nonce);
				commitments.insert(*identifier, commitment);
			}

			let message = {
				let mut bytes = [0u8; 32];
				rng.fill_bytes(&mut bytes);
				bytes
			};

			let signing_package = SigningPackage::new(commitments.clone(), &message);

			let mut signature_shares = BTreeMap::new();
			for identifier in selected {
				let package = key_packages.get(identifier).unwrap();
				let nonce = nonces.get(identifier).unwrap();
				let sig_share = round2::sign(&signing_package, nonce, package).expect("share");
				signature_shares.insert(*identifier, sig_share);
			}

			let aggregated_signature = frost_secp256k1::aggregate(
				&signing_package,
				&signature_shares,
				&public_key_package,
			)
			.expect("aggregate");

			public_key_package
				.verifying_key()
				.verify(&message, &aggregated_signature)
				.expect("frost verify");

			let (grin_signature, grin_pubkey, _grin_nonce) =
				signature_to_grin(&aggregated_signature, public_key_package.verifying_key())
					.expect("convert signature");

			assert_eq!(grin_pubkey, grin_pubkey_expected);
			let compressed = grin_pubkey.serialize_vec(&secp, true);
			assert_eq!(compressed.as_slice(), verifying_bytes.as_slice());
			let _serialized_sig = grin_signature.serialize_compact(&secp);
		}

		#[test]
		fn frost_signing_state_storage() {
			let secp = Secp256k1::new();
			let mut rng = OsRng;

			let base_secret = loop {
				let mut candidate = [0u8; 32];
				rng.fill_bytes(&mut candidate);
				if let Ok(sk) = GrinSecretKey::from_slice(&secp, &candidate) {
					break sk;
				}
			};

			let labels = vec!["alice".to_string(), "bob".to_string()];
			let session = split_secret_with_labels(&base_secret, 2, &labels).expect("session");
			let mut context = Context::with_excess(
				&secp,
				base_secret.clone(),
				&KeychainIdentifier::zero(),
				true,
			);
			context.set_frost_session(session.clone());

			let mut commitment_map = BTreeMap::new();
			let mut signing_inputs = Vec::new();
			for participant in &session.participants {
				let package = deserialize_key_package(&participant.key_package).expect("pkg");
				let identifier = identifier_from_bytes(&participant.identifier).expect("id");
				let (nonces, commitment) = round1::commit(package.signing_share(), &mut rng);
				record_round1_commitment(&mut context, participant.label.clone(), &commitment)
					.expect("store commitment");
				commitment_map.insert(identifier, commitment);
				signing_inputs.push((participant.label.clone(), identifier, nonces, package));
			}

			let message = [0u8; 32];
			let signing_package = SigningPackage::new(commitment_map.clone(), &message);
			let mut verifying_shares = BTreeMap::new();
			let mut signature_shares = BTreeMap::new();
			for (label, identifier, nonces, package) in signing_inputs {
				let share = round2::sign(&signing_package, &nonces, &package).expect("sign share");
				record_round2_signature(&mut context, label, &share).expect("store sig");
				verifying_shares.insert(identifier, *package.verifying_share());
				signature_shares.insert(identifier, share.clone());
			}

			let verifying_key = verify_key_from_bytes(&session.verifying_key).expect("vk");
			let public_key_package = keys::PublicKeyPackage::new(verifying_shares, verifying_key);
			let aggregated_signature = frost_secp256k1::aggregate(
				&signing_package,
				&signature_shares,
				&public_key_package,
			)
			.expect("aggregate");
			let expected =
				signature_to_grin(&aggregated_signature, public_key_package.verifying_key())
					.expect("convert");

			let aggregated = aggregate_signature(&context, &message).expect("aggregate stored");
			assert_eq!(aggregated.signature, expected.0);
			assert_eq!(aggregated.aggregated_pubkey, expected.1);
			assert_eq!(aggregated.aggregated_nonce, expected.2);

			let state = context.frost_signing_state().expect("state");
			assert_eq!(state.commitments.len(), labels.len());
			assert_eq!(state.partial_signatures.len(), labels.len());
			context.clear_frost_signing_state();
			assert!(context.frost_signing_state().is_none());
		}
	}
}
