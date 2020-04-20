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

use crate::grin_core::core::transaction::{KernelFeatures, OutputFeatures};
use crate::grin_core::libtx::secp_ser;
use crate::grin_core::map_vec;
use crate::grin_keychain::{BlindingFactor, Identifier};
use crate::grin_util::secp;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::pedersen::{Commitment, RangeProof};
use crate::grin_util::secp::Signature;
use crate::slate::CompatKernelFeatures;
use crate::slate_versions::ser;
use crate::{Error, ErrorKind};
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use serde::ser::{Serialize, Serializer};
use std::convert::TryFrom;
use uuid::Uuid;

use crate::slate_versions::v4::{
	InputV4, OutputV4, ParticipantDataV4, PaymentInfoV4, SlateV4, TransactionBodyV4, TransactionV4,
	TxKernelV4, VersionCompatInfoV4,
};

#[derive(Debug, Clone)]
pub struct SlateV4Bin(pub SlateV4);

impl Serialize for SlateV4Bin {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let ret_vec = vec![];
		let v4 = &self.0;
		let s = serializer.serialize_u16(v4.ver.version)?;
		s.serialize_u16(v4.ver.block_header_version)?;
		s.serialize_bytes(&ret_vec)
	}
}
