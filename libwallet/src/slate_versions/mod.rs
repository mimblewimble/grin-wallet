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
use crate::types::CbData;
use crate::Error;
use std::convert::TryFrom;

pub mod ser;

#[allow(missing_docs)]
pub mod v4;
#[allow(missing_docs)]
pub mod v4_bin;

/// The most recent version of the slate
pub const CURRENT_SLATE_VERSION: u16 = 4;

/// The grin block header this slate is intended to be compatible with
pub const GRIN_BLOCK_HEADER_VERSION: u16 = 3;

/// Existing versions of the slate
#[derive(EnumIter, Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum SlateVersion {
	/// V4 (most current)
	V4,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
/// Versions are ordered newest to oldest so serde attempts to
/// deserialize newer versions first, then falls back to older versions.
pub enum VersionedSlate {
	/// Current (4.0.0 Onwards )
	V4(SlateV4),
}

impl VersionedSlate {
	/// Return slate version
	pub fn version(&self) -> SlateVersion {
		match *self {
			VersionedSlate::V4(_) => SlateVersion::V4,
		}
	}

	/// convert this slate type to a specified older version
	pub fn into_version(slate: Slate, version: SlateVersion) -> Result<VersionedSlate, Error> {
		match version {
			SlateVersion::V4 => Ok(VersionedSlate::V4(slate.into())),
		}
	}
}

impl From<VersionedSlate> for Slate {
	fn from(slate: VersionedSlate) -> Slate {
		match slate {
			VersionedSlate::V4(s) => Slate::from(s),
		}
	}
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
/// Binary versions, can only be parsed 1:1 into the appropriate
/// version, and VersionedSlate can up/downgrade from there
pub enum VersionedBinSlate {
	/// Version 4, binary
	V4(SlateV4Bin),
}

impl TryFrom<VersionedSlate> for VersionedBinSlate {
	type Error = Error;
	fn try_from(slate: VersionedSlate) -> Result<VersionedBinSlate, Error> {
		match slate {
			VersionedSlate::V4(s) => Ok(VersionedBinSlate::V4(SlateV4Bin(s))),
		}
	}
}

impl From<VersionedBinSlate> for VersionedSlate {
	fn from(slate: VersionedBinSlate) -> VersionedSlate {
		match slate {
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
	V4(CoinbaseV4),
}

impl VersionedCoinbase {
	/// convert this coinbase data to a specific versioned representation for the json api.
	pub fn into_version(cb: CbData, version: SlateVersion) -> VersionedCoinbase {
		match version {
			SlateVersion::V4 => VersionedCoinbase::V4(cb.into()),
		}
	}
}
