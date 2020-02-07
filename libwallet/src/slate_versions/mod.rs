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

use crate::slate::Slate;
use crate::slate_versions::v2::{CoinbaseV2, SlateV2};
use crate::slate_versions::v3::{CoinbaseV3, SlateV3};
use crate::types::CbData;

pub mod ser;

#[allow(missing_docs)]
pub mod v2;
#[allow(missing_docs)]
pub mod v3;

/// The most recent version of the slate
pub const CURRENT_SLATE_VERSION: u16 = 3;

/// The grin block header this slate is intended to be compatible with
pub const GRIN_BLOCK_HEADER_VERSION: u16 = 3;

/// Existing versions of the slate
#[derive(EnumIter, Serialize, Deserialize, Clone, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum SlateVersion {
	/// V3 (most current)
	V3,
	/// V2 (2.0.0 - Onwards)
	V2,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
/// Versions are ordered newest to oldest so serde attempts to
/// deserialize newer versions first, then falls back to older versions.
pub enum VersionedSlate {
	/// Current (3.0.0 Onwards )
	V3(SlateV3),
	/// V2 (2.0.0 - Onwards)
	V2(SlateV2),
}

impl VersionedSlate {
	/// Return slate version
	pub fn version(&self) -> SlateVersion {
		match *self {
			VersionedSlate::V3(_) => SlateVersion::V3,
			VersionedSlate::V2(_) => SlateVersion::V2,
		}
	}

	/// convert this slate type to a specified older version
	pub fn into_version(slate: Slate, version: SlateVersion) -> VersionedSlate {
		match version {
			SlateVersion::V3 => VersionedSlate::V3(slate.into()),
			// Left here as a reminder of what needs to be inserted on
			// the release of a new slate
			SlateVersion::V2 => {
				let s = SlateV3::from(slate);
				let s = SlateV2::from(&s);
				VersionedSlate::V2(s)
			}
		}
	}
}

impl From<VersionedSlate> for Slate {
	fn from(slate: VersionedSlate) -> Slate {
		match slate {
			VersionedSlate::V3(s) => Slate::from(s),
			VersionedSlate::V2(s) => {
				let s = SlateV3::from(s);
				Slate::from(s)
			}
		}
	}
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
/// Versions are ordered newest to oldest so serde attempts to
/// deserialize newer versions first, then falls back to older versions.
pub enum VersionedCoinbase {
	/// Current supported coinbase version.
	V3(CoinbaseV3),
	/// Previous
	V2(CoinbaseV2),
}

impl VersionedCoinbase {
	/// convert this coinbase data to a specific versioned representation for the json api.
	pub fn into_version(cb: CbData, version: SlateVersion) -> VersionedCoinbase {
		match version {
			SlateVersion::V3 => VersionedCoinbase::V3(cb.into()),
			SlateVersion::V2 => VersionedCoinbase::V2(cb.into()),
		}
	}
}
