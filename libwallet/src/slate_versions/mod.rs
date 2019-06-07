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
use crate::slate_versions::v2::SlateV2;

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
