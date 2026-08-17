// Copyright 2021 The Grin Developers
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

//! Slate versioning tests

use grin_core::core::transaction::{KernelFeatures, NRDRelativeHeight};
use grin_core::core::FeeFields;
use grin_wallet_libwallet::{Slate, SlateVersion, Slatepacker, SlatepackerArgs, VersionedSlate};

#[test]
fn kernel_features_round_trip() {
	let fee = FeeFields::new(0, 42).unwrap();
	let features = [
		KernelFeatures::HeightLocked {
			fee,
			lock_height: 500_000,
		},
		KernelFeatures::NoRecentDuplicate {
			fee,
			relative_height: NRDRelativeHeight::new(10).unwrap(),
		},
	];
	let packer = Slatepacker::new(SlatepackerArgs {
		sender: None,
		recipients: vec![],
		dec_key: None,
	});

	for expected_features in features {
		let slate = Slate::blank_with_kernel_features(2, false, expected_features).unwrap();
		let expected_args = slate.kernel_features_args.clone();

		let versioned = VersionedSlate::into_version(slate.clone(), SlateVersion::V4).unwrap();
		let json = serde_json::to_string(&versioned).unwrap();
		let versioned: VersionedSlate = serde_json::from_str(&json).unwrap();
		let json_slate: Slate = versioned.into();
		assert_eq!(json_slate.kernel_features_args, expected_args);
		assert_eq!(
			json_slate.tx.unwrap().kernels()[0].features,
			expected_features
		);

		let slatepack = packer.create_slatepack(&slate).unwrap();
		let slatepack_slate = packer.get_slate(&slatepack).unwrap();
		assert_eq!(slatepack_slate.kernel_features_args, expected_args);
		assert_eq!(
			slatepack_slate.tx.unwrap().kernels()[0].features,
			expected_features
		);
	}
}

#[test]
fn kernel_features() {
	let fee = FeeFields::new(0, 42).unwrap();
	let features = [
		KernelFeatures::Plain { fee },
		KernelFeatures::HeightLocked {
			fee,
			lock_height: 500_000,
		},
		KernelFeatures::NoRecentDuplicate {
			fee,
			relative_height: NRDRelativeHeight::new(10).unwrap(),
		},
	];

	for expected_features in features {
		let slate = Slate::blank_with_kernel_features(2, false, expected_features).unwrap();
		assert_eq!(slate.kernel_features, expected_features.as_u8());
		assert_eq!(slate.tx.unwrap().kernels()[0].features, expected_features);
	}

	assert!(matches!(
		Slate::blank_with_kernel_features(2, false, KernelFeatures::Coinbase),
		Err(grin_wallet_libwallet::Error::InvalidKernelFeatures(1))
	));
}

// test all slate conversions
/* TODO: Turn back on upon release of new slate version
#[test]
fn slate_conversions() {
	// Test V0 to V2
	let v0 = include_str!("slates/v0.slate");
	let res = Slate::deserialize_upgrade(&v0);
	assert!(res.is_ok());
	// should serialize as latest
	let mut res = res.unwrap();
	assert_eq!(res.version_info.orig_version, 0);
	res.version_info.orig_version = 2;
	let s = serde_json::to_string(&res);
	assert!(s.is_ok());
	let s = s.unwrap();
	let v = Slate::parse_slate_version(&s);
	assert!(v.is_ok());
	assert_eq!(v.unwrap(), 2);
	println!("v0 -> v2: {}", s);

	// Test V1 to V2
	let v1 = include_str!("slates/v1.slate");
	let res = Slate::deserialize_upgrade(&v1);
	assert!(res.is_ok());
	// should serialize as latest
	let mut res = res.unwrap();
	assert_eq!(res.version_info.orig_version, 1);
	res.version_info.orig_version = 2;
	let s = serde_json::to_string(&res);
	assert!(s.is_ok());
	let s = s.unwrap();
	let v = Slate::parse_slate_version(&s);
	assert!(v.is_ok());
	assert_eq!(v.unwrap(), 2);
	println!("v1 -> v2: {}", s);

	// V2 -> V2, check version
	let v2 = include_str!("slates/v2.slate");
	let res = Slate::deserialize_upgrade(&v2);
	assert!(res.is_ok());
	let res = res.unwrap();
	assert_eq!(res.version_info.orig_version, 2);
	let s = serde_json::to_string(&res);
	assert!(s.is_ok());
	let s = s.unwrap();
	let v = Slate::parse_slate_version(&s);
	assert!(v.is_ok());
	assert_eq!(v.unwrap(), 2);

	// Downgrade to V1
	let v2 = include_str!("slates/v2.slate");
	let res = Slate::deserialize_upgrade(&v2);
	assert!(res.is_ok());
	let mut res = res.unwrap();
	// downgrade
	res.version_info.orig_version = 1;
	let s = serde_json::to_string(&res);
	assert!(s.is_ok());
	let s = s.unwrap();
	let v = Slate::parse_slate_version(&s);
	assert!(v.is_ok());
	assert_eq!(v.unwrap(), 1);
	println!("v2 -> v1: {}", s);

	// Downgrade to V0
	let v2 = include_str!("slates/v2.slate");
	let res = Slate::deserialize_upgrade(&v2);
	assert!(res.is_ok());
	let mut res = res.unwrap();
	// downgrade
	res.version_info.orig_version = 0;
	let s = serde_json::to_string(&res);
	assert!(s.is_ok());
	let s = s.unwrap();
	let v = Slate::parse_slate_version(&s);
	assert!(v.is_ok());
	assert_eq!(v.unwrap(), 0);
	println!("v2 -> v0: {}", s);
}
*/
