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

//! Higher level wallet functions which can be used by callers to operate
//! on the wallet, as well as helpers to invoke and instantiate wallets
//! and listeners

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#[macro_use]
extern crate grin_core as core;

extern crate grin_keychain as keychain;
extern crate grin_util as util;

use blake2_rfc as blake2;

use failure;
extern crate failure_derive;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;

pub mod api;
mod error;
pub mod internal;
pub mod slate;
pub mod slate_versions;
pub mod types;

pub use crate::error::{Error, ErrorKind};
