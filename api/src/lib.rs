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

use grin_wallet_util::grin_core as core;
use grin_wallet_util::grin_keychain as keychain;
use grin_wallet_util::grin_util as util;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_libwallet as libwallet;

extern crate failure_derive;
extern crate serde_json;

#[macro_use]
extern crate log;

mod foreign;
mod foreign_rpc;
mod owner;
mod owner_rpc;
pub use crate::foreign::{Foreign, ForeignCheckMiddleware, ForeignCheckMiddlewareFn};
pub use crate::foreign_rpc::ForeignRpc;
pub use crate::owner::Owner;
pub use crate::owner_rpc::OwnerRpc;

pub use crate::foreign_rpc::foreign_rpc as foreign_rpc_client;
pub use crate::foreign_rpc::run_doctest_foreign;
pub use crate::owner_rpc::run_doctest_owner;
