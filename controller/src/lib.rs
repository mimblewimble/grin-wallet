// Copyright 2018 The Grin Developers
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

//! Library module for the main wallet functionalities provided by Grin.

#[macro_use]
extern crate prettytable;

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
use failure;
use bitgrin_wallet_api as apiwallet;
use bitgrin_wallet_config as config;
use bitgrin_wallet_impls as impls;
use bitgrin_wallet_libwallet as libwallet;
use bitgrin_wallet_util::bitgrin_api as api;
use bitgrin_wallet_util::bitgrin_core as core;
use bitgrin_wallet_util::bitgrin_keychain as keychain;
use bitgrin_wallet_util::bitgrin_util as util;

pub mod command;
pub mod controller;
pub mod display;
mod error;

pub use crate::error::{Error, ErrorKind};
