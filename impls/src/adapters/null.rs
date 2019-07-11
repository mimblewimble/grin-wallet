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

//! Null implementation of some wallet comm adapters

use crate::libwallet::{Error, Slate};
use crate::{SlatePutter, SlateSender};

#[derive(Clone)]
pub struct NullAdapter;

impl SlateSender for NullAdapter {
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		Ok(slate.clone())
	}
}

impl SlatePutter for NullAdapter {
	fn put_tx(&self, _slate: &Slate) -> Result<(), Error> {
		Ok(())
	}
}
