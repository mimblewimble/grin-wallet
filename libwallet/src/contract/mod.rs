// Copyright 2022 The Grin Developers
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

//! This module contains contract related actions.

mod actions;
mod context;
mod selection;
mod slate;
pub mod types;
mod utils;

pub use self::actions::{new, revoke, setup, sign, view};

pub use self::slate::can_finalize;
pub use self::utils::my_fee_contribution;
