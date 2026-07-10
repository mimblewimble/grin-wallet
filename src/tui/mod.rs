// Copyright 2026 The Grin Developers
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

//! Ratatui-based interactive TUI for grin-wallet.
//!
//! Provides a live dashboard (account status, accounts, outputs,
//! transactions, settings, logs) plus an Actions menu covering every
//! wallet subcommand. Most actions run on background worker threads
//! (`worker.rs`) so slatepack exchange, chain scans, and Tor round-trips
//! never freeze the UI; only open/close/recover (password prompts) and
//! first-run init temporarily leave the alternate screen and go through
//! the CLI dispatch.

mod accounts;
mod actions;
mod app;
mod form;
mod logs;
mod menu;
mod modals;
mod outputs;
mod settings;
mod status;
mod txs;
mod ui;
mod worker;

pub use ui::run;
