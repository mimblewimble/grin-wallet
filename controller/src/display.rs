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

use crate::core::core::amount_to_hr_string;
use crate::core::core::FeeFields;
use crate::core::global;
use crate::libwallet::{
	address, AcctPathMapping, Error, OutputCommitMapping, OutputStatus, SlatepackAddress,
	TxLogEntry, TxLogEntryType, ViewWallet, WalletInfo,
};
use crate::util::ToHex;
use grin_wallet_libwallet::slatepack::SlatepackAddressIndex;
use prettytable;
use prettytable::format::{FormatBuilder, LinePosition, LineSeparator};
use std::io::prelude::Write;
use term;

/// Display outputs in a pretty way
pub fn outputs(
	account: &str,
	cur_height: u64,
	validated: bool,
	outputs: Vec<OutputCommitMapping>,
	dark_background_color_scheme: bool,
) -> Result<(), Error> {
	let title = format!(
		"Wallet Outputs - Account '{}' - Block Height: {}",
		account, cur_height
	);
	println!();
	if term::stdout().is_none() {
		println!("Could not open terminal");
		return Ok(());
	}
	let mut t = term::stdout().unwrap();
	let _ = t.fg(term::color::MAGENTA);
	writeln!(t, "{}", title)?;
	let _ = t.reset();

	let mut table = table!();

	table.set_titles(row![
		bMG->"Output Commitment",
		bMG->"MMR Index",
		bMG->"Block Height",
		bMG->"Locked Until",
		bMG->"Status",
		bMG->"Coinbase?",
		bMG->"# Confirms",
		bMG->"Value",
		bMG->"Tx"
	]);

	for m in outputs {
		let commit = m.commit.as_ref().to_hex();
		let index = match m.output.mmr_index {
			None => "None".to_owned(),
			Some(t) => t.to_string(),
		};
		let height = format!("{}", m.output.height);
		let lock_height = format!("{}", m.output.lock_height);
		let is_coinbase = format!("{}", m.output.is_coinbase);

		// Mark unconfirmed coinbase outputs as "Mining" instead of "Unconfirmed"
		let status = match m.output.status {
			OutputStatus::Unconfirmed if m.output.is_coinbase => "Mining".to_string(),
			_ => format!("{}", m.output.status),
		};

		let num_confirmations = format!("{}", m.output.num_confirmations(cur_height));
		let value = amount_to_hr_string(m.output.value, false);
		let tx = match m.output.tx_log_entry {
			None => "".to_owned(),
			Some(t) => t.to_string(),
		};

		if dark_background_color_scheme {
			table.add_row(row![
				bFC->commit,
				bFB->index,
				bFB->height,
				bFB->lock_height,
				bFR->status,
				bFY->is_coinbase,
				bFB->num_confirmations,
				bFG->value,
				bFC->tx,
			]);
		} else {
			table.add_row(row![
				bFD->commit,
				bFB->index,
				bFB->height,
				bFB->lock_height,
				bFR->status,
				bFD->is_coinbase,
				bFB->num_confirmations,
				bFG->value,
				bFD->tx,
			]);
		}
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_COLSEP);
	table.printstd();
	println!();

	if !validated {
		println!(
			"\nWARNING: Wallet failed to verify data. \
			 The above is from local cache and possibly invalid! \
			 (is your `grin server` offline or broken?)"
		);
	}
	Ok(())
}

/// Display transaction log in a pretty way
pub fn txs(
	account: &str,
	cur_height: u64,
	validated: bool,
	txs: &[TxLogEntry],
	include_status: bool,
	dark_background_color_scheme: bool,
) -> Result<(), Error> {
	let title = format!(
		"Transaction Log - Account '{}' - Block Height: {}",
		account, cur_height
	);
	println!();
	if term::stdout().is_none() {
		println!("Could not open terminal");
		return Ok(());
	}
	let mut t = term::stdout().unwrap();
	let _ = t.fg(term::color::MAGENTA);
	writeln!(t, "{}", title)?;
	let _ = t.reset();

	let mut table = table!();

	table.set_titles(if dark_background_color_scheme {
		row![
			bMG->"Id",
			bMG->"Type (State)",
			bMG->"Shared Transaction Id \nKernel",
			bMG->"Creation Time \nConfirmation Time",
			bMG->"Payment Proof \nTTL Cutoff Height",
			bMG->"Inputs \nOutputs",
			bMG->"Credited \nDebited",
			bMG->"Fee \nDifference",
		]
	} else {
		row![
			bFD	->"Id",
			bFD->"Type (State)",
			bFD->"Shared Transaction Id \nKernel",
			bFD->"Creation Time \nConfirmation Time",
			bFD->"Payment Proof \nTTL Cutoff Height",
			bFD->"Inputs \nOutputs",
			bFD->"Credited \nDebited",
			bFD->"Fee \nDifference",
		]
	});

	for (i, t) in txs.iter().enumerate() {
		let id = format!("{}", t.id);
		let slate_id = match t.tx_slate_id {
			Some(m) => format!("{}", m),
			None => "None".to_owned(),
		};

		let entry_type = (match t.tx_type {
			TxLogEntryType::ConfirmedCoinbase => "Coinbase",
			TxLogEntryType::TxReceived => "Received Tx",
			TxLogEntryType::TxSent => "Sent Tx",
			TxLogEntryType::TxReceivedCancelled => "Received Tx",
			TxLogEntryType::TxSentCancelled => "Sent Tx",
			TxLogEntryType::TxReverted => "Received Tx",
		})
		.to_string();
		let entry_type_state = match t.tx_slate_state.as_ref() {
			None => entry_type.to_string(),
			Some(s) => format!("{} ({})", entry_type, s),
		};
		let entry_type_desc = (match t.tx_type {
			TxLogEntryType::ConfirmedCoinbase => "Confirmed",
			TxLogEntryType::TxReceived => "",
			TxLogEntryType::TxSent => "",
			TxLogEntryType::TxReceivedCancelled => "Cancelled",
			TxLogEntryType::TxSentCancelled => "Cancelled",
			TxLogEntryType::TxReverted => "Reverted",
		})
		.to_string();
		let creation_ts = format!("{}", t.creation_ts.format("%Y-%m-%d %H:%M:%S"));
		let ttl_cutoff_height = match t.ttl_cutoff_height {
			Some(b) => b.to_string(),
			None => "None".to_owned(),
		};
		let confirmation_ts = match t.confirmation_ts {
			Some(m) => format!("{}", m.format("%Y-%m-%d %H:%M:%S")),
			None => "None".to_owned(),
		};
		let num_inputs = format!("{}", t.num_inputs);
		let num_outputs = format!("{}", t.num_outputs);
		let amount_debited_str = amount_to_hr_string(t.amount_debited, true);
		let amount_credited_str = amount_to_hr_string(t.amount_credited, true);
		let fee = match t.fee {
			Some(f) => amount_to_hr_string(f.fee(), true),
			None => "None".to_owned(),
		};
		let net_diff = if t.amount_credited >= t.amount_debited {
			amount_to_hr_string(t.amount_credited - t.amount_debited, true)
		} else {
			format!(
				"-{}",
				amount_to_hr_string(t.amount_debited - t.amount_credited, true)
			)
		};
		let kernel_excess = match t.kernel_excess {
			Some(e) => {
				let excess: &[u8] = e.0.as_ref();
				excess.to_hex()
			}
			None => "None".to_owned(),
		};
		let payment_proof = match t.payment_proof {
			Some(_) => "Yes".to_owned(),
			None => "None".to_owned(),
		};
		if dark_background_color_scheme {
			table.add_row(row![
				bFC->id,
				bFC->entry_type_state,
				bFC->slate_id,
				bFB->creation_ts,
				bFC->payment_proof,
				bFC->num_inputs,
				bFG->amount_credited_str,
				bFR->fee,
			]);
			table.add_row(row![
				bFD->"",
				bFC->entry_type_desc,
				bFB->kernel_excess,
				bFB->confirmation_ts,
				bFB->ttl_cutoff_height,
				bFC->num_outputs,
				bFR->amount_debited_str,
				bFY->net_diff,
			]);
		} else {
			table.add_row(row![
				bFD->id,
				bFb->entry_type_state,
				bFD->slate_id,
				bFB->creation_ts,
				bFD->payment_proof,
				bFD->num_inputs,
				bFG->amount_credited_str,
				bFR->fee,
			]);
			table.add_row(row![
				bFD->"",
				bFb->entry_type_desc,
				bFB->kernel_excess,
				bFB->confirmation_ts,
				bFB->ttl_cutoff_height,
				bFD->num_outputs,
				bFR->amount_debited_str,
				bFG->net_diff,
			]);
		}
		if i != txs.len() - 1 {
			table.add_empty_row();
		}
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
	table.printstd();
	println!();

	if !validated && include_status {
		println!(
			"\nWARNING: Wallet failed to verify data. \
			 The above is from local cache and possibly invalid! \
			 (is your `grin server` offline or broken?)"
		);
	}
	Ok(())
}

pub fn view_wallet_balance(w: ViewWallet, cur_height: u64, _dark_background_color_scheme: bool) {
	println!(
		"\n____ View Wallet Summary Info - Block Height: {} ____\n Rewind Hash - {}\n",
		cur_height, w.rewind_hash
	);
	let mut table = table!();

	table.add_row(row![
		bFG->"Total Balance",
		FG->amount_to_hr_string(w.total_balance, false)
	]);
	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table.printstd();
	println!();
}

pub fn view_wallet_output(
	view_wallet: ViewWallet,
	cur_height: u64,
	dark_background_color_scheme: bool,
) -> Result<(), Error> {
	println!();
	let title = format!("View Wallet Outputs - Block Height: {}", cur_height);

	if term::stdout().is_none() {
		println!("Could not open terminal");
		return Ok(());
	}

	let mut t = term::stdout().unwrap();
	let _ = t.fg(term::color::MAGENTA);
	writeln!(t, "{}", title)?;
	let _ = t.reset();

	let mut table = table!();

	table.set_titles(row![
		bMG->"Output Commitment",
		bMG->"MMR Index",
		bMG->"Block Height",
		bMG->"Locked Until",
		bMG->"Coinbase?",
		bMG->"# Confirms",
		bMG->"Value",
	]);

	for m in view_wallet.output_result {
		let commit = m.commit.as_str();
		let index = m.mmr_index;
		let height = format!("{}", m.height);
		let lock_height = format!("{}", m.lock_height);
		let is_coinbase = format!("{}", m.is_coinbase);
		let num_confirmations = format!("{}", m.num_confirmations(cur_height));
		let value = amount_to_hr_string(m.value, false);

		if dark_background_color_scheme {
			table.add_row(row![
				bFC->commit,
				bFB->index,
				bFB->height,
				bFB->lock_height,
				bFY->is_coinbase,
				bFB->num_confirmations,
				bFG->value,
			]);
		} else {
			table.add_row(row![
				bFD->commit,
				bFB->index,
				bFB->height,
				bFB->lock_height,
				bFD->is_coinbase,
				bFB->num_confirmations,
				bFG->value,
			]);
		}
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_COLSEP);
	table.printstd();
	println!();
	Ok(())
}

/// Display summary info in a pretty way
pub fn info(
	account: &str,
	wallet_info: &WalletInfo,
	validated: bool,
	dark_background_color_scheme: bool,
) {
	println!(
		"\n____ Wallet Summary Info - Account '{}' as of height {} ____\n",
		account, wallet_info.last_confirmed_height,
	);

	let mut table = table!();

	if dark_background_color_scheme {
		table.add_row(row![
			bFG->"Confirmed Total",
			FG->amount_to_hr_string(wallet_info.total, false)
		]);
		if wallet_info.amount_reverted > 0 {
			table.add_row(row![
				Fr->"Reverted",
				Fr->amount_to_hr_string(wallet_info.amount_reverted, false)
			]);
		}
		// Only display "Immature Coinbase" if we have related outputs in the wallet.
		// This row just introduces confusion if the wallet does not receive coinbase rewards.
		if wallet_info.amount_immature > 0 {
			table.add_row(row![
				bFY->format!("Immature Coinbase (< {})", global::coinbase_maturity()),
				FY->amount_to_hr_string(wallet_info.amount_immature, false)
			]);
		}
		table.add_row(row![
			bFY->format!("Awaiting Confirmation (< {})", wallet_info.minimum_confirmations),
			FY->amount_to_hr_string(wallet_info.amount_awaiting_confirmation, false)
		]);
		table.add_row(row![
			bFB->"Awaiting Finalization",
			FB->amount_to_hr_string(wallet_info.amount_awaiting_finalization, false)
		]);
		table.add_row(row![
			Fr->"Locked by previous transaction",
			Fr->amount_to_hr_string(wallet_info.amount_locked, false)
		]);
		table.add_row(row![
			Fw->"--------------------------------",
			Fw->"-------------"
		]);
		table.add_row(row![
			bFG->"Currently Spendable",
			FG->amount_to_hr_string(wallet_info.amount_currently_spendable, false)
		]);
	} else {
		table.add_row(row![
			bFG->"Total",
			FG->amount_to_hr_string(wallet_info.total, false)
		]);
		if wallet_info.amount_reverted > 0 {
			table.add_row(row![
				Fr->"Reverted",
				Fr->amount_to_hr_string(wallet_info.amount_reverted, false)
			]);
		}
		// Only display "Immature Coinbase" if we have related outputs in the wallet.
		// This row just introduces confusion if the wallet does not receive coinbase rewards.
		if wallet_info.amount_immature > 0 {
			table.add_row(row![
				bFB->format!("Immature Coinbase (< {})", global::coinbase_maturity()),
				FB->amount_to_hr_string(wallet_info.amount_immature, false)
			]);
		}
		table.add_row(row![
			bFB->format!("Awaiting Confirmation (< {})", wallet_info.minimum_confirmations),
			FB->amount_to_hr_string(wallet_info.amount_awaiting_confirmation, false)
		]);
		table.add_row(row![
			Fr->"Locked by previous transaction",
			Fr->amount_to_hr_string(wallet_info.amount_locked, false)
		]);
		table.add_row(row![
			Fw->"--------------------------------",
			Fw->"-------------"
		]);
		table.add_row(row![
			bFG->"Currently Spendable",
			FG->amount_to_hr_string(wallet_info.amount_currently_spendable, false)
		]);
	};
	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table.printstd();
	println!();
	if !validated {
		println!(
			"\nWARNING: Wallet failed to verify data against a live chain. \
			 The above is from local cache and only valid up to the given height! \
			 (is your `grin server` offline or broken?)"
		);
	}
}

/// Display summary info in a pretty way
pub fn estimate(
	amount: u64,
	strategies: Vec<(
		&str,      // strategy
		u64,       // total amount to be locked
		FeeFields, // fee
	)>,
	dark_background_color_scheme: bool,
) {
	println!(
		"\nEstimation for sending {}:\n",
		amount_to_hr_string(amount, false)
	);

	let mut table = table!();

	table.set_titles(row![
		bMG->"Selection strategy",
		bMG->"Fee",
		bMG->"Will be locked",
	]);

	for (strategy, total, fee_fields) in strategies {
		if dark_background_color_scheme {
			table.add_row(row![
				bFC->strategy,
				FR->amount_to_hr_string(fee_fields.fee(), false), // apply fee mask past HF4
				FY->amount_to_hr_string(total, false),
			]);
		} else {
			table.add_row(row![
				bFD->strategy,
				FR->amount_to_hr_string(fee_fields.fee(), false), // apply fee mask past HF4
				FY->amount_to_hr_string(total, false),
			]);
		}
	}
	table.printstd();
	println!();
}

/// Display list of wallet accounts in a pretty way
pub fn accounts(acct_mappings: Vec<AcctPathMapping>) {
	println!("\n____ Wallet Accounts ____\n");
	let mut table = table!();

	table.set_titles(row![
		mMG->"Name",
		bMG->"Parent Output Key",
		bMG->"Slatepack Address (Index 0)",
		bMG->"Spendable balance",
	]);
	for m in acct_mappings {
		let slatepack_path =
			address::address_derivation_path(&m.path, SlatepackAddressIndex(0)).to_bip_32_string();
		let spendable = if let Some(info) = m.info {
			amount_to_hr_string(info.amount_currently_spendable, true)
		} else {
			"-".to_string()
		};
		table.add_row(row![
			bFC->m.label,
			bGC->m.path.to_bip_32_string(),
			bGC->slatepack_path,
			bGC->spendable,
		]);
	}
	table.set_format(
		FormatBuilder::new()
			.column_separator('|')
			.separators(
				&[LinePosition::Top, LinePosition::Title],
				LineSeparator::new('-', '+', '+', '+'),
			)
			.padding(1, 1)
			.build(),
	);
	let width = table.to_string().find('\n').unwrap_or(0);
	println!("{:^1$}", "BIP-32 Derivation Path", width);
	table.printstd();
	println!("Balances use local data and may be out of date.");
	println!();
}

/// Display individual Payment Proof
pub fn payment_proof(tx: &TxLogEntry) -> Result<(), Error> {
	let title = format!("Payment Proof - Transaction '{}'", tx.id);
	println!();
	if term::stdout().is_none() {
		println!("Could not open terminal");
		return Ok(());
	}
	let mut t = term::stdout().unwrap();
	let _ = t.fg(term::color::MAGENTA);
	writeln!(t, "{}", title)?;
	let _ = t.reset();

	let pp = match &tx.payment_proof {
		None => {
			writeln!(t, "None")?;
			let _ = t.reset();
			return Ok(());
		}
		Some(p) => p.clone(),
	};

	let _ = t.fg(term::color::WHITE);
	writeln!(t)?;
	let receiver_signature = match pp.receiver_signature {
		Some(s) => {
			let sig_bytes = s.to_bytes();
			let sig_ref: &[u8] = sig_bytes.as_ref();
			sig_ref.to_hex()
		}
		None => "None".to_owned(),
	};
	let fee = match tx.fee {
		Some(f) => f.fee(), // apply fee mask past HF4
		None => 0,
	};
	let amount = if tx.amount_credited >= tx.amount_debited {
		amount_to_hr_string(tx.amount_credited - tx.amount_debited, true)
	} else {
		amount_to_hr_string(tx.amount_debited - tx.amount_credited - fee, true)
	};

	let sender_signature = match pp.sender_signature {
		Some(s) => {
			let sig_bytes = s.to_bytes();
			let sig_ref: &[u8] = sig_bytes.as_ref();
			sig_ref.to_hex()
		}
		None => "None".to_owned(),
	};
	let kernel_excess = match tx.kernel_excess {
		Some(e) => {
			let excess: &[u8] = e.0.as_ref();
			excess.to_hex()
		}
		None => "None".to_owned(),
	};

	writeln!(
		t,
		"Receiver Address: {}",
		SlatepackAddress::new(&pp.receiver_address)
	)?;
	writeln!(t, "Receiver Signature: {}", receiver_signature)?;
	writeln!(t, "Amount: {}", amount)?;
	writeln!(t, "Kernel Excess: {}", kernel_excess)?;
	writeln!(
		t,
		"Sender Address: {}",
		SlatepackAddress::new(&pp.sender_address)
	)?;
	writeln!(t, "Sender Signature: {}", sender_signature)?;

	let _ = t.reset();

	println!();

	Ok(())
}
