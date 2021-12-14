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

use crate::core::core::FeeFields;
use crate::core::core::{self, amount_to_hr_string};
use crate::core::global;
use crate::libwallet::{
	AcctPathMapping, Error, OutputCommitMapping, OutputStatus, TxLogEntry, ViewWallet, WalletInfo,
};
use crate::util::ToHex;
use grin_wallet_util::OnionV3Address;
use prettytable;
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
	t.fg(term::color::MAGENTA).unwrap();
	writeln!(t, "{}", title).unwrap();
	t.reset().unwrap();

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
		let commit = format!("{}", m.commit.as_ref().to_hex());
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
		let value = format!("{}", core::amount_to_hr_string(m.output.value, false));
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
			 The above is from local cache and possibly invalid! \
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
	t.fg(term::color::MAGENTA).unwrap();
	writeln!(t, "{}", title).unwrap();
	t.reset().unwrap();

	let mut table = table!();

	table.set_titles(row![
		bMG->"Id",
		bMG->"Type",
		bMG->"Shared Transaction Id",
		bMG->"Creation Time",
		bMG->"TTL Cutoff Height",
		bMG->"Confirmed?",
		bMG->"Confirmation Time",
		bMG->"Num. \nInputs",
		bMG->"Num. \nOutputs",
		bMG->"Amount \nCredited",
		bMG->"Amount \nDebited",
		bMG->"Fee",
		bMG->"Net \nDifference",
		bMG->"Payment \nProof",
		bMG->"Kernel",
		bMG->"Tx \nData",
	]);

	for t in txs {
		let id = format!("{}", t.id);
		let slate_id = match t.tx_slate_id {
			Some(m) => format!("{}", m),
			None => "None".to_owned(),
		};
		let entry_type = format!("{}", t.tx_type);
		let creation_ts = format!("{}", t.creation_ts.format("%Y-%m-%d %H:%M:%S"));
		let ttl_cutoff_height = match t.ttl_cutoff_height {
			Some(b) => format!("{}", b),
			None => "None".to_owned(),
		};
		let confirmation_ts = match t.confirmation_ts {
			Some(m) => format!("{}", m.format("%Y-%m-%d %H:%M:%S")),
			None => "None".to_owned(),
		};
		let confirmed = format!("{}", t.confirmed);
		let num_inputs = format!("{}", t.num_inputs);
		let num_outputs = format!("{}", t.num_outputs);
		let amount_debited_str = core::amount_to_hr_string(t.amount_debited, true);
		let amount_credited_str = core::amount_to_hr_string(t.amount_credited, true);
		let fee = match t.fee {
			Some(f) => format!("{}", core::amount_to_hr_string(f.fee(), true)),
			None => "None".to_owned(),
		};
		let net_diff = if t.amount_credited >= t.amount_debited {
			core::amount_to_hr_string(t.amount_credited - t.amount_debited, true)
		} else {
			format!(
				"-{}",
				core::amount_to_hr_string(t.amount_debited - t.amount_credited, true)
			)
		};
		let tx_data = match t.stored_tx {
			Some(_) => "Yes".to_owned(),
			None => "None".to_owned(),
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
				bFC->entry_type,
				bFC->slate_id,
				bFB->creation_ts,
				bFB->ttl_cutoff_height,
				bFC->confirmed,
				bFB->confirmation_ts,
				bFC->num_inputs,
				bFC->num_outputs,
				bFG->amount_credited_str,
				bFR->amount_debited_str,
				bFR->fee,
				bFY->net_diff,
				bfG->payment_proof,
				bFB->kernel_excess,
				bFb->tx_data,
			]);
		} else {
			if t.confirmed {
				table.add_row(row![
					bFD->id,
					bFb->entry_type,
					bFD->slate_id,
					bFB->creation_ts,
					bFg->confirmed,
					bFB->confirmation_ts,
					bFD->num_inputs,
					bFD->num_outputs,
					bFG->amount_credited_str,
					bFD->amount_debited_str,
					bFD->fee,
					bFG->net_diff,
					bfG->payment_proof,
					bFB->kernel_excess,
					bFB->tx_data,
				]);
			} else {
				table.add_row(row![
					bFD->id,
					bFb->entry_type,
					bFD->slate_id,
					bFB->creation_ts,
					bFR->confirmed,
					bFB->confirmation_ts,
					bFD->num_inputs,
					bFD->num_outputs,
					bFG->amount_credited_str,
					bFD->amount_debited_str,
					bFD->fee,
					bFG->net_diff,
					bfG->payment_proof,
					bFB->kernel_excess,
					bFB->tx_data,
				]);
			}
		}
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_COLSEP);
	table.printstd();
	println!();

	if !validated && include_status {
		println!(
			"\nWARNING: Wallet failed to verify data. \
			 The above is from local cache and possibly invalid! \
			 (is your `grin server` offline or broken?)"
		);
	}
	Ok(())
}

pub fn view_wallet_balance(w: ViewWallet, cur_height: u64, dark_background_color_scheme: bool) {
	println!(
		"\n____ View Wallet Summary Info - Block Height: {} ____\n Rewind Hash - {}\n",
		cur_height, w.rewind_hash
	);
	let mut table = table!();

	if dark_background_color_scheme {
		table.add_row(row![
			bFG->"Total Balance",
			FG->amount_to_hr_string(w.total_balance, false)
		]);
	} else {
		table.add_row(row![
			bFG->"Total Balance",
			FG->amount_to_hr_string(w.total_balance, false)
		]);
	};
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
	t.fg(term::color::MAGENTA).unwrap();
	writeln!(t, "{}", title).unwrap();
	t.reset().unwrap();

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
		let commit = format!("{}", m.commit);
		let index = m.mmr_index;
		let height = format!("{}", m.height);
		let lock_height = format!("{}", m.lock_height);
		let is_coinbase = format!("{}", m.is_coinbase);
		let num_confirmations = format!("{}", m.num_confirmations(cur_height));
		let value = format!("{}", core::amount_to_hr_string(m.value, false));

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
				Fr->format!("Reverted"),
				Fr->amount_to_hr_string(wallet_info.amount_reverted, false)
			]);
		}
		// Only dispay "Immature Coinbase" if we have related outputs in the wallet.
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
			bFB->format!("Awaiting Finalization"),
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
				Fr->format!("Reverted"),
				Fr->amount_to_hr_string(wallet_info.amount_reverted, false)
			]);
		}
		// Only dispay "Immature Coinbase" if we have related outputs in the wallet.
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
			 The above is from local cache and only valid up to the given height! \
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
	println!("\n____ Wallet Accounts ____\n",);
	let mut table = table!();

	table.set_titles(row![
		mMG->"Name",
		bMG->"Parent BIP-32 Derivation Path",
	]);
	for m in acct_mappings {
		table.add_row(row![
			bFC->m.label,
			bGC->m.path.to_bip_32_string(),
		]);
	}
	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table.printstd();
	println!();
}

/// Display individual Payment Proof
pub fn payment_proof(tx: &TxLogEntry) -> Result<(), Error> {
	let title = format!("Payment Proof - Transaction '{}'", tx.id,);
	println!();
	if term::stdout().is_none() {
		println!("Could not open terminal");
		return Ok(());
	}
	let mut t = term::stdout().unwrap();
	t.fg(term::color::MAGENTA).unwrap();
	writeln!(t, "{}", title).unwrap();
	t.reset().unwrap();

	let pp = match &tx.payment_proof {
		None => {
			writeln!(t, "None").unwrap();
			t.reset().unwrap();
			return Ok(());
		}
		Some(p) => p.clone(),
	};

	t.fg(term::color::WHITE).unwrap();
	writeln!(t).unwrap();
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
		core::amount_to_hr_string(tx.amount_credited - tx.amount_debited, true)
	} else {
		format!(
			"{}",
			core::amount_to_hr_string(tx.amount_debited - tx.amount_credited - fee, true)
		)
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
		OnionV3Address::from_bytes(pp.receiver_address.to_bytes())
	)
	.unwrap();
	writeln!(t, "Receiver Signature: {}", receiver_signature).unwrap();
	writeln!(t, "Amount: {}", amount).unwrap();
	writeln!(t, "Kernel Excess: {}", kernel_excess).unwrap();
	writeln!(
		t,
		"Sender Address: {}",
		OnionV3Address::from_bytes(pp.sender_address.to_bytes())
	)
	.unwrap();
	writeln!(t, "Sender Signature: {}", sender_signature).unwrap();

	t.reset().unwrap();

	println!();

	Ok(())
}
