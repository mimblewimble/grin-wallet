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
use crate::core::core::{self, amount_to_hr_string, Inputs, OutputFeatures};
use crate::core::global;
use crate::libwallet::contract::types::{ContractView, OwnCommitmentStatus};
use crate::libwallet::{
	AcctPathMapping, Error, OutputCommitMapping, OutputStatus, Slate, TxLogEntry, ViewWallet,
	WalletInfo,
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
		bMG->"State",
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
		let slate_state = match t.tx_slate_state.as_ref() {
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
				bFC->slate_state,
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

/// Display a summary of a contract slate
pub fn contract_view(slate: &Slate, view: &ContractView, was_encrypted: bool) {
	println!("\n____ Contract ____\n");
	contract_view_table(slate, view, was_encrypted).printstd();
	println!();
}

fn contract_view_table(
	slate: &Slate,
	view: &ContractView,
	was_encrypted: bool,
) -> prettytable::Table {
	let mut table = table!();

	table.add_row(row![bFC->"Slate Id", bGC->slate.id]);
	table.add_row(row![bFC->"State", bGC->slate.state]);
	table.add_row(row![bFC->"Encrypted for This Wallet", bGC->yes_no(was_encrypted)]);
	let deadline = match slate.ttl_cutoff_height {
		0 => "None".to_string(),
		height => height.to_string(),
	};
	table.add_row(row![bFC->"Signing Deadline Height", bGC->deadline]);
	table.add_row(row![bFC->"Participants", bGC->view.num_participants]);
	table.add_row(row![bFC->"Signatures", bGC->view.num_sigs]);
	table.add_row(row![bFC->"Transfer Amount", bGC->amount_to_hr_string(slate.amount, false)]);
	let suggested = view
		.suggested_net_change
		.map(|change| format_net_change(Some(change)))
		.unwrap_or_else(|| "Not applicable".to_string());
	table.add_row(row![bFC->"Expected Amount Change (Before Fee)", bGC->suggested]);
	let agreed = view
		.agreed_net_change
		.map(|change| format_net_change(Some(change)))
		.unwrap_or_else(|| "Not agreed yet".to_string());
	table.add_row(row![bFC->"Agreed Amount Change (Before Fee)", bGC->agreed]);
	table.add_row(
		row![bFC->"Current Transaction Fee", bGC->amount_to_hr_string(slate.fee_fields.fee(), false)],
	);
	let own_fee = view
		.own_fee
		.map(|fee| amount_to_hr_string(fee, false))
		.unwrap_or_else(|| "Not known before signing".to_string());
	table.add_row(row![bFC->"Your Fee", bGC->own_fee]);
	let balance_change = match view.balance_change {
		Some(change) => format_net_change(Some(change)),
		None => "Not known before signing".to_string(),
	};
	table.add_row(row![bFC->"Your Balance Change", bGC->balance_change]);
	table.add_row(row![bFC->"Confirmed", bGC->yes_no(view.is_executed)]);
	let (unexpected, warning) = match view.own_commitment_status {
		OwnCommitmentStatus::UnexpectedInput => ("Input", true),
		OwnCommitmentStatus::UnexpectedOutput => ("Output", true),
		OwnCommitmentStatus::UnexpectedInputAndOutput => ("Input and output", true),
		OwnCommitmentStatus::Clean => ("No", false),
		OwnCommitmentStatus::Unknown => ("Unknown", false),
	};
	if warning {
		table.add_row(row![bFC->"Unexpected Wallet Inputs/Outputs", bFR->unexpected]);
	} else {
		table.add_row(row![bFC->"Unexpected Wallet Inputs/Outputs", bGC->unexpected]);
	}
	if let Some(tx) = slate.tx.as_ref() {
		let inputs = tx.inputs();
		table.add_row(row![bFC->"Inputs", bGC->inputs.len()]);
		match inputs {
			Inputs::CommitOnly(inputs) => {
				for (index, input) in inputs.iter().enumerate() {
					table.add_row(
						row![bFC->format!("Input {}", index + 1), bGC->input.commitment().as_ref().to_hex()],
					);
				}
			}
			Inputs::FeaturesAndCommit(inputs) => {
				for (index, input) in inputs.iter().enumerate() {
					let commitment = input.commitment().as_ref().to_hex();
					let value = match input.features {
						OutputFeatures::Plain => commitment,
						OutputFeatures::Coinbase => format!("Coinbase {}", commitment),
					};
					table.add_row(row![bFC->format!("Input {}", index + 1), bGC->value]);
				}
			}
		}
		table.add_row(row![bFC->"Outputs", bGC->tx.outputs().len()]);
		for (index, output) in tx.outputs().iter().enumerate() {
			let commitment = output.commitment().as_ref().to_hex();
			let value = match output.features() {
				OutputFeatures::Plain => commitment,
				OutputFeatures::Coinbase => format!("Coinbase {}", commitment),
			};
			table.add_row(row![bFC->format!("Output {}", index + 1), bGC->value]);
		}
	} else {
		table.add_row(row![bFC->"Inputs", bGC->"Not in slate"]);
		table.add_row(row![bFC->"Outputs", bGC->"Not in slate"]);
	}

	table.set_format(*prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
	table
}

fn yes_no(value: bool) -> &'static str {
	if value {
		"Yes"
	} else {
		"No"
	}
}

fn format_net_change(change: Option<i64>) -> String {
	match change {
		Some(value) => format!(
			"{}{}",
			if value < 0 { "-" } else { "+" },
			amount_to_hr_string(value.unsigned_abs(), false)
		),
		None => String::from("None"),
	}
}

#[cfg(test)]
mod tests {
	use super::{contract_view_table, format_net_change};
	use crate::core::core::{FeeFields, Input, Inputs, Output, OutputFeatures, Transaction};
	use crate::core::global;
	use crate::libwallet::contract::types::ContractView;
	use crate::libwallet::Slate;
	use crate::util::secp::pedersen::{Commitment, RangeProof};

	fn table_value(table: &prettytable::Table, label: &str) -> String {
		let row = table
			.row_iter()
			.find(|row| {
				row.get_cell(0)
					.map(|cell| cell.get_content() == label)
					.unwrap_or(false)
			})
			.unwrap_or_else(|| panic!("missing table row: {}", label));
		row.get_cell(1)
			.expect("table row has a value")
			.get_content()
	}

	#[test]
	fn net_change_sign() {
		assert_eq!(format_net_change(Some(1_000_000_000)), "+1.000000000");
		assert_eq!(format_net_change(Some(-1_000_000_000)), "-1.000000000");
		assert_eq!(format_net_change(None), "None");
	}

	#[test]
	fn contract_view_rows() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let mut slate = Slate::blank(2, false);
		slate.amount = 1_000_000_000;
		slate.ttl_cutoff_height = 42;
		slate.fee_fields = FeeFields::new(0, 4_000_000).unwrap();
		let input_commit = Commitment::from_vec(vec![3]);
		let output_commit = Commitment::from_vec(vec![4]);
		slate.tx = Some(
			slate
				.tx
				.take()
				.unwrap()
				.with_input(Input::new(OutputFeatures::Plain, input_commit))
				.with_output(Output::new(
					OutputFeatures::Coinbase,
					output_commit,
					RangeProof::zero(),
				)),
		);
		let view = ContractView {
			own_fee: Some(2_000_000),
			balance_change: Some(-1_002_000_000),
			..Default::default()
		};
		let table = contract_view_table(&slate, &view, true);

		assert_eq!(table_value(&table, "Encrypted for This Wallet"), "Yes");
		assert_eq!(table_value(&table, "Signing Deadline Height"), "42");
		assert_eq!(table_value(&table, "Transfer Amount"), "1.000000000");
		assert_eq!(
			table_value(&table, "Current Transaction Fee"),
			"0.004000000"
		);
		assert_eq!(table_value(&table, "Your Fee"), "0.002000000");
		assert_eq!(table_value(&table, "Your Balance Change"), "-1.002000000");
		assert_eq!(table_value(&table, "Confirmed"), "No");
		assert_eq!(table_value(&table, "Inputs"), "1");
		assert!(table_value(&table, "Input 1").starts_with("03"));
		assert_eq!(table_value(&table, "Outputs"), "1");
		assert!(table_value(&table, "Output 1").starts_with("Coinbase 04"));

		let table = contract_view_table(&slate, &view, false);
		assert_eq!(table_value(&table, "Encrypted for This Wallet"), "No");
		slate.ttl_cutoff_height = 0;
		let table = contract_view_table(&slate, &view, false);
		assert_eq!(table_value(&table, "Signing Deadline Height"), "None");

		slate.tx = Some(Transaction::new(
			Inputs::CommitOnly(vec![input_commit.into()]),
			&[],
			&[],
		));
		let table = contract_view_table(&slate, &view, false);
		assert!(table_value(&table, "Input 1").starts_with("03"));
	}
}
