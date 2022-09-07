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

//! Contract coin selection functions

use crate::contract::types::{ContractSetupArgsAPI, OutputSelectionArgs};
use crate::contract::utils::my_fee_contribution;
use crate::grin_core::core::amount_to_hr_string;
use crate::grin_keychain::{Identifier, Keychain};
use crate::types::{NodeClient, WalletBackend};
use crate::{Error, OutputData};
use grin_core::core::FeeFields;

/// Prepares inputs & outputs that satisfy `Σmy_inputs >= Σmy_outputs + my_fee_cost` taking into account selection args
pub fn prepare_outputs<'a, T: ?Sized, C, K>(
	w: &mut T,
	parent_key_id: &Identifier,
	current_height: u64,
	setup_args: &ContractSetupArgsAPI,
	committed_fee: Option<FeeFields>,
) -> Result<(Vec<OutputData>, Vec<u64>, FeeFields), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Find available inputs
	let mut eligible_inputs = find_eligible(w, parent_key_id, current_height)?;
	// Select which inputs to use to satisfy the equation
	compute(setup_args, committed_fee, &mut eligible_inputs)
}

/// Find all inputs eligible to spend
pub fn find_eligible<'a, T: ?Sized, C, K>(
	w: &mut T,
	parent_key_id: &Identifier,
	current_height: u64,
) -> Result<Vec<OutputData>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Find eligible inputs in the wallet
	let eligible_inputs = w
		.iter()
		.filter(|out| out.root_key_id == *parent_key_id && out.eligible_to_spend(current_height, 1))
		.collect::<Vec<OutputData>>();
	Ok(eligible_inputs)
}
// Given a list of inputs, an optional committed fee and setup args, compute which inputs to use, what amount outputs to make and fee cost
pub fn compute(
	setup_args: &ContractSetupArgsAPI,
	committed_fee: Option<FeeFields>,
	inputs: &mut Vec<OutputData>,
) -> Result<(Vec<OutputData>, Vec<u64>, FeeFields), Error>
where
{
	let (inputs, fee) = select_inputs(setup_args, committed_fee, inputs)?;
	let output_amounts = build_output_amount_list(
		inputs.clone().iter().map(|out| out.value).sum::<u64>(),
		fee.fee(),
		setup_args,
	);
	Ok((inputs, output_amounts, fee))
}

// Given a list of inputs, an optional committed fee and setup args, compute which inputs to use
fn select_inputs(
	setup_args: &ContractSetupArgsAPI,
	committed_fee: Option<FeeFields>,
	inputs: &mut Vec<OutputData>,
) -> Result<(Vec<OutputData>, FeeFields), Error>
where
{
	// We use 'lhs' and 'rhs' to denote the amounts on the left/right-hand side of the equation.
	// To simulate receive/payment value we:
	// - add positive net_change to the 'lhs' for the receiver (to simulate sender's input)
	// - add positive net_change to the 'rhs' for the sender   (to simulate receiver's output)
	// For either party, the following MUST hold for the inputs the function returns:
	//  Σmy_inputs >= Σmy_outputs + my_fee_cost
	// Each party later balances the equation by adding an additional output (change output or receiver output)
	let net_change = setup_args.net_change.unwrap();
	let custom_outputs_amount_sum = setup_args.selection_args.sum_output_amounts();
	let pay_amount = if net_change < 0 {
		net_change.abs() as u64
	} else {
		0
	};
	// Add the amount we pay and the custom outputs to rhs of the equation
	let rhs = pay_amount + custom_outputs_amount_sum;
	let required_inputs = setup_args.selection_args.required_inputs();
	let is_payjoin = setup_args.selection_args.is_payjoin();
	let is_self_spend = setup_args.num_participants == 1;
	debug!(
		"contract::selection::selecting inputs: num_participants: {}, min_input_amount: {}, is_payjoin: {}",
		setup_args.num_participants, rhs, is_payjoin
	);
	// We don't try to contribute an input only in the case where we have multiple participants
	// where we are on the receiving end and we don't want to do a payjoin
	if !is_self_spend && (pay_amount == 0 && !is_payjoin) {
		return Ok((
			vec![],
			my_fee_contribution(
				0,
				setup_args.selection_args.num_custom_outputs() + 1,
				1,
				setup_args.num_participants,
			)?,
		));
	}
	// NOTE: that these are inputs that MUST be selected. We should lock the inputs if they're
	// required to minimize any potential race conditions.
	let must_use_list = required_inputs.unwrap_or(vec![]);
	if must_use_list.len() > 0 {
		// Sort the inputs first by the ones listed in the use_inputs and then by value
		inputs.sort_by_key(|out| {
			(
				// We have to negate the boolean to prioritize truthy values because
				// false is 0 and hence would be sorted before truthy entries
				!(out.commit.is_some()
					&& must_use_list.contains(&&out.commit.as_ref().unwrap()[..])),
				out.value,
			)
		});
	} else {
		// Sort the inputs only by value
		inputs.sort_by_key(|out| out.value);
	}

	// NOTE: Since we sort by value increasingly, if we hold any 0-value inputs, they will all be used if we're the sender
	// or a single one if we're the receiver doing a payjoin.
	// If we are the receiver, we pretend we have a virtual input from the sender (for which we don't pay the fees) so we can easily
	// test that lhs >= rhs and see if we will be able to satisfy equation. We simulate this by starting with lhs = net_change.
	let mut lhs = 0;
	if net_change > 0 {
		lhs = net_change as u64; // TODO: check bounds
	}
	// We want to count how many inputs we've picked _so far_. This is used to prevent picking
	// all 0*H +r*G outputs when we call with min_input_amount=0 and want just a payjoin.
	let mut n_inputs = 0;
	let mut must_use_list_cnt: u32 = 0;
	let my_num_outputs = setup_args.selection_args.num_custom_outputs() + 1;
	// If we have already committed to a fee (context.fee) then set this as our "minimum" fee. The reason we have to
	// do this is to avoid solving the equation for less than the committed fee. We have to guarantee the inputs we take
	// are enough to cover the committed fee. At the end of selection, we check that the fees for the selection were not
	// higher than the fee value we committed to.
	let mut my_fee = if committed_fee.is_some() {
		committed_fee.unwrap()
	} else {
		// We start with a fee of 1 output and a shared kernel which is minimum for both parties
		my_fee_contribution(0, 1, 1, setup_args.num_participants).unwrap()
		// FeeFields::zero()
	};

	// NOTE: This always takes at least one input if it is available. We take the inputs we must take and then we take
	// inputs until we fulfill Σmy_inputs >= Σmy_outputs + my_fee_cost
	let selected_inputs = inputs
		.iter()
		.take_while(|out| {
			// Take the commitment if it is listed as one of those we MUST take
			let must_take =
				out.commit.is_some() && must_use_list.contains(&&out.commit.as_ref().unwrap()[..]);
			// Compute the fee without this input
			let fee_without =
				my_fee_contribution(n_inputs, my_num_outputs, 1, setup_args.num_participants)
					.unwrap();
			// Compute the total fee cost if we took this input
			let mut fee_with =
				my_fee_contribution(n_inputs + 1, my_num_outputs, 1, setup_args.num_participants)
					.unwrap();
			// If the current fee is lower than the committed fee (my_fee) then set it to committed fee
			if my_fee.fee() > fee_with.fee() {
				fee_with = my_fee;
			}
			// If we don't have a "must take" input, have contributed an input and have enough to balance the equation, we can stop
			let could_finish = lhs >= (rhs + fee_without.fee()) && n_inputs > 0 && !must_take;
			if could_finish {
				return false;
			}
			// Take the commitment if `lhs < rhs+fees_with` (or if we have not yet taken an input - payjoins)
			let should_take = lhs < (rhs + fee_with.fee()) || n_inputs == 0;
			let res = must_take || should_take;
			if res {
				lhs += out.value;
				n_inputs += 1;
				// Update the fee cost if we decided to take the input
				my_fee = fee_with;
				if must_take {
					must_use_list_cnt += 1;
				}
			}
			debug!(
				"contract::selection::select_inputs => out_value:{}, new my_inputs_sum:{}",
				out.value, lhs
			);
			res
		})
		.cloned()
		.collect::<Vec<OutputData>>();

	// Return an error if the fee computed is larger than the committed fee
	if committed_fee.is_some() && my_fee.fee() > committed_fee.unwrap().fee() {
		// TODO: Return a specific Fee estimation error and suggest the user to cancel the transaction
		let msg = format!(
			"Fee computed ({}) is larger than the committed fee ({})",
			my_fee.fee(),
			committed_fee.unwrap().fee()
		);
		return Err(Error::GenericError(msg.into()).into());
	}

	// Check that the inputs we picked are enough to cover all our output amounts and fees
	// asserts that Σmy_inputs >= Σmy_outputs + my_fee_cost
	if lhs < rhs + my_fee.fee() {
		let total = inputs.iter().fold(0, |acc, x| acc + x.value);
		debug!("Not enough funds. Total funds eligible to spend: {}, needed: {}. Fee cost for this transaction: {}", total, rhs+my_fee.fee(), my_fee.fee());
		return Err(Error::NotEnoughFunds {
			available: total,
			available_disp: amount_to_hr_string(total, false),
			needed: rhs + my_fee.fee(),
			needed_disp: amount_to_hr_string(rhs + my_fee.fee(), false),
		}
		.into());
		// return Err(ErrorKind::GenericError(msg.into()).into());
	}

	// Assert that all the use_inputs have been selected
	if must_use_list.len() != must_use_list_cnt as usize {
		let msg = format!(
			"We have not found all the inputs that have been requested. {}, found only: {}",
			setup_args.selection_args.use_inputs.as_ref().unwrap(),
			must_use_list_cnt
		);
		return Err(Error::GenericError(msg.into()).into());
	}

	debug!(
		"contract::selection::select_inputs => selected_inputs: {:#?}",
		selected_inputs
	);
	// We are returning a set of inputs for which `Σmy_inputs >= Σmy_outputs + my_fee_cost` holds
	Ok((selected_inputs, my_fee))
}

fn build_output_amount_list(
	my_input_sum: u64,
	my_fee_cost: u64,
	setup_args: &ContractSetupArgsAPI,
) -> Vec<u64> {
	let expected_net_change = setup_args.net_change.unwrap();
	let mut my_output_amounts = setup_args.selection_args.output_amounts();
	let custom_outputs_sum = my_output_amounts.iter().sum::<u64>();
	// We know that `Σmy_inputs >= Σmy_outputs + my_fee_cost` holds so we balance the equation by adding
	// an additional output holding the missing amount (change output or receiver output)
	// TODO: check bounds when casting.
	let my_change_output_amount =
		(my_input_sum - custom_outputs_sum) as i64 + expected_net_change - my_fee_cost as i64;
	// TODO: Check if it's even possible for change output to be negative (it shouldn't be if the equation is correct)
	if my_change_output_amount < 0 {
		panic!(
			"contract_utils::add_outputs => ERROR: This should never happen!!! Values: my_input_sum: {}, expected_net_change: {}, my_fee_cost: {}",
			my_input_sum as i64, expected_net_change, my_fee_cost as i64
		);
	}
	// Add our change/receiver output (which can be a zero-value output) to the list of outputs
	my_output_amounts.push(my_change_output_amount as u64);
	debug!(
		"contract_utils::add_outputs => inputs sum: {}, my_output_amounts:{:#?}",
		my_input_sum, my_output_amounts
	);
	my_output_amounts
}

/// Compares the output selection args provided at call with those from Context and checks whether they conflict
pub fn verify_selection_consistency(
	ctx_args: &OutputSelectionArgs,
	cur_args: &OutputSelectionArgs,
) -> Result<(), Error> {
	// We can't define a selection strategy if we've already done the setup phase. We only allow to pass either the
	// default or exactly the same strategy we defined when doing the setup phase.
	// TODO: Test that this works. Perhaps we'd have to define how to compare the two?
	if cur_args != ctx_args && cur_args != &OutputSelectionArgs::default() {
		panic!("Can't define selection args now because we've already done the setup phase. ctx_selection_args:{:#?}, cur_selection_args:{:#?}", ctx_args, cur_args);
	}
	// NOTE: The logic above isn't perfect. This is because the user could define arguments that are the default. In this case
	// we'd simply silently use the arguments provided in the setup phase. This could be confusing for the user.
	Ok(())
}

// Tests
#[cfg(test)]
mod tests {

	use super::*;
	use crate::grin_keychain::{Identifier, IDENTIFIER_SIZE};
	use crate::OutputStatus;

	fn _create_output_data_for(amounts: Vec<u64>) -> Vec<OutputData> {
		let mut rv: Vec<OutputData> = vec![];
		for (idx, amount) in amounts.iter().enumerate() {
			let identifier = [0u8; IDENTIFIER_SIZE];
			let key_id = Identifier::from_bytes(&identifier);
			rv.push(OutputData {
				// The identifiers here don't make sense, but they're not needed for testing
				root_key_id: key_id.clone(),
				key_id: key_id.clone(),
				n_child: key_id.clone().to_path().last_path_index(),
				mmr_index: None,
				commit: Some(format!("{}{}", "abc", idx.to_string())),
				value: *amount,
				status: OutputStatus::Unspent,
				height: 1,
				lock_height: 0,
				is_coinbase: false,
				tx_log_entry: None,
			});
		}
		rv
	}

	#[test]
	fn sender_no_inputs() {
		// net_change=-1, no inputs, no fee committed => NotEnoughFunds
		let setup_args = ContractSetupArgsAPI {
			net_change: Some(-1_000_000_000),
			..Default::default()
		};
		let expected = Error::NotEnoughFunds {
			available: 0,
			available_disp: amount_to_hr_string(0, false),
			needed: 1_000_000_000 + my_fee_contribution(0, 1, 1, 2).unwrap().fee(),
			needed_disp: amount_to_hr_string(
				1_000_000_000 + my_fee_contribution(0, 1, 1, 2).unwrap().fee(),
				false,
			),
		};
		let result = compute(&setup_args, None, &mut vec![]);
		assert_eq!(result.err().unwrap(), expected);
	}

	#[test]
	fn sender_not_enough_funds_for_fee() {
		// net_change=-3, inputs=[2, 1], no fee committed => NotEnoughFunds because we can't pay for fees
		let setup_args = ContractSetupArgsAPI {
			net_change: Some(-3_000_000_000),
			..Default::default()
		};
		let expected = Error::NotEnoughFunds {
			available: 3_000_000_000,
			available_disp: amount_to_hr_string(3_000_000_000, false),
			needed: 3_000_000_000 + my_fee_contribution(2, 1, 1, 2).unwrap().fee(),
			needed_disp: amount_to_hr_string(
				3_000_000_000 + my_fee_contribution(2, 1, 1, 2).unwrap().fee(),
				false,
			),
		};
		let mut inputs = _create_output_data_for(vec![2_000_000_000, 1_000_000_000]);
		let result = compute(&setup_args, None, &mut inputs);
		assert_eq!(result.err().unwrap(), expected);
	}

	#[test]
	fn sender_happy_path() {
		// net_change=-3, inputs=[3, 2, 1, 2], no fee committed => Ok([1, 2, 2], fees)
		let setup_args = ContractSetupArgsAPI {
			net_change: Some(-3_000_000_000),
			..Default::default()
		};
		let inputs = _create_output_data_for(vec![
			3_000_000_000,
			2_000_000_000,
			1_000_000_000,
			2_000_000_000,
		]);
		// We expect 3 inputs with amounts 1, 2, 2
		let expected_inputs = vec![&inputs[2], &inputs[1], &inputs[3]];
		let expected_fee = my_fee_contribution(3, 1, 1, 2).unwrap();
		let expected_output_amounts = vec![
			// we expect a single output with change holding 5 - 3 - fees
			(5_000_000_000 as i64 + (setup_args.net_change.unwrap())) as u64 - expected_fee.fee(),
		];
		let result = compute(&setup_args, None, &mut inputs.clone()).unwrap();

		let result_ref = (
			result.0.iter().collect::<Vec<&OutputData>>(),
			result.1,
			result.2,
		);
		assert_eq!(
			result_ref,
			(expected_inputs, expected_output_amounts, expected_fee)
		);
	}

	#[test]
	fn sender_exact() {
		// net_change=-3, inputs=[3, my_fees(2, 1)], no fee committed => Ok([3, my_fees(2, 1)], fees)
		let setup_args = ContractSetupArgsAPI {
			net_change: Some(-3_000_000_000),
			..Default::default()
		};
		let inputs = _create_output_data_for(vec![
			my_fee_contribution(2, 1, 1, 2).unwrap().fee(),
			3_000_000_000,
		]);
		let expected_inputs = inputs.clone(); // we expect both inputs in the same order
		let expected_fee = my_fee_contribution(2, 1, 1, 2).unwrap();
		let expected_output_amounts = vec![0]; // we expect a change output of 0-value
		let result = compute(&setup_args, None, &mut inputs.clone()).unwrap();

		assert_eq!(
			result,
			(expected_inputs, expected_output_amounts, expected_fee)
		);
	}

	#[test]
	fn receiver_payjoin_exact() {
		// net_change=-my_fees(1, 1), inputs=[my_fees(1, 0)], no fee committed => Ok([3, my_fees(2, 1)], fees)
		let setup_args = ContractSetupArgsAPI {
			// we expect to receive exactly our fee contribution my_fees(1, 1)
			net_change: Some(my_fee_contribution(1, 1, 1, 2).unwrap().fee() as i64),
			..Default::default()
		};
		let inputs = _create_output_data_for(vec![0, 1_000_000_000]); // we have a 0-value and 1 grin input
		let expected_inputs = vec![&inputs[0]]; // we expect to use the 0-value input
		let expected_fee = my_fee_contribution(1, 1, 1, 2).unwrap();
		let expected_output_amounts = vec![0]; // we expect a change output of 0-value
		let result = compute(&setup_args, None, &mut inputs.clone()).unwrap();

		let result_ref = (
			result.0.iter().collect::<Vec<&OutputData>>(),
			result.1,
			result.2,
		);
		assert_eq!(
			result_ref,
			(expected_inputs, expected_output_amounts, expected_fee)
		);
	}

	#[test]
	fn receiver_no_payjoin() {
		let setup_args = ContractSetupArgsAPI {
			// we expect to receive exactly our fee contribution my_fees(1, 1)
			net_change: Some(3_000_000_000),
			selection_args: OutputSelectionArgs {
				use_inputs: None,
				..Default::default()
			},
			..Default::default()
		};
		let inputs = _create_output_data_for(vec![1_000_000_000]);
		let expected_inputs = vec![];
		let expected_fee = my_fee_contribution(0, 1, 1, 2).unwrap();
		let expected_output_amounts = vec![
			// we expect a single output with change holding 3 - fees
			(setup_args.net_change.unwrap() as u64) - expected_fee.fee(),
		];
		let result = compute(&setup_args, None, &mut inputs.clone()).unwrap();

		assert_eq!(
			result,
			(expected_inputs, expected_output_amounts, expected_fee)
		);
	}

	#[test]
	fn sender_use_inputs_ok() {
		let setup_args = ContractSetupArgsAPI {
			// we expect to receive exactly our fee contribution my_fees(1, 1)
			net_change: Some(-2_000_000_000),
			selection_args: OutputSelectionArgs {
				use_inputs: Some(String::from("abc0,abc2,abc3")),
				..Default::default()
			},
			..Default::default()
		};
		let inputs = _create_output_data_for(vec![
			1_000_000_000, // abc0
			2_000_000_000,
			3_000_000_000, // abc2
			4_000_000_000, // abc3
		]);
		let expected_inputs = vec![&inputs[0], &inputs[2], &inputs[3]];
		let expected_fee = my_fee_contribution(3, 1, 1, 2).unwrap();
		let expected_output_amounts = vec![
			// we expect a single output with change holding 3 - fees
			(8_000_000_000 as i64 + setup_args.net_change.unwrap()) as u64 - expected_fee.fee(),
		];
		let result = compute(&setup_args, None, &mut inputs.clone()).unwrap();

		let result_ref = (
			result.0.iter().collect::<Vec<&OutputData>>(),
			result.1,
			result.2,
		);
		assert_eq!(
			result_ref,
			(expected_inputs, expected_output_amounts, expected_fee)
		);
	}

	#[test]
	fn sender_use_inputs_happy_err() {
		let setup_args = ContractSetupArgsAPI {
			net_change: Some(-2_000_000_000),
			selection_args: OutputSelectionArgs {
				// there is no abc5 input
				use_inputs: Some(String::from("abc0,abc2,abc5")),
				..Default::default()
			},
			..Default::default()
		};
		let inputs = _create_output_data_for(vec![
			1_000_000_000, // abc0
			2_000_000_000,
			3_000_000_000, // abc2
			4_000_000_000,
		]);
		let msg = format!(
			"We have not found all the inputs that have been requested. abc0,abc2,abc5, found only: 2"
		);
		let expected_err = Error::GenericError(msg.into()).into();
		let result = compute(&setup_args, None, &mut inputs.clone());

		assert_eq!(result.err().unwrap(), expected_err);
	}

	#[test]
	fn sender_make_outputs_ok() {
		let setup_args = ContractSetupArgsAPI {
			net_change: Some(-2_000_000_000),
			selection_args: OutputSelectionArgs {
				// there is no abc5 input
				make_outputs: Some(String::from("1,3")),
				..Default::default()
			},
			..Default::default()
		};
		let inputs = _create_output_data_for(vec![
			1_000_000_000,
			2_000_000_000,
			3_000_000_000,
			4_000_000_000,
		]);
		// we expect all to be used (2+1+3+fees)
		let expected_inputs = inputs.clone();
		let expected_fee = my_fee_contribution(4, 3, 1, 2).unwrap();
		let expected_output_amounts = vec![
			1_000_000_000u64,
			3_000_000_000u64,
			// change output
			((10_000_000_000u64 - 4_000_000_000u64) as i64 + setup_args.net_change.unwrap()) as u64
				- expected_fee.fee(),
		];
		let result = compute(&setup_args, None, &mut inputs.clone()).unwrap();

		assert_eq!(
			result,
			(expected_inputs, expected_output_amounts, expected_fee)
		);
	}

	/*

	Tests to add:
	- compute_receiver_invariant - test that receiving_amount - my_fees >= 0 (to prevent going into negative accidentally)
	- compute_sender_invariant - test that -send_amount - my_fees < 0 (do you need this one and is it correct?)
	- compute_receiver_payjoin_negative_fee - could the receiver receive a negative amount through fees? but the thing
	  would go through because they made a payjoin so they could pay for the fees?
	- compute_receiver_omit_payjoin - we can't contribute an input, but have enough for other fees
	- compute_make_outputs_fee_err - fail due to not enough funds for fees
	- compute_make_outputs_sum_err - is this even possible?
	- compute_zero_value_outputs_sender - sender uses all 0-value outputs when sending
	- compute_zero_value_inputs_receiver - receiver uses 0-value inputs in payjoin
	- test_fee_committed_err - we have already committed to a certain fee which we no longer satisfy
	- think if we should have sender/receiver separate testing
	- sender_use_all_features
	- coinbase output cases
	- validate --make-outputs has all positive u64 numbers

	*/
}
