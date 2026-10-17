#![no_std]

//! StreamPay: continuous, linear streaming payments for Stellar (Soroban).
//!
//! Lock a deposit and let it accrue to a recipient per second between
//! `start_time` and `end_time` — for payroll, DAO contributor pay,
//! subscriptions, or vesting. The recipient withdraws accrued funds at any
//! time; the sender can top up or cancel with a fair pro-rata refund.
//!
//! # Entry points
//!
//! - [`StreamingPayments::create_stream`] — open a stream and pull the deposit
//! - [`StreamingPayments::withdraw`] — recipient claims accrued funds
//! - [`StreamingPayments::withdraw_max`] — recipient claims *all* accrued
//!   funds in one atomic call
//! - [`StreamingPayments::cancel_stream`] — sender (or recipient, if the
//!   stream is `cancelable`) closes the stream with a pro-rata split
//! - [`StreamingPayments::top_up`] — add funds to a running stream
//! - `propose_sender_transfer` / `accept_sender_transfer` — hand off payer rights
//! - `propose_recipient_transfer` / `accept_recipient_transfer` — redirect claims
//! - [`StreamingPayments::get_stream`] / [`StreamingPayments::available`] —
//!   read-only views
//! - [`StreamingPayments::recipient_streams`] /
//!   [`StreamingPayments::sender_streams`] — paginated on-chain discovery
//!   indexes per address
//!
//! # Invariants
//!
//! - `0 <= withdrawn <= streamed <= deposit` for every stored stream.
//! - The contract's token balance always covers `sum(deposit - withdrawn)`
//!   over all streams (funds are only ever moved by these entry points).
//! - All state changes happen *before* token transfers (checks-effects-
//!   interactions), so reentrant token callbacks cannot over-withdraw.

mod errors;
mod events;
mod stream;
#[cfg(test)]
mod test;
#[cfg(test)]
mod test_client;

use soroban_sdk::{contract, contractimpl, token::TokenClient, Address, Env, Vec};

pub use errors::StreamError;
pub use events::{
    OwnershipAccepted, OwnershipProposed, OwnershipRole, StreamCancelled, StreamCreated,
    StreamToppedUp, Withdrawn,
};
// `streamed_at` is re-exported for the fuzz target and downstream rate
// calculators: it is a pure function requiring no `Env`.
pub use stream::{streamed_at, Stream, StreamStatus, MAX_DURATION_SECONDS, MAX_PAGE_SIZE};

/// The StreamPay streaming-payments contract.
#[contract]
pub struct StreamingPayments;

#[contractimpl]
impl StreamingPayments {
    /// Creates a linear payment stream and pulls `deposit_amount` of `token`
    /// from `sender` into this contract.
    ///
    /// The sender must first approve this contract as a spender on `token`
    /// (`token.approve(sender, streaming_contract, deposit_amount, ...)`).
    ///
    /// * `start_time` must not be in the past (UIs pass the current time to
    ///   start streaming immediately).
    /// * `end_time` must be strictly after `start_time` (zero-duration streams
    ///   are rejected) and at most `MAX_DURATION_SECONDS` long.
    #[allow(clippy::too_many_arguments)] // 8-arg surface is the intended client API
    /// * `cancelable` controls whether the recipient may also call
    ///   `cancel_stream` to reclaim their accrued balance.
    ///
    /// Returns the new stream id (monotonically increasing, starting at 1).
    pub fn create_stream(
        env: Env,
        sender: Address,
        recipient: Address,
        token: Address,
        deposit_amount: i128,
        start_time: u64,
        end_time: u64,
        cancelable: bool,
    ) -> Result<u64, StreamError> {
        sender.require_auth();

        if deposit_amount <= 0 {
            return Err(StreamError::ZeroAmount);
        }
        let now = env.ledger().timestamp();
        if start_time < now {
            return Err(StreamError::StartTimeInPast);
        }
        if end_time <= start_time {
            return Err(StreamError::InvalidTimeRange);
        }
        let duration = end_time - start_time;
        if duration > MAX_DURATION_SECONDS {
            return Err(StreamError::DurationTooLong);
        }
        stream::validate_capacity(deposit_amount, duration)?;

        // Interaction: pull the deposit from the sender.
        TokenClient::new(&env, &token).transfer_from(
            &env.current_contract_address(),
            &sender,
            &env.current_contract_address(),
            &deposit_amount,
        );

        // Effects: persist the stream and announce it.
        let id = stream::next_stream_id(&env);
        let s = Stream {
            id,
            sender: sender.clone(),
            recipient: recipient.clone(),
            token: token.clone(),
            deposit: deposit_amount,
            withdrawn: 0,
            start_time,
            end_time,
            cancelable,
            status: StreamStatus::Active,
        };
        stream::put_stream(&env, &s);
        stream::index_stream(&env, &s);

        StreamCreated {
            stream_id: id,
            sender,
            recipient,
            token,
            deposit: deposit_amount,
            start_time,
            end_time,
            cancelable,
        }
        .publish(&env);

        Ok(id)
    }

    /// Withdraws up to `amount` of the accrued-but-unwithdrawn balance and
    /// pays it to the stream recipient. Only the recipient can call this
    /// (their authorization is required).
    ///
    /// Reverts with [`StreamError::AmountExceedsAvailable`] if `amount`
    /// exceeds what has accrued so far; before `start_time` nothing has
    /// accrued, at or after `end_time` the full remainder is available.
    pub fn withdraw(env: Env, stream_id: u64, amount: i128) -> Result<(), StreamError> {
        if amount <= 0 {
            return Err(StreamError::ZeroAmount);
        }
        let mut s = Self::authorize_withdrawal(&env, stream_id)?;

        let available = stream::available_amount(&env, &s)?;
        if amount > available {
            return Err(StreamError::AmountExceedsAvailable);
        }

        Self::pay_out(&env, &mut s, amount)
    }

    /// Withdraws the entire accrued-but-unwithdrawn balance in one call and
    /// returns the amount paid. Only the recipient can call this (their
    /// authorization is required).
    ///
    /// This is the atomic form of "read `available`, then `withdraw` it":
    /// clients never risk a stale amount between the two calls. Reverts with
    /// [`StreamError::NothingToWithdraw`] when nothing has accrued yet (or
    /// everything accrued has already been withdrawn), and with
    /// [`StreamError::StreamNotActive`] on cancelled or depleted streams.
    pub fn withdraw_max(env: Env, stream_id: u64) -> Result<i128, StreamError> {
        let mut s = Self::authorize_withdrawal(&env, stream_id)?;

        let amount = stream::available_amount(&env, &s)?;
        if amount <= 0 {
            return Err(StreamError::NothingToWithdraw);
        }

        Self::pay_out(&env, &mut s, amount)?;
        Ok(amount)
    }

    /// Shared preamble for both withdrawal paths: load the stream, require
    /// the recipient's authorization, and reject terminal streams.
    fn authorize_withdrawal(env: &Env, stream_id: u64) -> Result<Stream, StreamError> {
        let s = stream::get_stream(env, stream_id)?;
        s.recipient.require_auth();
        if s.status != StreamStatus::Active {
            return Err(StreamError::StreamNotActive);
        }
        Ok(s)
    }

    /// Shared payout tail for both withdrawal paths, checks-effects-
    /// interactions ordered: record `withdrawn` and emit the event *before*
    /// moving tokens, so a reentrant token callback can never double-spend.
    fn pay_out(env: &Env, s: &mut Stream, amount: i128) -> Result<(), StreamError> {
        s.withdrawn = s
            .withdrawn
            .checked_add(amount)
            .ok_or(StreamError::MathOverflow)?;
        if s.withdrawn == s.deposit {
            s.status = StreamStatus::Depleted;
        }
        stream::put_stream(env, s);
        if s.status == StreamStatus::Depleted {
            stream::clear_transfer_proposals(env, s.id);
        }

        Withdrawn {
            stream_id: s.id,
            recipient: s.recipient.clone(),
            amount,
            withdrawn_total: s.withdrawn,
        }
        .publish(env);

        TokenClient::new(env, &s.token).transfer(
            &env.current_contract_address(),
            stream::muxed(&s.recipient),
            &amount,
        );

        Ok(())
    }

    /// Cancels a stream: pays the recipient their accrued-but-unwithdrawn
    /// balance and refunds the sender the unaccrued remainder, atomically.
    ///
    /// Callable by the sender always, and by the recipient only if the stream
    /// was created with `cancelable = true`. Cancelling an already-cancelled
    /// or depleted stream reverts with [`StreamError::StreamNotActive`].
    pub fn cancel_stream(env: Env, caller: Address, stream_id: u64) -> Result<(), StreamError> {
        caller.require_auth();

        let mut s = stream::get_stream(&env, stream_id)?;
        if s.status != StreamStatus::Active {
            return Err(StreamError::StreamNotActive);
        }
        if caller != s.sender {
            if caller == s.recipient {
                if !s.cancelable {
                    return Err(StreamError::StreamNotCancellable);
                }
            } else {
                return Err(StreamError::NotAuthorized);
            }
        }

        let (recipient_amount, sender_amount) = stream::cancel_amounts(&env, &s)?;

        // Effects first (CEI): finalise state before moving tokens.
        s.status = StreamStatus::Cancelled;
        s.withdrawn = s
            .withdrawn
            .checked_add(recipient_amount)
            .ok_or(StreamError::MathOverflow)?;
        stream::put_stream(&env, &s);
        stream::clear_transfer_proposals(&env, stream_id);

        StreamCancelled {
            stream_id,
            cancelled_by: caller,
            recipient_amount,
            sender_amount,
        }
        .publish(&env);

        let token = TokenClient::new(&env, &s.token);
        if recipient_amount > 0 {
            token.transfer(
                &env.current_contract_address(),
                stream::muxed(&s.recipient),
                &recipient_amount,
            );
        }
        if sender_amount > 0 {
            token.transfer(
                &env.current_contract_address(),
                stream::muxed(&s.sender),
                &sender_amount,
            );
        }

        Ok(())
    }

    /// Adds funds to an existing active stream. The deposit grows and accrual
    /// remains linear over the original window, so the recipient's accrued
    /// amount increases pro-rata immediately (Sablier-v1 `increaseAmount`
    /// semantics).
    ///
    /// Top-ups are rejected on cancelled or depleted streams. Topping up a
    /// stream that has already passed `end_time` adds fully-accrued funds the
    /// recipient can withdraw immediately.
    ///
    /// Note: extending `end_time` is intentionally not supported in v1 —
    /// retroactively re-baselining accrual is lossy for the recipient; see
    /// `docs/ARCHITECTURE.md` for the design considerations and roadmap.
    pub fn top_up(env: Env, stream_id: u64, amount: i128) -> Result<(), StreamError> {
        if amount <= 0 {
            return Err(StreamError::ZeroAmount);
        }
        let mut s = stream::get_stream(&env, stream_id)?;
        if s.status != StreamStatus::Active {
            return Err(StreamError::StreamNotActive);
        }
        s.sender.require_auth();

        let new_deposit = s
            .deposit
            .checked_add(amount)
            .ok_or(StreamError::MathOverflow)?;
        stream::validate_capacity(new_deposit, s.duration())?;

        // Interaction: pull the added funds from the sender.
        TokenClient::new(&env, &s.token).transfer_from(
            &env.current_contract_address(),
            &s.sender,
            &env.current_contract_address(),
            &amount,
        );

        // Effects: record the new deposit and announce it.
        s.deposit = new_deposit;
        stream::put_stream(&env, &s);

        StreamToppedUp {
            stream_id,
            sender: s.sender.clone(),
            amount,
            new_deposit,
        }
        .publish(&env);

        Ok(())
    }

    /// Proposes handing sender rights (top-up and sender cancellation) to `target`.
    /// The current sender remains authoritative until the target accepts.
    pub fn propose_sender_transfer(
        env: Env,
        stream_id: u64,
        target: Address,
    ) -> Result<(), StreamError> {
        Self::propose_transfer(&env, stream_id, target, OwnershipRole::Sender)
    }

    /// Accepts a sender-role transfer proposed by the current sender.
    pub fn accept_sender_transfer(env: Env, stream_id: u64) -> Result<(), StreamError> {
        Self::accept_transfer(&env, stream_id, OwnershipRole::Sender)
    }

    /// Proposes redirecting future claims and recipient rights to `target`.
    /// The current recipient remains authoritative until the target accepts.
    pub fn propose_recipient_transfer(
        env: Env,
        stream_id: u64,
        target: Address,
    ) -> Result<(), StreamError> {
        Self::propose_transfer(&env, stream_id, target, OwnershipRole::Recipient)
    }

    /// Accepts a recipient-role transfer proposed by the current recipient.
    pub fn accept_recipient_transfer(env: Env, stream_id: u64) -> Result<(), StreamError> {
        Self::accept_transfer(&env, stream_id, OwnershipRole::Recipient)
    }

    fn propose_transfer(
        env: &Env,
        stream_id: u64,
        target: Address,
        role: OwnershipRole,
    ) -> Result<(), StreamError> {
        let s = stream::get_stream(env, stream_id)?;
        if s.status != StreamStatus::Active {
            return Err(StreamError::StreamNotActive);
        }
        let owner = match role {
            OwnershipRole::Sender => s.sender,
            OwnershipRole::Recipient => s.recipient,
        };
        owner.require_auth();
        if target == owner {
            return Err(StreamError::InvalidTransferTarget);
        }

        stream::put_stream(env, &s);
        let key = Self::transfer_key(stream_id, role);
        stream::put_pending_transfer(env, &key, &owner, &target);
        OwnershipProposed {
            stream_id,
            role,
            current_owner: owner,
            proposed_owner: target,
        }
        .publish(env);
        Ok(())
    }

    fn accept_transfer(
        env: &Env,
        stream_id: u64,
        role: OwnershipRole,
    ) -> Result<(), StreamError> {
        let mut s = stream::get_stream(env, stream_id)?;
        if s.status != StreamStatus::Active {
            return Err(StreamError::StreamNotActive);
        }
        let pending_key = Self::transfer_key(stream_id, role);
        let pending = stream::get_pending_transfer(env, &pending_key)?;
        let current_owner = match role {
            OwnershipRole::Sender => &s.sender,
            OwnershipRole::Recipient => &s.recipient,
        };
        if &pending.proposer != current_owner {
            return Err(StreamError::TransferNotProposed);
        }
        pending.target.require_auth();

        match role {
            OwnershipRole::Sender => {
                stream::transfer_index(
                    env,
                    &stream::DataKey::SenderStreams(s.sender.clone()),
                    &stream::DataKey::SenderStreams(pending.target.clone()),
                    stream_id,
                );
                s.sender = pending.target.clone();
            }
            OwnershipRole::Recipient => {
                stream::transfer_index(
                    env,
                    &stream::DataKey::RecipientStreams(s.recipient.clone()),
                    &stream::DataKey::RecipientStreams(pending.target.clone()),
                    stream_id,
                );
                s.recipient = pending.target.clone();
            }
        }
        stream::put_stream(env, &s);
        stream::remove_pending_transfer(env, &pending_key);
        OwnershipAccepted {
            stream_id,
            role,
            previous_owner: pending.proposer,
            new_owner: pending.target,
        }
        .publish(env);
        Ok(())
    }

    fn transfer_key(stream_id: u64, role: OwnershipRole) -> stream::DataKey {
        match role {
            OwnershipRole::Sender => stream::DataKey::PendingSenderTransfer(stream_id),
            OwnershipRole::Recipient => stream::DataKey::PendingRecipientTransfer(stream_id),
        }
    }

    /// Read-only view of a stream's full state.
    pub fn get_stream(env: Env, stream_id: u64) -> Result<Stream, StreamError> {
        stream::get_stream(&env, stream_id)
    }

    /// Read-only view of the accrued-but-unwithdrawn balance at the current
    /// ledger time. Zero before `start_time` and for cancelled streams; the
    /// full remainder at or after `end_time`.
    pub fn available(env: Env, stream_id: u64) -> Result<i128, StreamError> {
        let s = stream::get_stream(&env, stream_id)?;
        stream::available_amount(&env, &s)
    }

    /// A page of stream ids where `recipient` is the current recipient.
    /// `limit` is clamped to `MAX_PAGE_SIZE`; paginate by advancing `offset`.
    /// Unknown addresses yield an empty page.
    ///
    /// Proposals do not move ids; accepting
    /// a transfer removes the id from the old recipient and appends it to the
    /// new recipient's index. Terminal streams remain indexed; read `status`
    /// for lifecycle state. This view never authorizes an action.
    pub fn recipient_streams(env: Env, recipient: Address, offset: u32, limit: u32) -> Vec<u64> {
        stream::page_stream_ids(
            &env,
            &stream::DataKey::RecipientStreams(recipient),
            offset,
            limit,
        )
    }

    /// A page of stream ids currently owned by `sender`. Accepted transfers
    /// move ids to the new sender's index; they are appended at acceptance
    /// time. Same pagination and advisory semantics as
    /// [`StreamingPayments::recipient_streams`].
    pub fn sender_streams(env: Env, sender: Address, offset: u32, limit: u32) -> Vec<u64> {
        stream::page_stream_ids(&env, &stream::DataKey::SenderStreams(sender), offset, limit)
    }
}
