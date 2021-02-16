%%%-------------------------------------------------------------------
%% @doc
%% == Blockchain Transaction Stake Validator ==
%% @end
%%%-------------------------------------------------------------------
-module(blockchain_txn_stake_validator_v1).

-behavior(blockchain_txn).

-behavior(blockchain_json).
-include("blockchain_json.hrl").
-include("blockchain_utils.hrl").
-include("blockchain_txn_fees.hrl").
-include("blockchain_vars.hrl").
-include_lib("helium_proto/include/blockchain_txn_stake_validator_v1_pb.hrl").

-export([
         new/5, new/6,
         hash/1,
         validator/1,
         owner/1,
         stake/1,
         nonce/1,
         description/1,
         validator_signature/1,
         owner_signature/1,
         fee/1, calculate_fee/2, calculate_fee/5,
         sign/2, validator_sign/2,
         is_valid/2,
         absorb/2,
         print/1,
         to_json/2
        ]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-type txn_stake_validator() :: #blockchain_txn_stake_validator_v1_pb{}.
-export_type([txn_stake_validator/0]).

-spec new(libp2p_crypto:pubkey_bin(), libp2p_crypto:pubkey_bin(),
          pos_integer(), string(), pos_integer()) ->
          txn_stake_validator().
new(ValidatorAddress, OwnerAddress,
    Stake, Description, Fee) ->
    new(ValidatorAddress, OwnerAddress,
        Stake, Description, 0, Fee).

-spec new(libp2p_crypto:pubkey_bin(), libp2p_crypto:pubkey_bin(),
          pos_integer(), string(), pos_integer(), non_neg_integer()) ->
          txn_stake_validator().
new(ValidatorAddress, OwnerAddress,
    Stake, Description, Nonce, Fee) ->
    #blockchain_txn_stake_validator_v1_pb{
       validator = ValidatorAddress,
       owner = OwnerAddress,
       stake = Stake,
       description = Description,
       fee = Fee,
       nonce = Nonce
    }.

-spec hash(txn_stake_validator()) -> blockchain_txn:hash().
hash(Txn) ->
    BaseTxn = Txn#blockchain_txn_stake_validator_v1_pb{owner_signature = <<>>, validator_signature = <<>>},
    EncodedTxn = blockchain_txn_stake_validator_v1_pb:encode_msg(BaseTxn),
    crypto:hash(sha256, EncodedTxn).

-spec owner(txn_stake_validator()) -> libp2p_crypto:pubkey_bin().
owner(Txn) ->
    Txn#blockchain_txn_stake_validator_v1_pb.owner.

-spec validator(txn_stake_validator()) -> libp2p_crypto:pubkey_bin().
validator(Txn) ->
    Txn#blockchain_txn_stake_validator_v1_pb.validator.

-spec stake(txn_stake_validator()) -> pos_integer().
stake(Txn) ->
    Txn#blockchain_txn_stake_validator_v1_pb.stake.

-spec nonce(txn_stake_validator()) -> pos_integer().
nonce(Txn) ->
    Txn#blockchain_txn_stake_validator_v1_pb.nonce.

-spec description(txn_stake_validator()) -> string().
description(Txn) ->
    Txn#blockchain_txn_stake_validator_v1_pb.description.

-spec fee(txn_stake_validator()) -> non_neg_integer().
fee(Txn) ->
    Txn#blockchain_txn_stake_validator_v1_pb.fee.

-spec calculate_fee(txn_stake_validator(), blockchain:blockchain()) ->
          non_neg_integer().
calculate_fee(Txn, Chain) ->
    ?calculate_fee_prep(Txn, Chain).

-spec calculate_fee(txn_stake_validator(), blockchain_ledger_v1:ledger(),
                    pos_integer(), pos_integer(), boolean()) ->
          non_neg_integer().
calculate_fee(Txn, Ledger, DCPayloadSize, TxnFeeMultiplier, _) ->
    ?calculate_fee(Txn#blockchain_txn_stake_validator_v1_pb{fee=0,
                                                            validator_signature = <<0:512>>,
                                                            owner_signature = <<0:512>>},
    Ledger, DCPayloadSize, TxnFeeMultiplier).


-spec owner_signature(txn_stake_validator()) -> binary().
owner_signature(Txn) ->
    Txn#blockchain_txn_stake_validator_v1_pb.owner_signature.

-spec validator_signature(txn_stake_validator()) -> binary().
validator_signature(Txn) ->
    Txn#blockchain_txn_stake_validator_v1_pb.validator_signature.

-spec sign(txn_stake_validator(), libp2p_crypto:sig_fun()) -> txn_stake_validator().
sign(Txn, SigFun) ->
    BaseTxn = Txn#blockchain_txn_stake_validator_v1_pb{owner_signature= <<>>,
                                                       validator_signature= <<>>},
    EncodedTxn = blockchain_txn_stake_validator_v1_pb:encode_msg(BaseTxn),
    Txn#blockchain_txn_stake_validator_v1_pb{owner_signature=SigFun(EncodedTxn)}.

-spec validator_sign(txn_stake_validator(), libp2p_crypto:sig_fun()) -> txn_stake_validator().
validator_sign(Txn, SigFun) ->
    BaseTxn = Txn#blockchain_txn_stake_validator_v1_pb{owner_signature= <<>>,
                                                       validator_signature= <<>>},
    EncodedTxn = blockchain_txn_stake_validator_v1_pb:encode_msg(BaseTxn),
    Txn#blockchain_txn_stake_validator_v1_pb{validator_signature=SigFun(EncodedTxn)}.

-spec is_valid_validator(txn_stake_validator()) -> boolean().
is_valid_validator(#blockchain_txn_stake_validator_v1_pb{validator=PubKeyBin,
                                                         validator_signature=Signature}=Txn) ->
    BaseTxn = Txn#blockchain_txn_stake_validator_v1_pb{owner_signature= <<>>,
                                                       validator_signature= <<>>},
    EncodedTxn = blockchain_txn_stake_validator_v1_pb:encode_msg(BaseTxn),
    PubKey = libp2p_crypto:bin_to_pubkey(PubKeyBin),
    libp2p_crypto:verify(EncodedTxn, Signature, PubKey).

-spec is_valid_owner(txn_stake_validator()) -> boolean().
is_valid_owner(#blockchain_txn_stake_validator_v1_pb{owner=PubKeyBin,
                                                     owner_signature=Signature}=Txn) ->
    BaseTxn = Txn#blockchain_txn_stake_validator_v1_pb{owner_signature= <<>>,
                                                   validator_signature= <<>>},
    EncodedTxn = blockchain_txn_stake_validator_v1_pb:encode_msg(BaseTxn),
    PubKey = libp2p_crypto:bin_to_pubkey(PubKeyBin),
    libp2p_crypto:verify(EncodedTxn, Signature, PubKey).

-spec is_valid(txn_stake_validator(), blockchain:blockchain()) ->
          ok | {error, atom()} | {error, {atom(), any()}}.
is_valid(Txn, Chain) ->
    Ledger = blockchain:ledger(Chain),
    Owner = ?MODULE:owner(Txn),
    Validator = ?MODULE:validator(Txn),
    Stake = stake(Txn),
    Fee = fee(Txn),
    Nonce = nonce(Txn),
    case {is_valid_owner(Txn), is_valid_validator(Txn)} of
        {false, _} ->
            {error, bad_owner_signature};
        {_, false} ->
            {error, bad_validator_signature};
        {true, true} ->
            try
                %% check fee
                AreFeesEnabled = blockchain_ledger_v1:txn_fees_active(Ledger),
                ExpectedTxnFee = calculate_fee(Txn, Chain),
                {ok, MinStake} = blockchain:config(?validator_minimum_stake, Ledger),
                case ExpectedTxnFee =< Fee orelse not AreFeesEnabled of
                    false -> throw({wrong_txn_fee, {ExpectedTxnFee, Fee}});
                    true -> ok
                end,
                %% make sure that this validator doesn't already exist
                case blockchain_ledger_v1:get_validator(Validator, Ledger) of
                    {ok, Val} ->
                        ValNonce = blockchain_ledger_validator_v1:nonce(Val),
                        case Nonce of
                            0 ->
                                throw(already_exists);
                            N when N =:= (ValNonce + 1) ->
                                %% check that we have adequate stake in cooldown to restore
                                {ok, CooldownStake} = blockchain_ledger_v1:cooldown_stake(Val, Ledger),
                                case CooldownStake >= MinStake of
                                    true -> ok;
                                    false -> throw({not_enough_cooldown, cool,
                                                    CooldownStake, min, MinStake})
                                end,                                
                                ok;
                            N -> 
                                throw({bad_nonce, exp, (ValNonce + 1), got, N})
                        end;
                    {error, not_found} ->
                        case Nonce of
                            0 ->
                                %% make sure the staking amount is high enough
                                case Stake == MinStake of
                                    true -> ok;
                                    false -> throw(stake_too_low)
                                end,
                                %% make sure that the owner has enough HNT to stake
                                case blockchain_ledger_v1:find_entry(Owner, Ledger) of
                                    {ok, Entry} ->
                                        Balance = blockchain_ledger_entry_v1:balance(Entry),
                                        case Balance >= Stake of
                                            true -> ok;
                                            false -> throw({balance_too_low, {bal, Balance, stk, Stake}})
                                        end;
                                    {error, _} ->
                                        throw(bad_owner_entry)
                                end,
                                ok;
                            _ -> throw(nonce_not_zero)
                        end;
                    {error, Reason} -> throw({validator_fetch_error, Reason})
                end,
                ok
            catch throw:Cause ->
                    {error, Cause}
            end
    end.

-spec absorb(txn_stake_validator(), blockchain:blockchain()) -> ok | {error, atom()} | {error, {atom(), any()}}.
absorb(Txn, Chain) ->
    Ledger = blockchain:ledger(Chain),
    Owner = owner(Txn),
    Validator = validator(Txn),
    Stake = stake(Txn),
    Description = description(Txn),
    TxnNonce = nonce(Txn),
    Fee = fee(Txn),
    {ok, Entry} = blockchain_ledger_v1:find_entry(Owner, Ledger),
    Nonce = blockchain_ledger_entry_v1:nonce(Entry),

    case blockchain_ledger_v1:debit_fee(Owner, Fee, Ledger, true) of
        {error, _Reason} = Err -> Err;
        ok ->
            case blockchain_ledger_v1:debit_account(Owner, Stake, Nonce + 1, Ledger) of
                {error, _Reason} = Err1 -> Err1;
                ok ->
                    case TxnNonce of
                        0 ->
                            blockchain_ledger_v1:add_validator(Validator, Owner, Stake,
                                                               Description, Ledger);
                        _ ->
                            blockchain_ledger_v1:activate_validator(Validator, Ledger)                            
                    end
            end
    end.

-spec print(txn_stake_validator()) -> iodata().
print(undefined) -> <<"type=stake_validator, undefined">>;
print(#blockchain_txn_stake_validator_v1_pb{
         owner = O,
         validator = Val,
         stake = S,
         description = D}) ->
    io_lib:format("type=stake_validator, owner=~p, validator=~p, stake=~p, description=~s",
                  [?TO_B58(O), ?TO_ANIMAL_NAME(Val), S, D]).


-spec to_json(txn_stake_validator(), blockchain_json:opts()) -> blockchain_json:json_object().
to_json(Txn, _Opts) ->
    #{
      type => <<"stake_validator_v1">>,
      hash => ?BIN_TO_B64(hash(Txn)),
      validator => ?BIN_TO_B58(validator(Txn)),
      owner => ?BIN_TO_B58(owner(Txn)),
      validator_signature => ?BIN_TO_B64(validator_signature(Txn)),
      owner_signature => ?BIN_TO_B64(owner_signature(Txn)),
      description => description(Txn),
      fee => fee(Txn),
      nonce => nonce(Txn),
      stake => stake(Txn)
     }.

%% ------------------------------------------------------------------
%% EUNIT Tests
%% ------------------------------------------------------------------
-ifdef(TEST).

to_json_test() ->
    Tx = new(<<"validator_address">>, <<"owner_address">>, 1000,
             <<"some random description">>, 20),
    Json = to_json(Tx, []),
    ?assertEqual(lists:sort(maps:keys(Json)),
                 lists:sort([type, hash] ++ record_info(fields, blockchain_txn_stake_validator_v1_pb))).


-endif.
