%%%-------------------------------------------------------------------
%% @doc
%% == Blockchain Transaction Stake Validator ==
%% @end
%%%-------------------------------------------------------------------
-module(blockchain_txn_unstake_validator_v1).

-behavior(blockchain_txn).

-behavior(blockchain_json).
-include("blockchain_json.hrl").
-include("blockchain_utils.hrl").
-include("blockchain_txn_fees.hrl").
-include("blockchain_vars.hrl").
-include_lib("helium_proto/include/blockchain_txn_unstake_validator_v1_pb.hrl").

-export([
         new/3,
         hash/1,
         addr/1,
         owner/1,
         owner_signature/1,
         nonce/1,
         fee/1, calculate_fee/2, calculate_fee/5,
         sign/2,
         is_valid/2,
         absorb/2,
         print/1,
         to_json/2
        ]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-type txn_unstake_validator() :: #blockchain_txn_unstake_validator_v1_pb{}.
-export_type([txn_unstake_validator/0]).

-spec new(libp2p_crypto:pubkey_bin(), libp2p_crypto:pubkey_bin(), pos_integer()) ->
          txn_unstake_validator().
new(ValidatorAddress, OwnerAddress, Nonce) ->
    #blockchain_txn_unstake_validator_v1_pb{
       addr = ValidatorAddress,
       owner = OwnerAddress,
       nonce = Nonce
    }.

-spec hash(txn_unstake_validator()) -> blockchain_txn:hash().
hash(Txn) ->
    BaseTxn = Txn#blockchain_txn_unstake_validator_v1_pb{owner_signature = <<>>},
    EncodedTxn = blockchain_txn_unstake_validator_v1_pb:encode_msg(BaseTxn),
    crypto:hash(sha256, EncodedTxn).

-spec owner(txn_unstake_validator()) -> libp2p_crypto:pubkey_bin().
owner(Txn) ->
    Txn#blockchain_txn_unstake_validator_v1_pb.owner.

-spec addr(txn_unstake_validator()) -> libp2p_crypto:pubkey_bin().
addr(Txn) ->
    Txn#blockchain_txn_unstake_validator_v1_pb.addr.

-spec fee(txn_unstake_validator()) -> non_neg_integer().
fee(Txn) ->
    Txn#blockchain_txn_unstake_validator_v1_pb.fee.

-spec calculate_fee(txn_unstake_validator(), blockchain:blockchain()) ->
          non_neg_integer().
calculate_fee(Txn, Chain) ->
    ?calculate_fee_prep(Txn, Chain).

-spec calculate_fee(txn_unstake_validator(), blockchain_ledger_v1:ledger(),
                    pos_integer(), pos_integer(), boolean()) ->
          non_neg_integer().
calculate_fee(Txn, Ledger, DCPayloadSize, TxnFeeMultiplier, _) ->
    ?calculate_fee(Txn#blockchain_txn_unstake_validator_v1_pb{fee=0,
                                                              owner_signature = <<0:512>>},
    Ledger, DCPayloadSize, TxnFeeMultiplier).

-spec owner_signature(txn_unstake_validator()) -> binary().
owner_signature(Txn) ->
    Txn#blockchain_txn_unstake_validator_v1_pb.owner_signature.

-spec nonce(txn_unstake_validator()) -> pos_integer().
nonce(Txn) ->
    Txn#blockchain_txn_unstake_validator_v1_pb.nonce.

-spec sign(txn_unstake_validator(), libp2p_crypto:sig_fun()) -> txn_unstake_validator().
sign(Txn, SigFun) ->
    BaseTxn = Txn#blockchain_txn_unstake_validator_v1_pb{owner_signature= <<>>},
    EncodedTxn = blockchain_txn_unstake_validator_v1_pb:encode_msg(BaseTxn),
    Txn#blockchain_txn_unstake_validator_v1_pb{owner_signature=SigFun(EncodedTxn)}.

-spec is_valid_owner(txn_unstake_validator()) -> boolean().
is_valid_owner(#blockchain_txn_unstake_validator_v1_pb{owner=PubKeyBin,
                                                       owner_signature=Signature}=Txn) ->
    BaseTxn = Txn#blockchain_txn_unstake_validator_v1_pb{owner_signature= <<>>},
    EncodedTxn = blockchain_txn_unstake_validator_v1_pb:encode_msg(BaseTxn),
    PubKey = libp2p_crypto:bin_to_pubkey(PubKeyBin),
    libp2p_crypto:verify(EncodedTxn, Signature, PubKey).

-spec is_valid(txn_unstake_validator(), blockchain:blockchain()) ->
          ok | {error, atom()} | {error, {atom(), any()}}.
is_valid(Txn, Chain) ->
    Ledger = blockchain:ledger(Chain),
    Validator = addr(Txn),
    Nonce = nonce(Txn),
    Fee = fee(Txn),
    case is_valid_owner(Txn) of
        false ->
            {error, bad_owner_signature};
        _ ->
            try
                %% check fee
                AreFeesEnabled = blockchain_ledger_v1:txn_fees_active(Ledger),
                ExpectedTxnFee = calculate_fee(Txn, Chain),
                case ExpectedTxnFee =< Fee orelse not AreFeesEnabled of
                    false -> throw({wrong_txn_fee, {ExpectedTxnFee, Fee}});
                    true -> ok
                end,
                %% make sure that this validator exists and is staked
                case blockchain_ledger_v1:get_validator(Validator, Ledger) of
                    {ok, V} ->
                        case blockchain_ledger_validator_v1:status(V) of
                            staked -> ok;
                            unstaked -> throw(already_unstaked)
                        end,
                        %% make sure that the nonce is correct
                        VNonce = blockchain_ledger_validator_v1:nonce(V),
                        case Nonce == (VNonce + 1) of
                            true -> ok;
                            false -> throw({bad_nonce, exp, VNonce + 1, got, Nonce})
                        end;
                    {error, not_found} -> throw(nonexistent_validator);
                    {error, Reason} -> throw({validator_fetch_error, Reason})
                end,
                ok
            catch throw:Cause ->
                    {error, Cause}
            end
    end.

-spec absorb(txn_unstake_validator(), blockchain:blockchain()) -> ok | {error, atom()} | {error, {atom(), any()}}.
absorb(Txn, Chain) ->
    Ledger = blockchain:ledger(Chain),
    Owner = owner(Txn),
    Validator = addr(Txn),
    Fee = fee(Txn),

    case blockchain_ledger_v1:debit_fee(Owner, Fee, Ledger, true) of
        {error, _Reason} = Err -> Err;
        ok ->
            blockchain_ledger_v1:deactivate_validator(Validator, Ledger)
    end.

-spec print(txn_unstake_validator()) -> iodata().
print(undefined) -> <<"type=unstake_validator, undefined">>;
print(#blockchain_txn_unstake_validator_v1_pb{
         owner = O,
         addr = Val,
         nonce = N}) ->
    io_lib:format("type=unstake_validator, owner=~p, validator=~p, nonce=~p",
                  [?TO_B58(O), ?TO_ANIMAL_NAME(Val), N]).


-spec to_json(txn_unstake_validator(), blockchain_json:opts()) -> blockchain_json:json_object().
to_json(Txn, _Opts) ->
    #{
      type => <<"unstake_validator_v1">>,
      hash => ?BIN_TO_B64(hash(Txn)),
      addr => ?BIN_TO_B58(addr(Txn)),
      owner => ?BIN_TO_B58(owner(Txn)),
      owner_signature => ?BIN_TO_B64(owner_signature(Txn)),
      fee => fee(Txn),
      nonce => nonce(Txn)
     }.

%% ------------------------------------------------------------------
%% EUNIT Tests
%% ------------------------------------------------------------------
-ifdef(TEST).

to_json_test() ->
    Tx = new(<<"validator_address">>, <<"owner_address">>, 10),
    Json = to_json(Tx, []),
    ?assertEqual(lists:sort(maps:keys(Json)),
                 lists:sort([type, hash] ++ record_info(fields, blockchain_txn_unstake_validator_v1_pb))).


-endif.