%%%-------------------------------------------------------------------
%% @doc
%% == Blockchain Transaction Transfer Validator Stake ==
%% @end
%%%-------------------------------------------------------------------
-module(blockchain_txn_transfer_validator_stake_v1).

-behavior(blockchain_txn).

-behavior(blockchain_json).
-include("blockchain_json.hrl").
-include("blockchain_utils.hrl").
-include("blockchain_txn_fees.hrl").
-include("blockchain_vars.hrl").
-include_lib("helium_proto/include/blockchain_txn_transfer_validator_stake_v1_pb.hrl").

-export([
         new/5, new/6,
         hash/1,
         old_validator/1,
         new_validator/1,
         old_owner/1,
         new_owner/1,
         new_validator_signature/1,
         old_owner_signature/1,
         new_owner_signature/1,
         fee/1, calculate_fee/2, calculate_fee/5,
         sign/2,
         new_validator_sign/2,
         new_owner_sign/2,
         is_valid/2,
         absorb/2,
         print/1,
         to_json/2
        ]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-type txn_transfer_validator_stake() :: #blockchain_txn_transfer_validator_stake_v1_pb{}.
-export_type([txn_transfer_validator_stake/0]).

-spec new(libp2p_crypto:pubkey_bin(), libp2p_crypto:pubkey_bin(),
          libp2p_crypto:pubkey_bin(),
          pos_integer(), pos_integer()) ->
          txn_transfer_validator_stake().
new(OldValidatorAddress, NewValidatorAddress,
    OwnerAddress,
    Nonce, Fee) ->
    new(OldValidatorAddress, NewValidatorAddress,
        OwnerAddress, <<>>,
        Nonce, Fee).

-spec new(libp2p_crypto:pubkey_bin(), libp2p_crypto:pubkey_bin(),
          libp2p_crypto:pubkey_bin(), libp2p_crypto:pubkey_bin(),
          pos_integer(), pos_integer()) ->
          txn_transfer_validator_stake().
new(OldValidatorAddress, NewValidatorAddress,
    OldOwnerAddress, NewOwnerAddress,
    Nonce, Fee) ->
    #blockchain_txn_transfer_validator_stake_v1_pb{
       old_addr = OldValidatorAddress,
       new_addr = NewValidatorAddress,
       new_owner = NewOwnerAddress,
       old_owner = OldOwnerAddress,
       fee = Fee,
       nonce = Nonce
    }.

-spec hash(txn_transfer_validator_stake()) -> blockchain_txn:hash().
hash(Txn) ->
    BaseTxn = base(Txn),
    EncodedTxn = blockchain_txn_transfer_validator_stake_v1_pb:encode_msg(BaseTxn),
    crypto:hash(sha256, EncodedTxn).

-spec old_owner(txn_transfer_validator_stake()) -> libp2p_crypto:pubkey_bin().
old_owner(Txn) ->
    Txn#blockchain_txn_transfer_validator_stake_v1_pb.old_owner.

-spec new_owner(txn_transfer_validator_stake()) -> libp2p_crypto:pubkey_bin().
new_owner(Txn) ->
    Txn#blockchain_txn_transfer_validator_stake_v1_pb.new_owner.

-spec new_validator(txn_transfer_validator_stake()) -> libp2p_crypto:pubkey_bin().
new_validator(Txn) ->
    Txn#blockchain_txn_transfer_validator_stake_v1_pb.new_addr.

-spec old_validator(txn_transfer_validator_stake()) -> libp2p_crypto:pubkey_bin().
old_validator(Txn) ->
    Txn#blockchain_txn_transfer_validator_stake_v1_pb.old_addr.

-spec nonce(txn_transfer_validator_stake()) -> pos_integer().
nonce(Txn) ->
    Txn#blockchain_txn_transfer_validator_stake_v1_pb.nonce.

-spec fee(txn_transfer_validator_stake()) -> non_neg_integer().
fee(Txn) ->
    Txn#blockchain_txn_transfer_validator_stake_v1_pb.fee.

-spec calculate_fee(txn_transfer_validator_stake(), blockchain:blockchain()) ->
          non_neg_integer().
calculate_fee(Txn, Chain) ->
    ?calculate_fee_prep(Txn, Chain).

-spec calculate_fee(txn_transfer_validator_stake(), blockchain_ledger_v1:ledger(),
                    pos_integer(), pos_integer(), boolean()) ->
          non_neg_integer().
calculate_fee(Txn, Ledger, DCPayloadSize, TxnFeeMultiplier, _) ->
    ?calculate_fee(Txn#blockchain_txn_transfer_validator_stake_v1_pb{fee=0,
                                                                     new_validator_signature = <<0:512>>,
                                                                     old_owner_signature = <<0:512>>,
                                                                     new_owner_signature = <<0:512>>},
    Ledger, DCPayloadSize, TxnFeeMultiplier).


-spec new_owner_signature(txn_transfer_validator_stake()) -> binary().
new_owner_signature(Txn) ->
    Txn#blockchain_txn_transfer_validator_stake_v1_pb.new_owner_signature.

-spec old_owner_signature(txn_transfer_validator_stake()) -> binary().
old_owner_signature(Txn) ->
    Txn#blockchain_txn_transfer_validator_stake_v1_pb.old_owner_signature.

-spec new_validator_signature(txn_transfer_validator_stake()) -> binary().
new_validator_signature(Txn) ->
    Txn#blockchain_txn_transfer_validator_stake_v1_pb.new_validator_signature.

-spec sign(txn_transfer_validator_stake(), libp2p_crypto:sig_fun()) -> txn_transfer_validator_stake().
sign(Txn, SigFun) ->
    BaseTxn = base(Txn),
    EncodedTxn = blockchain_txn_transfer_validator_stake_v1_pb:encode_msg(BaseTxn),
    Txn#blockchain_txn_transfer_validator_stake_v1_pb{old_owner_signature=SigFun(EncodedTxn)}.

-spec new_validator_sign(txn_transfer_validator_stake(), libp2p_crypto:sig_fun()) -> txn_transfer_validator_stake().
new_validator_sign(Txn, SigFun) ->
    BaseTxn = base(Txn),
    EncodedTxn = blockchain_txn_transfer_validator_stake_v1_pb:encode_msg(BaseTxn),
    Txn#blockchain_txn_transfer_validator_stake_v1_pb{new_validator_signature=SigFun(EncodedTxn)}.

-spec new_owner_sign(txn_transfer_validator_stake(), libp2p_crypto:sig_fun()) -> txn_transfer_validator_stake().
new_owner_sign(Txn, SigFun) ->
    BaseTxn = base(Txn),
    EncodedTxn = blockchain_txn_transfer_validator_stake_v1_pb:encode_msg(BaseTxn),
    Txn#blockchain_txn_transfer_validator_stake_v1_pb{new_owner_signature=SigFun(EncodedTxn)}.

base(Txn) ->
  Txn#blockchain_txn_transfer_validator_stake_v1_pb{old_owner_signature = <<>>,
                                                    new_owner_signature = <<>>,
                                                    new_validator_signature = <<>>}.

-spec is_valid_new_validator(txn_transfer_validator_stake()) -> boolean().
is_valid_new_validator(#blockchain_txn_transfer_validator_stake_v1_pb{
                          new_addr=PubKeyBin,
                          new_validator_signature=Signature}=Txn) ->
    BaseTxn = base(Txn),
    EncodedTxn = blockchain_txn_transfer_validator_stake_v1_pb:encode_msg(BaseTxn),
    PubKey = libp2p_crypto:bin_to_pubkey(PubKeyBin),
    libp2p_crypto:verify(EncodedTxn, Signature, PubKey).

-spec is_valid_new_owner(txn_transfer_validator_stake()) -> boolean().
is_valid_new_owner(#blockchain_txn_transfer_validator_stake_v1_pb{
                      new_owner=PubKeyBin,
                      new_owner_signature=Signature}=Txn) ->
    BaseTxn = base(Txn),
    EncodedTxn = blockchain_txn_transfer_validator_stake_v1_pb:encode_msg(BaseTxn),
    PubKey = libp2p_crypto:bin_to_pubkey(PubKeyBin),
    libp2p_crypto:verify(EncodedTxn, Signature, PubKey).

-spec is_valid_old_owner(txn_transfer_validator_stake()) -> boolean().
is_valid_old_owner(#blockchain_txn_transfer_validator_stake_v1_pb{
                      old_owner=PubKeyBin,
                      old_owner_signature=Signature}=Txn) ->
    BaseTxn = base(Txn),
    EncodedTxn = blockchain_txn_transfer_validator_stake_v1_pb:encode_msg(BaseTxn),
    PubKey = libp2p_crypto:bin_to_pubkey(PubKeyBin),
    libp2p_crypto:verify(EncodedTxn, Signature, PubKey).

-spec is_valid(txn_transfer_validator_stake(), blockchain:blockchain()) ->
          ok | {error, atom()} | {error, {atom(), any()}}.
is_valid(Txn, Chain) ->
    Ledger = blockchain:ledger(Chain),
    NewValidator = new_validator(Txn),
    OldValidator = old_validator(Txn),
    Nonce = nonce(Txn),
    Fee = fee(Txn),
    case {is_valid_old_owner(Txn), is_valid_new_validator(Txn)} of
        {false, _} ->
            {error, bad_owner_signature};
        {_, false} ->
            {error, bad_validator_signature};
        {true, true} ->
            try
                case new_owner(Txn) /= <<>> of
                    true ->
                        case is_valid_new_owner(Txn) of
                            true ->
                                ok;
                            false ->
                                throw(bad_new_owner_signature)
                        end;
                    _ ->
                        %% no new owner just means this is an in-account transfer
                        ok
                end,
                %% check fee
                AreFeesEnabled = blockchain_ledger_v1:txn_fees_active(Ledger),
                ExpectedTxnFee = calculate_fee(Txn, Chain),
                case ExpectedTxnFee =< Fee orelse not AreFeesEnabled of
                    false -> throw({wrong_txn_fee, {ExpectedTxnFee, Fee}});
                    true -> ok
                end,
                %% make sure that this validator doesn't already exist
                case blockchain_ledger_v1:get_validator(NewValidator, Ledger) of
                    {ok, _} -> throw(already_exists);
                    {error, not_found} -> ok;
                    {error, Reason} -> throw({validator_fetch_error, Reason})
                end,
                %% make sure that existing validator exists and is staked
                case blockchain_ledger_v1:get_validator(OldValidator, Ledger) of
                    {ok, OV} ->                         
                        %% make sure that the nonce is correct
                        VNonce = blockchain_ledger_validator_v1:nonce(OV),
                        case Nonce == (VNonce + 1) of
                            true -> ok;
                            false -> throw({bad_nonce, exp, VNonce + 1, got, Nonce})
                        end,
                        %% check staked status
                        case blockchain_ledger_validator_v1:status(OV) of
                            staked -> ok;
                            unstaked -> throw(cant_transfer_unstaked_validator)
                        end,
                        %% check stake is not 0
                        case blockchain_ledger_validator_v1:stake(OV) of
                            0 -> throw(cant_transfer_zero_stake);
                            _ -> ok
                        end;
                    {error, not_found} -> throw(old_validator_non_existant);
                    {error, Reason1} -> throw({validator_fetch_error, Reason1})
                end,
                ok
            catch throw:Cause ->
                    {error, Cause}
            end
    end.

-spec absorb(txn_transfer_validator_stake(), blockchain:blockchain()) -> ok | {error, atom()} | {error, {atom(), any()}}.
absorb(Txn, Chain) ->
    Ledger = blockchain:ledger(Chain),
    NewOwner = new_owner(Txn),
    OldOwner = old_owner(Txn),
    NewValidator = new_validator(Txn),
    OldValidator = old_validator(Txn),
    Nonce = nonce(Txn),
    Fee = fee(Txn),
    
    case blockchain_ledger_v1:debit_fee(OldOwner, Fee, Ledger, true) of
        {error, _Reason} = Err -> Err;
        ok ->
            case blockchain_ledger_v1:get_validator(OldValidator, Ledger) of
                {ok, OV} ->                         
                    %% for old set stake to 0 and mark as unstaked
                    OV1 = blockchain_ledger_validator_v1:status(unstaked, OV),
                    OV2 = blockchain_ledger_validator_v1:stake(0, OV1),
                    %% increment nonce 
                    OV3 = blockchain_ledger_validator_v1:nonce(Nonce, OV2),
                    ok = blockchain_ledger_v1:update_validator(OldValidator, OV3, Ledger),
                    %% change address on old record 
                    NV =  blockchain_ledger_validator_v1:address(NewValidator, OV),
                    NV1 = blockchain_ledger_validator_v1:nonce(Nonce, NV),
                    NV2 =
                        case NewOwner == <<>> of
                            true -> NV1;
                            false -> blockchain_ledger_validator_v1:owner_address(NewOwner, NV1)
                        end,
                    ok = blockchain_ledger_v1:update_validator(NewValidator, NV2, Ledger);
                Err -> Err
            end
    end.

-spec print(txn_transfer_validator_stake()) -> iodata().
print(undefined) -> <<"type=transfer_validator_stake, undefined">>;
print(#blockchain_txn_transfer_validator_stake_v1_pb{
         new_owner = NO,
         old_owner = OO,
         new_addr = NewVal,
         old_addr = OldVal,
         nonce = N}) ->
    io_lib:format("type=transfer_validator_stake, old_owner=~p, new_owner(optional)=~p "
                  "new_validator=~p, old_validator=~p, nonce=~p",
                  [?TO_B58(OO), ?TO_B58(NO), ?TO_ANIMAL_NAME(NewVal), ?TO_ANIMAL_NAME(OldVal), N]).


-spec to_json(txn_transfer_validator_stake(), blockchain_json:opts()) -> blockchain_json:json_object().
to_json(Txn, _Opts) ->
    #{
      type => <<"transfer_validator_stake_v1">>,
      hash => ?BIN_TO_B64(hash(Txn)),
      new_addr => ?BIN_TO_B58(new_validator(Txn)),
      old_addr => ?BIN_TO_B58(old_validator(Txn)),
      new_owner => ?BIN_TO_B58(new_owner(Txn)),
      old_owner => ?BIN_TO_B58(old_owner(Txn)),
      new_validator_signature => ?BIN_TO_B64(new_validator_signature(Txn)),
      old_owner_signature => ?BIN_TO_B64(old_owner_signature(Txn)),
      new_owner_signature => ?BIN_TO_B64(new_owner_signature(Txn)),
      fee => fee(Txn),
      nonce => nonce(Txn)
     }.

%% ------------------------------------------------------------------
%% EUNIT Tests
%% ------------------------------------------------------------------
-ifdef(TEST).

to_json_test() ->
    Tx = new(<<"old_validator_address">>, <<"new_validator_address">>,
             <<"owner_address">>, 10, 10),
    Json = to_json(Tx, []),
    ?assertEqual(lists:sort(maps:keys(Json)),
                 lists:sort([type, hash] ++ record_info(fields, blockchain_txn_transfer_validator_stake_v1_pb))).


-endif.
