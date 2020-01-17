%%%-------------------------------------------------------------------
%% @doc
%% == Blockchain Transaction reward ==
%%%-------------------------------------------------------------------
-module(blockchain_txn_reward_v1).

-include("../../pb/blockchain_txn_rewards_v1_pb.hrl").

-export([
    new/4,
    hash/1,
    account/1,
    gateway/1,
    amount/1,
    type/1,
    is_valid/1,
    print/1
]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-type reward() :: #blockchain_txn_reward_v1_pb{}.
-type rewards() :: [reward()].
-type type() :: securities | data_credits | poc_challengees | poc_challengers | poc_witnesses | consensus.

-export_type([reward/0, rewards/0, type/0]).

-define(TYPES, [securities, data_credits, poc_challengees, poc_challengers, poc_witnesses, consensus]).
-define(TO_B58(X), libp2p_crypto:bin_to_b58(X)).
-define(TO_ANIMAL_NAME(X), element(2, erl_angry_purple_tiger:animal_name(libp2p_crypto:bin_to_b58(X)))).

%%--------------------------------------------------------------------
%% @doc
%% Gateway might be `undefined` when it is a security reward
%% @end
%%--------------------------------------------------------------------
-spec new(Account :: libp2p_crypto:pubkey_bin(),
          Gateway :: libp2p_crypto:pubkey_bin() | undefined,
          Amount :: non_neg_integer(),
          Type :: type()) -> reward().
new(Account, Gateway, Amount, Type) ->
    #blockchain_txn_reward_v1_pb{
        account=Account,
        gateway=Gateway,
        amount=Amount,
        type=Type
    }.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec hash(reward()) -> blockchain_txn:hash().
hash(Reward) ->
    EncodedReward = blockchain_txn_rewards_v1_pb:encode_msg(Reward),
    crypto:hash(sha256, EncodedReward).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec account(Reward :: reward()) -> libp2p_crypto:pubkey_bin().
account(Reward) ->
    Reward#blockchain_txn_reward_v1_pb.account.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec gateway(Reward :: reward()) -> libp2p_crypto:pubkey_bin().
gateway(Reward) ->
    Reward#blockchain_txn_reward_v1_pb.gateway.


%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec amount(Reward :: reward()) -> non_neg_integer().
amount(Reward) ->
    Reward#blockchain_txn_reward_v1_pb.amount.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec type(Reward :: reward()) -> type().
type(Reward) ->
    Reward#blockchain_txn_reward_v1_pb.type.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec is_valid(Reward :: reward()) -> boolean().
is_valid(#blockchain_txn_reward_v1_pb{account=Account, gateway=Gateway,
                                      amount=Amount, type=Type}) ->
    erlang:is_binary(Account) andalso
    (erlang:is_binary(Gateway) orelse Gateway == undefined) andalso
    Amount > 0 andalso
    lists:member(Type, ?TYPES).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec print(reward()) -> iodata().
print(undefined) -> <<"type=reward undefined">>;
print(#blockchain_txn_reward_v1_pb{account=Account, gateway=Gateway,
                                   amount=Amount, type=Type}) ->
    io_lib:format("type=reward account=~p, gateway=~p, amount=~p, type=~p",
                  [?TO_B58(Account), ?TO_ANIMAL_NAME(Gateway), Amount, Type]).



%% ------------------------------------------------------------------
%% EUNIT Tests
%% ------------------------------------------------------------------
-ifdef(TEST).

new_test() ->
    Reward = #blockchain_txn_reward_v1_pb{
        account= <<"account">>,
        gateway= <<"gateway">>,
        amount= 12,
        type= poc_challengees
    },
    ?assertEqual(Reward, new(<<"account">>, <<"gateway">>, 12, poc_challengees)).

account_test() ->
    Reward = new(<<"account">>, <<"gateway">>, 12, poc_challengees),
    ?assertEqual(<<"account">>, account(Reward)).

gateway_test() ->
    Reward = new(<<"account">>, <<"gateway">>, 12, poc_challengees),
    ?assertEqual(<<"gateway">>, gateway(Reward)).

amount_test() ->
    Reward = new(<<"account">>, <<"gateway">>, 12, poc_challengees),
    ?assertEqual(12, amount(Reward)).

type_test() ->
    Reward = new(<<"account">>, <<"gateway">>, 12, poc_challengees),
    ?assertEqual(poc_challengees, type(Reward)).

-endif.
