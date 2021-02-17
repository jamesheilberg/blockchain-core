%%%-------------------------------------------------------------------
%% @doc
%% == Blockchain Ledger validator ==
%% @end
%%%-------------------------------------------------------------------
-module(blockchain_ledger_validator_v1).

-export([
         new/3,
         address/1, address/2,
         owner_address/1, owner_address/2,
         stake/1, stake/2,
         last_heartbeat/1, last_heartbeat/2,
         status/1, status/2,
         nonce/1, nonce/2,
         version/1, version/2,
         serialize/1, deserialize/1
        ]).

-import(blockchain_utils, [normalize_float/1]).

-include("blockchain.hrl").
-include("blockchain_vars.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-record(validator_v1,
        {
         address :: libp2p_crypto:pubkey_bin(),
         owner_address :: libp2p_crypto:pubkey_bin(),
         stake = 0 :: non_neg_integer(),
         heartbeat = 1 :: pos_integer(),
         nonce = 1 :: pos_integer(),
         version = 1 :: pos_integer(),
         status = staked :: staked | unstaked
        }).

-type validator() :: #validator_v1{}.

-export_type([validator/0]).

-spec new(Address :: libp2p_crypto:pubkey_bin(),
          OwnerAddress :: libp2p_crypto:pubkey_bin(),
          Stake :: non_neg_integer()) ->
          validator().
new(Address, OwnerAddress, Stake) ->
    #validator_v1{
       address = Address,
       owner_address = OwnerAddress,
       stake = Stake
      }.

-spec address(Validator :: validator()) -> libp2p_crypto:pubkey_bin().
address(Validator) ->
    Validator#validator_v1.address.

-spec address(Address :: libp2p_crypto:pubkey_bin(),
              Validator :: validator()) -> validator().
address(Address, Validator) ->
    Validator#validator_v1{address = Address}.

-spec owner_address(Validator :: validator()) -> libp2p_crypto:pubkey_bin().
owner_address(Validator) ->
    Validator#validator_v1.owner_address.

-spec owner_address(OwnerAddress :: libp2p_crypto:pubkey_bin(),
                    Validator :: validator()) -> validator().
owner_address(OwnerAddress, Validator) ->
    Validator#validator_v1{owner_address = OwnerAddress}.

-spec stake(Validator :: validator()) -> non_neg_integer().
stake(Validator) ->
    Validator#validator_v1.stake.

-spec stake(Stake :: non_neg_integer(),
            Validator :: validator()) -> validator().
stake(Stake, Validator) ->
    Validator#validator_v1{stake = Stake}.

-spec version(Validator :: validator()) -> pos_integer().
version(Validator) ->
    Validator#validator_v1.version.

-spec version(Version :: pos_integer(),
            Validator :: validator()) -> validator().
version(Version, Validator) ->
    Validator#validator_v1{version = Version}.

-spec last_heartbeat(Validator :: validator()) -> non_neg_integer().
last_heartbeat(Validator) ->
    Validator#validator_v1.heartbeat.

-spec last_heartbeat(Heartbeat :: non_neg_integer(),
            Validator :: validator()) -> validator().
last_heartbeat(Heartbeat, Validator) ->
    Validator#validator_v1{heartbeat = Heartbeat}.

-spec nonce(Validator :: validator()) -> non_neg_integer().
nonce(Validator) ->
    Validator#validator_v1.nonce.

-spec nonce(Nonce :: non_neg_integer(),
            Validator :: validator()) -> validator().
nonce(Nonce, Validator) ->
    Validator#validator_v1{nonce = Nonce}.

-spec status(Validator :: validator()) -> staked | unstaked.
status(Validator) ->
    Validator#validator_v1.status.

-spec status(Status :: staked | unstaked,
            Validator :: validator()) -> validator().
status(Status, Validator) ->
    Validator#validator_v1{status = Status}.

-spec serialize(Validator :: validator()) -> binary().
serialize(Validator) ->
    BinVal = erlang:term_to_binary(Validator, [compressed]),
    <<1, BinVal/binary>>.

-spec deserialize(binary()) -> validator().
deserialize(<<1, Bin/binary>>) ->
    erlang:binary_to_term(Bin).
