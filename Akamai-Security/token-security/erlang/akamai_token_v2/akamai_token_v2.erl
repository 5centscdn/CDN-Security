% Copyright (c) 2012, Akamai Technologies, Inc.
% All rights reserved.
% 
% Redistribution and use in source and binary forms, with or without
% modification, are permitted provided that the following conditions are met:
%     * Redistributions of source code must retain the above copyright
%       notice, this list of conditions and the following disclaimer.
%     * Redistributions in binary form must reproduce the above copyright
%       notice, this list of conditions and the following disclaimer in the
%       documentation and/or other materials provided with the distribution.
%     * Neither the name of Akamai Technologies nor the
%       names of its contributors may be used to endorse or promote products
%       derived from this software without specific prior written permission.
% 
% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
% ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
% WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
% DISCLAIMED. IN NO EVENT SHALL AKAMAI TECHNOLOGIES BE LIABLE FOR ANY
% DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
% (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
% ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
% SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%
-module(akamai_token_v2).
-export([akamai_token_v2/1]).

% akamai_token_v2 expects a list of parameters to generate a token.
% TokenConfig -- list of tagged tuples and atoms
%
% ie.
% TokenConfig = [
%   {key,"aaabbb"},
%   {acl,"/*"},
%   {start_time,"now"},
%   {window_seconds,"86400"},
%   verbose,
%   {token_name,"hdnts"},
%   {algo,"sha256"},
%   {field_delimiter,"~"},
%   {acl_delimiter,"!"}]
%
% Parameters
% token_type -- Select a preset: (Not Supported Yet) [2.0, 2.0.2 ,PV, Debug] (Not implemented yet)
% token_name -- Paramter name for the new token. [Default:hdnts]
% ip_address -- IP Address to restrict this token to.
% start_time -- What is the start time. (Use now for the current time)
% end_time -- When does this token expire? --end_time overrides --window [Used for:URL or COOKIE]
% window_seconds -- How long is this token valid for?
% url -- URL path. [Used for:URL]
% acl -- Access control list delimited by ! [ie. /*]
% key -- Secret required to generate the token.
% payload -- Additional text added to the calculated digest.
% algo -- Algorithm to use to generate the token. (sha1, sha256, or md5) [Default:sha256]
% salt -- Additional data validated by the token but NOT included in the token body.
% session_id -- The session identifier for single use tokens or other advanced cases.
% field_delimiter -- Character used to delimit token body fields. [Default:~]
% acl_delimiter -- Character used to delimit acl fields. [Default:!]
% escape_early -- Causes strings to be url encoded before being used. (legacy 2.0 behavior)
% escape_early_upper -- Causes strings to be url encoded before being used. (legacy 2.0 behavior)
% verbose -- Display details about each parameter before generating the token
%
% Running this interactively:
% $erl
% Erlang R15B03 (erts-5.9.3) [source] [64-bit] [smp:8:8] [async-threads:0] [hipe] [kernel-poll:false]
% 
% Eshell V5.9.3  (abort with ^G)
% 1> akamai_token_v2:akamai_token_v2([{key,"aaabbb"}, {acl,"/*"}, {window_seconds, 86400}]).
% "hdnts=exp=1356003857~acl=/*~hmac=fcec836c5ff9d098ae8079aaa1e8cf4828d4fa74f56c49318fe89eac2d48461d"

akamai_token_v2([]) ->
    {error, required_fields_missing};
akamai_token_v2(TokenConfig) ->
    case lists:member(version, TokenConfig) of
        true -> "2.0.7";
        _ -> validate_token_config(TokenConfig),
             generate_token(TokenConfig)
    end.

% Pre-check the validity of all provided parameters.
validate_token_config(TokenConfig) ->
    case lists:keysearch(key, 1, TokenConfig) of
        false -> erlang:error("You must provide a key");
        {value, _} -> true
    end,
    case [lists:keymember(url, 1, TokenConfig),
          lists:keymember(acl, 1, TokenConfig)] of
        [false, false] -> erlang:error("You must provide either an acl or url");
        [true, true] ->erlang:error("You must provide either an acl or url, not both");
        [_, _] -> true
    end,
    Algo = get_key_value(TokenConfig, algo),
    case Algo of
        "sha1" -> true;
        "sha256" -> true;
        "md5" -> true;
        _Algo -> erlang:error("Algo must be one of sha1, sha256, or md5")
    end,
    StartTime = get_key_value(TokenConfig, start_time),
    case StartTime of
        "" -> true;
        "now" -> true;
        _OtherStart ->
            case is_integer(StartTime) of
                true -> true;
                false ->
                    case string:to_integer(StartTime) of
                        {error,_} -> erlang:error("start_time must be now or an integer");
                        {_,[]} -> true
                    end
            end
    end,
    EndTime = get_key_value(TokenConfig, end_time),
    case EndTime of
        "" -> true;
        "now" -> true;
        _OtherEnd ->
            case is_integer(EndTime) of
                true -> true;
                false ->
                    case string:to_integer(EndTime) of
                        {error,_} -> erlang:error("end_time must be now or an integer");
                        {_,[]} -> true
                    end
            end
    end,
    Window = get_key_value(TokenConfig, window_seconds),
    case Window of
        "" -> true;
        _OtherWindow ->
            case is_integer(Window) of
                true -> true;
                false ->
                    case string:to_integer(Window) of
                        {error,_} -> erlang:error("window_seconds must be an integer");
                        {_,[]} -> true
                    end
            end
    end,
    case get_start_time(TokenConfig) < get_end_time(TokenConfig) of
        false -> erlang:error("Your token has already expired.");
        true -> true
    end.

get_utc_timestamp() ->
    UnixEpoch = 62167219200,
    Universal = calendar:now_to_universal_time(now()),
    Seconds = calendar:datetime_to_gregorian_seconds(Universal),
    (Seconds - UnixEpoch).

get_key_value(TokenConfig, Key) ->
    DefaultValues = [
        {token_name, "hdnts"},
        {algo, "sha256"},
        {field_delimiter, "~"},
        {acl_delimiter, "!"}
    ],
    case lists:keyfind(Key, 1, TokenConfig) of
        false ->
            case lists:keyfind(Key, 1, DefaultValues) of
                false -> Value = "";
                {_DefaultKey, Value} -> Value
            end;
        {_FoundKey, Value} -> Value
    end,
    Value.

get_start_time(TokenConfig) ->
    StartTimeValue = get_key_value(TokenConfig, start_time),
    case is_integer(StartTimeValue) of
        true -> StartTimeValue;
        false ->
            case StartTimeValue of
                "now" -> get_utc_timestamp();
                "" -> get_utc_timestamp();
                _ -> {IntStartTime, _} = string:to_integer(StartTimeValue),
                     IntStartTime
            end
    end.

get_window(TokenConfig) ->
    WindowValue = get_key_value(TokenConfig, window_seconds),
    case is_integer(WindowValue) of
        true -> WindowValue;
        false ->
            case WindowValue of
                "" -> 0;
                _ -> {IntWindow, _} = string:to_integer(WindowValue),
                     IntWindow
            end
    end.

get_end_time(TokenConfig) ->
    EndTimeValue = get_key_value(TokenConfig, end_time),
    case is_integer(EndTimeValue) of
        true -> EndTimeValue;
        false ->
            case EndTimeValue of
                "now" -> get_utc_timestamp();
                "" ->
                    case lists:keymember(window_seconds, 1, TokenConfig) of
                        true ->get_start_time(TokenConfig) + get_window(TokenConfig);
                        false -> erlang:error("You must provide an expiration time or a duration window")
                    end;
                _ -> {IntEndTime, _} = string:to_integer(EndTimeValue),
                     IntEndTime
            end
    end.

get_escape_early(TokenConfig) ->
    case lists:member(escape_early, TokenConfig) of
        false -> case lists:member(escape_early_upper, TokenConfig) of
                     false -> EscapeEarly = false;
                     true -> EscapeEarly = true
                 end;
        true -> EscapeEarly = true
    end,
    EscapeEarly.

escape_early(TokenConfig, Value) ->
    case get_escape_early(TokenConfig) of
        true -> EscapedValue = edoc_lib:escape_uri(Value),
                case lists:member(escape_early_upper, TokenConfig) of
                    true -> escape_early_upper(EscapedValue);
                    false -> EscapedValue
                end;
        false -> Value
    end.

escape_early_upper(Value) ->
    case re:run(Value, "(%..)", [global, {capture, [1], list}]) of
        nomatch -> Value;
        {match, Matches} -> escape_early_upper(Value, Matches)
    end.

% Loop over a list of %ff hexadecimal matches in Value and convert them to upper case.
escape_early_upper(Value, []) -> Value;
escape_early_upper(Value, [H|T]) ->
    H2 = lists:last(H),
    escape_early_upper(re:replace(Value, H2, string:to_upper(H2), [global, {return, list}]), T).

show_verbose(TokenConfig) ->
    io:format(
"Akamai Token Generation Parameters~n"
"Token Type      : ~p~n"
"Token Name      : ~p~n"
"Start Time      : ~p~n"
"Window(seconds) : ~p~n"
"End Time        : ~p~n"
"IP              : ~p~n"
"URL             : ~p~n"
"ACL             : ~p~n"
"Key/Secret      : ~p~n"
"Payload         : ~p~n"
"Algo            : ~p~n"
"Salt            : ~p~n"
"Session ID      : ~p~n"
"Field Delimiter : ~p~n"
"ACL Delimiter   : ~p~n"
"Escape Early    : ~p~n"
"Generating token...~n", [
    get_key_value(TokenConfig, token_type),
    get_key_value(TokenConfig, token_name),
    get_key_value(TokenConfig, start_time),
    get_key_value(TokenConfig, window_seconds),
    get_key_value(TokenConfig, end_time),
    get_key_value(TokenConfig, ip_address),
    get_key_value(TokenConfig, url),
    get_key_value(TokenConfig, acl),
    get_key_value(TokenConfig, key),
    get_key_value(TokenConfig, payload),
    get_key_value(TokenConfig, algo),
    get_key_value(TokenConfig, salt),
    get_key_value(TokenConfig, session_id),
    get_key_value(TokenConfig, field_delimiter),
    get_key_value(TokenConfig, acl_delimiter),
    get_escape_early(TokenConfig)]).

get_token_ip_address(TokenConfig) ->
    case lists:keymember(ip_address, 1, TokenConfig) of
        true -> lists:flatten(io_lib:format("ip=~s~s", [
                    escape_early(TokenConfig, get_key_value(TokenConfig, ip_address)),
                    get_key_value(TokenConfig, field_delimiter)]));
        false -> ""
    end.

get_token_start_time(TokenConfig) ->
    case lists:keymember(start_time, 1, TokenConfig) of
        true -> lists:flatten(io_lib:format("st=~w~s", [
                    get_start_time(TokenConfig),
                    get_key_value(TokenConfig, field_delimiter)]));
        false -> ""
    end.

get_token_end_time(TokenConfig) ->
    lists:flatten(io_lib:format("exp=~w~s", [
        get_end_time(TokenConfig),
        get_key_value(TokenConfig, field_delimiter)])).

get_token_acl(TokenConfig) ->
    case lists:keymember(acl, 1, TokenConfig) of
        true -> lists:flatten(io_lib:format("acl=~s~s", [
                    escape_early(TokenConfig, get_key_value(TokenConfig, acl)),
                    get_key_value(TokenConfig, field_delimiter)]));
        false -> ""
    end.

get_token_session_id(TokenConfig) ->
    case lists:keymember(session_id, 1, TokenConfig) of
        true -> lists:flatten(io_lib:format("id=~s~s", [
                    escape_early(TokenConfig, get_key_value(TokenConfig, session_id)),
                    get_key_value(TokenConfig, field_delimiter)]));
        false -> ""
    end.

get_token_payload(TokenConfig) ->
    case lists:keymember(payload, 1, TokenConfig) of
        true -> lists:flatten(io_lib:format("data=~s~s", [
                    escape_early(TokenConfig, get_key_value(TokenConfig, payload)),
                    get_key_value(TokenConfig, field_delimiter)]));
        false -> ""
    end.

get_token_url(TokenConfig) ->
    case lists:keymember(url, 1, TokenConfig) of
        true -> lists:flatten(io_lib:format("url=~s~s", [
                    escape_early(TokenConfig, get_key_value(TokenConfig, url)),
                    get_key_value(TokenConfig, field_delimiter)]));
        false -> ""
    end.

get_token_salt(TokenConfig) ->
    case lists:keymember(salt, 1, TokenConfig) of
        true -> lists:flatten(io_lib:format("salt=~s~s", [
                    get_key_value(TokenConfig, salt),
                    get_key_value(TokenConfig, field_delimiter)]));
        false -> ""
    end.

get_hmac(TokenConfig, HashSource) ->
    Hmac = hmac:hexlify(get_hmac_text(TokenConfig, HashSource)),
    case lists:member(escape_early_upper, TokenConfig) of
        true -> string:to_upper(Hmac);
        false -> string:to_lower(Hmac)
    end.

get_hmac_text(TokenConfig, HashSource) ->
    case get_key_value(TokenConfig, algo) of
        "md5" -> crypto:md5_mac(
            hmac:hexlify(list_to_binary(get_key_value(TokenConfig, key))),
            HashSource);
        "sha1" -> crypto:sha_mac(
            hmac:hexlify(list_to_binary(get_key_value(TokenConfig, key))),
            HashSource);
        "sha256" -> hmac:hmac256(
            hex:hex_to_bin(get_key_value(TokenConfig, key)),
            HashSource)
    end.

generate_token(TokenConfig) ->
    case lists:member(verbose, TokenConfig) of
        true -> show_verbose(TokenConfig);
        false -> not_verbose
    end,
    NewTokenPieces = string:join([
        get_token_ip_address(TokenConfig),
        get_token_start_time(TokenConfig),
        get_token_end_time(TokenConfig),
        get_token_acl(TokenConfig),
        get_token_session_id(TokenConfig),
        get_token_payload(TokenConfig)
    ], ""),
    HashSource = string:join([
        NewTokenPieces,
        get_token_url(TokenConfig),
        get_token_salt(TokenConfig)
    ], ""),
  get_key_value(TokenConfig, token_name) ++ "=" ++ NewTokenPieces ++ "hmac=" ++
     get_hmac(TokenConfig, string:strip(HashSource, right,
         lists:nth(1, get_key_value(TokenConfig, field_delimiter)))).

