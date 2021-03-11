#!/usr/bin/env escript

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

main([]) ->
    getopt:usage(option_spec_list(), escript:script_name());
main(Args) ->
    OptSpecList = option_spec_list(),
    case getopt:parse(OptSpecList, Args) of
        {ok, {Options, _NonOptions}} ->
            io:format("~s~n", [akamai_token_v2:akamai_token_v2(Options)]);
        {error, {Reason, Error}} ->
            io:format("Error: ~s ~p~n~n", [Reason, Error]),
            getopt:usage(OptSpecList, "akamai_token_v2_cmd_line.escript")
    end.

option_spec_list() ->
    [
    %% {Name, ShortOpt, LongOpt, ArgSpec, HelpMsg}
    {version, undefined, "version", undefined, "show program's version number and exit"},
    {help, $h, "help", undefined, "show this help message and exit"},
    {token_type, $t, "token_type", {string, "2.0.2"}, "Select a preset: (Not Supported Yet) [2.0, 2.0.2 ,PV, Debug]"},
    {token_name, $n, "token_name", {string, "hdnts"}, "Paramter name for the new token. [Default:hdnts]"},
    {ip_address, $i, "ip", string, "IP Address to restrict this token to."},
    {start_time, $s, "start_time", string, "What is the start time. (Use now for the current time)"},
    {end_time, $e, "end_time", string, "When does this token expire? --end_time overrides --window [Used for:URL or COOKIE]"},
    {window_seconds, $w, "window_seconds", string, "How long is this token valid for?"},
    {url, $u, "url", string, "URL path. [Used for:URL]"},
    {acl, $a, "acl", string, "Access control list delimited by ! [ie. /*]"},
    {key, $k, "key", string, "Secret required to generate the token."},
    {payload, $p, "payload", string, "Additional text added to the calculated digest."},
    {algo, $A, "algo", {string, "sha256"}, "Algorithm to use to generate the token. (sha1, sha256, or md5) [Default:sha256]"},
    {salt, $S, "salt", string, "Additional data validated by the token but NOT included in the token body."},
    {session_id, $I, "session_id", string, "The session identifier for single use tokens or other advanced cases."},
    {field_delimiter, $d, "field_delimiter", {string, "~"}, "Character used to delimit token body fields. [Default:~]"},
    {acl_delimiter, $D, "acl_delimiter", {string, "!"}, "Character used to delimit acl fields. [Default:!]"},
    {escape_early, $x, "escape_early", undefined, "Causes strings to be url encoded before being used. (legacy 2.0 behavior)"},
    {escape_early_upper, $X, "escape_early_upper", undefined, "Causes strings to be url encoded before being used. (legacy 2.0 behavior)"},
    {verbose, $v, "verbose", undefined, "Display details about each parameter before generating the token"}
    ].

