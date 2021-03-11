#! /usr/bin/env perl

# Copyright (c) 2012, Akamai Technologies, Inc.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of Akamai Technologies nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL AKAMAI TECHNOLOGIES BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use Digest::HMAC_MD5 qw(hmac_md5_hex);
use Digest::SHA qw(hmac_sha1_hex);
use Digest::SHA qw(hmac_sha256_hex);
use URI::Escape;
use DateTime;

sub displayVersion {
    print "2.0.7\n";
}

sub displayHelp {
    print << "EOF"
Usage:perl akamai_token_v2 [options]
   -t, --token_type TOKEN_TYPE      Select a preset: (Not Supported Yet)
                                        2.0
                                        2.0.2
                                        PV
                                        Debug
   -n, --token_name TOKEN_NAME      Parameter name for the new token. [Default:hdnts]
   -i, --ip IP_ADDRESS              IP Address to restrict this token to.
   -s, --start_time START_TIME      What is the start time. (use now for the current time)
   -e, --end_time END_TIME          When does this token expire? --end_time overrides --window
   -w, --window WINDOW_SECONDS      How long is this token valid for?
   -u, --url URL                    URL path.
   -a, --acl ACCESS_LIST            Access control list delimted by ! [ie. /*]
   -k, --key KEY                    Secret required to generate the token.
   -p, --payload PAYLOAD            Additional text added to the calculated digest.
   -A, --algo ALGORITHM             Algorithm to use to generate the token. (sha1, sha256, or md5) [Default:sha256]
   -S, --salt SALT                  Additional data validated by the token but NOT included in the token body.
   -I, --session_id SESSION_ID      The session identifier for single use tokens or other advanced cases.
   -d, --field_delimiter            Character used to delimit token body fields. [Default:~]
   -D, --acl_delimiter              Character used to delimit acl fields. [Default:!]
   -x, --escape_early               Causes strings to be url encoded before being used. (legacy 2.0 behavior)
   -X, --escape_early_upper         Causes strings to be url encoded before being used. (legacy 2.0 behavior)
   -v, --verbose                    Display more details about the inputs
   -h, --help                       Display this help info
EOF
}

sub displayParameters {
    my ($token_config) = @_;
    my ($escape_early) = ${ $token_config }{escape_early};
    my ($escape_early_upper) = ${ $token_config }{escape_early_upper};
    if ($escape_early =~ m/true/i || $escape_early_upper =~ m/true/i) {
        $escape_early = "true";
    }
    print << "EOF"
Akamai Token Generation Parameters
    Token Type      : ${ $token_config }{token_type}
    Token Name      : ${ $token_config }{token_name}
    Start Time      : ${ $token_config }{start_time}
    Window(seconds) : ${ $token_config }{window_seconds}
    End Time        : ${ $token_config }{end_time}
    IP              : ${ $token_config }{ip_address}
    URL             : ${ $token_config }{url}
    ACL             : ${ $token_config }{acl}
    Key/Secret      : ${ $token_config }{key}
    Payload         : ${ $token_config }{payload}
    Algo            : ${ $token_config }{algo}
    Salt            : ${ $token_config }{salt}
    Session ID      : ${ $token_config }{session_id}
    Field Delimiter : ${ $token_config }{field_delimiter}
    ACL Delimiter   : ${ $token_config }{acl_delimiter}
    Escape Early    : $escape_early
Generating token...
EOF
}

sub escapeEarly {
    my ($token_config, $text) = @_;
    my ($escape_early) = ${ $token_config }{escape_early};
    my ($escape_early_upper) = ${ $token_config }{escape_early_upper};
    if ($escape_early =~ m/true/i || $escape_early_upper =~ m/true/i) {
        $text = uri_escape($text);
        if ($escape_early_upper =~ m/true/i) {
            $text =~ tr/%[0-9a-f][0-9a-f]/%[0-9A-F][0-9A-F]/;
        } else {
            $text =~ tr/%[0-9A-F][0-9A-F]/%[0-9a-f][0-9a-f]/;
        }
    }
    return $text;
}

sub getTokenIP {
    my ($token_config) = @_;
    my ($ip_address) = escapeEarly($token_config, ${ $token_config }{ip_address});
    if (length($ip_address) > 0) {
        return "ip=" . $ip_address . ${ $token_config }{field_delimiter};
    }
    return "";
}

sub getTokenStartTime {
    my ($token_config) = @_;
    my ($start_time) = ${ $token_config }{start_time};
    if (length($start_time) > 0) {
        return "st=" . $start_time . ${ $token_config }{field_delimiter};
    }
    return "";
}

sub getTokenEndTime {
    my ($token_config) = @_;
    return "exp=" . ${ $token_config }{end_time} . ${ $token_config }{field_delimiter};
}

sub getTokenAcl {
    my ($token_config) = @_;
    my ($acl) = escapeEarly($token_config, ${ $token_config }{acl});
    if (length($acl) > 0) {
        return "acl=" . $acl . ${ $token_config }{field_delimiter};
    }
    return "";
}

sub getTokenSessionID {
    my ($token_config) = @_;
    my ($session_id) = escapeEarly($token_config, ${ $token_config }{session_id});
    if (length($session_id) > 0) {
        return "id=" . $session_id . ${ $token_config }{field_delimiter};
    }
    return "";
}

sub getTokenPayload {
    my ($token_config) = @_;
    my ($payload) = escapeEarly($token_config, ${ $token_config }{payload});
    if (length($payload) > 0) {
        return "data=" . $payload . ${ $token_config }{field_delimiter};
    }
    return "";
}

sub getTokenUrl {
    my ($token_config) = @_;
    my ($url) = escapeEarly($token_config, ${ $token_config }{url});
    if (length($url) > 0) {
        return "url=" . $url . ${ $token_config }{field_delimiter};
    }
    return "";
}

sub getTokenSalt {
    my ($token_config) = @_;
    my ($salt) = escapeEarly($token_config, ${ $token_config }{salt});
    if (length($salt) > 0) {
        return "salt=" . $salt . ${ $token_config }{field_delimiter};
    }
    return "";
}

sub generateToken {
    my ($token_config) = @_;
    my ($time,$time2,$sec,$min,$hour,$mday,$mon,$year,$isdst);
    my ($wday, $yday);

    my ($start_time) = ${ $token_config }{start_time};
    if ($start_time =~ m/now/i) {
        $start_time = DateTime->now( time_zone => 'GMT' )->epoch();
        $token_config->{start_time} = $start_time;
    }

    my ($window) = ${ $token_config }{window_seconds};

    my ($end_time) = ${ $token_config }{end_time};
    if ($end_time =~ m/now/i) {
        $token_config->{end_time} = DateTime->now( time_zone => 'GMT' )->epoch();
    } else {
        if (length($end_time) > 0) {
            $token_config->{end_time} = $end_time;
        } else {
            if (length($start_time) > 0) {
                $token_config->{end_time} = $start_time + $window;
            } else {
                $token_config->{end_time} = DateTime->now( time_zone => 'GMT' )->epoch() + $window;
            }
        }
    }

    my ($acl) = ${ $token_config }{acl};
    my ($url) = ${ $token_config }{url};
    if ($acl =~ m/^$/ && $url =~ m/^$/) {
        return (1, "you must provide an acl or url");
    } elsif (length($acl) >= 1 && length($url) >= 1) {
        return (1, "you must provide an acl or url, not both");
    }

    if (length(${ $token_config }{key}) < 1) {
        return (1, "you must provide a key");
    }

    if (${ $token_config }{verbose} =~ m/true/i) {
        displayParameters($token_config);
    }

    my ($new_token) = getTokenIP($token_config) .
                      getTokenStartTime($token_config) .
                      getTokenEndTime($token_config) .
                      getTokenAcl($token_config) .
                      getTokenSessionID($token_config) .
                      getTokenPayload($token_config);

    my ($hash_source) = $new_token . getTokenUrl($token_config) .
                        getTokenSalt($token_config);
    $hash_source = substr $hash_source, 0, length($hash_source) - 1;

    my ($key) = ${ $token_config }{key};
    $key =~ s/(..)/chr(hex($1))/ge;

    my ($hmac) = "";
    my ($algo) = ${ $token_config }{algo};
    if ($algo =~ m/^$/) {
        $token_config->{algo} = "sha256";
    } elsif ($algo =~ m/md5/i) {
        $hmac=hmac_md5_hex($hash_source, $key);
    } elsif ($algo =~ m/sha1/i) {
        $hmac=hmac_sha1_hex($hash_source, $key);
    } elsif ($algo =~ m/sha256/i) {
        $hmac=hmac_sha256_hex($hash_source, $key);
    } else {
        return (1, "unknown algorithm\n");
    }

    return (0, ${ $token_config }{token_name} . "=" . $new_token . "hmac=" . $hmac);
}

my $num_args = $#ARGV + 1;
my %token_config = (
    token_name => "hdnts",
    field_delimiter => "~",
    acl_delimiter => "!",
    algo => "sha256",
    escape_early => "false",
    escape_early_upper => "false");
for (my $i = 0; $i < $num_args ; $i++) {
    my $arg = $ARGV[$i];
    if ($arg =~ m/-h/i || $arg =~ m/--help/i) {
        displayHelp();
        exit 0;
    } elsif ($arg =~ m/--version/i) {
        displayVersion();
        exit 0;
    } elsif ($arg =~ m/-t/ || $arg =~ m/--token_type/) {
        $token_config{token_type} = $ARGV[++$i];
    } elsif ($arg =~ m/-n/ || $arg =~ m/--token_name/) {
        $token_config{token_name} = $ARGV[++$i];
    } elsif ($arg =~ m/-i/ || $arg =~ m/--ip_address/) {
        $token_config{ip_address} = $ARGV[++$i];
    } elsif ($arg =~ m/-s/ || $arg =~ m/--start_time/) {
        $token_config{start_time} = $ARGV[++$i];
    } elsif ($arg =~ m/-e/ || $arg =~ m/--end_time/) {
        $token_config{end_time} = $ARGV[++$i];
    } elsif ($arg =~ m/-w/ || $arg =~ m/--window/) {
        $token_config{window_seconds} = $ARGV[++$i];
    } elsif ($arg =~ m/-u/ || $arg =~ m/--url/) {
        $token_config{url} = $ARGV[++$i];
    } elsif ($arg =~ m/-a/ || $arg =~ m/--acl/) {
        $token_config{acl} = $ARGV[++$i];
    } elsif ($arg =~ m/-k/ || $arg =~ m/--key/) {
        $token_config{key} = $ARGV[++$i];
    } elsif ($arg =~ m/-p/ || $arg =~ m/--payload/) {
        $token_config{payload} = $ARGV[++$i];
    } elsif ($arg =~ m/-A/ || $arg =~ m/--algo/) {
        $token_config{algo} = $ARGV[++$i];
    } elsif ($arg =~ m/-S/ || $arg =~ m/--salt/) {
        $token_config{salt} = $ARGV[++$i];
    } elsif ($arg =~ m/-I/ || $arg =~ m/--session_id/) {
        $token_config{session_id} = $ARGV[++$i];
    } elsif ($arg =~ m/-d/ || $arg =~ m/--field_delimiter/) {
        $token_config{field_delimiter} = $ARGV[++$i];
    } elsif ($arg =~ m/-D/ || $arg =~ m/--acl_delimiter/) {
        $token_config{acl_delimiter} = $ARGV[++$i];
    } elsif ($arg =~ m/-x/ || $arg =~ m/--escape_early/) {
        $token_config{escape_early} = "true";
    } elsif ($arg =~ m/-X/ || $arg =~ m/--escape_early_upper/) {
        $token_config{escape_early_upper} = "true";
    } elsif ($arg =~ m/-v/ || $arg =~ m/--verbose/) {
        $token_config{verbose} = "true";
    }
}
my ($exit_code, $new_token) = generateToken(\%token_config);
print $new_token . "\n";
exit $exit_code;

