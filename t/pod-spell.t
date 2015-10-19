#!/usr/bin/perl

use strict;
use warnings;
use Test::More;

eval "use Test::Spelling";
plan skip_all => "Test::Spelling required for testing POD spelling" if $@;

my @ignore = (qw(libssh SFTP sftp cbc hmac sha aes publickey diffie
                 hellman keepalive ARCFOUR Blowfish DES EAGAIN FIPS
                 Salvador API CPAN GitHub KEX LibSSH OpenSSL Golemon
                 HOSTKEY Stenberg Josefsson RIPEMD SIGPIPE SIGPIPEs
                 SecureFTP arcfour auth bitmask blowfish cp crypto des
                 dh dir dss fx fxf hostkey iff lowercased knownhosts
                 pty readfile realpath revents rsa shost tcpip
                 writefile writeline redistributions TCP hup md
                 privatekey ripemd secsh setstat zlib Kitover
                 pipelining perlish PEM),
                 "Fandi\xf1o");

local $ENV{LC_ALL} = 'C';
add_stopwords(@ignore);
all_pod_files_spelling_ok();

