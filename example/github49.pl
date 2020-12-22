#!/usr/bin/perl

use 5.018;
use strict;
use warnings;

use Net::SSH2;
my $command  = 'ls';

@ARGV == 2 or die "Usage:\n  $0 remote key_path";

my ($remote, $key_path) = @ARGV;

my ($user, $host, $port) = $remote =~ /^(?:(.*?)\@)?(.*?)(?::(\d+))?$/;
$port //= 22;

#my $ssh = Net::SSH2->new(debug => -1, trace => -1);
my $ssh = Net::SSH2->new();

$ssh->connect($host, $port)
  or $ssh->die_with_error;

$ssh->auth(username => $user,
	   publickey => "$key_path.pub",
	   #passphrase => "",
	   privatekey => $key_path) or $ssh->die_with_error;

my $ch = $ssh->channel;
$ch->exec($command);

while(<$ch>) {
    print
}
