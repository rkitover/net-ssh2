#!/usr/bin/perl

use strict;
use warnings;

use Net::SSH2;
use Getopt::Long;

my ($host, $port, $user, $pwd);
GetOptions("host|h=s" => \$host,
           "port|p=s" => \$port,
           "user|u=s" => \$user,
           "password|pwd|pw|w=s" => \$pwd)
    or die "Failed to process arguments";

$host // die "hostname missing";
$user //= getpwuid $<;
$port //= '22';

my $ssh2 = Net::SSH2->new();
# $ssh2->debug(1);
$ssh2->connect($host, $port) or $ssh2->die_with_error;
$ssh2->check_remote_hostkey  or $ssh2->die_with_error;

if ($pwd) {
    $ssh2->auth_password($user, $pwd);
}
else {
    $ssh2->auth_password_interact($user);
}

my $channel = $ssh2->channel or $ssh2->die_with_error;
$channel->exec("cat @ARGV") # FIXME: quote the arguments!
    or $ssh2->die_with_error;

$channel->send_eof;

my $buffer;
while (1) {
    $channel->read($buffer, 32*1024) or last;
    print $buffer;
}

my $exit_status = $channel->exit_status;

undef $channel;
$ssh2->disconnect;

exit($exit_status);
