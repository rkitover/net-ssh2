#!/usr/bin/perl

use strict;
use warnings;

use Net::SSH2;
use Getopt::Std;
use IO::Scalar;
use 5.010;

my %opts = (h => 'localhost');
getopts('h:u:p:', \%opts);
my ($hostname, $user, $password) = @opts{qw(h u p)};

my $fn = shift // die "filename argument missing";

sub ssh2_die {
    my $ssh2 = shift;
    die join(': ', @_, join('|', $ssh2->error));
}


my $ssh2 = Net::SSH2->new();
$ssh2->connect($hostname) or ssh2_die($ssh2, "Unable to connect to host $hostname");
$ssh2->auth(username => $user, password => $password) or ssh2_die($ssh2, "Authentication failed");

my $chan = $ssh2->channel();
my $output = IO::Scalar->new;
$ssh2->scp_get($fn, $output) or ssh2_die($ssh2, "SCP failed");
my $lines = $output =~ tr/\n/\n/;
say "Number of lines in remote file: $lines\n";
$chan->close;
$ssh2->disconnect();
