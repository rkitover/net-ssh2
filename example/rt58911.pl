#!/usr/bin/perl -W

use strict;
use Fcntl;
use warnings FATAL => qw (all);
use Getopt::Std;
use Net::SSH2;
use 5.010;

my %opts = (h => 'localhost');
getopts('h:u:p:', \%opts);
my ($hostname, $user, $password) = @opts{qw(h u p)};
my $fn = shift // die "filename argument missing";

my $ssh2 = Net::SSH2->new();
sub ssh2_die { die join(': ', @_, join('|', $ssh2->error)) }
$ssh2->debug(1);

$ssh2->connect($hostname)
    or ssh2_die("connect failed");;

$ssh2->auth(username => $user, password => $password)
    or ssh2_die('auth failed');

my $sftp = $ssh2->sftp()
    or ssh2_die("sftp failed");

my $remote = $sftp->open($fn, O_WRONLY | O_CREAT | O_TRUNC);

my $str = 'A' x 327480;
my $bytes = print $remote $str;
say "print returned $bytes, expected " . length($str);

