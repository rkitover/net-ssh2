# -*- Mode: CPerl -*-

use strict;
use warnings;
use Test::More;
use threads;
use threads::shared qw(share);
use Net::SSH2;

our $debug;

BEGIN {
    $debug //= $ENV{TEST_NET_SSH2_DEBUG_THREADS};

    if ($debug) {
        select STDERR;
        $|=1;
        select STDOUT;
        $|=1;
        require Devel::Peek;
        *debug = sub {
            warn "Dumping from $_[0]:\n";
            Devel::Peek::Dump($_[1]);
        };
    }
    else {
        *debug = sub { 0 };
    }
}

my $lock :shared = 1;
sub child {
    lock $lock;
    $lock++ if $_[0];
    debug thread => $_[0];
    return 0;
}


plan tests => 3;

ok(my $ssh2 = Net::SSH2->new, "constructor");
debug main => $ssh2;

$ssh2->debug(1) if $debug;

my $thr;
do {
    lock $lock;
    $thr = threads->create('child', $ssh2);
    debug "master after child creation", $ssh2;
}; # unlock $lock;
$thr->join;
debug "from master after join", $ssh2;

is($lock, 2, "the thread used the object");

undef $ssh2;
ok(1, "we are still alive");


