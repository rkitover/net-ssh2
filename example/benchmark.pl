#!/usr/bin/perl

use strict;
use warnings;
use feature 'say';

my $host = shift @ARGV // die "host missing";
my $local_iface = 'lxcbr0';
my $remote_iface = 'eth0';

#my $size = 512 * 1024 * 1024;
my $size = 16 * 1024 * 1024;
my $dd_bs = 16 * 1024;
my $dd_count = int($size / $dd_bs);
my $cmd = "dd bs=$dd_bs count=$dd_count if=/dev/zero 2>/dev/null";

my $read_size = 4 * 64 * 1024;
my $n = 5;

#$cmd = "cat /home/salva/Downloads/Renta2014_unix_1_25.sh";

#my @delays  = (0, map 2**$_, 4, 6, 7, 8, 9);
#my @windows = (0.25, 0.5, 1, 2, 4);

my @delays = (0, map int 4 * 1.5 ** $_, 0..8);
my @windows = (2, 2, 2, 2, 2);
my %names;

use Time::HiRes qw(time);
use Net::SSH2;

my $ssh2 = Net::SSH2->new(compress => 0);
$ssh2->trace(-1);
$ssh2->connect($host)
    or $ssh2->die_with_error;

my $key_path = scalar(<~/.ssh/id_rsa>);
$ssh2->auth(username => undef,
            publickey => "$key_path.pub", privatekey => $key_path)
    or $ssh2->die_with_error;

my %summary;
$| = 1;

sub test {
    my ($ssh2, $delay, $ix) = @_;
    my $c = $ssh2->channel
        or $ssh2->die_with_error;
    $c->ext_data('ignore');
    $c->exec($cmd)
        or $ssh2->die_with_error;
    $c->send_eof;
    my $total = 0;
    my $buf;
    my $time0 = time;
    while (my $bytes = $c->read($buf, $read_size)) {
        $total += $bytes;
    }
    $c->wait_close
        or $ssh2->die_with_error;
    my $time1 = time;

    my $dt = $time1 - $time0;
    my $speed = $total / $dt / 1024 / 1024; # MB/s
    printf "ix: %s, delay: %dms, time: %.2fs, speed: %.2fMB/s\n", $ix, $delay, $dt, $speed;
    $summary{"$ix,$delay"} = $speed;
}

sub rsys {
    my ($ssh2, $cmd) = shift;
    my $c = $ssh2->channel or $ssh2->die_with_error;
    $c->exec($cmd);
    $c->send_eof();
    close $c or warn "rsys failed $?";
}

for my $delay (@delays) {
    system "tc qdisc del dev $local_iface root netem delay 0ms 2>/dev/null";
    rsys($ssh2, "tc qdisc del dev $remote_iface root netem delay 0ms 2>/dev/null");
    rsys($ssh2, "tc qdisc add dev $remote_iface root netem delay ${delay}ms");
    system "tc qdisc add dev $local_iface root netem delay ${delay}ms";
    test($ssh2, $delay, $_) for 1..$n;
    system "tc qdisc del dev $local_iface root netem delay 0ms 2>/dev/null";
    rsys($ssh2, "tc qdisc del dev $remote_iface root netem delay ${delay}ms");
    say "";
}

END {
    if (%summary) {
        my @ixs = 1..$n;
        say join(', ', 'ix', @ixs);
        for my $delay (@delays) {
            say join(', ', $delay, map $summary{"$_,$delay"}, @ixs);
        }
    }
}
