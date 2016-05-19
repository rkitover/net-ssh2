#!/usr/bin/perl

use strict;
use warnings;
use feature 'say';

use Sort::Key::Top qw(ntop);

my $host = shift @ARGV // die "host missing";
my $local_iface = 'lxcbr0';
my $remote_iface = 'eth0';
my $rate_unit = 'Mbit';

my $size = 16 * 1024 * 1024;
my $dd_bs = 16 * 1024;
my $dd_count = int($size / $dd_bs);
my $cmd = "dd bs=$dd_bs count=$dd_count if=/dev/zero 2>/dev/null";

my $read_size = 4 * 64 * 1024;
my $n = 8;

my $delay_min = 10;
my $delay_max = 100;
my $delay_steps = 5;

my $delay_f = ($delay_max / $delay_min) ** (1 / ($delay_steps - 1));
my @delays = (0, map int(0.5 + $delay_min * $delay_f ** $_), 0 .. $delay_steps - 1);

my @rates = (10, 20, 100, 200, 1000);

use Time::HiRes qw(time);
use Net::SSH2;
use Net::OpenSSH;

my $ssh2 = Net::SSH2->new(compress => 0);
#$ssh2->trace(-1);
$ssh2->connect($host)
    or $ssh2->die_with_error;

my $key_path = scalar(<~/.ssh/id_rsa>);
$ssh2->auth(username => undef,
            publickey => "$key_path.pub", privatekey => $key_path)
    or $ssh2->die_with_error;

$ssh2->auth_ok or die "auth failed";

my $openssh = Net::OpenSSH->new($host, key_path => $key_path);
$openssh->die_on_error;


my %save;
$| = 1;

sub mean1 {
    my $n = int (0.5 + 0.66 * @_);
    my @n = ntop -$n, @_;
    my $acu = 0;
    $acu += $_ for @n;
    return $acu / @n;
}

sub test {
    my ($ssh, $rate, $delay, $ix) = @_;

    my ($name, $sub) = ($ssh->isa('Net::SSH2')
                        ? (libssh2 => \&test_net_ssh2)
                        : (openssh => \&test_net_openssh));

    my ($dt, $total) = $sub->($ssh);
    my $speed = $total / $dt / 1024 / 1024; # MB/s
    printf("%s => ix: %s, delay: %dms, rate: %d%s time: %.2fs, speed: %.2fMB/s\n",
           $name, $ix, $delay, $rate, $rate_unit, $dt, $speed);
    push @{$save{$rate}{$name}{$delay} //= []}, $speed;
}

sub test_net_ssh2 {
    my $ssh2 = shift;
    my $c = $ssh2->channel
        or $ssh2->die_with_error;
    $c->ext_data('ignore');
    my $time0 = time;
    $c->exec($cmd)
        or $ssh2->die_with_error;
    $c->send_eof;
    my $total = 0;
    my $buf;
    while (my $bytes = $c->read($buf, $read_size)) {
        $total += $bytes;
    }
    $c->wait_closed
        or $ssh2->die_with_error;

    return (time - $time0, $total);
}

sub test_net_openssh {
    my $ssh = shift;
    my $time0 = time;
    my $fh = $ssh->pipe_out($cmd) or $ssh->die_on_error;
    my $total = 0;
    my $buf;
    while (my $bytes = sysread($fh, $buf, $read_size)) {
        $total += $bytes;
    }
    close $fh or die "close failed";

    return (time - $time0, $total);
}

sub rsys {
    my ($ssh2, $cmd) = @_;
    my $c = $ssh2->channel or $ssh2->die_with_error;
    $c->exec($cmd);
    $c->send_eof();
    while (my @o = $c->read2) {
        print for @o;
    }
    close $c or warn "rsys >>$cmd<< failed $?";
}

sleep 1;
for my $ssh ($openssh, $ssh2) {
    for my $rate (@rates) {
        for my $delay (@delays) {
            system "tc qdisc del dev $local_iface root netem 2>/dev/null; true";
            rsys($ssh2, "tc qdisc del dev $remote_iface root netem 2>/dev/null; true");
            rsys($ssh2, "tc qdisc add dev $remote_iface root netem delay ${delay}ms rate $rate$rate_unit");
            system "tc qdisc add dev $local_iface root netem delay ${delay}ms rate $rate$rate_unit";
            test($ssh, $rate, $delay, $_) for 1..$n;
            system "tc qdisc del dev $local_iface root netem 2>/dev/null";
            rsys($ssh2, "tc qdisc del dev $remote_iface root netem 2>/dev/null; true");
            say "";
        }
    }
}

sub csv { say join ', ', @_ }

END {
    csv Delays => @delays;
    if (%save) {
        for my $rate (sort { $a <=> $b } keys %save) {
            csv Rate => "$rate$rate_unit";
            my $h1 = $save{$rate};
            for my $name (sort keys %$h1) {
                my $h2 = $h1->{$name};
                my @means = map mean1( @{$h2->{$_}} ), @delays;
                csv "$name  $rate$rate_unit" => @means;
            }
            say "";
        }
    }
}
