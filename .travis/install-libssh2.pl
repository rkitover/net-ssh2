#!/usr/bin/perl

use strict;
use warnings;
use File::Spec;

unless ($ENV{TRAVIS}) {
    die "This script is only intended to be run from Travis CI platform\n";
}

my $workdir = "footomizeme";
my $libssh2_ver = "1.6.0";
my $tgz_dir = "libssh2-$libssh2_ver";
my $tgz_name = "$tgz_dir.tar.gz";
my $tgz_url = "https://github.com/libssh2/libssh2/releases/download/$tgz_dir/$tgz_name";
my $cflags = "-g -O0";
my $prefix = "libssh2";

$prefix = File::Spec->rel2abs($prefix);

system "rm -Rf $prefix" and die "execution of 'rm -Rf $prefix' failed, RC: $?";
system "rm -Rf $workdir";
mkdir $workdir or die $!;
chdir $workdir or die $!;

for (1..5) {
    system "wget --retry-connrefused --tries=8 $tgz_url" or last;
}
system "tar xf $tgz_name" and die;
chdir $tgz_dir or die $!;
system "CFLAGS='$cflags' ./configure --prefix=$prefix && make && make install" and die $?;
