#!/usr/bin/perl

use strict;
use warnings;
use File::Spec;

unless ($ENV{TRAVIS}) {
    die "This script is only intended to be run from Travis CI platform\n";
}

my $workdir = "footomizeme";
my $libssh2_ver = shift || "1.7.0";
my $tgz_dir = "libssh2-$libssh2_ver";
my $tgz_name = "$tgz_dir.tar.gz";
my $tgz_url = "https://www.libssh2.org/download/libssh2-$libssh2_ver.tar.gz";
my $cflags = "-g -O0";
my $prefix = "libssh2";

$prefix = File::Spec->rel2abs($prefix);

system "rm -Rf $prefix" and die "execution of 'rm -Rf $prefix' failed, RC: $?";
system "rm -Rf $workdir";
mkdir $workdir or die $!;
chdir $workdir or die $!;

for (1..5) {
    system "wget --retry-connrefused --tries=8 --no-check-certificate $tgz_url" or last;
}
system "tar xf $tgz_name" and die;
chdir $tgz_dir or die $!;
system "CFLAGS='$cflags' ./configure --prefix=$prefix --enable-shared=yes --enable-static=no --disable-examples-build && make && make install" and die $?;
