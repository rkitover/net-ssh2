#!perl

use strict;
use warnings;

# Sample Net::SSH2 code illustrating several ways to read the remote
# /etc/passwd file.

use Net::SSH2;
use IO::Scalar;

my $ssh2 = Net::SSH2->new;
die "can't connect" unless $ssh2->connect('localhost');
# use an interactive authentication method with default callback
# (if a password is provided here, it will forward it without prompting)
die "can't authenticate"
 unless $ssh2->auth(username => scalar getpwuid($<), interact => 1);

sub _read {
    my $handle = shift;
    while (my $line = <$handle>) {
        chomp $line;
        $line =~ s/:.*$//;
        print "found user '$line'\n";
    }
}

# (a) read using SCP
my $passwd = IO::Scalar->new;
die "can't fetch /etc/passwd" unless 
 $ssh2->scp_get('/etc/passwd', $passwd);
$passwd->seek(0, 0);
_read($passwd);

# (b) read a line at a time with SFTP
my $sftp = $ssh2->sftp;
my $file = $sftp->open('/etc/passwd') or die;
_read($file);

# (c) type it over a channel
my $chan = $ssh2->channel;
$chan->exec('cat /etc/passwd') or die;
_read($chan);

