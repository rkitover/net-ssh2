# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-SSH2.t'
# THIS LINE WILL BE READ BY A TEST BELOW

#########################

use Test::More tests => 73;

use strict;
use File::Basename;
use Fcntl ':mode';

#########################

# to speed up testing, set host, user and pass here
my ($host, $user, $pass) = qw();

# (1) use module
BEGIN { use_ok('Net::SSH2', ':all') };

# (4) basics: create an object, check status
my $ssh2 = Net::SSH2->new();
isa_ok($ssh2, 'Net::SSH2', 'new session');
ok(!$ssh2->error(), 'error state clear');
ok($ssh2->banner('SSH TEST'), 'set banner');
is(LIBSSH2_ERROR_SOCKET_NONE(), -1, 'LIBSSH2_* constants');

# (4) version
my $version = $ssh2->version();
my ($version2, $vernum, $banner) = $ssh2->version();
is($version, $version2, 'list version match');
my ($major) = $version =~ /^(\d+)/;

SKIP: {
    skip 'old libssh2', 1 if !defined($vernum);
    skip 'version not decimal', 1 if ($version =~ y/.//) > 1;

    if ($major > 0) {
      ok(($vernum >> 8) == ($major << 8) + ($version - $major) * 10,
       'decimal version matches');
    } else {
      ok(($vernum >> 8) == ($major << 8) + ($version - $major) * 100,
       'decimal version matches');
    }
}

is($banner, "SSH-2.0-libssh2_$version", "banner is $banner");

# (2) timeout
is($ssh2->poll(0), 0, 'poll indefinite');
is($ssh2->poll(2000), 0, 'poll 2 second');

is($ssh2->sock, undef, '->sock is undef before connect');

# (1) connect
SKIP: { # SKIP-connect
skip '- non-interactive session', 62 unless $host or -t STDOUT;
$| = 1;
unless ($host) {
    print <<TEST;

To test the connection capabilities of Net::SSH2, we need a test site running
a secure shell server daemon.  Enter 'localhost' or '127.0.0.1' to use this
host over IPv4. Enter '::1' to use this host over IPv6.

TEST
    print "Hostname or IP address [ENTER to skip]: ";
    chomp($host = <STDIN>);
    print "\n";
}
SKIP: { # SKIP-server
skip '- no server daemon available', 62 unless $host;
ok($ssh2->connect($host), "connect to $host");

isa_ok($ssh2->sock, 'IO::Socket', '->sock isa IO::Socket');

# (8) server methods
for my $type(qw(kex hostkey crypt_cs crypt_sc mac_cs mac_sc comp_cs comp_sc)) {
    my $method = $ssh2->method($type);
    ok($ssh2->method($type), "$type method: $method");
}

# (2) hostkey hash
my $md5 = $ssh2->hostkey_hash('md5');
is(length $md5, 16, 'have MD5 hostkey hash');
my $sha1 = $ssh2->hostkey_hash('sha1');
is(length $sha1, 20, 'have SHA1 hostkey hash');

# (3) authentication methods
unless ($user) {
    my $def_user;
    $def_user = getpwuid $< if $^O !~ /mswin/i;
    print $def_user ? "\nEnter username [$def_user]: " : "\nEnter username: ";
    chomp($user = <STDIN>);
    $user ||= $def_user;
}
my $auth = $ssh2->auth_list($user);
ok($auth, "authenticate: $auth");
my @auth_methods = split /,/, $auth;
is_deeply(\@auth_methods, [$ssh2->auth_list($user)], 'list matches comma-separated');
ok(!$ssh2->auth_ok, 'not authenticated yet');

# (2) authenticate
my @auth = ((defined $pass)     ? (password => $pass) :
            ($^O =~ /MSWin32/i) ? win32_auth()        :
            ());

my $type = $ssh2->auth(username => $user, @auth,
                       publickey  => "$ENV{HOME}/.ssh/id_dsa.pub",
                       privatekey => "$ENV{HOME}/.ssh/id_dsa",
                       passphrase => undef,
                       interact => 1 );
ok($type, "authenticated via: $type");
SKIP: { # SKIP-auth
skip '- failed to authenticate with server', 37 unless $ssh2->auth_ok;
pass('authenticated successfully');

# (5) channels
my $chan = $ssh2->channel();
isa_ok($chan, 'Net::SSH2::Channel', 'new channel');
$chan->blocking(0); pass('set blocking');
ok(!$chan->eof(), 'not at EOF');
ok($chan->ext_data('normal'), 'normal extended data handling');
ok($chan->ext_data('merge'), 'merge extended data');

# (3) environment
is($chan->setenv(), 0, 'empty setenv');
my %env = (test1 => 'A', test2 => 'something', test3 => 'E L S E');
# most sshds disallow set, so we're happy if these don't crash
ok($chan->setenv(%env) <= keys %env, 'set environment variables');  
is($chan->session, $ssh2, 'verify session');

# (1) callback
ok($ssh2->callback(disconnect => sub { warn "SSH_MSG_DISCONNECT!\n"; }),
 'set disconnect callback');

# (2) SFTP
$ssh2->blocking(1);  # creating channel may block
my $sftp = $ssh2->sftp();
isa_ok($sftp, 'Net::SSH2::SFTP', 'SFTP session');
is($sftp->session, $ssh2, 'verify session');

# (4) directories
my $dir = "net_ssh2_$$";
ok($sftp->mkdir($dir), "create directory $dir");
my %stat = $sftp->stat($dir);
ok(scalar keys %stat, 'stat directory');
ok(S_ISDIR($stat{mode}), 'type is directory');
is($stat{name}, $dir, 'directory name matches');

# (4) SCP
my $remote = "$dir/".basename($0);
ok($ssh2->scp_put($0, $remote), "put $0 to remote");
SKIP: { # SKIP-scalar
eval { require IO::Scalar };
skip '- IO::Scalar required', 2 if $@;
my $check = IO::Scalar->new;
ok($ssh2->scp_get($remote, $check), "get $remote from remote");
SKIP: { # SKIP-slurp
eval { require File::Slurp };
skip '- File::Slurp required', 1 if $@;
if($^O =~ /MSWin32/i) {
  is(${$check->sref}, File::Slurp::read_file($0, binmode => ':raw'), 'files match');
}
else {
  is(${$check->sref}, File::Slurp::read_file($0), 'files match');
}
} # SKIP-slurp
} # SKIP-scalar

# (3) rename
my $altname = "$remote.renamed";
$sftp->unlink($altname);
ok(!$sftp->unlink($altname), 'unlink non-existant file fails');
my @error = $sftp->error();
is_deeply(\@error, [LIBSSH2_FX_NO_SUCH_FILE(), 'SSH_FX_NO_SUCH_FILE'],
 'got LIBSSH2_FX_NO_SUCH_FILE error');
ok($sftp->rename($remote, $altname), "rename $remote -> $altname");

# (3) stat
%stat = $sftp->stat($altname);
ok(scalar keys %stat, "stat $altname");
is($stat{name}, $altname, 'stat filename matches');
is($stat{size}, -s $0, 'stat filesize matches');

# (3) open
my $fh = $sftp->open($altname);
isa_ok($fh, 'Net::SSH2::File', 'opened file');
my %fstat = $fh->stat;
delete $stat{name};  # fstat has no name
is_deeply(\%stat, \%fstat, 'compare stat and fstat');
my $fstat = $fh->stat;
is_deeply($fstat, \%fstat, 'compare fstat % and %$');
undef $fh;

# (2) SFTP dir
my $dh = $sftp->opendir($dir);
isa_ok($dh, 'Net::SSH2::Dir', 'opened directory');
my $found;
while(my $item = $dh->read) {
    $found = 1, last if $item->{name} eq basename $altname;
}
ok($found, "found $altname");
undef $dh;

# (2) read file
$fh = $sftp->open($altname);
isa_ok($fh, 'Net::SSH2::File', 'opened file');
scalar <$fh> for 1..2;
my $line = <$fh>;
chomp $line;
if($^O =~ /MSWin32/i) {
  $line =~ s/\r//;
}
is($line, '# THIS LINE WILL BE READ BY A TEST BELOW', "read '$line'");
#undef $fh;  # don't undef it, ensure reference counts work properly

# (3) cleanup SFTP
ok($sftp->unlink($altname), "unlink $altname");
ok($sftp->rmdir($dir), "remove directory $dir");
undef $sftp; pass('close SFTP session');

# (5) poll
$chan = $ssh2->channel();
ok($chan->exec('ls -d /'), "exec 'ls -d /'");
$chan->blocking(0);  # don't block, or we'll wait forever
my @poll = { handle => $chan, events => ['in'] };
ok($ssh2->poll(2000, \@poll), 'got poll response');
ok($poll[0]->{revents}->{in}, 'got input event');
$line = <$chan>;
chomp $line;
is($line, '/', "got result '/'");
$line = <$chan>;
ok(!$line, 'no more lines');

# (4) public key
$ssh2->blocking(1);  # creating channel may block
my $pk = $ssh2->public_key;
SKIP: {
skip ' - public key infrastructure not present', 4 unless $pk;
isa_ok($pk, 'Net::SSH2::PublicKey', 'public key session');
my @keys = $pk->fetch();
pass('got '.(scalar @keys).' keys in array');
my $keys = $pk->fetch();
pass("got $keys keys available");
is(scalar @keys, $keys, 'public key counts match');
}
undef $pk;

# (2) disconnect
ok($chan->close(), 'close channel'); # optional step
undef $fh;
ok($ssh2->disconnect('leaving'), 'sent disconnect message');
} # SKIP-auth
} # SKIP-server
} # SKIP-connect

# vim:filetype=perl

sub win32_auth {
  eval{require Term::ReadKey;};
  print "\n  NOTE: The password you are about to enter\n  will be printed to the console." if $@;
  print "\n  To avoid this, either install Term::ReadKey\n  or assign the correct value to \$pass" if $@;
  print "\n  at the beginning of this test script." if $@;
  print "\nEnter password: ";
  if($@) {$pass = <STDIN>}
  else {
    Term::ReadKey::ReadMode('noecho');
    $pass = Term::ReadKey::ReadLine(0);
    Term::ReadKey::ReadMode('normal');
  }
  chomp($pass);
  return (password => $pass);
}
