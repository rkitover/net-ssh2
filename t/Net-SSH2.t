# -*- Mode: CPerl -*-

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-SSH2.t'
# THIS LINE WILL BE READ BY A TEST BELOW

#########################

use Test::More;

use strict;
use Fcntl qw(O_CREAT O_EXCL O_WRONLY);
use File::Basename;
use File::Spec;
use Getopt::Long;

#########################

# default testing items from %ENV to facilitate testing
my $host        = $ENV{TEST_NET_SSH2_HOST};
my $user        = $ENV{TEST_NET_SSH2_USER};
my $password    = $ENV{TEST_NET_SSH2_PASSWORD};
my $passphrase  = $ENV{TEST_NET_SSH2_PASSPHRASE};
my $known_hosts = $ENV{TEST_NET_SSH2_KNOWN_HOSTS};

$known_hosts ||= File::Spec->devnull;
GetOptions("host|h=s" => \$host,
           "user|u=s" => \$user,
           "password|pwd|pw|w=s" => \$password,
           "passphrase|pp=s" => \$passphrase,
           "known_hosts|kh|k=s" => \$known_hosts);

$| = 1;
sub slurp;

# (1) use module
BEGIN { use_ok('Net::SSH2', ':all') };

# (4) basics: create an object, check status
my $ssh2 = Net::SSH2->new();
isa_ok($ssh2, 'Net::SSH2', 'new session');
ok(!$ssh2->error(), 'error state clear');
#$ssh2->trace(-1);

ok($ssh2->banner('SSH TEST'), 'set banner');
is(LIBSSH2_ERROR_SOCKET_NONE(), -1, 'LIBSSH2_* constants');

# (4) version
my $version = $ssh2->version();
my ($version2, $vernum, $banner) = $ssh2->version();
is($version, $version2, 'list version match');
my ($major) = $version =~ /^(\d+)/;

diag "libssh2 version: $version\n";
if (!defined($vernum) or $vernum < 0x010500) {
    diag "\n*** Your version of libssh2 is very old and broken. Upgrade it!!! ***\n\n";
}
elsif ($vernum < 0x010700) {
    diag "Your version of libssh2 is behind the recomended 1.7.0";
}

is($banner, "SSH-2.0-libssh2_$version", "banner is $banner");

# (2) timeout
is($ssh2->poll(0), 0, 'poll indefinite');
is($ssh2->poll(2000), 0, 'poll 2 second');

is($ssh2->sock, undef, '->sock is undef before connect');
is($ssh2->hostname, undef, '->hostname is undef before connect');

# (1) connect
unless (defined $host) {
    if (-t STDIN and -t STDOUT) {
        chomp(my $prompt = <<EOP);
To test the connection capabilities of Net::SSH2, we need a test site running
a secure shell server daemon.  Enter 'localhost' or '127.0.0.1' to use this
host over IPv4. Enter '::1' to use this host over IPv6.

Hostname or IP address [ENTER to skip]: 
EOP
        $host = $ssh2->_ask_user($prompt, 1);
    }
    unless (defined $host and length $host) {
        done_testing;
        exit(0);
    }
}

ok($ssh2->connect($host), "connect to $host");
isa_ok($ssh2->sock, 'IO::Socket', '->sock isa IO::Socket');
is($ssh2->hostname, $host, '->hostname');

# (8) server methods
for my $type (qw(kex hostkey crypt_cs crypt_sc mac_cs mac_sc comp_cs comp_sc)) {
    my $method = $ssh2->method($type);
    ok($ssh2->method($type), "$type method: $method");
}

# (2) check host key
my $md5 = $ssh2->hostkey_hash('md5');
is(length $md5, 16, 'have MD5 hostkey hash');
my $sha1 = $ssh2->hostkey_hash('sha1');
is(length $sha1, 20, 'have SHA1 hostkey hash');

ok($ssh2->check_hostkey('advisory', $known_hosts), "check remote key - advisory")
    or diag(join " ", "Error:", $ssh2->error);

ok($ssh2->check_hostkey('ask', $known_hosts), "check remote key - ask")
    or diag(join " ", "Error:", $ssh2->error);

# (3) authentication methods
unless ($user) {
    my $def_user = eval { getpwuid $< };
    $user = $ssh2->_ask_user("Enter username" . ($def_user ? " [$def_user]: " : ": "), 1);
    $user = $def_user unless defined $user and length $user;
}
my $auth = $ssh2->auth_list($user);
ok($auth, "authenticate: $auth");
my @auth_methods = split /,/, $auth;
is_deeply(\@auth_methods, [$ssh2->auth_list($user)], 'list matches comma-separated');
ok(!$ssh2->auth_ok, 'not authenticated yet');

# (2) authenticate
my $type;
my $home = $ssh2->_local_home;
if (defined $home) {
    for my $key (qw(dsa rsa)) {
        my $path = "$home/.ssh/id_$key";
        if ($ssh2->auth_publickey($user, "$path.pub", $path,
                                  $passphrase)) {
            diag "authenticated with key at $path";
            $type = 'pubkey';
            last;
        }
        else {
            diag "failed to authenticate with key at $path";
        }
    }
}

unless ($type) {
    diag "reverting to password authentication";
    $type = $ssh2->auth(username => $user,
                        password => $password,
                        interact => 1);
}

ok($ssh2->auth_ok, 'authenticated successfully');
ok($type, "authentication type is defined (".($type||undef).")");

# (5) channels
ok(!defined eval { $ssh2->channel("direct-tcpip") }, "only session channels");

my $chan = $ssh2->channel();
isa_ok($chan, 'Net::SSH2::Channel');
$chan->blocking(0); pass('set blocking');
ok(!$chan->eof(), 'not at EOF');
ok($chan->ext_data('normal'), 'normal extended data handling');
ok($chan->ext_data('merge'), 'merge extended data');

# (3) environment
is($chan->setenv(), 1, 'empty setenv');
my %env = (test1 => 'A', test2 => 'something', test3 => 'E L S E', LANG => 'C');
# most sshds disallow set, so we're happy if these don't crash
ok($chan->setenv(%env) || 1, 'set environment variables, it is ok if it fails');
is($chan->session, $ssh2, 'verify session');

# (1) callback
ok($ssh2->callback(disconnect => sub { warn "SSH_MSG_DISCONNECT!\n"; }),
 'set disconnect callback');

# (2) SFTP
$ssh2->blocking(1);  # creating channel may block
my $sftp = $ssh2->sftp();
isa_ok($sftp, 'Net::SSH2::SFTP');
is($sftp->session, $ssh2, 'verify session');

# (4) directories
my $dir = "net_ssh2_$$";
ok($sftp->mkdir($dir), "create directory $dir");
my %stat = $sftp->stat($dir);
ok(scalar keys %stat, 'stat directory');
ok($stat{mode} & 0x4000, 'type is directory');
is($stat{name}, $dir, 'directory name matches');

# (4) SCP
my $remote = "$dir/".basename($0);
ok($ssh2->scp_put($0, $remote), "put $0 to remote ($remote)");

SKIP: { # SKIP-scalar
    eval { require IO::Scalar };
    skip '- IO::Scalar required', 2 if $@;
    my $check = IO::Scalar->new;
    ok($ssh2->scp_get($remote, $check), "get $remote from remote");
    my $content = ${$check->sref};
 SKIP: { # SKIP-slurp
        my $data = slurp($0);
        defined $data or skip "- Unable to read '$0': $!", 1;
        if (length $content == length $data) {
            is($content, $data, 'files match');
        }
        else {
            fail('file size match');
            if (length $content == 0) {
                diag <<MSG
This is a known bug of Straberry perl: there is a mismatch between perl and libssh2 about the layout of 'struct stat'.
The best way to avoid it is to upgrade libssh2 to version 1.6.1 or later.
This bug affects SCP methods only.
MSG
            }
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

# (3) exercise File tie interface
my $fh = $sftp->open($altname);
isa_ok($fh, 'Net::SSH2::File', 'opened file');
my $line = '';
my $count = read($fh,$line,10);
is($count,10,'read partial first line via tie interface');
$count = read($fh,$line,12,10);
is($count,12,'read remaining first line via tie interface');
chomp($line);
is($line,'# -*- Mode: CPerl -*-','validate first line received via tie interface');
my @lines = <$fh>;
$line = pop(@lines);
chomp($line);
is($line,'# vim:filetype=perl','read remaining lines via tie interface');
my $mode = binmode $fh;
is($mode,undef,'binmode via tie interface');
is(eof $fh,0,'eof via tie interface');
is(close $fh,undef,'close via tie interface');
undef $fh;
my $outfile = $dir . '/write.out';
my $fh = $sftp->open($outfile,O_CREAT|O_EXCL|O_WRONLY);
isa_ok($fh, 'Net::SSH2::File', 'opened file for writing');
$count = print $fh 'test ';
is($count,5,'print via tie interface');
$, = ',';
$count = print $fh 'test ';
undef $,;
is($count,5,'print with separator via tie interface');
$count = printf $fh 'test %d',1;
is($count,1,'printf via tie interface');
undef $fh;
$sftp->unlink($outfile);

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
scalar <$fh> for 1..4;
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
ok($chan = $ssh2->channel("session"), "open channel stating type session");
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

$chan = $ssh2->channel();
ok($chan->exec('cat'), "exec 'cat'");
is($ssh2->timeout(100), 100, "sets timeout");
is($ssh2->timeout, 100, "timeout is 100");
ok(!$chan->read(my $buf, 10), "read fails");
is(($ssh2->error)[0], Net::SSH2::LIBSSH2_ERROR_TIMEOUT(), "error timeout");
is($ssh2->timeout(0), undef, "sets timeout to 0");
is($ssh2->timeout, undef, "timeout is undef");
is($ssh2->timeout(10), 10, "sets timeout to 10");
is($ssh2->timeout(undef), undef, "sets timeout to undef");
is($ssh2->timeout, undef, "timeout is undef 2");

my $pk = $ssh2->public_key;
SKIP: {
    skip ' - public key infrastructure not present', 4 unless $pk;
    diag "What? you have the public key module working!!!";
    isa_ok($pk, 'Net::SSH2::PublicKey', 'public key session');
    my @keys = $pk->fetch();
    pass('got '.(scalar @keys).' keys in array');
    my $keys = $pk->fetch();
    pass("got $keys keys available");
    is(scalar @keys, $keys, 'public key counts match');
}
undef $pk;

ok($chan->close(), 'close channel'); # optional step
undef $fh;

# (5) exercise Channel tie interface
$chan = $ssh2->channel();
isa_ok($chan, 'Net::SSH2::Channel');
#is(eof $chan,0,'channel eof via tie interface');
$mode = binmode $chan;
is($mode,undef,'channel binmode via tie interface');
$chan->shell;
$chan->subsystem('dummy');
is($chan->error,-39, 'channel error');
$, = ';';
$count = print $chan "exit\n";
is($count,5,'channel print with separator via tie interface');
undef $,;
$count = print $chan "exit\n";
is($count,5,'channel print via tie interface');
$count = printf $chan "exit\n";
is($count,1,'channel printf via tie interface');
is(close $chan,1,'channel close via tie interface');
undef $chan;

# (2) disconnect
ok($ssh2->disconnect('leaving'), 'sent disconnect message');

done_testing;
exit(0);

sub slurp {
    my $file = shift;
    if (open my $fh, '<', $file) {
        binmode $fh;
        local $/;
        my $data = <$fh>;
        return $data if close $fh;
    }
    ()
}

# vim:filetype=perl
