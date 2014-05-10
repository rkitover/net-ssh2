use inc::Module::Install 0.91;
use Cwd;
use Config;
use Module::Install::CheckLib ();

# override library and include directories here if desired
my $lib = $ENV{LIBSSH2_LIB} || '';
my $inc = $ENV{LIBSSH2_INCLUDE} || '';
my $extra_libs = '-lz' . ($ENV{LIBSSH2_LDARGS} ? (' ' . $ENV{LIBSSH2_LDARGS}) : '');
my $ldargs; # from command line
my $use_gcrypt = 0;

my @args = @ARGV;
my @pass_through_args;
while (my $arg = shift @args) {
    if (my ($param, $val) = $arg =~ /^(inc|lib|ldargs)=(.*)\z/) {
        my $var = $param eq 'inc' ? \$inc : ($param eq 'lib' ? \$lib : \$ldargs);
        $$var   = $val;
        next;
    }
    elsif ($arg eq 'gcrypt') {
        $use_gcrypt = 1;
        next;
    }
    push @pass_through_args, $arg;
}
@ARGV = @pass_through_args;

# Windows, as usual, is a special case
my $win32 = ($^O eq 'MSWin32');

if ($use_gcrypt) {
    $extra_libs .= ' -lgcrypt';
}
else {
  if ($win32 && $Config{cc} =~ /cl/) {
    $extra_libs .= ' -lssleay32 -llibeay32'; # Win32 + MSVC compiler
  }
  if ($win32 && $Config{cc} =~ /gcc/) {
    $extra_libs .= ' -lssl32 -leay32'; # Win32 + GCC compiler (mingw)
  }
  else {
    $extra_libs .= ' -lssl -lcrypto';
  }
}

$extra_libs = "$extra_libs $ldargs" if $ldargs;

my $defines = '';
$defines .= '-DLIBSSH2_WIN32 ' if $win32;
$defines .= '-DUSE_GCRYPT ' if $use_gcrypt;
my @define = $defines ? (DEFINE => $defines) : ();

name 'Net-SSH2';
all_from 'lib/Net/SSH2.pm';
perl_version '5.006000';

my @search_paths = (
  (split /\Q$Config{path_sep}\E/, $ENV{LD_RUN_PATH}),
  (split /\Q$Config{path_sep}\E/, ($^O eq 'darwin' ?
    $ENV{DYLD_LIBRARY_PATH} : $ENV{LD_LIBRARY_PATH})),
  $ENV{HOME}, ($ENV{HOME}."/libssh2"),
  (split ' ', $Config{libspath}),
  $Config{siteprefixexp}, $Config{prefixexp},
  '/usr/local/ssl', '/usr', '/usr/local', '/opt', '/opt/local', '/',
);

my %seen;
foreach my $path (@search_paths) {
    $seen{$path}++;
}
my (%skip, @without_dups);
foreach my $path (@search_paths) {
    next if $skip{$path};

    if ($seen{$path} > 1) {
        $skip{$path} = 1;
    }

    push @without_dups, $path;
}
@search_paths = @without_dups;

my @search_libs = grep -d, map +("$_/lib", "$_/lib64", $_), @search_paths;
my @search_incs = grep -d, map "$_/include", @search_paths;

print <<'EOF';

The libssh2 library is required by this module.  If you don't have it, you can
download it from http://www.libssh2.org; you may also need OpenSSL, which can
be obtained from http://www.openssl.org , or libgcrypt, which can be obtained
from http://www.gnupg.org .

Debian:   sudo aptitude install libssh2-1-dev
OpenSUSE: sudo zypper in libssh2-1 libssh2-devel

You can pass your libssh2 lib and include dirs (and extra link args) on the
command line. E.g.:

    perl Makefile.PL lib=$HOME/libssh2/lib inc=$HOME/libssh2/include \
        ldargs="-lz"

These can also be set through the LIBSSH2_LIB/LIBSSH2_INCLUDE/LIBSSH2_LDARGS
environment variables.

To build with libgcrypt instead of OpenSSL, pass 'gcrypt' as a parameter to
Makefile.PL, e.g.:

    perl Makefile.PL gcrypt

If you want to build on Windows, see the file BUILDING.WIN32 in the
distribution.

EOF

if (!$lib && !$inc) {

    checklibs
        lib => 'ssh2',
        header => 'libssh2.h',
        libpath => [@search_libs],
        incpath => [@search_incs],
    ;

    $lib = (join ' ', map "-L$_", @search_libs) . " -lssh2 $extra_libs";
    $inc =  join ' ', map "-I$_", @search_incs;
} else {
    $lib = "-L$lib -lssh2 $extra_libs" if $lib;
    $inc = "-I$inc" if $inc;
}

my $extra_ccflags = ' ';
if ($^O eq 'darwin') {
	$extra_ccflags .= '-Wno-deprecated-declarations'
}

auto_provides;

libs $lib;

inc "$inc -I.";

makemaker_args 
    @define,
    # this is known to NOT work on mingw, solaris and darwin, and we only turn it on for devs
    ($Module::Install::AUTHOR && $^O ne 'MSWin32' && $^O ne 'solaris' && $^O ne 'darwin' && $Config{cc} =~ /gcc/i ? (
        CCFLAGS => '-DPERL_GCC_PEDANTIC -std=c99 -pedantic-errors -Wno-long-long '
    ) : (
        CCFLAGS => $Config{ccflags} . $extra_ccflags
    ))
;

realclean_files qw/const-c.inc const-xs.inc/;

resources repository =>
    'git://github.com/rkitover/net-ssh2.git';

WriteAll;

if  (eval {require ExtUtils::Constant; 1}) {
  # If you edit these definitions to change the constants used by this module,
  # you will need to use the generated const-c.inc and const-xs.inc
  # files to replace their "fallback" counterparts before distributing your
  # changes.
  my @names = (qw(
     LIBSSH2_CALLBACK_DEBUG
     LIBSSH2_CALLBACK_DISCONNECT LIBSSH2_CALLBACK_IGNORE
     LIBSSH2_CALLBACK_MACERROR LIBSSH2_CALLBACK_X11
     LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE
     LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE
     LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL LIBSSH2_CHANNEL_FLUSH_ALL
     LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA LIBSSH2_CHANNEL_MINADJUST
     LIBSSH2_CHANNEL_PACKET_DEFAULT LIBSSH2_CHANNEL_WINDOW_DEFAULT
     LIBSSH2_DH_GEX_MAXGROUP LIBSSH2_DH_GEX_MINGROUP
     LIBSSH2_DH_GEX_OPTGROUP LIBSSH2_ERROR_ALLOC
     LIBSSH2_ERROR_BANNER_NONE LIBSSH2_ERROR_BANNER_SEND
     LIBSSH2_ERROR_CHANNEL_CLOSED LIBSSH2_ERROR_CHANNEL_EOF_SENT
     LIBSSH2_ERROR_CHANNEL_FAILURE LIBSSH2_ERROR_CHANNEL_OUTOFORDER
     LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED
     LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED
     LIBSSH2_ERROR_CHANNEL_UNKNOWN
     LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED LIBSSH2_ERROR_DECRYPT
     LIBSSH2_ERROR_FILE LIBSSH2_ERROR_HOSTKEY_INIT
     LIBSSH2_ERROR_HOSTKEY_SIGN LIBSSH2_ERROR_INVAL
     LIBSSH2_ERROR_INVALID_MAC LIBSSH2_ERROR_INVALID_POLL_TYPE
     LIBSSH2_ERROR_KEX_FAILURE LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE
     LIBSSH2_ERROR_METHOD_NONE LIBSSH2_ERROR_METHOD_NOT_SUPPORTED
     LIBSSH2_ERROR_PASSWORD_EXPIRED LIBSSH2_ERROR_PROTO
     LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED
     LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED
     LIBSSH2_ERROR_REQUEST_DENIED LIBSSH2_ERROR_SCP_PROTOCOL
     LIBSSH2_ERROR_PUBLICKEY_PROTOCOL
     LIBSSH2_ERROR_SFTP_PROTOCOL LIBSSH2_ERROR_SOCKET_DISCONNECT
     LIBSSH2_ERROR_SOCKET_NONE LIBSSH2_ERROR_SOCKET_SEND
     LIBSSH2_ERROR_SOCKET_TIMEOUT LIBSSH2_ERROR_TIMEOUT
     LIBSSH2_ERROR_ZLIB
     LIBSSH2_FLAG_SIGPIPE
     LIBSSH2_FLAG_COMPRESS
     LIBSSH2_FXF_APPEND
     LIBSSH2_ERROR_EAGAIN
     LIBSSH2_SOCKET_BLOCK_INBOUND
     LIBSSH2_SOCKET_BLOCK_OUTBOUND
     LIBSSH2_TRACE_TRANS
     LIBSSH2_TRACE_KEX
     LIBSSH2_TRACE_AUTH
     LIBSSH2_TRACE_CONN
     LIBSSH2_TRACE_SCP
     LIBSSH2_TRACE_SFTP
     LIBSSH2_TRACE_ERROR
     LIBSSH2_TRACE_PUBLICKEY
     LIBSSH2_TRACE_SOCKET
     LIBSSH2_FXF_CREAT LIBSSH2_FXF_EXCL LIBSSH2_FXF_READ
     LIBSSH2_FXF_TRUNC LIBSSH2_FXF_WRITE LIBSSH2_FX_BAD_MESSAGE
     LIBSSH2_FX_CONNECTION_LOST LIBSSH2_FX_DIR_NOT_EMPTY
     LIBSSH2_FX_EOF LIBSSH2_FX_FAILURE
     LIBSSH2_FX_FILE_ALREADY_EXISTS LIBSSH2_FX_INVALID_FILENAME
     LIBSSH2_FX_INVALID_HANDLE LIBSSH2_FX_LINK_LOOP
     LIBSSH2_FX_LOCK_CONFlICT LIBSSH2_FX_NOT_A_DIRECTORY
     LIBSSH2_FX_NO_CONNECTION LIBSSH2_FX_NO_MEDIA
     LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM LIBSSH2_FX_NO_SUCH_FILE
     LIBSSH2_FX_NO_SUCH_PATH LIBSSH2_FX_OK
     LIBSSH2_FX_OP_UNSUPPORTED LIBSSH2_FX_PERMISSION_DENIED
     LIBSSH2_FX_QUOTA_EXCEEDED LIBSSH2_FX_UNKNOWN_PRINCIPLE
     LIBSSH2_FX_WRITE_PROTECT LIBSSH2_H LIBSSH2_HOSTKEY_HASH_MD5
     LIBSSH2_HOSTKEY_HASH_SHA1 LIBSSH2_METHOD_COMP_CS
     LIBSSH2_METHOD_COMP_SC LIBSSH2_METHOD_CRYPT_CS
     LIBSSH2_METHOD_CRYPT_SC LIBSSH2_METHOD_HOSTKEY
     LIBSSH2_METHOD_KEX LIBSSH2_METHOD_LANG_CS
     LIBSSH2_METHOD_LANG_SC LIBSSH2_METHOD_MAC_CS
     LIBSSH2_METHOD_MAC_SC LIBSSH2_PACKET_MAXCOMP
     LIBSSH2_PACKET_MAXDECOMP LIBSSH2_PACKET_MAXPAYLOAD
     LIBSSH2_POLLFD_CHANNEL LIBSSH2_POLLFD_CHANNEL_CLOSED
     LIBSSH2_POLLFD_LISTENER LIBSSH2_POLLFD_LISTENER_CLOSED
     LIBSSH2_POLLFD_POLLERR LIBSSH2_POLLFD_POLLEX
     LIBSSH2_POLLFD_POLLEXT LIBSSH2_POLLFD_POLLHUP
     LIBSSH2_POLLFD_POLLIN LIBSSH2_POLLFD_POLLNVAL
     LIBSSH2_POLLFD_POLLOUT LIBSSH2_POLLFD_POLLPRI
     LIBSSH2_POLLFD_SESSION_CLOSED LIBSSH2_POLLFD_SOCKET
     LIBSSH2_SFTP_ATTR_ACMODTIME LIBSSH2_SFTP_ATTR_EXTENDED
     LIBSSH2_SFTP_ATTR_PERMISSIONS LIBSSH2_SFTP_ATTR_SIZE
     LIBSSH2_SFTP_ATTR_UIDGID LIBSSH2_SFTP_LSTAT
     LIBSSH2_SFTP_OPENDIR LIBSSH2_SFTP_OPENFILE
     LIBSSH2_SFTP_PACKET_MAXLEN LIBSSH2_SFTP_READLINK
     LIBSSH2_SFTP_REALPATH LIBSSH2_SFTP_RENAME_ATOMIC
     LIBSSH2_SFTP_RENAME_NATIVE LIBSSH2_SFTP_RENAME_OVERWRITE
     LIBSSH2_SFTP_SETSTAT LIBSSH2_SFTP_STAT LIBSSH2_SFTP_SYMLINK
     LIBSSH2_SFTP_TYPE_BLOCK_DEVICE LIBSSH2_SFTP_TYPE_CHAR_DEVICE
     LIBSSH2_SFTP_TYPE_DIRECTORY LIBSSH2_SFTP_TYPE_FIFO
     LIBSSH2_SFTP_TYPE_REGULAR LIBSSH2_SFTP_TYPE_SOCKET
     LIBSSH2_SFTP_TYPE_SPECIAL LIBSSH2_SFTP_TYPE_SYMLINK
     LIBSSH2_SFTP_TYPE_UNKNOWN LIBSSH2_SFTP_VERSION
     LIBSSH2_SOCKET_POLL_MAXLOOPS LIBSSH2_SOCKET_POLL_UDELAY
     LIBSSH2_TERM_HEIGHT
     LIBSSH2_TERM_HEIGHT_PX LIBSSH2_TERM_WIDTH
     LIBSSH2_TERM_WIDTH_PX
     LIBSSH2_KNOWNHOST_TYPE_MASK
     LIBSSH2_KNOWNHOST_TYPE_PLAIN
     LIBSSH2_KNOWNHOST_TYPE_SHA1
     LIBSSH2_KNOWNHOST_TYPE_CUSTOM
     LIBSSH2_KNOWNHOST_KEYENC_MASK
     LIBSSH2_KNOWNHOST_KEYENC_RAW
     LIBSSH2_KNOWNHOST_KEYENC_BASE64
     LIBSSH2_KNOWNHOST_KEY_MASK
     LIBSSH2_KNOWNHOST_KEY_SHIFT
     LIBSSH2_KNOWNHOST_KEY_RSA1
     LIBSSH2_KNOWNHOST_KEY_SSHRSA
     LIBSSH2_KNOWNHOST_KEY_SSHDSS
     LIBSSH2_KNOWNHOST_CHECK_MATCH
     LIBSSH2_KNOWNHOST_CHECK_MISMATCH
     LIBSSH2_KNOWNHOST_CHECK_NOTFOUND
     LIBSSH2_KNOWNHOST_CHECK_FAILURE
  ));
  ExtUtils::Constant::WriteConstants(
    NAME         => 'Net::SSH2',
    NAMES        => \@names,
    DEFAULT_TYPE => 'IV',
    C_FILE       => 'const-c.inc',
    XS_FILE      => 'const-xs.inc',
  );

}
else {
  use File::Copy;
  use File::Spec;
  foreach my $file ('const-c.inc', 'const-xs.inc') {
    my $fallback = File::Spec->catfile('fallback', $file);
    copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
  }
}
