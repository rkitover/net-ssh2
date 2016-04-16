use inc::Module::Install 0.91;
use Cwd;
use Config;
use File::Glob qw(bsd_glob);

use strict;
use warnings;

my $win32   = ($^O eq 'MSWin32');
my $darwin  = ($^O eq 'darwin');
my $solaris = ($^O eq 'solaris');
my $linux   = !($win32 || $darwin || $solaris ); # yea, more than linux are going to end here!

my $cc_gcc   = $Config{cc} =~ /gcc/;
my $cc_wincl = $win32 && $Config{cc} =~ /cl/;

my $path_sep = $Config{path_sep};

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

my $crypto_backend;
my $do_not_check_libs;

sub makemaker_append_once;
sub capture;
sub findlib;

name 'Net-SSH2';
all_from 'lib/Net/SSH2.pm';
perl_version '5.006000';
auto_provides;
makemaker_append_once CCFLAGS   => $Config{ccflags};
makemaker_append_once LDDLFLAGS => $Config{lddlflags};

my %arg2mmappend = ( inc => 'INC',
                     lib => 'LIBS',
                     ldargs => 'LDDLFLAGS' );
my %arg2prefix = (inc => '-I',
                  lib => '-L');

my $arg_keys = join('|', map quotemeta, keys %arg2mmappend);
my $do_not_check_libs_keys = 'lib|inc';

for (keys %ENV) {
    if (/^LIBSSH2_($arg_keys)$/) {
        my $value = $ENV{$_};
        my $prefix = $arg2prefix{lc $1} || '';
        $value = File::Spec->rel2abs($value) if $prefix;
        makemaker_append_once $arg2mmappend{lc $1} => $prefix . $value;
        $do_not_check_libs ||= /^LIBSSH2_($do_not_check_libs_keys)$/i;
    }
}

my @pass_through_args;
for (@ARGV) {
    if (/^($arg_keys)=(.*)\z/) {
        my $prefix = $arg2prefix{$1} || '';
        my $value = $2;
        $value = File::Spec->rel2abs($value) if $prefix;
        makemaker_append_once $arg2mmappend{$1} => $prefix.$value;
        $do_not_check_libs ||= /^($do_not_check_libs_keys)=/;
    }
    elsif ($_ eq 'gcrypt') {
        $crypto_backend = 'gcrypt';
    }
    elsif ($_ eq 'openssl') {
        $crypto_backend = 'openssl';
    }
    else {
        push @pass_through_args, $_;
    }
}
@ARGV = @pass_through_args;

my @search_paths;
for my $env ('LD_RUN_PATH', ($darwin ? 'DYLD_LIBRARY_PATH' : 'LD_LIBRARY_PATH')) {
    my $v = $ENV{$env};
    push @search_paths, split(/\Q$path_sep\E/, $v) if defined $v;
}
push @search_paths,
    split(' ', $Config{libspath}),
    $Config{siteprefixexp}, $Config{prefixexp},
    '/usr', '/usr/local', '/opt', '/opt/local',
    '/usr/local/libssh2', '/opt/libssh2',
    '/usr/local/libssh2/*', '/usr/local/ssl';

push @search_paths, $ENV{HOME}, "$ENV{HOME}/libssh2" if defined $ENV{HOME};

# mac homebrew support
if ($^O eq 'darwin' && -x '/usr/local/bin/brew') {
    system("/usr/local/bin/brew info libssh2 | grep '^Not installed' >/dev/null");
    if ($? >> 8 == 0) {
        system("/usr/local/bin/brew -v install libssh2");
    }
    system("/usr/local/bin/brew info openssl | grep '^Not installed' >/dev/null");
    if ($? >> 8 == 0) {
        system("/usr/local/bin/brew -v install openssl");
    }

    push @search_paths, '/usr/local/Cellar/openssl/*';
}

@search_paths = map { /\*/
                      ? (sort { (stat $b)[9] <=> (stat $a)[9] } grep -d, bsd_glob($_))
                      : $_ } @search_paths;
my %sp_seen;
@search_paths = grep !$sp_seen{$_}++, @search_paths;

sub findlib {
    local $Module::Install::AUTHOR;
    my %args = @_;
    my @search_paths = @{delete $args{search_paths} || []};
    for my $sp (undef, @search_paths) {
        for my $libpath (defined $sp ? (map [$_], grep -d, "$sp/lib", "$sp/lib64", $sp) : []) {
            my $incpath = (defined $sp ? [grep -d, "$sp/include"] : []);
            my @ldflags = '';
            push @ldflags, "-Wl,-rpath=".$libpath->[0] if $cc_gcc and defined $sp;
            for my $ldflags (@ldflags) {
                if (eval {
                    assertlibs( %args,
                                libpath => $libpath,
                                incpath => $incpath,
                                ldflags => $ldflags);
                    1; }) {

                    warn "Library $args{lib} found in ".(defined $sp ? $sp : "standard place")."\n";
                    makemaker_append_once INC => "-I$_" for @$incpath;
                    makemaker_append_once LIBS => "-L$_" for @$libpath;
                    makemaker_append_once LIBS => "-l$args{lib}";
                    makemaker_append_once LDDLFLAGS => $ldflags if $ldflags;
                    return 1;
                }
            }
        }
    }
    die "Unable to find a working version of library $args{lib} in the following directories:\n  ".
        (join "\n  ", @search_paths)."\n";
}

if ($do_not_check_libs) {
    $crypto_backend ||= 'openssl';
}
else {
    warn "Looking for libraries...\n";
    my $detected_crypto_backend;

    # This is a workaround for Module::Install::CheckLib behaving
    # differently in user and author mode. Specifically, in author
    # mode, we call M::I::CheckLib normally so that it can copy
    # its files under "inc/", and then, we hide we are in author
    # mode and call it again so that it actually runs the
    # checklibs stuff..
    if ($Module::Install::AUTHOR) {
        eval {
            assertlibs( lib => 'ssh2',
                        header => 'libssh2.h',
                        libpath => [],
                        incpath => []);
        };
    }

    findlib(lib => 'ssh2',
            header => 'libssh2.h',
            search_paths => \@search_paths,
            function => <<EOF,
                if (libssh2_init(0))
                  return 1;
                /* check that library and headers are on par */
                return (libssh2_version(LIBSSH2_VERSION_NUM) ? 0 : 1);
EOF
            analyze_binary => sub {
                warn "Analyzing file $_[1]\n";
                my $out = capture ldd => $_[1];
                # warn "out:\n$out";
                if ($out =~ /gcrypt/i) {
                    $detected_crypto_backend = 'gcrypt';
                }
                elsif ($out =~ /lib(ssl|crypto)/i) {
                    $detected_crypto_backend = 'openssl';
                }
                else {
                    warn "Unable to detect crypto backend used by libssh2!\n"
                }
                1;
            },
            run_checks_as_author => 1, );

    if (defined $detected_crypto_backend) {
        if (defined $crypto_backend) {
            $crypto_backend eq $detected_crypto_backend or
                warn "Detected crypto backend ($detected_crypto_backend) does not match ".
                     "the one requested on the command line ($crypto_backend)";
        }
        else {
            warn "Detected crypto backend: $detected_crypto_backend\n";
            $crypto_backend = $detected_crypto_backend;
        }
    }
    $crypto_backend ||= 'openssl';

    unless ($win32) {
        findlib(lib => 'z',
                header => 'zlib.h',
                search_paths => \@search_paths,
                run_checks_as_author => 1);

        if ($crypto_backend eq 'gcrypt') {
            findlib(lib => 'gcrypt',
                    header => 'gcrypt.h',
                    search_paths => \@search_paths,
                    run_checks_as_author => 1);
        }
        else {
            findlib(lib => 'ssl',
                    header => 'openssl/ssl.h',
                    search_paths => \@search_paths,
                    run_checks_as_author => 1);

            findlib(lib => 'crypto',
                    header => 'openssl/crypto.h',
                    search_paths => \@search_paths,
                    run_checks_as_author => 1);
        }
    }
}

if ($crypto_backend eq 'gcrypt') {
    makemaker_append_once(LDDLFLAGS => '-lgcrypt');
}
else {
    if ($cc_wincl) {
        makemaker_append_once(LIBS => "-l$_") for qw(ssleay32 libeay32); # Win32 + MSVC compiler
    }
    if ($cc_gcc && $win32) {
        makemaker_append_once(LIBS => "-l$_") for qw(ssl32 eay32); # Win32 + GCC compiler (mingw)
    }
    else {
        makemaker_append_once(LIBS => "-l$_") for qw(ssl crypto);
    }
}

makemaker_append_once(DEFINE => '-DLIBSSH2_WIN32') if $win32;
makemaker_append_once(DEFINE => '-DUSE_GCRYPT')    if $crypto_backend eq 'gcrypt';

makemaker_append_once(CCFLAGS => '-Wno-deprecated-declarations') if $^O eq 'darwin';

makemaker_append_once(CCFLAGS => '-DPERL_GCC_PEDANTIC -std=c99 -pedantic-errors -Wno-long-long')
    if $Module::Install::AUTHOR and $linux and $cc_gcc;

realclean_files qw/const-c.inc const-xs.inc/;
resources repository => 'git://github.com/rkitover/net-ssh2.git';

makemaker_append_once LIBS => '-lssh2', '-lz';



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
     LIBSSH2_ERROR_AUTHENTICATION_FAILED
     LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED
     LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED
     LIBSSH2_ERROR_REQUEST_DENIED LIBSSH2_ERROR_SCP_PROTOCOL
     LIBSSH2_ERROR_PUBLICKEY_PROTOCOL
     LIBSSH2_ERROR_SFTP_PROTOCOL LIBSSH2_ERROR_SOCKET_DISCONNECT
     LIBSSH2_ERROR_SOCKET_NONE LIBSSH2_ERROR_SOCKET_SEND
     LIBSSH2_ERROR_SOCKET_TIMEOUT LIBSSH2_ERROR_TIMEOUT
     LIBSSH2_ERROR_ZLIB LIBSSH2_ERROR_KNOWN_HOSTS
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
     LIBSSH2_HOSTKEY_POLICY_STRICT
     LIBSSH2_HOSTKEY_POLICY_ASK
     LIBSSH2_HOSTKEY_POLICY_TOFU
     LIBSSH2_HOSTKEY_POLICY_ADVISORY
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
  require File::Copy;
  require File::Spec;
  foreach my $file ('const-c.inc', 'const-xs.inc') {
    my $fallback = File::Spec->catfile('fallback', $file);
    File::Copy::copy ($fallback, $file) or die "Can't copy $fallback to $file: $!";
  }
}

my %appended;
sub makemaker_append_once {
    my $key = shift;
    for (@_) {
        makemaker_append $key, $_
            unless $appended{$key}{$_}++;
    }
}

sub capture {
    if (open my $fh, '-|', @_) {
        my $out  = do { local $/, <$fh> };
        close $fh;
        return $out;
    }
    ''
}

