
BEGIN {
    unshift @INC, '.' unless -d ".git";
}

use inc::Module::Install 1.17;
use Cwd;
use Config;
use File::Glob qw(bsd_glob);

use strict;
use warnings;

my $win32   = ($^O eq 'MSWin32');
my $darwin  = ($^O eq 'darwin');
my $solaris = ($^O eq 'solaris');
my $linux   = ($^O eq 'linux');

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

    perl Makefile.PL libs=$HOME/libssh2/lib inc=$HOME/libssh2/include \
        ldargs="-lz"

These can also be set through the LIBSSH2_LIBS/LIBSSH2_INC/LIBSSH2_LDDLFLAGS
environment variables.

To build with libgcrypt instead of OpenSSL, pass 'gcrypt' as a parameter to
Makefile.PL, e.g.:

    perl Makefile.PL gcrypt

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

# On MSYS2 there are issues finding system DLL import libs.
makemaker_append_once LIBS => ':nosearch' if $win32;

my %arg2mmappend = ( inc => 'INC',
                     libs => 'LIBS',
                     ldargs => 'LDDLFLAGS' );
my %arg2prefix = (inc => '-I',
                  libs => '-L');

my $arg_keys = join('|', map quotemeta, keys %arg2mmappend);
my $arg_values = join('|', map quotemeta, values %arg2mmappend);
my $do_not_check_libs_keys = 'LIBS|INC';

for (keys %ENV) {
    if (/^LIBSSH2_($arg_values)$/) {
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
if ($^O eq 'darwin' && (qx`command -v brew`)[0]) {
    if(system("brew info libssh2 | grep '^Not installed' 2>&1 >/dev/null") >> 8 == 0) {
        system("brew -v install libssh2");
    }

    if(system("brew info openssl | grep '^Not installed' 2>&1 >/dev/null") >> 8 == 0) {
        system("brew -v install openssl");
    }

    for(qw/openssl libssh2/) {
        push @search_paths, map { chomp; $_ } (qx`brew --prefix $_`)[0];
    }
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
                else {
                    warn $@ if $@ and $ENV{AUTOMATED_TESTING};
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
                local $@;
                eval {
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
                };
                warn $@ if $@ and $ENV{AUTOMATED_TESTING};
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

makemaker_append_once LIBS => '-lssh2', '-lz';

if ($crypto_backend eq 'gcrypt') {
    makemaker_append_once(LDDLFLAGS => '-lgcrypt');
}
else {
    makemaker_append_once(LIBS => "-l$_") for qw(ssl crypto);
}

makemaker_append_once(DEFINE => '-DLIBSSH2_WIN32') if $win32;
makemaker_append_once(LIBS => '-lCrypt32') if $win32;

makemaker_append_once(DEFINE => '-DUSE_GCRYPT')    if $crypto_backend eq 'gcrypt';

makemaker_append_once(CCFLAGS => '-Wno-deprecated-declarations') if $^O eq 'darwin';

makemaker_append_once(CCFLAGS => '-DPERL_GCC_PEDANTIC -std=c99 -pedantic-errors -Wno-long-long')
    if $Module::Install::AUTHOR and $linux and $cc_gcc;

resources repository => 'git://github.com/rkitover/net-ssh2.git';

resources bugtracker => 'https://github.com/rkitover/net-ssh2/issues';

my $gen = "util/gen_constants.pl";
if (-f $gen) {
    system $^X, $gen
        and warn "$gen failed: $?\n";
}

WriteAll;

# Generate README.pod
if ($Module::Install::AUTHOR and -d '.git') {
    require Pod::Simple::JustPod;
    my $parser = Pod::Simple::JustPod->new;
    $parser->output_string(\my $out_str);
    $parser->parse_file('lib/Net/SSH2.pm');

    open my $out_fh, '>README.pod' or die "Can't open README.pod for writing: $!";
    print $out_fh $out_str;
    close $out_fh;
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
    # Ignore not found errors.
    open(my $olderr, '>&STDERR') or die "can't dup STDERR: $!";
    close STDERR;

    my $out = '';

    if (open my $fh, '-|', @_) {
        $out = do { local $/, <$fh> };
        close $fh;
    }

    open(STDERR, '>&', $olderr) or die "can't dup STDERR: $!";

    return $out;
}

