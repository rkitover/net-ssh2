use 5.008;

use Module::Build;
use Alien::Libssh2;
use Alien::OpenSSL;

my @alien = qw(Alien::Libssh2 Alien::OpenSSL);

my $builder = Module::Build->new(module_name => 'Net::SSH2',
                                 license => 'perl',
                                 extra_compiler_flags => join(' ', map $_->cflags, @alien),
                                 extra_linker_flags => join(' ', map $_->libs, @alien),
                                 requires => { 'Alien::Libssh2' => 0 },
                                 build_requires => { 'ExtUtils::CBuilder' => 0, },
                                 autosplit => 0,
                                 # xs_files => { 'SSH2.xs' => 'lib/Net/SSH2.xs' },
                                );

$builder->create_build_script;
