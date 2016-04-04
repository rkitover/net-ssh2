use 5.008;

use Module::Build;

my $class = Module::Build->subclass(class => 'Net::SSH2::Builder',
                                    code => <<'EOC');

use strict;
use warnings;
use Carp;

__PACKAGE__->add_property(use_alien => 1);

sub in_Build_PL {
  my $self = shift;
  $self->{action} and $self->{action} eq 'Build_PL'
}

sub alien_libs { @{shift->config_data('alien_libs') || []} }

sub auto_require {
  my $self = shift;
  $self->SUPER::auto_require(@_);

  my @alien_libs;
  my $use_alien = $self->use_alien;
  $self->log_verbose("use_alien: $use_alien\n");
  if ($self->use_alien) {
    $self->_add_prereq(configure_requires => 'Alien::Libssh2');
    unless (eval "require Alien::Libssh2::ConfigData; 1") {
      print "Can't configure the module without 'Alien::Libssh2'.\nInstall that module and rerun 'perl Build.PL'!!!\n\n";
      return;
    }

    my $cbe = Alien::Libssh2::ConfigData->config('crypto_backend');
    my $alien_libssh2_libs = Alien::Libssh2::ConfigData->config('alien_libs');
    push @alien_libs, 'Alien::Libssh2';
    push @alien_libs, grep defined, @$alien_libssh2_libs
      if $alien_libssh2_libs;
  }
  $self->log_verbose("alien_libs: @alien_libs\n");
  $self->config_data(alien_libs => \@alien_libs);
  ()
}

sub alien_libs_and_load {
  my $self = shift;
  my @libs = $self->alien_libs;
  eval "require $_; 1" or die for @libs;
  @libs
}

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);

  if ($self->in_Build_PL) {
    if ($self->use_alien) {
      $self->_add_prereq('configure_requires', 'Alien::Libssh2')
    }
    #for my $lib ($self->alien_libs) {
    #  for my $stage (qw(build_requires requires)) {
    #    $self->_add_prereq($stage, $lib);
    #  }
    #}
  }
  return $self;
}

sub extra_flags {
  my ($self, $key, $method) = @_;
  my $super_method = "SUPER::extra_${key}_flags";
  my @flags = @{$self->$super_method || []};
  my @alien_libs = $self->alien_libs;
  print "alien_libs: @alien_libs\n";
  for my $lib ($self->alien_libs) {
    eval "require $lib; 1" or die $@;
    push @flags, $self->split_like_shell($lib->$method)
  }
  use Data::Dumper;
  print Dumper [$key, @flags];
  \@flags;
}

sub extra_compiler_flags { shift->extra_flags('compiler', 'cflags') }
sub extra_linker_flags   { shift->extra_flags('linker',   'libs'  ) }

EOC

my $builder = $class->new( module_name => 'Net::SSH2',
                           license => 'perl',
                           build_requires => { "Module::Build" => "0.42_17" } );

$builder->create_build_script;



