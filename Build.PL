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

sub alien_libs {
  my $self = shift;
  my $alien_libs = $self->config_data('alien_libs');
  unless (defined $alien_libs) {
    if ($self->use_alien) {
      require Alien::Libssh2::ConfigData;
      my $use_gcrypt = Alien::Libssh2::ConfigData->config('use_gcrypt');
      $alien_libs = ['Alien::Libssh2',
                     ($use_gcrypt ? 'Alien::Libgcrypt' : 'Alien::OpenSSL')];
    }
    else {
      $alien_libs = [];
    }
    $self->config_data(alien_libs => $alien_libs);
  }
  return @$alien_libs;
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

sub extra_compiler_flags {
  my $self = shift;
  my @all = $self->SUPER::extra_compiler_flags;
  unless ($self->in_Build_PL) {
    push @all, $_->cflags for $self->alien_libs_and_load;
  }
  join ' ', @all;
}

sub extra_linker_flags {
  my $self = shift;
  my @all = $self->SUPER::extra_linker_flags;
  unless ($self->in_Build_PL) {
    push @all, $_->libs for $self->alien_libs_and_load;
  }
  join ' ', @all;
}

EOC

my $builder = $class->new(module_name => 'Net::SSH2',
                          license => 'perl',
                          #extra_compiler_flags => join(' ', map $_->cflags, @alien),
                          #extra_linker_flags => join(' ', map $_->libs, @alien),
                         );

$builder->create_build_script;



