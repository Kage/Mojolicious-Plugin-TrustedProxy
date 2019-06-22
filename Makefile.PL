use strict;
use warnings;
use utf8;
use ExtUtils::MakeMaker;

my %WriteMakefileArgs = (
  NAME           => 'Mojolicious::Plugin::TrustedProxy',
  VERSION_FROM   => 'lib/Mojolicious/Plugin/TrustedProxy.pm',
  AUTHOR         => 'Kage <kage@kage.wtf>',
  LICENSE        => 'mit',
  EXE_FILES      => [qw()],
  BUILD_REQUIRES => {},
  TEST_REQUIRES  => {'Test::More' => '0.88'},
  PREREQ_PM      => {
    'Mojolicious'        => '6.00',
    'Data::Validate::IP' => '0.27',
    'Net::CIDR::Lite'    => '0.21',
    'Net::IP::Lite'      => '0.03',
  },
  test           => {TESTS => 't/*.t'},
  META_MERGE     => {
    'dynamic_config' => 0,
    'meta-spec'      => {version => 2},
    'resources'      => {
      bugtracker => {web => 'https://github.com/kage/mojolicious-plugin-trustedproxy/issues'},
      homepage   => 'https://github.com/kage/mojolicious-plugin-trustedproxy',
      repository => {
        type => 'git',
        url  => 'https://github.com/kage/mojolicious-plugin-trustedproxy.git',
        web  => 'https://github.com/kage/mojolicious-plugin-trustedproxy',
      },
    },
    'x_contributors' => ['Kage'],
  },
  test => {TESTS => (-e 'META.yml' ? 't/*.t' : 't/*.t xt/*.t')},
);

unless (eval { ExtUtils::MakeMaker->VERSION('6.63_03') }) {
  my $test_requires = delete $WriteMakefileArgs{TEST_REQUIRES};
  @{$WriteMakefileArgs{PREREQ_PM}}{keys %$test_requires} = values %$test_requires;
}

WriteMakefile(%WriteMakefileArgs);
