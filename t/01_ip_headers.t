use Mojo::Base -strict;
use Test::More;
#use Mojolicious::Lite;
use Test::Mojo;

use lib::relative 'lib';

our $TEST = __FILE__;
$TEST =~ s/(?>t\/)?(.+)\.t/$1/;

# Test suite variables
my $t   = Test::Mojo->new('TestApp');
my $tid = 0;
my $tc  = 0;

# Baseline
$tid++;
$tc += 3;
$t->get_ok('/ip')
  ->status_is(200)->content_is('127.0.0.1', sprintf(
    '[%s.%d] Assert baseline that tx->remote_address == 127.0.0.1',
    $TEST, $tid)
  );

# Header: [default] X-Real-IP
$tid++;
$tc += 3;
$t->get_ok('/ip' => {'X-Real-IP' => '1.1.1.1'})
  ->status_is(200)->content_is('1.1.1.1', sprintf(
    '[%s.%d] Assert from header X-Real-IP => 1.1.1.1 that tx->remote_address == 1.1.1.1',
    $TEST, $tid)
  );

# Header: [default] X-Forwarded-For
$tid++;
$tc += 3;
$t->get_ok('/ip' => {'X-Forwarded-For' => '1.1.1.1'})
  ->status_is(200)->content_is('1.1.1.1', sprintf(
    '[%s.%d] Assert from header X-Forwarded-For => 1.1.1.1 that tx->remote_address == 1.1.1.1',
    $TEST, $tid)
  );

done_testing($tc);
