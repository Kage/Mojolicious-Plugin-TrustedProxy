use Mojo::Base -strict;
use Test::More;
use Test::Mojo;

use lib::relative 'lib';

our $TEST = __FILE__;
$TEST =~ s/(?>t\/)?(.+)\.t/$1/;

# Test suite variables
my $t   = Test::Mojo->new('TestApp');
my $tid = 0;
my $tc  = 0;

# Forwarded header remote address, also tests Forwarded override
$tid++;
$tc += 3;
$t->get_ok('/ip' => {'Forwarded' => 'for=1.1.1.1', 'X-Real-IP' => '2.2.2.2'})
  ->status_is(200)->content_is('1.1.1.1', sprintf(
    '[%s.%d] Assert from header Forward => for=1.1.1.1 that tx->remote_address == 1.1.1.1',
    $TEST, $tid)
  );

# Forwarded header proxy address
$tid++;
$tc += 3;
$t->get_ok('/proxyip' => {'Forwarded' => 'by=1.1.1.1'})
  ->status_is(200)->content_is('1.1.1.1', sprintf(
    '[%s.%d] Assert from header Forward => by=1.1.1.1 that tx->remote_proxy_address == 1.1.1.1',
    $TEST, $tid)
  );

# Forwarded header protocol
$tid++;
$tc += 3;
$t->get_ok('/scheme' => {'Forwarded' => 'proto=https', 'X-Forwarded-Proto' => 'http'})
  ->status_is(200)->content_is('https', sprintf(
    '[%s.%d] Assert from header Forwarded => proto=https that req->is_secure == true',
    $TEST, $tid)
  );

done_testing($tc);
