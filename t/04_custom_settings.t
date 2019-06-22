use Mojo::Base -strict;
use Test::More;
use Mojolicious::Lite;
use Test::Mojo;

our $TEST = __FILE__;
$TEST =~ s/(?>t\/)?(.+)\.t/$1/;

plugin 'TrustedProxy' => {
  ip_headers     => ['x-foo-ip'],
  scheme_headers => ['x-foo-scheme'],
  https_values   => ['aye'],
};

# Returns current value of tx->remote_address
get '/ip' => sub {
  my $c = shift;
  $c->render(text => $c->tx->remote_address);
};

# Returns current connection scheme as 'http' or 'https'
get '/scheme' => sub {
  my $c = shift;
  $c->render(text => $c->req->is_secure ? 'https' : 'http');
};

# Test suite variables
my $t   = Test::Mojo->new;
my $tid = 0;
my $tc  = 0;

# Header X-Foo-IP
$tid++;
$tc += 3;
$t->get_ok('/ip' => {'X-Foo-IP' => '1.1.1.1'})
  ->status_is(200)->content_is('1.1.1.1', sprintf(
    '[%s.%d] Assert from header X-Foo-IP => 1.1.1.1 that tx->remote_address == 1.1.1.1',
    $TEST, $tid)
  );

# Header X-Foo-Scheme
$tid++;
$tc += 3;
$t->get_ok('/scheme' => {'X-Foo-Scheme' => 'aye'})
  ->status_is(200)->content_is('https', sprintf(
    '[%s.%d] Assert from header X-Foo-Scheme => aye that req->is_secure == true',
    $TEST, $tid)
  );

done_testing($tc);
