use Mojo::Base -strict;

use Test::More;
use Mojolicious::Lite;
use Test::Mojo;

plugin 'RealIP';

get '/ip' => sub {
  my $c = shift;
  $c->render(text => $c->tx->remote_address);
};

get '/scheme' => sub {
  my $c = shift;
  $c->render(text => $c->req->is_secure ? 'https' : 'http');
};

my $t = Test::Mojo->new;

# IP from transaction
$t->get_ok('/ip')->status_is(200)->content_is('127.0.0.1', 'IP from transaction');

# Scheme from transaction
$t->get_ok('/scheme')->status_is(200)->content_is('http', 'Scheme from transaction');

# IP from X-Real-IP header
$t->ua->on(start => sub {
  my ($ua, $tx) = @_;
  $tx->req->headers->header('X-Real-IP', '1.1.1.1');
});
$t->get_ok('/ip')->status_is(200)->content_is('1.1.1.1', 'IP from X-Real-IP header');

# Scheme from X-SSL header
$t->ua->on(start => sub {
  my ($ua, $tx) = @_;
  $tx->req->headers->header('X-SSL', '1');
});
$t->get_ok('/scheme')->status_is(200)->content_is('https', 'Scheme from X-SSL header');

done_testing();
