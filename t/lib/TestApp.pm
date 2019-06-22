package TestApp;
use Mojo::Base 'Mojolicious';

sub startup {
  my $self = shift;
  my $r    = $self->routes;

  $self->plugin('TrustedProxy');

  # Returns current value of tx->remote_address
  $r->get(
    '/ip' => sub {
      my $c = shift;
      $c->render(text => $c->tx->remote_address);
    }
  );

  # Returns current connection scheme as 'http' or 'https'
  $r->get(
    '/scheme' => sub {
      my $c = shift;
      $c->render(text => $c->req->is_secure ? 'https' : 'http');
    }
  );

  # Returns all header names
  $r->get(
    '/headers' => sub {
      my $c = shift;
      $c->render(json => $c->req->headers->names);
    }
  );

}

1;
