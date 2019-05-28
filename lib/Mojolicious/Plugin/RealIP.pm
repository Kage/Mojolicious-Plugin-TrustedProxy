package Mojolicious::Plugin::RealIP;
use Mojo::Base 'Mojolicious::Plugin';
use Net::CIDR::Lite;

# https://github.com/Kage/Mojolicious-Plugin-RealIP

our $VERSION = '0.01';

use constant DEBUG => $ENV{MOJO_REALIP_DEBUG} || 0;

sub register {
  my ($self, $app, $conf) = @_;

  $app->log->debug(sprintf('[%s] VERSION = %s', __PACKAGE__, $VERSION))
    if DEBUG;

  # Set config defaults if undefined
  $conf->{ip_headers}      //= ['x-real-ip', 'x-forwarded-for'];
  $conf->{ip_headers}        = [$conf->{ip_headers}]
    unless ref($conf->{ip_headers}) eq 'ARRAY';

  $conf->{scheme_headers}  //= ['x-ssl', 'x-forwarded-protocol'];
  $conf->{scheme_headers}    = [$conf->{scheme_headers}]
    unless ref($conf->{scheme_headers}) eq 'ARRAY';

  $conf->{trusted_sources} //= ['127.0.0.0/8', '10.0.0.0/8'];
  $conf->{trust_sources}     = [$conf->{trust_sources}]
    unless ref($conf->{trusted_sources}) eq 'ARRAY';

  $conf->{hide_headers}    //= 1;

  # Assemble trusted source CIDR map
  my $cidr = Net::CIDR::Lite->new;
  foreach my $trust (@{$conf->{trusted_sources}}) {
    if (ref($trust) eq 'ARRAY') {
      $cidr->add_any(@$trust);
    } elsif (ref($trust) eq 'HASH') {
      $cidr->add_any(values(%$trust));
    } else {
      $cidr->add_any($trust);
    }
    $cidr->clean;
  }
  $app->defaults->{'realip.conf'} = $conf;
  $app->defaults->{'realip.cidr'} = $cidr;

  # Register hook
  $app->hook(around_dispatch => sub {
    my ($next, $c) = @_;
    my $conf = $c->stash('realip.conf');
    my $cidr = $c->stash('realip.cidr');
    return $next->() unless
      defined $conf && defined $cidr && $cidr->isa('Net::CIDR::Lite');

    # Validate that the upstream source IP is within the CIDR map
    my $src_addr = '127.0.0.1';#$c->tx->remote_address;
    unless (defined $src_addr && $cidr->find($src_addr)) {
      $c->app->log->debug(sprintf(
        '[%s] %s not found in trusted_sources CIDR map',
        __PACKAGE__, $src_addr)) if DEBUG;
      return $next->();
    }

    # Set forwarded IP address from header
    foreach my $header (@{$conf->{ip_headers}}) {
      if (my $ip = $c->req->headers->header($header)) {
        $c->app->log->debug(sprintf(
          '[%s] Matched on IP header "%s" (value: "%s")',
          __PACKAGE__, $header, $ip)) if DEBUG;
        $c->tx->original_remote_address($src_addr);
        $c->tx->remote_address($ip);
        last;
      }
    }

    # Set forwarded scheme from header
    foreach my $header (@{$conf->{scheme_headers}}) {
      if (my $scheme = $c->req->headers->header($header)) {
        if (!!$scheme && $scheme !~ /\b[http|off|false]\b/i) {
          $c->app->log->debug(sprintf(
            '[%s] Matched on HTTPS header "%s" (value: "%s")',
            __PACKAGE__, $header, $scheme)) if DEBUG;
          $c->req->url->base->scheme('https');
          last;
        }
      }
    }

    # Hide headers from the rest of the application
    if (!!$conf->{hide_headers}) {
      $c->app->log->debug(sprintf(
        '[%s] Removing headers from request', __PACKAGE__)) if DEBUG;
      $c->req->headers->remove($_) foreach @{$conf->{ip_headers}};
      $c->req->headers->remove($_) foreach @{$conf->{scheme_headers}};
    }

    # Carry on :)
    $next->();
  });

}

1;
__END__
=head1 NAME

Mojolicious::Plugin::RealIP - Set the user agent remote address and connection
scheme from a trusted upstream proxy

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

  # Mojolicious
  $self->plugin('RealIP' => {
    ip_headers      => ['x-real-ip', 'x-forwarded-for'],
    scheme_headers  => ['x-ssl', 'x-forwarded-protocol'],
    trusted_sources => ['127.0.0.0/8', '10.0.0.0/8'],
    hide_headers    => 0,
  });

=head1 DESCRIPTION

L<Mojolicious::Plugin::RealIP> modifies every L<Mojolicious> request transaction
to inject the real user agent IP address and HTTP scheme only when the request
comes from trusted upstream sources. You can specify multiple request headers
where trusted upstream sources define the real user agent IP address and the
real connection scheme, or disable either, and can hide the headers from the
rest of the application if needed.

Debug logging can be enabled by setting the C<MOJO_OPENAPI_DEBUG> environment
variable.

=head1 CONFIG

=head2 ip_headers

List of zero, one, or many HTTP headers where the real user agent IP address
will be defined by the trusted upstream sources. The first matched header is
used. An empty value will disable this and keep the original scheme value.
Default is C<['x-real-ip', 'x-forwarded-for']>.

If a header is matched in the request, then C<< tx->remote_address >> is set to
the value, and C<< tx->original_remote_address >> is set to the IP address of the
upstream source.

=head2 scheme_headers

List of zero, one, or many HTTP headers where the real user agent connection
scheme will be defined by the trusted upstream sources. The first matched header
is used. An empty value will disable this and keep the original remote address
value. Default is C<['x-ssl', 'x-forwarded-protocol']>.

This tests that the header value is "truthy" but does not contain the literal
barewords C<http>, C<off>, or C<false>. If the header contains any other
"truthy" value, then C<< req->url->base->scheme >> is set to C<https>.

=head2 trusted_sources

List of one or more IP addresses or CIDR classes that are trusted upstream
sources. (B<Warning!> An empty value will trust from all IPv4 sources!) Default
is C<['127.0.0.0/8', '10.0.0.0/8']>.

Supports all IP, CIDR, and range definition types from L<Net::CIDR::Lite>.

=head2 hide_headers

Hide all headers defined in L</ip_headers> and L</scheme_headers> from the rest
of the application when coming from trusted upstream sources. Default is C<0>
(disabled).

=head1 AUTHOR

Kage <kage@kage.wtf>

=head1 BUGS

Please report any bugs or feature requests on Github:
L<https://github.com/Kage/Mojolicious-Plugin-RealIP>

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<Mojolicious::Plugin::RemoteAddr>,
L<Net::CIDR::Lite>, L<http://mojolicio.us>.

=head1 COPYRIGHT

MIT License

Copyright (c) 2019 Kage

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

=cut
