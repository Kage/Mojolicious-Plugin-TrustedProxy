package Mojolicious::Plugin::TrustedProxy;

# https://github.com/Kage/Mojolicious-Plugin-TrustedProxy

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Util qw(trim monkey_patch);
use Data::Validate::IP qw(is_ipv4 is_ipv6 is_ipv4_mapped_ipv6);
use Net::CIDR::Lite;
use Net::IP::Lite qw(ip_transform);

our $VERSION = '0.05';

use constant DEBUG => $ENV{MOJO_TRUSTEDPROXY_DEBUG} || 0;

sub register {
  my ($self, $app, $conf) = @_;

  $app->log->debug(sprintf('[%s] VERSION = %s', __PACKAGE__, $VERSION))
    if DEBUG;

  # Normalize config and set defaults
  $conf->{enabled}         //= 1;

  $conf->{ip_headers}      //= ['x-forwarded-for', 'x-real-ip'];
  $conf->{ip_headers}        = [$conf->{ip_headers}]
    unless ref($conf->{ip_headers}) eq 'ARRAY';

  $conf->{scheme_headers}  //=
    ($conf->{protocol_headers} // ['x-forwarded-proto', 'x-ssl']);
  $conf->{scheme_headers}    = [$conf->{scheme_headers}]
    unless ref($conf->{scheme_headers}) eq 'ARRAY';

  $conf->{https_values}    //= ['https', 'on', '1', 'true', 'enable', 'enabled'];
  $conf->{https_values}      = [$conf->{https_values}]
    unless ref($conf->{https_values}) eq 'ARRAY';

  $conf->{parse_rfc7239}   //= ($conf->{parse_forwarded} // 1);

  $conf->{trusted_sources} //= ['127.0.0.0/8', '10.0.0.0/8'];
  $conf->{trusted_sources}   = [$conf->{trusted_sources}]
    unless ref($conf->{trusted_sources}) eq 'ARRAY';

  $conf->{hide_headers}    //= 0;

  # Monkey patch a remote_proxy_address attribute into Mojo::Transaction
  monkey_patch 'Mojo::Transaction',
    'remote_proxy_address' => sub {
      my $self = shift;
      return $self->{remote_proxy_addr} unless @_;
      $self->{remote_proxy_addr} = shift;
      return $self;
    };

  # Assemble trusted source CIDR map
  my $cidr = Net::CIDR::Lite->new;
  foreach my $trust (@{$conf->{trusted_sources}}) {
    if (ref($trust) eq 'ARRAY') {
      $cidr->add_any(@$trust); # uncoverable statement
    } else {
      $cidr->add_any($trust);
    }
    $cidr->clean;
  }
  $app->defaults(
    'trustedproxy.conf' => $conf,
    'trustedproxy.cidr' => $cidr,
  );

  # Helper: is_trusted_source - Check if IP is in the trusted_sources list
  $app->helper(is_trusted_source => sub {
    my $c    = shift;
    my $ip   = shift || $c->tx->remote_proxy_address || $c->tx->remote_address;
    my $cidr = $c->stash('trustedproxy.cidr');

    # Return undef if IP is invalid or $cidr is unusable
    return undef unless
      (is_ipv4($ip) || is_ipv6($ip)) && $cidr && $cidr->isa('Net::CIDR::Lite');

    # Transform the IP if in an RFC 4291 4to6 map
    $ip = ip_transform($ip, {convert_to => 'ipv4'}) if is_ipv4_mapped_ipv6($ip);

    # Log activity and return results
    $c->app->log->debug(sprintf(
      '[%s] Testing if IP address "%s" is in trusted sources list',
      __PACKAGE__, $ip)) if DEBUG;
    return $cidr->find($ip);
  });

  # Helper: process_ip_headers - Process and set IP from first match in
  #     ip_headers list
  $app->helper(process_ip_headers => sub {
    my $c             = shift;
    my $check_trusted = shift // 0;
    my $conf          = $c->stash('trustedproxy.conf');

    # Return undef if $check_trusted is enabled and is_trusted_source is false
    return undef if (!!$check_trusted && !$c->is_trusted_source);

    # Set forwarded IP address from first matching header
    my $match;
    foreach my $header (@{$conf->{ip_headers}}) {
      if (my $ip = $c->req->headers->header($header)) {
        $ip = trim lc $ip;
        if (lc $header eq 'x-forwarded-for') {
          my @xff = split /\s*,\s*/, $ip;
          $ip = trim $xff[0];
        }
        last unless (is_ipv4($ip) || is_ipv6($ip));
        $match = {$header => $ip};
        $c->app->log->debug(sprintf(
          '[%s] Matched on IP header "%s" (value: "%s")',
          __PACKAGE__, $header, $ip)) if DEBUG;
        $c->tx->remote_proxy_address($c->tx->remote_address);
        $c->tx->remote_address($ip);
        last;
      }
    }

    # Return matched header or 0 if no match found
    return $match || 0;
  });

  # Helper: process_scheme_headers - Process and set scheme from first match in
  #     scheme_headers list
  # Helper: process_protocol_headers - Alias of process_scheme_headers
  my $sub_process_scheme_headers = sub {
    my $c             = shift;
    my $check_trusted = shift // 0;
    my $conf          = $c->stash('trustedproxy.conf');

    # Return undef if $check_trusted is enabled and is_trusted_source is false
    return undef if (!!$check_trusted && !$c->is_trusted_source);

    # Set forwarded scheme from first matching header
    my $match;
    foreach my $header (@{$conf->{scheme_headers}}) {
      if (my $scheme = $c->req->headers->header($header)) {
        $scheme = trim lc $scheme;
        if (!!$scheme && grep { $scheme eq lc $_ } @{$conf->{https_values}}) {
          $c->app->log->debug(sprintf(
            '[%s] Matched on HTTPS header "%s" (value: "%s")',
            __PACKAGE__, $header, $scheme)) if DEBUG;
          $match = {$header => $scheme};
          $c->req->url->base->scheme('https');
          last;
        }
      }
    }

    # Return matched header or 0 if no match found
    return $match || 0;
  };
  $app->helper(process_scheme_headers   => $sub_process_scheme_headers);
  $app->helper(process_protocol_headers => $sub_process_scheme_headers);

  # Helper: process_rfc7239_header - Process and set values from an RFC-7239
  #     ("Forwarded") header
  # Helper: process_forwarded_header - Alias of process_rfc7239_header
  my $sub_process_rfc7239_header = sub {
    my $c             = shift;
    my $check_trusted = shift // 0;

    # Return undef if $check_trusted is enabled and is_trusted_source is false
    return undef if (!!$check_trusted && !$c->is_trusted_source);

    # Set values from RFC 7239 ("Forwarded") header if present
    my @matches;
    if (my $fwd = $c->req->headers->header('forwarded')) {
      $fwd = trim lc $fwd;
      $c->app->log->debug(sprintf(
        '[%s] Matched on Forwarded header (value: "%s")',
        __PACKAGE__, $fwd)) if DEBUG;
      my @pairs = map { split /\s*,\s*/, $_ } split ';', $fwd;
      my ($fwd_for, $fwd_by, $fwd_proto, $fwd_host);
      my $ipv4_mask = qr/\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/;
      my $ipv6_mask = qr/(([0-9a-fA-F]{0,4})([:|.])){2,7}([0-9a-fA-F]{0,4})/;
      foreach my $param (@pairs) {
        $param = trim $param;
        if ($param =~ /(for|by)=($ipv4_mask|$ipv6_mask)/i) {
          $fwd_for = $2 if lc $1 eq 'for';
          $fwd_by  = $2 if lc $1 eq 'by';
        } elsif ($param =~ /proto=(https?)/i) {
          $fwd_proto = $1;
        } elsif ($param =~ /host=((([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))$/i) {
          $fwd_host = $1;
        }
      }
      if ($fwd_for && (is_ipv4($fwd_for) || is_ipv6($fwd_for))) {
        $c->app->log->debug(sprintf(
          '[%s] Matched Forwarded header "for" parameter (value: "%s")',
          __PACKAGE__, $fwd_for)) if DEBUG;
        push @matches, {for => $fwd_for};
        $c->tx->remote_proxy_address($c->tx->remote_address);
        $c->tx->remote_address($fwd_for);
      }
      if ($fwd_by && (is_ipv4($fwd_by) || is_ipv6($fwd_by))) {
        $c->app->log->debug(sprintf(
          '[%s] Matched Forwarded header "by" parameter (value: "%s")',
          __PACKAGE__, $fwd_by)) if DEBUG;
        push @matches, {by => $fwd_by};
        $c->tx->remote_proxy_address($fwd_by);
      }
      if ($fwd_proto) {
        $c->app->log->debug(sprintf(
          '[%s] Matched Forwarded header "proto" parameter (value: "%s")',
          __PACKAGE__, $fwd_proto)) if DEBUG;
        push @matches, {proto => $fwd_proto};
        $c->req->url->base->scheme($fwd_proto);
      }
      if ($fwd_host) {
        $c->app->log->debug(sprintf(
          '[%s] Matched Forwarded header "host" parameter (value: "%s")',
          __PACKAGE__, $fwd_host)) if DEBUG;
        push @matches, {host => $fwd_host};
        $c->req->url->base->host($fwd_host);
      }
    }

    # Return matched RFC 7239 parameters or 0 if no matches found
    return @matches || 0;
  };
  $app->helper(process_rfc7239_header   => $sub_process_rfc7239_header);
  $app->helper(process_forwarded_header => $sub_process_rfc7239_header);

  # Helper: hide_upstream_headers - Remove any matching headers
  $app->helper(hide_upstream_headers => sub {
    my $c             = shift;
    my $check_trusted = shift // 0;
    my $conf          = $c->stash('trustedproxy.conf');

    # Return undef if $check_trusted is enabled and is_trusted_source is false
    return undef if (!!$check_trusted && !$c->is_trusted_source);

    # Remove any matching headers
    $c->app->log->debug(sprintf(
      '[%s] Removing headers from request', __PACKAGE__)) if DEBUG;
    $c->req->headers->remove($_) foreach @{$conf->{ip_headers}};
    $c->req->headers->remove($_) foreach @{$conf->{scheme_headers}};
    $c->req->headers->remove('forwarded');
    return 1;
  });

  # Register hook
  $app->hook(around_dispatch => sub {
    my ($next, $c) = @_;
    my $conf       = $c->stash('trustedproxy.conf');
    return $next->() unless defined $conf;

    # Validate that the upstream source IP is within the CIDR map
    my $src_addr = $c->tx->remote_address;
    unless (defined $src_addr && $c->is_trusted_source($src_addr)) {
      $c->app->log->debug(sprintf(
        '[%s] %s not found in trusted_sources CIDR map',
        __PACKAGE__, $src_addr)) if DEBUG;
      return $next->();
    }

    # Set forwarded scheme from first matching header
    $c->process_ip_headers;

    # Set forwarded scheme from first matching header
    $c->process_scheme_headers;

    # Set values from RFC 7239 ("Forwarded") header
    $c->process_rfc7239_header if !!$conf->{parse_rfc7239};

    # Hide headers from the rest of the application
    $c->hide_upstream_headers if !!$conf->{hide_headers};

    # Carry on :)
    $next->();
  });

}

1;
__END__

=pod

=head1 NAME

Mojolicious::Plugin::TrustedProxy - Mojolicious plugin to set the remote
address, connection scheme, and more from trusted upstream proxies

=head1 VERSION

Version 0.05

=head1 SYNOPSIS

  use Mojolicious::Lite;

  plugin 'TrustedProxy' => {
    enabled         => 1,
    ip_headers      => ['x-forwarded-for', 'x-real-ip'],
    scheme_headers  => ['x-forwarded-proto', 'x-ssl'],
    https_values    => ['https', 'on', '1', 'true', 'enable', 'enabled'],
    parse_rfc7239   => 1,
    trusted_sources => ['127.0.0.0/8', '10.0.0.0/8'],
    hide_headers    => 0,
  };

  # Example of how you could verify expected functionality
  get '/test' => sub {
    my $c = shift;
    $c->render(json => {
      'tx.remote_address'            => $c->tx->remote_address,
      'tx.remote_proxy_address'      => $c->tx->remote_proxy_address,
      'req.url.base.scheme'          => $c->req->url->base->scheme,
      'req.url.base.host'            => $c->req->url->base->host,
      'is_trusted_source'            => $c->is_trusted_source,
      'is_trusted_source("1.1.1.1")' => $c->is_trusted_source('1.1.1.1'),
    });
  };

  app->start;

=head1 DESCRIPTION

L<Mojolicious::Plugin::TrustedProxy> modifies every L<Mojolicious> request
transaction to override connecting user agent values only when the request
comes from trusted upstream sources. You can specify multiple request headers
where trusted upstream sources define the real user agent IP address or the
real connection scheme, or disable either, and can hide the headers from the
rest of the application if needed.

This plugin provides much of the same functionality as setting
C<MOJO_REVERSE_PROXY=1>, but with more granular control over what headers to
use and what upstream sources can send them. This is especially useful if your
Mojolicious app is directly exposed to the internet, or if it sits behind
multiple upstream proxies. You should therefore ensure your application does
not enable the default Mojolicious reverse proxy handler when using this plugin.

This plugin supports parsing L<RFC 7239|http://tools.ietf.org/html/rfc7239>
compliant C<Forwarded> headers, validates all IP addresses, and will
automatically convert RFC-4291 IPv4-to-IPv6 mapped values (useful for when your
Mojolicious listens on both IP versions). Please be aware that C<Forwarded>
headers are only partially supported. More information is available in L</BUGS>.

Debug logging can be enabled by setting the C<MOJO_TRUSTEDPROXY_DEBUG>
environment variable. This plugin also adds a C<remote_proxy_address>
attribute into C<Mojo::Transaction>. If a remote IP address override header is
matched from a trusted upstream proxy, then C<< tx->remote_proxy_address >>
will be set to the IP address of that proxy.

=head1 CONFIG

=head2 enabled

This allows you to load this plugin to access the L<helper|/HELPERS> functions
without automatically running the C<around_dispatch> hook on each request.
Default is C<1> (enabled).

=head2 ip_headers

List of zero, one, or many HTTP headers where the real user agent IP address
will be defined by the trusted upstream sources. The first matched header is
used. An empty value will disable this and keep the original scheme value.
Default is C<['x-forwarded-for', 'x-real-ip']>.

If a header is matched in the request, then C<< tx->remote_address >> is set to
the value, and C<< tx->remote_proxy_address >> is set to the IP address of the
upstream source.

=head2 scheme_headers

List of zero, one, or many HTTP headers where the real user agent connection
scheme will be defined by the trusted upstream sources. The first matched
header is used. An empty value will disable this and keep the original remote
address value. Default is C<['x-forwarded-proto', 'x-ssl']>.

This tests that the header value is "truthy" but does not contain the literal
barewords C<http>, C<off>, or C<false>. If the header contains any other
"truthy" value, then C<< req->url->base->scheme >> is set to C<https>.

=head2 protocol_headers

Alias for L</scheme_headers>.

=head2 https_values

List of values to consider as "truthy" when evaluating the headers in
L</scheme_headers>. Default is
C<['https', 'on', '1', 'true', 'enable', 'enabled']>.

=head2 parse_rfc7239

Enable support for parsing L<RFC 7239|http://tools.ietf.org/html/rfc7239>
compliant C<Forwarded> HTTP headers. Default is C<1> (enabled).

If a C<Forwarded> header is matched, the following actions occur with the first
semicolon-delimited group of parameters found in the header value:

=over

=item

If the C<for> parameter is found, then C<< tx->remote_address >> is set to the
first matching value.

=item

If the C<by> parameter is found, then C<< tx->remote_proxy_address >> is set
to the first matching value, otherwise it is set to the IP address of the
upstream source.

=item

If the C<proto> parameter is found, then C<< req->url->base->scheme >> is set
to the first matching value.

=item

If the C<host> parameter is found, then C<< req->url->base->host >> is set to
the first matching value.

=back

B<Note!> If enabled, the headers defined in L</ip_headers> and
L</scheme_headers> will be overridden by any corresponding values found in
the C<Forwarded> header.

=head2 parse_forwarded

Alias for L</parse_rfc7239>.

=head2 trusted_sources

List of one or more IP addresses or CIDR classes that are trusted upstream
sources. (B<Warning!> An empty value will trust from all IPv4 sources!) Default
is C<['127.0.0.0/8', '10.0.0.0/8']>.

Supports all IP, CIDR, and range definition types from L<Net::CIDR::Lite>.

=head2 hide_headers

Hide all headers defined in L</ip_headers>, L</scheme_headers>, and
C<Forwarded> from the rest of the application when coming from trusted upstream
sources. Default is C<0> (disabled).

=head1 HELPERS

=head2 is_trusted_source

  # From Controller context
  sub get_page {
    my $c = shift;
    if ($c->is_trusted_source || $c->is_trusted_source('1.2.3.4')) {
      ...
    }
  }

Validate if an IP address is in the L</trusted_sources> list. If no argument is
provided, then this helper will first check C<< tx->remote_proxy_address >>
then C<< tx->remote_address >>. Returns C<1> if in the L</trusted_sources>
list, C<0> if not, or C<undef> if the IP address is invalid.

=head2 process_ip_headers

  # From Controller context
  sub get_page {
    my $c = shift;
    my $matched_header = $c->process_ip_headers(1);
  }

Finds the first matching header from L</ip_headers> and sets
C<< tx->remote_address >> to the value (if a valid IP address), sets
C<< tx->remote_proxy_address >> to the IP address of the upstream proxy, and
returns a hash of the name and value of the matched header. Otherwise returns
C<0> if no match is found.

If any "truthy" value is passed as a parameter to this helper, it will first
run the L</is_trusted_source> helper (no arguments passed) and will return
C<undef> if it returns a false value.

B<WARNING!> Calling this helper when L</enabled> is set to true will likely
produce unexpected results.

=head2 process_scheme_headers

  # From Controller context
  sub get_page {
    my $c = shift;
    my $matched_header = $c->process_scheme_headers(1);
  }

Finds the first matching header from L</scheme_headers> and sets
C<< req->url->base->scheme >> to C<https> if the header value matches any
defined in L</https_values>, and returns a hash of the name and value of the
matched header. Otherwise returns C<0> if no match is found.

If any "truthy" value is passed as a parameter to this helper, it will first
run the L</is_trusted_source> helper (no arguments passed) and will return
C<undef> if it returns a false value.

B<WARNING!> Calling this helper when L</enabled> is set to true will likely
produce unexpected results.

=head2 process_protocol_headers

Alias for L</process_scheme_headers>.

=head2 process_rfc7239_header

  # From Controller context
  sub get_page {
    my $c = shift;
    my @matched_params = $c->process_rfc7239_header(1);
  }

Process an RFC 7239 ("Forwarded") HTTP header if found. See L</parse_rfc7239>
for more details. If the "Forwarded" header is found, this helper will return
an array of hashes of the matched RFC 7239 parameters and values, or C<0> if no
matches are found.

If any "truthy" value is passed as a parameter to this helper, it will first
run the L</is_trusted_source> helper (no arguments passed) and will return
C<undef> if it returns a false value.

B<WARNING!> Calling this helper when L</enabled> is set to true will likely
produce unexpected results.

=head2 process_forwarded_header

Alias for L</process_rfc7239_header>.

=head2 hide_upstream_headers

  # From Controller context
  sub get_page {
    my $c = shift;
    $c->hide_headers(1);
  }

Remove all headers defined in L</ip_headers>, L</scheme_headers>, and
C<Forwarded> from the request.

If any "truthy" value is passed as a parameter to this helper, it will first
run the L</is_trusted_source> helper (no arguments passed) and will return
C<undef> if it returns a false value.

=head1 CDN AND CLOUD SUPPORT

L<Mojolicious::Plugin::TrustedProxy> is compatible with assumedly all
third-party content delivery networks and cloud providers. Below is an
incomplete list of some of the most well-known providers and the recommended
L<config|/CONFIG> values to use for them.

=head2 Akamai

=over

=item ip_headers

Set L</ip_headers> to C<['true-client-ip']> (unless you set this to a different
value) and enable True Client IP in the origin server behavior for your site
property. Akamai also supports C<['x-forwarded-for']>, which is enabled by
default in L<Mojolicious::Plugin::TrustedProxy>.

=item scheme_headers

There is no known way to pass this by default with Akamai. It may be possible
to pass a custom header via a combination of a Site Property variable and a
custom behavior that injects an outgoing request header based on that variable,
but this has not been tested or confirmed.

=item trusted_sources

This is only possible if you have the
L<Site Shield|https://www.akamai.com/us/en/products/security/site-shield.jsp>
product from Akamai. If so, set L</trusted_sources> to the complete list of
IPs provided in your Site Shield map.

=back

=head2 AWS

=over

=item ip_headers

The AWS Elastic Load Balancer uses C<['x-forwarded-for']>, which is enabled by
default in L<Mojolicious::Plugin::TrustedProxy>.

=item scheme_headers

The AWS Elastic Load Balancer uses C<['x-forwarded-proto']>, which is enabled
by default in L<Mojolicious::Plugin::TrustedProxy>.

=item trusted_sources

Depending on your setup, this could be one of the C<172.x.x.x> IP addresses
or ranges within your Virtual Private Cloud, the IP address(es) of your Elastic
or Application Load Balancer, or could be the public IP ranges for your AWS
region. Go to
L<https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html> for an
updated list of AWS's IPv4 and IPv6 CIDR ranges.

=back

=head2 Cloudflare

=over

=item ip_headers

Set L</ip_headers> to C<['cf-connecting-ip']>, or C<['true-client-ip']> if
using an enterprise plan. Cloudflare also supports C<['x-forwarded-for']>,
which is enabled by default in L<Mojolicious::Plugin::TrustedProxy>.

=item scheme_headers

Cloudflare uses the C<x-forwarded-proto> header, which is enabled by default
in L<Mojolicious::Plugin::TrustedProxy>.

=item trusted_sources

Go to L<https://www.cloudflare.com/ips/> for an updated list of Cloudflare's
IPv4 and IPv6 CIDR ranges.

=back

=head1 SECURITY

Caution should be taken that you set only the L</CONFIG> values necessary for
your application in a most-common-first order, and that your upstream proxies
remove any headers you do not want passed through to your application.

For example, if you use Cloudflare and set L</ip_headers> to
C<['x-real-ip', 'cf-connecting-ip']> and did not configure Cloudflare to
remove C<x-real-ip> headers from requests, an attacker could use this trick
your application into using whatever IP he or she defines due to being passed
through your trusted proxy and the C<x-real-ip> header being the first to be
evaluated.

=head1 AUTHOR

Kage <kage I<AT> kage I<DOT> wtf>

=head1 BUGS

Please report any bugs or feature requests on Github:
L<https://github.com/Kage/Mojolicious-Plugin-TrustedProxy>

=over

=item Hostnames not supported

Excluding the C<host> parameter of RFC 7239, this plugin does not currently
support hostnames or hostname resolution and there are no plans to implement
this. If you have a use case that requires this, please feel free to submit a
pull request.

=item HTTP 'Forwarded' only partially supported

Only partial support for RFC 7239 is currently implemented, but this should
work with most common use cases. The full specification allows for complex
structures and quoting that is difficult to implement safely. Full RFC support
is expected to be implemented soon.

=back

=head1 SEE ALSO

L<Mojolicious::Plugin::RemoteAddr>, L<Mojolicious::Plugin::ClientIP::Pluggable>,
L<Mojolicious>, L<Mojolicious::Guides>, L<http://mojolicio.us>.

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
