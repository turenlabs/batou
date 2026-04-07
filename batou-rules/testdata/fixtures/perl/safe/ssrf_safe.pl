#!/usr/bin/perl
use strict;
use warnings;
use LWP::UserAgent;
use URI;
use Data::Validate::URI qw(is_https_uri);

# Safe: URL validated via Data::Validate::URI before fetch
sub fetch_safe_url {
    my ($user_url) = @_;

    # Validate URL format and scheme
    unless (is_https_uri($user_url)) {
        die "Invalid URL: must be HTTPS";
    }

    # Parse and check host allowlist
    my $uri = URI->new($user_url);
    my %allowed_hosts = ('api.example.com' => 1, 'cdn.example.com' => 1);
    unless ($allowed_hosts{$uri->host}) {
        die "Host not in allowlist";
    }

    my $ua = LWP::UserAgent->new;
    $ua->protocols_allowed(['https']);
    my $response = $ua->get($user_url);
    return $response->decoded_content;
}
