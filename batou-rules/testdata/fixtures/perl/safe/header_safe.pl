#!/usr/bin/perl
use strict;
use warnings;
use CGI;

# Safe: CRLF stripped before setting response header
sub set_header_safe {
    my ($cgi, $user_value) = @_;

    # Strip CRLF to prevent header injection
    (my $clean_value = $user_value) =~ s/[\r\n]//g;

    print $cgi->header(
        -type     => 'text/html',
        -charset  => 'UTF-8',
        -location => $clean_value,
    );
}

# Safe: Log message sanitized
sub log_safe {
    my ($logger, $user_input) = @_;

    # Replace newlines to prevent log injection
    (my $clean = $user_input) =~ s/[\r\n]+/ /g;

    $logger->info("User action: $clean");
}
