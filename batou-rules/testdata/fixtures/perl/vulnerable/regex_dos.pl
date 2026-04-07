#!/usr/bin/perl
use strict;
use warnings;
use CGI;

my $cgi = CGI->new;
my $search = $cgi->param('search');

# Vulnerable: user input in regex without quotemeta
if ($text =~ /$search/) {
    print "found\n";
}

# Vulnerable: qr with user input
my $re = qr/$search/i;
