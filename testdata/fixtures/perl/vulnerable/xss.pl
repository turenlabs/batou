#!/usr/bin/perl
use strict;
use warnings;
use CGI;

my $cgi = CGI->new;

# Vulnerable: direct print of CGI param
print "Content-Type: text/html\n\n";
print "<h1>Hello " . $cgi->param('name') . "</h1>";

# Vulnerable: print with $q style
my $q = CGI->new;
print "<p>Search: " . $q->param('query') . "</p>";
